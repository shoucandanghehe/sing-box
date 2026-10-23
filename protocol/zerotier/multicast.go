//go:build with_zerotier && with_gvisor

package zerotier

import (
	"encoding/binary"
	"net/netip"
	"sort"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	zt "github.com/scdhh/go-zt"
)

func zeroTierSolicitedNodeGroup(addr netip.Addr) (zeroTierMulticastGroup, bool) {
	if !addr.Is6() || addr.Is4In6() {
		return zeroTierMulticastGroup{}, false
	}
	b := addr.As16()
	return zeroTierMulticastGroup{
		mac: zeroTierSolicitedNodeMACPrefix | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15]),
	}, true
}
func zeroTierIPv4BroadcastGroup(addr netip.Addr) (zeroTierMulticastGroup, bool) {
	if !addr.Is4() {
		return zeroTierMulticastGroup{}, false
	}
	bytes := addr.As4()
	return zeroTierMulticastGroup{
		mac: zeroTierBroadcastMAC,
		adi: binary.NativeEndian.Uint32(bytes[:]),
	}, true
}

func zeroTierMulticastGroupFromAddr(addr netip.Addr) (zeroTierMulticastGroup, bool) {
	if !addr.IsValid() || addr.IsUnspecified() {
		return zeroTierMulticastGroup{}, false
	}
	tcpipAddr := tcpip.AddrFromSlice(addr.AsSlice())
	if addr.Is4() {
		if !header.IsV4MulticastAddress(tcpipAddr) {
			return zeroTierMulticastGroup{}, false
		}
		mac, ok := macFromLinkAddress(header.EthernetAddressFromMulticastIPv4Address(tcpipAddr))
		if !ok {
			return zeroTierMulticastGroup{}, false
		}
		return zeroTierMulticastGroup{mac: mac}, true
	}
	if addr.Is6() && !addr.Is4In6() {
		if !header.IsV6MulticastAddress(tcpipAddr) {
			return zeroTierMulticastGroup{}, false
		}
		mac, ok := macFromLinkAddress(header.EthernetAddressFromMulticastIPv6Address(tcpipAddr))
		if !ok {
			return zeroTierMulticastGroup{}, false
		}
		return zeroTierMulticastGroup{mac: mac}, true
	}
	return zeroTierMulticastGroup{}, false
}

func (ep *Endpoint) multicastGroupsSnapshot() []zeroTierMulticastGroup {
	ep.multicastGroupsMu.Lock()
	defer ep.multicastGroupsMu.Unlock()

	groups := make([]zeroTierMulticastGroup, 0, len(ep.multicastGroups))
	for group, refs := range ep.multicastGroups {
		if refs.active() {
			groups = append(groups, group)
		}
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].mac != groups[j].mac {
			return groups[i].mac < groups[j].mac
		}
		return groups[i].adi < groups[j].adi
	})
	return groups
}

func (ep *Endpoint) addMulticastGroup(group zeroTierMulticastGroup) bool {
	ep.multicastGroupsMu.Lock()
	defer ep.multicastGroupsMu.Unlock()
	refs := ep.multicastGroups[group]
	wasActive := refs.active()
	refs.dynamic++
	ep.multicastGroups[group] = refs
	return !wasActive
}

func (ep *Endpoint) removeMulticastGroup(group zeroTierMulticastGroup) bool {
	ep.multicastGroupsMu.Lock()
	defer ep.multicastGroupsMu.Unlock()
	refs, exists := ep.multicastGroups[group]
	if !exists || refs.dynamic == 0 {
		return false
	}
	refs.dynamic--
	if !refs.active() {
		delete(ep.multicastGroups, group)
		return true
	}
	ep.multicastGroups[group] = refs
	return false
}

func (ep *Endpoint) setReportedMulticastGroupMembership(group zeroTierMulticastGroup, joined bool) {
	ep.multicastGroupsMu.Lock()
	refs := ep.multicastGroups[group]
	wasActive := refs.active()
	refs.reported = joined
	isActive := refs.active()
	if isActive {
		ep.multicastGroups[group] = refs
	} else {
		delete(ep.multicastGroups, group)
	}
	ep.multicastGroupsMu.Unlock()
	if joined {
		if !wasActive && isActive {
			ep.subscribeMulticastGroupOnNode(group, "subscribe")
		}
	} else if wasActive && !isActive {
		ep.unsubscribeMulticastGroupOnNode(group)
	}
}

func (ep *Endpoint) hasMulticastGroup(group zeroTierMulticastGroup) bool {
	ep.multicastGroupsMu.Lock()
	defer ep.multicastGroupsMu.Unlock()
	refs, exists := ep.multicastGroups[group]
	return exists && refs.active()
}

func (ep *Endpoint) clearMulticastGroups() {
	ep.multicastGroupsMu.Lock()
	defer ep.multicastGroupsMu.Unlock()
	clear(ep.multicastGroups)
}

func (ep *Endpoint) subscribeMulticastGroupOnNode(group zeroTierMulticastGroup, action string) {
	ep.withNode(func(node zeroTierNode) {
		if err := node.MulticastSubscribe(ep.networkID, group.mac, group.adi); err != nil {
			ep.logger.Warn("failed to ", action, " multicast group ", group.String(), ": ", err)
		} else {
			ep.logger.Info(action, "d multicast group ", group.String())
		}
	})
}

func (ep *Endpoint) unsubscribeMulticastGroupOnNode(group zeroTierMulticastGroup) {
	ep.withNode(func(node zeroTierNode) {
		if err := node.MulticastUnsubscribe(ep.networkID, group.mac, group.adi); err != nil {
			ep.logger.Warn("failed to unsubscribe from multicast group ", group.String(), ": ", err)
		} else {
			ep.logger.Info("unsubscribed from multicast group ", group.String())
		}
	})
}

func (ep *Endpoint) subscribeMulticastGroup(group zeroTierMulticastGroup) {
	if !ep.addMulticastGroup(group) {
		return
	}
	ep.subscribeMulticastGroupOnNode(group, "subscribe")
}

func (ep *Endpoint) unsubscribeMulticastGroup(group zeroTierMulticastGroup) {
	if !ep.removeMulticastGroup(group) {
		return
	}
	ep.unsubscribeMulticastGroupOnNode(group)
}

func (ep *Endpoint) resubscribeMulticastGroupsIfActive() {
	state := ep.currentNetworkState()
	if state.networkClosed || state.status != zt.NetworkStatusOK || len(state.localAddresses) == 0 {
		return
	}
	for _, group := range ep.multicastGroupsSnapshot() {
		ep.subscribeMulticastGroupOnNode(group, "re-subscribe")
	}
}

func desiredManagedMulticastGroupCounts(state *endpointNetworkState) map[zeroTierMulticastGroup]int {
	if state.networkClosed || state.status != zt.NetworkStatusOK || len(state.localAddresses) == 0 {
		return nil
	}
	counts := map[zeroTierMulticastGroup]int{
		zeroTierBroadcastGroup: 1,
	}
	hasIPv6 := false
	for _, prefix := range state.localAddresses {
		addr := prefix.Addr()
		if group, ok := zeroTierIPv4BroadcastGroup(addr); ok {
			counts[group]++
		}
		if group, ok := zeroTierSolicitedNodeGroup(addr); ok {
			counts[group]++
			hasIPv6 = true
		}
	}
	if hasIPv6 {
		counts[zeroTierIPv6AllNodesGroup] = 1
	}
	return counts
}

func groupsNeedingPreDADSubscriptions(current, next []netip.Prefix) []zeroTierMulticastGroup {
	currentIPv6 := make(map[netip.Addr]struct{}, len(current))
	for _, prefix := range current {
		addr := prefix.Addr()
		if addr.Is6() && !addr.Is4In6() {
			currentIPv6[addr] = struct{}{}
		}
	}
	groupSet := make(map[zeroTierMulticastGroup]struct{})
	for _, prefix := range next {
		addr := prefix.Addr()
		if !addr.Is6() || addr.Is4In6() {
			continue
		}
		if _, exists := currentIPv6[addr]; exists {
			continue
		}
		groupSet[zeroTierIPv6AllNodesGroup] = struct{}{}
		if group, ok := zeroTierSolicitedNodeGroup(addr); ok {
			groupSet[group] = struct{}{}
		}
	}
	groups := make([]zeroTierMulticastGroup, 0, len(groupSet))
	for group := range groupSet {
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].mac != groups[j].mac {
			return groups[i].mac < groups[j].mac
		}
		return groups[i].adi < groups[j].adi
	})
	return groups
}

func (ep *Endpoint) ensureManagedMulticastGroups(groups []zeroTierMulticastGroup) []zeroTierMulticastGroup {
	ep.multicastGroupsMu.Lock()
	newlyManaged := make([]zeroTierMulticastGroup, 0, len(groups))
	newlyActive := make([]zeroTierMulticastGroup, 0, len(groups))
	for _, group := range groups {
		refs := ep.multicastGroups[group]
		if refs.managed > 0 {
			continue
		}
		wasActive := refs.active()
		refs.managed = 1
		ep.multicastGroups[group] = refs
		newlyManaged = append(newlyManaged, group)
		if !wasActive {
			newlyActive = append(newlyActive, group)
		}
	}
	ep.multicastGroupsMu.Unlock()
	for _, group := range newlyActive {
		group := group
		ep.queueMulticastOperation(func() {
			ep.subscribeMulticastGroupOnNode(group, "subscribe")
		})
	}
	return newlyManaged
}

func (ep *Endpoint) rollbackManagedMulticastGroups(groups []zeroTierMulticastGroup) {
	ep.multicastGroupsMu.Lock()
	deactivate := make([]zeroTierMulticastGroup, 0, len(groups))
	for _, group := range groups {
		refs, exists := ep.multicastGroups[group]
		if !exists || refs.managed == 0 {
			continue
		}
		refs.managed--
		if refs.active() {
			ep.multicastGroups[group] = refs
		} else {
			delete(ep.multicastGroups, group)
			deactivate = append(deactivate, group)
		}
	}
	ep.multicastGroupsMu.Unlock()
	for _, group := range deactivate {
		group := group
		ep.queueMulticastOperation(func() {
			ep.unsubscribeMulticastGroupOnNode(group)
		})
	}
}

func desiredManagedMulticastGroups(state *endpointNetworkState) []zeroTierMulticastGroup {
	counts := desiredManagedMulticastGroupCounts(state)
	groups := make([]zeroTierMulticastGroup, 0, len(counts))
	for group := range counts {
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].mac != groups[j].mac {
			return groups[i].mac < groups[j].mac
		}
		return groups[i].adi < groups[j].adi
	})
	return groups
}

func (ep *Endpoint) syncManagedMulticastGroups(state *endpointNetworkState) []zeroTierMulticastGroup {
	desiredCounts := desiredManagedMulticastGroupCounts(state)

	ep.multicastGroupsMu.Lock()
	defer ep.multicastGroupsMu.Unlock()

	newRefs := make(map[zeroTierMulticastGroup]zeroTierMulticastGroupRef, len(ep.multicastGroups)+len(desiredCounts))
	for group, refs := range ep.multicastGroups {
		if refs.dynamic > 0 || refs.reported {
			newRefs[group] = zeroTierMulticastGroupRef{dynamic: refs.dynamic, reported: refs.reported}
		}
	}
	for group, count := range desiredCounts {
		refs := newRefs[group]
		refs.managed = count
		newRefs[group] = refs
	}

	removed := make([]zeroTierMulticastGroup, 0)
	for group, refs := range ep.multicastGroups {
		if !refs.active() {
			continue
		}
		if nextRefs, keep := newRefs[group]; keep && nextRefs.active() {
			continue
		}
		removed = append(removed, group)
	}
	sort.Slice(removed, func(i, j int) bool {
		if removed[i].mac != removed[j].mac {
			return removed[i].mac < removed[j].mac
		}
		return removed[i].adi < removed[j].adi
	})
	ep.multicastGroups = newRefs
	return removed
}
