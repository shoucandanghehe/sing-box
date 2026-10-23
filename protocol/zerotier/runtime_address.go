//go:build with_zerotier && with_gvisor

package zerotier

import (
	"net/netip"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
)

type ipv6AddressStateTracker struct {
	ep   *Endpoint
	addr netip.Addr
}

func (t *ipv6AddressStateTracker) OnChanged(_ stack.AddressLifetimes, state stack.AddressAssignmentState) {
	if !t.addr.Is6() || t.addr.Is4In6() {
		return
	}
	t.ep.tentativeIPv6Mu.Lock()
	defer t.ep.tentativeIPv6Mu.Unlock()
	if state == stack.AddressTentative {
		t.ep.tentativeIPv6[t.addr.String()] = true
	} else {
		delete(t.ep.tentativeIPv6, t.addr.String())
	}
}

func (t *ipv6AddressStateTracker) OnRemoved(stack.AddressRemovalReason) {
	if !t.addr.Is6() || t.addr.Is4In6() {
		return
	}
	t.ep.tentativeIPv6Mu.Lock()
	delete(t.ep.tentativeIPv6, t.addr.String())
	t.ep.tentativeIPv6Mu.Unlock()
}

func (ep *Endpoint) runtimeAddressProperties(prefix netip.Prefix) stack.AddressProperties {
	if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
		return stack.AddressProperties{}
	}
	return stack.AddressProperties{Disp: &ipv6AddressStateTracker{ep: ep, addr: prefix.Addr()}}
}

func (ep *Endpoint) isTentativeRuntimeIPv6Address(addr netip.Addr) bool {
	if !addr.Is6() || addr.Is4In6() {
		return false
	}
	ep.tentativeIPv6Mu.Lock()
	defer ep.tentativeIPv6Mu.Unlock()
	return ep.tentativeIPv6[addr.String()]
}

func (ep *Endpoint) markTentativeRuntimeIPv6Address(addr netip.Addr) {
	if !addr.Is6() || addr.Is4In6() {
		return
	}
	ep.tentativeIPv6Mu.Lock()
	ep.tentativeIPv6[addr.String()] = true
	ep.tentativeIPv6Mu.Unlock()
}

func protocolAddressFromPrefix(prefix netip.Prefix) tcpip.ProtocolAddress {
	protocol := ipv6.ProtocolNumber
	if prefix.Addr().Is4() {
		protocol = ipv4.ProtocolNumber
	}
	return tcpip.ProtocolAddress{
		Protocol: protocol,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tun.AddressFromAddr(prefix.Addr()),
			PrefixLen: prefix.Bits(),
		},
	}
}

func runtimeAddressesFromPrefixes(prefixes []netip.Prefix) (tcpip.Address, tcpip.Address) {
	var addr4 tcpip.Address
	var addr6 tcpip.Address
	for _, prefix := range prefixes {
		addr := tun.AddressFromAddr(prefix.Addr())
		if prefix.Addr().Is4() {
			addr4 = addr
		} else {
			addr6 = addr
		}
	}
	return addr4, addr6
}

func (ep *Endpoint) syncRuntimeAddresses(current, next []netip.Prefix) error {
	ep.runtimeStateMu.Lock()
	defer ep.runtimeStateMu.Unlock()

	addr4, addr6 := runtimeAddressesFromPrefixes(next)
	if ep.ipStack == nil {
		ep.addr4 = addr4
		ep.addr6 = addr6
		return nil
	}

	currentByAddr := make(map[netip.Addr]netip.Prefix, len(current))
	for _, prefix := range current {
		currentByAddr[prefix.Addr()] = prefix
	}
	nextByAddr := make(map[netip.Addr]netip.Prefix, len(next))
	for _, prefix := range next {
		nextByAddr[prefix.Addr()] = prefix
	}

	var added []netip.Prefix
	rollbackAdded := func() {
		for i := len(added) - 1; i >= 0; i-- {
			_ = ep.ipStack.RemoveAddress(tun.DefaultNIC, tun.AddressFromAddr(added[i].Addr()))
		}
	}

	var replaced []netip.Prefix
	rollbackReplaced := func() {
		for _, prefix := range replaced {
			_ = ep.ipStack.AddProtocolAddress(tun.DefaultNIC, protocolAddressFromPrefix(prefix), ep.runtimeAddressProperties(prefix))
			ep.markTentativeRuntimeIPv6Address(prefix.Addr())
		}
	}

	for addr, nextPrefix := range nextByAddr {
		currentPrefix, exists := currentByAddr[addr]
		if !exists {
			if err := ep.ipStack.AddProtocolAddress(tun.DefaultNIC, protocolAddressFromPrefix(nextPrefix), ep.runtimeAddressProperties(nextPrefix)); err != nil {
				rollbackAdded()
				rollbackReplaced()
				return E.New("add address ", nextPrefix, ": ", err.String())
			}
			ep.markTentativeRuntimeIPv6Address(nextPrefix.Addr())
			added = append(added, nextPrefix)
			continue
		}
		if currentPrefix == nextPrefix {
			continue
		}
		if err := ep.ipStack.RemoveAddress(tun.DefaultNIC, tun.AddressFromAddr(addr)); err != nil {
			rollbackAdded()
			rollbackReplaced()
			return E.New("remove address ", currentPrefix, ": ", err.String())
		}
		replaced = append(replaced, currentPrefix)
		if err := ep.ipStack.AddProtocolAddress(tun.DefaultNIC, protocolAddressFromPrefix(nextPrefix), ep.runtimeAddressProperties(nextPrefix)); err != nil {
			rollbackAdded()
			rollbackReplaced()
			return E.New("add address ", nextPrefix, ": ", err.String())
		}
		ep.markTentativeRuntimeIPv6Address(nextPrefix.Addr())
		added = append(added, nextPrefix)
	}

	var removed []netip.Prefix
	rollbackRemoved := func() {
		for _, prefix := range removed {
			_ = ep.ipStack.AddProtocolAddress(tun.DefaultNIC, protocolAddressFromPrefix(prefix), ep.runtimeAddressProperties(prefix))
			ep.markTentativeRuntimeIPv6Address(prefix.Addr())
		}
	}

	for addr, currentPrefix := range currentByAddr {
		if _, keep := nextByAddr[addr]; keep {
			continue
		}
		if err := ep.ipStack.RemoveAddress(tun.DefaultNIC, tun.AddressFromAddr(addr)); err != nil {
			rollbackAdded()
			rollbackReplaced()
			rollbackRemoved()
			return E.New("remove address ", currentPrefix, ": ", err.String())
		}
		removed = append(removed, currentPrefix)
	}

	ep.addr4 = addr4
	ep.addr6 = addr6
	return nil
}

func (ep *Endpoint) runtimeBindAddresses() (tcpip.Address, tcpip.Address) {
	ep.runtimeStateMu.Lock()
	defer ep.runtimeStateMu.Unlock()
	return ep.addr4, ep.addr6
}
