//go:build with_zerotier && with_gvisor

package zerotier

import (
	"fmt"
	"net/netip"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	zt "github.com/scdhh/go-zt"
)

func clonePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	cloned := make([]netip.Prefix, len(prefixes))
	copy(cloned, prefixes)
	return cloned
}

func prefixesEqual(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (ep *Endpoint) initializeNetworkState(localAddresses []netip.Prefix) {
	ep.networkState.Store(&endpointNetworkState{
		localAddresses: clonePrefixes(localAddresses),
		mtu:            ep.defaultMTU,
	})
}

func (ep *Endpoint) currentNetworkState() *endpointNetworkState {
	state := ep.networkState.Load()
	if state == nil {
		return emptyEndpointNetworkState
	}
	return state
}

func (ep *Endpoint) networkStateSnapshot() endpointNetworkState {
	state := ep.currentNetworkState()
	return endpointNetworkState{
		hasConfig:      state.hasConfig,
		networkClosed:  state.networkClosed,
		status:         state.status,
		localAddresses: clonePrefixes(state.localAddresses),
		routes:         cloneRoutes(state.routes),
		nwMac:          state.nwMac,
		mtu:            state.mtu,
	}
}

func (ep *Endpoint) applyVirtualNetworkConfig(op zt.VirtualNetworkConfigOperation, config *zt.VirtualNetworkConfig) ([]netip.Prefix, error) {
	current := ep.currentNetworkState()
	next := &endpointNetworkState{}
	publishMTU := ep.mtu.Load()

	switch op {
	case zt.VirtualNetworkConfigOperationUp, zt.VirtualNetworkConfigOperationConfigUpdate:
		next.hasConfig = true
		next.networkClosed = false
		if config != nil {
			next.status = config.Status
			next.localAddresses = clonePrefixes(config.AssignedAddresses)
			next.routes = cloneRoutes(config.Routes)
			next.nwMac = config.MAC
			if config.MTU != 0 {
				next.mtu = uint32(config.MTU)
			}
		}
		if len(next.localAddresses) == 0 {
			next.localAddresses = clonePrefixes(ep.staticAddresses)
		}
		if next.mtu == 0 {
			next.mtu = ep.defaultMTU
		}
		publishMTU = next.mtu
	case zt.VirtualNetworkConfigOperationDown, zt.VirtualNetworkConfigOperationDestroy:
		next.hasConfig = true
		next.networkClosed = true
		if config != nil {
			next.status = config.Status
		}
		publishMTU = ep.defaultMTU
	default:
		*next = *current
		next.localAddresses = clonePrefixes(current.localAddresses)
		next.routes = cloneRoutes(current.routes)
		publishMTU = current.mtu
	}

	routesChanged := !routesEqual(current.routes, next.routes)
	pendingStateChanged := !prefixesEqual(current.localAddresses, next.localAddresses) || routesChanged || current.networkClosed != next.networkClosed || current.status != next.status
	topologyChanged := pendingStateChanged || current.nwMac != next.nwMac
	if topologyChanged {
		ep.topologyGeneration.Add(1)
		defer func() {
			if topologyChanged {
				ep.topologyGeneration.Add(1)
			}
		}()
	}
	ep.pendingConfigReady.Store(!next.networkClosed && next.status == zt.NetworkStatusOK && next.nwMac != 0)
	ep.pendingConfigNWMac.Store(next.nwMac)
	defer func() {
		ep.pendingConfigReady.Store(false)
		ep.pendingConfigNWMac.Store(0)
	}()
	preJoinedDADGroups := []zeroTierMulticastGroup(nil)
	if ep.multicastLifecycleReady.Load() && ep.pendingConfigReady.Load() {
		preJoinedDADGroups = ep.ensureManagedMulticastGroups(groupsNeedingPreDADSubscriptions(current.localAddresses, next.localAddresses))
	}
	if err := ep.syncRuntimeAddresses(current.localAddresses, next.localAddresses); err != nil {
		if len(preJoinedDADGroups) > 0 {
			ep.rollbackManagedMulticastGroups(preJoinedDADGroups)
		}
		return nil, err
	}
	ep.routesMu.Lock()
	ep.routes = cloneRoutes(next.routes)
	if pendingStateChanged {
		ep.clearPendingIPv6Packets()
	}
	ep.networkState.Store(next)
	ep.routesMu.Unlock()
	if topologyChanged {
		ep.topologyGeneration.Add(1)
		topologyChanged = false
	}
	ep.mtu.Store(publishMTU)
	if op == zt.VirtualNetworkConfigOperationDown || op == zt.VirtualNetworkConfigOperationDestroy {
		ep.macTableMu.Lock()
		clear(ep.macTable)
		ep.macTableMu.Unlock()
		ep.arpPendingMu.Lock()
		clear(ep.arpPending)
		ep.arpPendingMu.Unlock()
	}
	if !prefixesEqual(current.localAddresses, next.localAddresses) {
		return clonePrefixes(next.localAddresses), nil
	}
	return nil, nil
}

func (ep *Endpoint) handleVirtualNetworkConfig(nwid uint64, op zt.VirtualNetworkConfigOperation, config *zt.VirtualNetworkConfig) int {
	status := zt.NetworkStatusRequestingConfiguration
	var mtu uint
	if config != nil {
		status = config.Status
		mtu = config.MTU
	}
	ep.logger.Info(fmt.Sprintf("network %016x %s: status=%s mtu=%d", nwid, op, status, mtu))
	ep.topologyMu.Lock()
	defer ep.topologyMu.Unlock()
	assigned, err := ep.applyVirtualNetworkConfig(op, config)
	if err != nil {
		ep.logger.Warn("failed to apply ZeroTier runtime config: ", err)
		return -1
	}
	if len(assigned) > 0 {
		ep.logger.Info(fmt.Sprint("assigned addresses: ", assigned))
	}
	if ep.multicastLifecycleReady.Load() {
		state := ep.currentNetworkState()
		removedManaged := ep.syncManagedMulticastGroups(state)
		if len(removedManaged) > 0 {
			ep.queueSpecificMulticastGroupsUnsubscribe(removedManaged, time.Millisecond)
		}
		if op == zt.VirtualNetworkConfigOperationUp || op == zt.VirtualNetworkConfigOperationConfigUpdate {
			groups := ep.multicastGroupsSnapshot()
			if len(groups) > 0 {
				ep.queueMulticastGroupsResubscribe(10 * time.Millisecond)
				ep.queueMulticastOperation(func() {
					ep.goManaged(ep.announceARP)
				})
			}
		} else if op == zt.VirtualNetworkConfigOperationDown {
			ep.queueMulticastGroupsUnsubscribeIfClosed(time.Millisecond)
		} else if op == zt.VirtualNetworkConfigOperationDestroy {
			groups := ep.multicastGroupsSnapshot()
			ep.clearMulticastGroups()
			ep.queueSpecificMulticastGroupsUnsubscribe(groups, time.Millisecond)
		}
	}
	state := ep.currentNetworkState()
	ep.logger.Info(fmt.Sprintf("routes: %d entries", len(state.routes)))
	for _, r := range state.routes {
		if r.Via.IsValid() {
			ep.logger.Info(fmt.Sprintf("  route: %s via %s (flags=%d metric=%d)", r.Target, r.Via, r.Flags, r.Metric))
		} else {
			ep.logger.Info(fmt.Sprintf("  route: %s (local, flags=%d metric=%d)", r.Target, r.Flags, r.Metric))
		}
	}
	return 0
}

func zeroTierNetworkStatusError(status zt.VirtualNetworkStatus) error {
	switch status {
	case zt.NetworkStatusAccessDenied, zt.NetworkStatusNotFound, zt.NetworkStatusPortError, zt.NetworkStatusAuthenticationRequired:
		return E.New("zerotier network status ", status.String())
	default:
		return nil
	}
}

func zeroTierNetworkStateError(state *endpointNetworkState) error {
	if state.networkClosed {
		return E.New("zerotier network closed")
	}
	return zeroTierNetworkStatusError(state.status)
}

func (ep *Endpoint) waitForNetworkReady() error {
	state := ep.currentNetworkState()
	if err := zeroTierNetworkStateError(state); err != nil {
		return err
	}
	if state.hasConfig && state.status == zt.NetworkStatusOK && len(state.localAddresses) > 0 {
		return nil
	}

	ep.logger.Info("waiting for ZeroTier network readiness")
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(60 * time.Second)
	for {
		select {
		case <-ep.done:
			return E.New("node closed while waiting for ZeroTier network readiness")
		case <-deadline:
			state = ep.currentNetworkState()
			if err := zeroTierNetworkStateError(state); err != nil {
				return err
			}
			return E.New("timeout waiting for ZeroTier network readiness")
		case <-ticker.C:
			state = ep.currentNetworkState()
			if err := zeroTierNetworkStateError(state); err != nil {
				return err
			}
			if state.hasConfig && state.status == zt.NetworkStatusOK && len(state.localAddresses) > 0 {
				return nil
			}
		}
	}
}
