//go:build with_zerotier && with_gvisor

package zerotier

import (
	"time"

	zt "github.com/scdhh/go-zt"
)

func (ep *Endpoint) runMulticastOps() {
	defer ep.clearMulticastOperations()
	for {
		select {
		case <-ep.done:
			return
		case <-ep.multicastWake:
		}
		for {
			op, ok := ep.popMulticastOperation()
			if !ok {
				break
			}
			if ep.closed.Load() {
				return
			}
			op()
		}
	}
}

func (ep *Endpoint) popMulticastOperation() (func(), bool) {
	ep.multicastOpsMu.Lock()
	defer ep.multicastOpsMu.Unlock()
	if len(ep.multicastOps) == 0 {
		return nil, false
	}
	op := ep.multicastOps[0]
	ep.multicastOps[0] = nil
	ep.multicastOps = ep.multicastOps[1:]
	return op, true
}

func (ep *Endpoint) clearMulticastOperations() {
	ep.multicastOpsMu.Lock()
	clear(ep.multicastOps)
	ep.multicastOps = nil
	ep.multicastOpsMu.Unlock()
}

func (ep *Endpoint) queueMulticastOperation(op func()) {
	if op == nil || ep.closed.Load() {
		return
	}
	ep.multicastOpsMu.Lock()
	if ep.closed.Load() {
		ep.multicastOpsMu.Unlock()
		return
	}
	ep.multicastOps = append(ep.multicastOps, op)
	ep.multicastOpsMu.Unlock()
	select {
	case ep.multicastWake <- struct{}{}:
	default:
	}
}

func (ep *Endpoint) waitForMulticastQueueDrain() {
	done := make(chan struct{})
	ep.queueMulticastOperation(func() {
		close(done)
	})
	select {
	case <-ep.done:
	case <-done:
	}
}

func (ep *Endpoint) queueMulticastGroupSubscribe(group zeroTierMulticastGroup, delay time.Duration) {
	if !ep.addMulticastGroup(group) {
		return
	}
	ep.queueMulticastOperation(func() {
		if delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-ep.done:
				return
			case <-timer.C:
			}
		}
		state := ep.currentNetworkState()
		if !ep.hasMulticastGroup(group) || state.networkClosed || state.status != zt.NetworkStatusOK || len(state.localAddresses) == 0 {
			return
		}
		ep.subscribeMulticastGroupOnNode(group, "subscribe")
	})
}

func (ep *Endpoint) queueMulticastGroupsResubscribe(delay time.Duration) {
	ep.queueMulticastOperation(func() {
		if delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-ep.done:
				return
			case <-timer.C:
			}
		}
		ep.resubscribeMulticastGroupsIfActive()
	})
}

func (ep *Endpoint) queueSpecificMulticastGroupsUnsubscribeIfClosed(groups []zeroTierMulticastGroup, delay time.Duration) {
	ep.queueMulticastOperation(func() {
		if delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-ep.done:
				return
			case <-timer.C:
			}
		}
		if !ep.currentNetworkState().networkClosed {
			return
		}
		for _, group := range groups {
			ep.unsubscribeMulticastGroupOnNode(group)
		}
	})
}

func (ep *Endpoint) queueMulticastGroupsUnsubscribeIfClosed(delay time.Duration) {
	ep.queueSpecificMulticastGroupsUnsubscribeIfClosed(ep.multicastGroupsSnapshot(), delay)
}

func (ep *Endpoint) queueMulticastGroupUnsubscribe(group zeroTierMulticastGroup, delay time.Duration) {
	ep.queueMulticastOperation(func() {
		if delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-ep.done:
				return
			case <-timer.C:
			}
		}
		ep.unsubscribeMulticastGroup(group)
	})
}

func (ep *Endpoint) queueSpecificMulticastGroupsUnsubscribe(groups []zeroTierMulticastGroup, delay time.Duration) {
	ep.queueMulticastOperation(func() {
		if delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-ep.done:
				return
			case <-timer.C:
			}
		}
		for _, group := range groups {
			state := ep.currentNetworkState()
			if !state.networkClosed && ep.hasMulticastGroup(group) {
				continue
			}
			ep.unsubscribeMulticastGroupOnNode(group)
		}
	})
}

func (ep *Endpoint) queueMulticastGroupsUnsubscribe(delay time.Duration) {
	ep.queueSpecificMulticastGroupsUnsubscribe(ep.multicastGroupsSnapshot(), delay)
}
