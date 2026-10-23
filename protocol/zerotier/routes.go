//go:build with_zerotier && with_gvisor

package zerotier

import (
	"net/netip"

	zt "github.com/scdhh/go-zt"
)

func cloneRoutes(routes []zt.Route) []zt.Route {
	if len(routes) == 0 {
		return nil
	}
	cloned := make([]zt.Route, len(routes))
	copy(cloned, routes)
	return cloned
}

func routesEqual(a, b []zt.Route) bool {
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

// findGateway returns the gateway IP for dstIP, if any managed route matches,
// using longest prefix match against managed routes.
func (ep *Endpoint) findGateway(dstIP netip.Addr) netip.Addr {
	ep.routesMu.RLock()
	defer ep.routesMu.RUnlock()
	return ep.findGatewayLocked(dstIP)
}

func (ep *Endpoint) findGatewayLocked(dstIP netip.Addr) netip.Addr {
	var bestGateway netip.Addr
	bestBits := -1
	for _, route := range ep.routes {
		if route.Target.Contains(dstIP) && route.Target.Bits() > bestBits {
			bestBits = route.Target.Bits()
			bestGateway = route.Via
		}
	}
	return bestGateway
}

// resolveNextHopMAC resolves the MAC address for the next hop.
// If a gateway route exists, it resolves the gateway's MAC instead of the destination's.
// Returns (mac, found, nextHopIP).
func (ep *Endpoint) resolveNextHopMAC(dstIP string) (mac uint64, found bool, nextHopIP string) {
	ep.routesMu.RLock()
	defer ep.routesMu.RUnlock()
	return ep.resolveNextHopMACLocked(dstIP)
}

func (ep *Endpoint) resolveNextHopMACLocked(dstIP string) (mac uint64, found bool, nextHopIP string) {
	nextHopIP = dstIP
	dst, err := netip.ParseAddr(dstIP)
	if err == nil {
		gw := ep.findGatewayLocked(dst)
		if gw.IsValid() {
			nextHopIP = gw.String()
		}
	}
	mac, found = ep.lookupMAC(nextHopIP)
	return
}
