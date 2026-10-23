//go:build with_zerotier && with_gvisor

package zerotier

import (
	"net/netip"
	"testing"
	"time"

	zt "github.com/scdhh/go-zt"
)

func TestResolveNextHopMACPrefersMoreSpecificLocalRoute(t *testing.T) {
	const (
		destinationMAC uint64 = 0x001122334455
		gatewayMAC     uint64 = 0x0066778899aa
	)
	ep := &Endpoint{
		routes: []zt.Route{
			{Target: netip.MustParsePrefix("10.0.0.0/8"), Via: netip.MustParseAddr("192.0.2.1")},
			{Target: netip.MustParsePrefix("10.1.0.0/16")},
		},
		macTable: map[string]macTableEntry{
			"10.1.2.3":  {mac: destinationMAC, learnedAt: time.Now()},
			"192.0.2.1": {mac: gatewayMAC, learnedAt: time.Now()},
		},
	}

	mac, found, nextHop := ep.resolveNextHopMAC("10.1.2.3")
	if !found {
		t.Fatal("destination MAC was not resolved")
	}
	if nextHop != "10.1.2.3" {
		t.Fatalf("next hop = %q, want destination address", nextHop)
	}
	if mac != destinationMAC {
		t.Fatalf("MAC = %012x, want destination MAC %012x", mac, destinationMAC)
	}
}
