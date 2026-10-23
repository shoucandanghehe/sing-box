//go:build with_zerotier && with_gvisor

package zerotier

import (
	"net/netip"
	"testing"
	"time"

	zt "github.com/scdhh/go-zt"
)

func TestLearnMACAcceptsOnlyReachableNeighborSources(t *testing.T) {
	ep := newTestEndpoint(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	defer ep.Close()
	ep.routes = []zt.Route{{
		Target: netip.MustParsePrefix("203.0.113.0/24"),
		Via:    netip.MustParseAddr("192.0.2.1"),
	}}

	allowed := []netip.Addr{
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("fe80::1234"),
		netip.MustParseAddr("192.0.2.1"),
	}
	for index, addr := range allowed {
		mac := uint64(index + 1)
		ep.learnMAC(addr, mac)
		learned, found, _ := ep.resolveNextHopMAC(addr.String())
		if !found || learned != mac {
			t.Fatalf("reachable source %s was not learned", addr)
		}
	}

	rejected := netip.MustParseAddr("198.51.100.7")
	ep.learnMAC(rejected, 0x1234)
	if _, found, _ := ep.resolveNextHopMAC(rejected.String()); found {
		t.Fatalf("off-link source %s was learned", rejected)
	}
}

func TestLearnMACBoundsNeighborCache(t *testing.T) {
	ep := newTestEndpoint(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/8")})
	defer ep.Close()

	for index := 0; index <= maxMACTableEntries; index++ {
		addr := netip.AddrFrom4([4]byte{10, byte(index >> 16), byte(index >> 8), byte(index)})
		ep.learnMAC(addr, uint64(index+1))
	}
	if size := len(ep.macTable); size != maxMACTableEntries {
		t.Fatalf("neighbor cache size = %d, want %d", size, maxMACTableEntries)
	}
}

func TestResolveNextHopMACExpiresStaleEntries(t *testing.T) {
	ep := newTestEndpoint(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	defer ep.Close()

	now := time.Unix(1_700_000_000, 0)
	ep.macTableNow = func() time.Time { return now }
	neighbor := netip.MustParseAddr("10.0.0.2")
	ep.learnMAC(neighbor, 0x1234)
	now = now.Add(macTableEntryTTL + time.Nanosecond)

	if _, found, _ := ep.resolveNextHopMAC(neighbor.String()); found {
		t.Fatal("expired neighbor cache entry was returned")
	}
	if size := len(ep.macTable); size != 0 {
		t.Fatalf("expired neighbor cache entry was retained: size=%d", size)
	}
}
