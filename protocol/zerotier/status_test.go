//go:build with_zerotier && with_gvisor

package zerotier

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	zt "github.com/scdhh/go-zt"
)

func TestGetAllStatusReturnsEmptyArrayWithoutEndpoints(t *testing.T) {
	activeEndpointsMu.Lock()
	previous := activeEndpoints
	activeEndpoints = make(map[string]*Endpoint)
	activeEndpointsMu.Unlock()
	defer func() {
		activeEndpointsMu.Lock()
		activeEndpoints = previous
		activeEndpointsMu.Unlock()
	}()

	if status := GetAllStatus(); status != "[]" {
		t.Fatalf("GetAllStatus() = %q, want []", status)
	}
}

func TestClosingReplacedEndpointKeepsCurrentRegistryEntry(t *testing.T) {
	activeEndpointsMu.Lock()
	previous := activeEndpoints
	activeEndpoints = make(map[string]*Endpoint)
	activeEndpointsMu.Unlock()
	defer func() {
		activeEndpointsMu.Lock()
		activeEndpoints = previous
		activeEndpointsMu.Unlock()
	}()

	const tag = "replacement"
	oldEndpoint, err := NewEndpoint(context.Background(), nil, logger.NOP(), tag, option.ZeroTierEndpointOptions{NetworkID: "0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	currentEndpoint, err := NewEndpoint(context.Background(), nil, logger.NOP(), tag, option.ZeroTierEndpointOptions{NetworkID: "0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	old := oldEndpoint.(*Endpoint)
	current := currentEndpoint.(*Endpoint)
	activeEndpointsMu.Lock()
	activeEndpoints[tag] = current
	activeEndpointsMu.Unlock()

	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	activeEndpointsMu.RLock()
	registered := activeEndpoints[tag]
	activeEndpointsMu.RUnlock()
	if registered != current {
		t.Fatalf("closing replaced endpoint removed current registry entry: got %p, want %p", registered, current)
	}
	if err := current.Close(); err != nil {
		t.Fatal(err)
	}
}

type statusPeerNode struct {
	fakeNode
	peers []zt.Peer
}

func (n *statusPeerNode) Peers() []zt.Peer {
	return n.peers
}

func TestGetPlanetIPsAppliesFallbackPerEndpoint(t *testing.T) {
	activeEndpointsMu.Lock()
	previous := activeEndpoints
	activeEndpoints = make(map[string]*Endpoint)
	activeEndpointsMu.Unlock()
	defer func() {
		activeEndpointsMu.Lock()
		activeEndpoints = previous
		activeEndpointsMu.Unlock()
	}()

	const (
		peerIP     = "198.51.100.1"
		fallbackIP = "203.0.113.2"
	)
	peerEndpoint := &Endpoint{
		node: &statusPeerNode{peers: []zt.Peer{{
			Role: zt.PeerRolePlanet,
			Paths: []zt.PeerPhysicalPath{{
				Address: netip.MustParseAddrPort(peerIP + ":9993"),
			}},
		}}},
	}
	fallbackEndpoint := &Endpoint{
		node:        &fakeNode{},
		wireTargets: map[string]bool{fallbackIP: true},
	}
	activeEndpointsMu.Lock()
	activeEndpoints[peerIP] = peerEndpoint
	activeEndpoints[fallbackIP] = fallbackEndpoint
	activeEndpointsMu.Unlock()

	for range 100 {
		got := make(map[string]bool)
		for _, ip := range strings.Split(GetPlanetIPs(), ",") {
			got[ip] = true
		}
		if !got[peerIP] || !got[fallbackIP] {
			t.Fatalf("GetPlanetIPs() omitted per-endpoint fallback: %v", got)
		}
	}
}
