//go:build with_zerotier && with_gvisor

package zerotier

import (
	"encoding/binary"
	"net/netip"
	"testing"

	zt "github.com/scdhh/go-zt"
)

func ipv4BroadcastGroupForTest(addr netip.Addr) zeroTierMulticastGroup {
	bytes := addr.As4()
	return zeroTierMulticastGroup{
		mac: zeroTierBroadcastMAC,
		adi: binary.NativeEndian.Uint32(bytes[:]),
	}
}

func TestManagedMulticastGroupsSubscribeIPv4AddressADI(t *testing.T) {
	ep := newTestEndpoint(t, nil)
	defer ep.Close()
	node := &fakeNode{}
	ep.node = node
	ep.multicastLifecycleReady.Store(true)
	address := netip.MustParseAddr("10.0.0.1")

	ep.handleVirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		AssignedAddresses: []netip.Prefix{netip.PrefixFrom(address, 24)},
	})
	ep.waitForMulticastQueueDrain()

	want := ipv4BroadcastGroupForTest(address)
	if !containsMulticastCall(node.multicastSubscribeCalls(), multicastCall{nwid: ep.networkID, mac: want.mac, adi: want.adi}) {
		t.Fatalf("IPv4 broadcast group %s was not subscribed", want.String())
	}
}

func TestManagedMulticastGroupsReplaceIPv4AddressADI(t *testing.T) {
	ep := newTestEndpoint(t, nil)
	defer ep.Close()
	node := &fakeNode{}
	ep.node = node
	ep.multicastLifecycleReady.Store(true)
	oldAddress := netip.MustParseAddr("10.0.0.1")
	newAddress := netip.MustParseAddr("10.0.0.2")

	ep.handleVirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		AssignedAddresses: []netip.Prefix{netip.PrefixFrom(oldAddress, 24)},
	})
	drainAndResetMulticastCalls(ep, node)
	ep.handleVirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		AssignedAddresses: []netip.Prefix{netip.PrefixFrom(newAddress, 24)},
	})
	ep.waitForMulticastQueueDrain()

	oldGroup := ipv4BroadcastGroupForTest(oldAddress)
	newGroup := ipv4BroadcastGroupForTest(newAddress)
	if !containsMulticastCall(node.multicastUnsubscribeCalls(), multicastCall{nwid: ep.networkID, mac: oldGroup.mac, adi: oldGroup.adi}) {
		t.Fatalf("old IPv4 broadcast group %s was not unsubscribed", oldGroup.String())
	}
	if !containsMulticastCall(node.multicastSubscribeCalls(), multicastCall{nwid: ep.networkID, mac: newGroup.mac, adi: newGroup.adi}) {
		t.Fatalf("new IPv4 broadcast group %s was not subscribed", newGroup.String())
	}
}
