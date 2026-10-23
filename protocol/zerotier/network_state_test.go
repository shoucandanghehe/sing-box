//go:build with_zerotier && with_gvisor

package zerotier

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-tun"
	zt "github.com/scdhh/go-zt"
)

func TestVirtualNetworkConfigReturnsFailureWhenRuntimeApplyFails(t *testing.T) {
	ep := newTestEndpoint(t, nil)
	defer ep.Close()
	if err := ep.createStack(); err != nil {
		t.Fatal(err)
	}
	address := netip.MustParsePrefix("10.0.0.1/24")
	if err := ep.ipStack.AddProtocolAddress(tun.DefaultNIC, protocolAddressFromPrefix(address), ep.runtimeAddressProperties(address)); err != nil {
		t.Fatalf("seed duplicate runtime address: %s", err)
	}

	result := ep.handleVirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		AssignedAddresses: []netip.Prefix{address},
	})
	if result == 0 {
		t.Fatal("VirtualNetworkConfig reported success after runtime address apply failed")
	}
	if state := ep.currentNetworkState(); len(state.localAddresses) != 0 {
		t.Fatalf("failed runtime config was published: %v", state.localAddresses)
	}
}
