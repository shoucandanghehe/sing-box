//go:build with_zerotier && with_gvisor

package zerotier

import (
	"net/netip"
	"testing"
	"time"

	zt "github.com/scdhh/go-zt"
)

func TestVirtualNetworkConfigDoesNotBlockOnQueuedMulticastOperations(t *testing.T) {
	ep := newTestEndpoint(t, nil)
	ep.node = &fakeNode{}
	ep.multicastLifecycleReady.Store(true)

	consumerEntered := make(chan struct{})
	releaseConsumer := make(chan struct{})
	ep.queueMulticastOperation(func() {
		close(consumerEntered)
		<-releaseConsumer
	})
	<-consumerEntered
	for range 64 {
		ep.queueMulticastOperation(func() {})
	}

	callbackResult := make(chan int, 1)
	go func() {
		callbackResult <- ep.handleVirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
			Status:            zt.NetworkStatusOK,
			AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		})
	}()
	defer func() {
		close(releaseConsumer)
		_ = ep.Close()
	}()

	select {
	case result := <-callbackResult:
		if result != 0 {
			t.Fatalf("callback result = %d, want success", result)
		}
	case <-time.After(time.Second):
		t.Fatal("VirtualNetworkConfig callback blocked behind multicast operations")
	}
}
