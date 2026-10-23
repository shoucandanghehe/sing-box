//go:build with_zerotier && with_gvisor

package zerotier

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/icmp"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	zt "github.com/scdhh/go-zt"
	"github.com/stretchr/testify/require"
)

func TestEndpointApplyVirtualNetworkConfigConcurrentReads(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	ep.initializeNetworkState([]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})

	stop := make(chan struct{})
	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		for i := uint64(1); ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
				Status:            zt.NetworkStatusOK,
				MAC:               i,
				AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
			})
		}
	}()

	var readers sync.WaitGroup
	for range 8 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				state := ep.networkStateSnapshot()
				_ = state.status
				_ = state.nwMac
				_ = state.mtu
				_ = len(state.localAddresses)
				_ = len(state.routes)
			}
		}()
	}

	time.Sleep(100 * time.Millisecond)
	close(stop)
	writers.Wait()
	readers.Wait()

	state := ep.networkStateSnapshot()
	require.Equal(t, zt.NetworkStatusOK, state.status)
	require.NotZero(t, state.nwMac)
	require.NotEmpty(t, state.localAddresses)
}

func TestZtLinkEndpointMTUConcurrentWithConfigUpdates(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	ep.initializeNetworkState([]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	stop := make(chan struct{})
	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		for i := uint64(0); ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
				Status:            zt.NetworkStatusOK,
				MAC:               0x112233445566 + i,
				MTU:               uint(1400 + (i % 64)),
				AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
			})
		}
	}()

	le := (*ztLinkEndpoint)(ep)
	var readers sync.WaitGroup
	for range 8 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = le.MTU()
			}
		}()
	}

	time.Sleep(150 * time.Millisecond)
	close(stop)
	writers.Wait()
	readers.Wait()

	require.NotZero(t, le.MTU())
}

func TestEndpointDispatcherConcurrentAttachAndFrameDelivery(t *testing.T) {
	t.Parallel()

	localPrefix := netip.MustParsePrefix("10.0.0.1/24")
	peerIP := netip.MustParseAddr("10.0.0.2")
	ep := newTestEndpoint(t, []netip.Prefix{localPrefix})
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	frame := buildIPv4UDPDatagram(t, peerIP, localPrefix.Addr())
	primary := &fakeNetworkDispatcher{}
	secondary := &fakeNetworkDispatcher{}

	stop := make(chan struct{})
	le := (*ztLinkEndpoint)(ep)
	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				le.Attach(primary)
			} else {
				le.Attach(secondary)
			}
		}
	}()

	var readers sync.WaitGroup
	for range 8 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ep.onVirtualNetworkFrame(ep.networkID, 0x010203040506, 0, 0x0800, 0, append([]byte(nil), frame...))
			}
		}()
	}

	time.Sleep(150 * time.Millisecond)
	close(stop)
	writers.Wait()
	readers.Wait()

	require.NotZero(t, primary.deliveries.Load()+secondary.deliveries.Load())
}

func TestEndpointApplyVirtualNetworkConfigReplacesAddressesAndMTU(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	require.NoError(t, ep.createStack())
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	routes := []zt.Route{{Target: netip.MustParsePrefix("192.168.0.0/16"), Via: netip.MustParseAddr("10.0.1.1")}}
	assigned, err := ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		MTU:               1500,
		AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("10.0.1.5/24"), netip.MustParsePrefix("fd00::5/64")},
		Routes:            routes,
	})
	require.NoError(t, err)

	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.0.1.5/24"), netip.MustParsePrefix("fd00::5/64")}, assigned)
	state := ep.networkStateSnapshot()
	require.True(t, state.hasConfig)
	require.Equal(t, zt.NetworkStatusOK, state.status)
	require.Equal(t, uint32(1500), state.mtu)
	require.Equal(t, uint64(0x112233445566), state.nwMac)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.0.1.5/24"), netip.MustParsePrefix("fd00::5/64")}, state.localAddresses)
	require.Equal(t, routes, state.routes)
	require.Equal(t, tcpip.AddrFromSlice(netip.MustParseAddr("10.0.1.5").AsSlice()), ep.addr4)
	require.Equal(t, tcpip.AddrFromSlice(netip.MustParseAddr("fd00::5").AsSlice()), ep.addr6)
	requireProtocolAddresses(t, ep, []netip.Prefix{netip.MustParsePrefix("10.0.1.5/24"), netip.MustParsePrefix("fd00::5/64")})
}

func TestEndpointApplyVirtualNetworkConfigDownAndDestroyClearRuntimeState(t *testing.T) {
	t.Parallel()

	for _, op := range []zt.VirtualNetworkConfigOperation{zt.VirtualNetworkConfigOperationDown, zt.VirtualNetworkConfigOperationDestroy} {
		t.Run(op.String(), func(t *testing.T) {
			ep := newTestEndpoint(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
			require.NoError(t, ep.createStack())
			t.Cleanup(func() {
				require.NoError(t, ep.Close())
			})

			node := &fakeNode{}
			ep.node = node
			ep.multicastLifecycleReady.Store(true)
			ep.handleVirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
				Status:            zt.NetworkStatusOK,
				MAC:               0x112233445566,
				MTU:               1500,
				AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("10.0.1.5/24"), netip.MustParsePrefix("fd00::5/64")},
				Routes:            []zt.Route{{Target: netip.MustParsePrefix("192.168.0.0/16")}},
			})
			ep.macTableMu.Lock()
			ep.macTable["10.0.1.1"] = macTableEntry{mac: 0xaabbccddeeff, learnedAt: time.Now()}
			ep.macTableMu.Unlock()
			ep.arpPendingMu.Lock()
			ep.arpPending["10.0.1.1"] = time.Now()
			ep.arpPendingMu.Unlock()

			ep.handleVirtualNetworkConfig(ep.networkID, op, &zt.VirtualNetworkConfig{Status: zt.NetworkStatusRequestingConfiguration})

			state := ep.networkStateSnapshot()
			require.True(t, state.hasConfig)
			require.True(t, state.networkClosed)
			require.Equal(t, zt.NetworkStatusRequestingConfiguration, state.status)
			require.Zero(t, state.nwMac)
			require.Zero(t, state.mtu)
			require.Empty(t, state.localAddresses)
			require.Empty(t, state.routes)
			require.Equal(t, tcpip.Address{}, ep.addr4)
			require.Equal(t, tcpip.Address{}, ep.addr6)
			requireProtocolAddresses(t, ep, nil)
			ep.macTableMu.RLock()
			require.Empty(t, ep.macTable)
			ep.macTableMu.RUnlock()
			ep.arpPendingMu.Lock()
			require.Empty(t, ep.arpPending)
			ep.arpPendingMu.Unlock()
			require.Eventually(t, func() bool {
				for _, call := range node.multicastUnsubscribeCalls() {
					if call == (multicastCall{nwid: ep.networkID, mac: 0xffffffffffff, adi: 0}) {
						return true
					}
				}
				return false
			}, time.Second, 10*time.Millisecond)
		})
	}
}

func TestEndpointApplyVirtualNetworkConfigDoesNotPublishStateBeforeRuntimeSync(t *testing.T) {
	t.Parallel()

	oldAddress := netip.MustParsePrefix("10.0.0.1/24")
	newAddress := netip.MustParsePrefix("10.0.1.5/24")
	ep := newTestEndpoint(t, []netip.Prefix{oldAddress})
	require.NoError(t, ep.createStack())
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x111111111111,
		MTU:               1400,
		AssignedAddresses: []netip.Prefix{oldAddress},
		Routes:            []zt.Route{{Target: netip.MustParsePrefix("192.168.0.0/16")}},
	})
	require.Nil(t, ep.ipStack.AddProtocolAddress(tun.DefaultNIC, protocolAddressFromPrefix(newAddress), stack.AddressProperties{}))

	assigned, err := ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x222222222222,
		MTU:               1500,
		AssignedAddresses: []netip.Prefix{newAddress},
		Routes:            []zt.Route{{Target: netip.MustParsePrefix("198.51.100.0/24")}},
	})
	require.Error(t, err)

	require.Nil(t, assigned)
	state := ep.networkStateSnapshot()
	require.Equal(t, uint64(0x111111111111), state.nwMac)
	require.Equal(t, uint32(1400), state.mtu)
	require.Equal(t, []netip.Prefix{oldAddress}, state.localAddresses)
	require.Equal(t, []zt.Route{{Target: netip.MustParsePrefix("192.168.0.0/16")}}, state.routes)
	require.Equal(t, tcpip.AddrFromSlice(oldAddress.Addr().AsSlice()), ep.addr4)
	requireProtocolAddressesContain(t, ep, oldAddress)
}

func TestEndpointApplyVirtualNetworkConfigUpdatesPrefixLengthForSameAddress(t *testing.T) {
	t.Parallel()

	oldPrefix := netip.MustParsePrefix("10.0.0.1/24")
	newPrefix := netip.MustParsePrefix("10.0.0.1/16")
	ep := newTestEndpoint(t, []netip.Prefix{oldPrefix})
	require.NoError(t, ep.createStack())
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	assigned, err := ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x333333333333,
		MTU:               1500,
		AssignedAddresses: []netip.Prefix{newPrefix},
	})
	require.NoError(t, err)

	require.Equal(t, []netip.Prefix{newPrefix}, assigned)
	state := ep.networkStateSnapshot()
	require.Equal(t, []netip.Prefix{newPrefix}, state.localAddresses)
	requireProtocolAddresses(t, ep, []netip.Prefix{newPrefix})
	require.Equal(t, tcpip.AddrFromSlice(newPrefix.Addr().AsSlice()), ep.addr4)
}

func TestEndpointApplyVirtualNetworkConfigRollbackRestoresReplacedPrefix(t *testing.T) {
	t.Parallel()

	oldPrefix := netip.MustParsePrefix("10.0.0.1/24")
	replacedPrefix := netip.MustParsePrefix("10.0.0.1/16")
	failingAddedPrefix := netip.MustParsePrefix("10.0.2.5/24")
	ep := newTestEndpoint(t, []netip.Prefix{oldPrefix})
	require.NoError(t, ep.createStack())
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	// Preload the would-be added address so AddProtocolAddress fails during the update.
	require.Nil(t, ep.ipStack.AddProtocolAddress(tun.DefaultNIC, protocolAddressFromPrefix(failingAddedPrefix), stack.AddressProperties{}))

	assigned, err := ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		AssignedAddresses: []netip.Prefix{replacedPrefix, failingAddedPrefix},
	})
	require.Error(t, err)

	require.Nil(t, assigned)
	state := ep.networkStateSnapshot()
	require.Equal(t, []netip.Prefix{oldPrefix}, state.localAddresses)
	requireProtocolAddressesContain(t, ep, oldPrefix)
	require.Equal(t, tcpip.AddrFromSlice(oldPrefix.Addr().AsSlice()), ep.addr4)
}

func TestEndpointStartReturnsStatusErrors(t *testing.T) {
	t.Parallel()

	statuses := []zt.VirtualNetworkStatus{
		zt.NetworkStatusAccessDenied,
		zt.NetworkStatusNotFound,
		zt.NetworkStatusPortError,
		zt.NetworkStatusAuthenticationRequired,
	}
	for _, status := range statuses {
		t.Run(status.String(), func(t *testing.T) {
			ep := newTestEndpoint(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
			socket := &fakePacketConn{}
			node := &fakeNode{joinHook: func(n *fakeNode) error {
				n.callbacks.VirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{Status: status})
				return nil
			}}
			ep.listenUDP = func() (udpPacketConn, error) { return socket, nil }
			ep.newNode = func(callbacks zt.NodeCallbacks, _ *zt.NodeConfig) (zeroTierNode, error) {
				node.callbacks = callbacks
				return node, nil
			}
			ep.createStackFn = func() error {
				t.Fatal("createStack should not run for terminal network status")
				return nil
			}

			scope := adapter.NewScope(ep.ctx, ep.logger)
			t.Cleanup(func() { require.NoError(t, scope.Close()) })
			require.NoError(t, scope.Start(ep.Tag(), ep, adapter.StartStateInitialize))
			err := scope.Start(ep.Tag(), ep, adapter.StartStateStart)
			require.Error(t, err)
			require.ErrorContains(t, err, status.String())
			require.True(t, socket.closed.Load())
			require.True(t, node.closed.Load())
		})
	}
}

func TestHandleVirtualNetworkConfigQueuesBroadcastSubscribeAsync(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	blocked := make(chan struct{})
	release := make(chan struct{})
	var blockedOnce sync.Once
	node := &fakeNode{
		multicastSubscribeHook: func(multicastCall) error {
			blockedOnce.Do(func() {
				close(blocked)
			})
			<-release
			return nil
		},
	}
	ep.node = node
	ep.multicastLifecycleReady.Store(true)

	done := make(chan struct{})
	go func() {
		ep.handleVirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
			Status:            zt.NetworkStatusOK,
			AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("VirtualNetworkConfig callback blocked on multicast subscribe")
	}
	close(release)
	require.Eventually(t, func() bool {
		return len(node.multicastSubscribeCalls()) >= 1
	}, time.Second, 10*time.Millisecond)
}

func TestGetStatusReturnsMinimalSnapshotWhileCloseInProgress(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	node := &closeSensitiveNode{
		fakeNode:     &fakeNode{},
		closeStarted: make(chan struct{}),
		releaseClose: make(chan struct{}),
	}
	ep.node = node

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- ep.Close()
	}()

	<-node.closeStarted

	var status StatusInfo
	require.NotPanics(t, func() {
		status = ep.getStatus()
	})
	require.Equal(t, ep.Tag(), status.Tag)
	require.Equal(t, fmt.Sprintf("%016x", ep.networkID), status.NetworkID)
	require.Empty(t, status.NodeID)
	require.Empty(t, status.Peers)
	require.Empty(t, status.Routes)

	close(node.releaseClose)
	require.NoError(t, <-closeDone)
}

func TestCurrentARPAnnouncementStateRequiresOKStatus(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusRequestingConfiguration,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
	})

	_, _, ok := ep.currentARPAnnouncementState()
	require.False(t, ok)
}

func TestHandleARPIgnoresInvalidSenderIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		srcMAC    uint64
		senderMAC [6]byte
		senderIP  [4]byte
		key       string
	}{
		{
			name:      "unspecified sender ip",
			srcMAC:    0x010203040506,
			senderMAC: [6]byte{1, 2, 3, 4, 5, 6},
			senderIP:  [4]byte{0, 0, 0, 0},
			key:       "0.0.0.0",
		},
		{
			name:      "multicast sender ip",
			srcMAC:    0x010203040506,
			senderMAC: [6]byte{1, 2, 3, 4, 5, 6},
			senderIP:  [4]byte{224, 0, 0, 1},
			key:       "224.0.0.1",
		},
		{
			name:      "zero sender mac",
			srcMAC:    0,
			senderMAC: [6]byte{},
			senderIP:  [4]byte{10, 0, 0, 9},
			key:       "10.0.0.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := &Endpoint{logger: logger.NOP(), macTable: make(map[string]macTableEntry)}
			arp := make([]byte, 28)
			arp[0], arp[1] = 0x00, 0x01
			arp[2], arp[3] = 0x08, 0x00
			arp[4], arp[5] = 6, 4
			arp[6], arp[7] = 0x00, 0x01
			copy(arp[8:14], tt.senderMAC[:])
			copy(arp[14:18], tt.senderIP[:])
			arp[24], arp[25], arp[26], arp[27] = 10, 0, 0, 2

			ep.handleARP(tt.srcMAC, arp)
			ep.macTableMu.RLock()
			_, present := ep.macTable[tt.key]
			ep.macTableMu.RUnlock()
			require.False(t, present)
		})
	}
}
func TestEndpointWaitForNetworkReadyReturnsClosedOnNetworkDown(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationDown, &zt.VirtualNetworkConfig{Status: zt.NetworkStatusRequestingConfiguration})

	err := ep.waitForNetworkReady()
	require.Error(t, err)
	require.ErrorContains(t, err, "zerotier network closed")
}

func TestEndpointWaitForNetworkReadyReturnsWhenDoneCloses(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	t.Cleanup(func() {
		ep.managed.Wait()
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- ep.waitForNetworkReady()
	}()

	time.Sleep(20 * time.Millisecond)
	close(ep.done)

	select {
	case err := <-errCh:
		require.Error(t, err)
		require.ErrorContains(t, err, "node closed")
	case <-time.After(200 * time.Millisecond):
		t.Fatal("waitForNetworkReady did not return promptly after done closed")
	}
}

func TestEndpointResubscribeMulticastGroupsSkipsClosedNetwork(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	node := &fakeNode{}
	ep.node = node
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationDown, &zt.VirtualNetworkConfig{Status: zt.NetworkStatusRequestingConfiguration})

	ep.resubscribeMulticastGroupsIfActive()
	require.Empty(t, node.multicastSubscribeCalls())
}

func TestEndpointApplyVirtualNetworkConfigReSubscribesBroadcastGroupOnRecovery(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	node := &fakeNode{}
	ep.node = node
	ep.multicastLifecycleReady.Store(true)

	ep.handleVirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationDown, &zt.VirtualNetworkConfig{Status: zt.NetworkStatusRequestingConfiguration})
	ep.handleVirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
	})

	require.Eventually(t, func() bool {
		for _, call := range node.multicastSubscribeCalls() {
			if call == (multicastCall{nwid: ep.networkID, mac: 0xffffffffffff, adi: 0}) {
				return true
			}
		}
		return false
	}, time.Second, 10*time.Millisecond)
	require.Empty(t, node.multicastUnsubscribeCalls())
}

func TestHandleVirtualNetworkConfigReplaysCachedBroadcastGroupOnConfigUpdate(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	node := &fakeNode{}
	ep.node = node
	ep.multicastLifecycleReady.Store(true)
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
	})
	ep.subscribeMulticastGroup(zeroTierBroadcastGroup)
	drainAndResetMulticastCalls(ep, node)

	ep.handleVirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")},
	})

	require.Eventually(t, func() bool {
		for _, call := range node.multicastSubscribeCalls() {
			if call == (multicastCall{nwid: ep.networkID, mac: zeroTierBroadcastGroup.mac, adi: zeroTierBroadcastGroup.adi}) {
				return true
			}
		}
		return false
	}, time.Second, 10*time.Millisecond)
}

func TestHandleVirtualNetworkConfigReplaysCachedNonBroadcastGroupOnConfigUpdate(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	node := &fakeNode{}
	ep.node = node
	ep.multicastLifecycleReady.Store(true)
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
	})
	group := zeroTierMulticastGroup{mac: 0x334455667788, adi: 0x42}
	ep.subscribeMulticastGroup(group)
	drainAndResetMulticastCalls(ep, node)

	ep.handleVirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")},
	})

	require.Eventually(t, func() bool {
		var sawGroup bool
		var sawBroadcast bool
		for _, call := range node.multicastSubscribeCalls() {
			if call == (multicastCall{nwid: ep.networkID, mac: group.mac, adi: group.adi}) {
				sawGroup = true
			}
			if call == (multicastCall{nwid: ep.networkID, mac: zeroTierBroadcastGroup.mac, adi: zeroTierBroadcastGroup.adi}) {
				sawBroadcast = true
			}
		}
		return sawGroup && sawBroadcast
	}, time.Second, 10*time.Millisecond)
}

func TestHandleVirtualNetworkConfigUnsubscribesCachedNonBroadcastGroupOnDown(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	node := &fakeNode{}
	ep.node = node
	ep.multicastLifecycleReady.Store(true)
	group := zeroTierMulticastGroup{mac: 0x334455667788, adi: 0x42}
	ep.subscribeMulticastGroup(group)
	drainAndResetMulticastCalls(ep, node)

	ep.handleVirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationDown, &zt.VirtualNetworkConfig{Status: zt.NetworkStatusRequestingConfiguration})

	require.Eventually(t, func() bool {
		for _, call := range node.multicastUnsubscribeCalls() {
			if call == (multicastCall{nwid: ep.networkID, mac: group.mac, adi: group.adi}) {
				return true
			}
		}
		return false
	}, time.Second, 10*time.Millisecond)
}

func TestHandleVirtualNetworkConfigDestroyClearsMulticastGroupCache(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	node := &fakeNode{}
	ep.node = node
	ep.multicastLifecycleReady.Store(true)
	group := zeroTierMulticastGroup{mac: 0x334455667788, adi: 0x42}
	ep.subscribeMulticastGroup(group)
	drainAndResetMulticastCalls(ep, node)

	ep.handleVirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationDestroy, &zt.VirtualNetworkConfig{Status: zt.NetworkStatusRequestingConfiguration})

	require.Eventually(t, func() bool {
		return len(ep.multicastGroupsSnapshot()) == 0
	}, time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool {
		for _, call := range node.multicastUnsubscribeCalls() {
			if call == (multicastCall{nwid: ep.networkID, mac: group.mac, adi: group.adi}) {
				return true
			}
		}
		return false
	}, time.Second, 10*time.Millisecond)
}

func TestZeroTierSolicitedNodeGroupFromIPv6Address(t *testing.T) {
	t.Parallel()

	group, ok := zeroTierSolicitedNodeGroup(netip.MustParseAddr("fd00::1234:5678"))
	require.True(t, ok)
	require.Equal(t, zeroTierMulticastGroup{mac: 0x3333ff345678}, group)

	_, ok = zeroTierSolicitedNodeGroup(netip.MustParseAddr("10.0.0.1"))
	require.False(t, ok)
}

func TestZeroTierMulticastGroupFromAddr(t *testing.T) {
	t.Parallel()

	v4Group, ok := zeroTierMulticastGroupFromAddr(netip.MustParseAddr("224.0.0.251"))
	require.True(t, ok)
	require.Equal(t, zeroTierMulticastGroup{mac: 0x01005e0000fb}, v4Group)

	v6Group, ok := zeroTierMulticastGroupFromAddr(netip.MustParseAddr("ff02::fb"))
	require.True(t, ok)
	require.Equal(t, zeroTierMulticastGroup{mac: 0x3333000000fb}, v6Group)

	_, ok = zeroTierMulticastGroupFromAddr(netip.MustParseAddr("10.0.0.1"))
	require.False(t, ok)
}

func TestEndpointForwardOutboundIPv4MulticastUsesMappedMAC(t *testing.T) {
	t.Parallel()

	localPrefix := netip.MustParsePrefix("10.0.0.1/24")
	dstIP := netip.MustParseAddr("224.0.0.251")
	ep := newTestEndpoint(t, []netip.Prefix{localPrefix})
	node := &fakeNode{}
	ep.node = node
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{localPrefix},
	})
	ep.goManaged(ep.forwardOutbound)
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	queueOutboundPacket(ep, buildIPv4UDPDatagram(t, localPrefix.Addr(), dstIP))
	require.Eventually(t, func() bool {
		return len(node.virtualNetworkFrames()) == 1
	}, time.Second, 10*time.Millisecond)
	group, ok := zeroTierMulticastGroupFromAddr(dstIP)
	require.True(t, ok)
	frame := node.virtualNetworkFrames()[0]
	require.Equal(t, uint(0x0800), frame.etherType)
	require.Equal(t, group.mac, frame.dstMAC)
}

func TestEndpointForwardOutboundIPv6MulticastUsesMappedMAC(t *testing.T) {
	t.Parallel()

	localPrefix := netip.MustParsePrefix("fd00::1/64")
	dstIP := netip.MustParseAddr("ff02::fb")
	ep := newTestEndpoint(t, []netip.Prefix{localPrefix})
	node := &fakeNode{}
	ep.node = node
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{localPrefix},
	})
	ep.goManaged(ep.forwardOutbound)
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	queueOutboundPacket(ep, buildIPv6UDPDatagram(t, localPrefix.Addr(), dstIP))
	require.Eventually(t, func() bool {
		return len(node.virtualNetworkFrames()) == 1
	}, time.Second, 10*time.Millisecond)
	group, ok := zeroTierMulticastGroupFromAddr(dstIP)
	require.True(t, ok)
	frame := node.virtualNetworkFrames()[0]
	require.Equal(t, uint(0x86DD), frame.etherType)
	require.Equal(t, group.mac, frame.dstMAC)
}

func TestEndpointForwardOutboundIGMPv3ReportUpdatesSubscriptions(t *testing.T) {
	t.Parallel()

	localPrefix := netip.MustParsePrefix("10.0.0.1/24")
	groupAddr := netip.MustParseAddr("224.0.0.251")
	ep := newTestEndpoint(t, []netip.Prefix{localPrefix})
	node := &fakeNode{}
	ep.node = node
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{localPrefix},
	})
	ep.goManaged(ep.forwardOutbound)
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	group, ok := zeroTierMulticastGroupFromAddr(groupAddr)
	require.True(t, ok)
	queueOutboundPacket(ep, buildIPv4IGMPv3Report(t, localPrefix.Addr(), groupAddr, header.IGMPv3ReportRecordChangeToExcludeMode))
	require.Eventually(t, func() bool {
		return containsMulticastCall(node.multicastSubscribeCalls(), multicastCall{nwid: ep.networkID, mac: group.mac, adi: group.adi})
	}, time.Second, 10*time.Millisecond)
	queueOutboundPacket(ep, buildIPv4IGMPv3Report(t, localPrefix.Addr(), groupAddr, header.IGMPv3ReportRecordChangeToExcludeMode))
	time.Sleep(50 * time.Millisecond)
	require.Len(t, node.multicastSubscribeCalls(), 1)

	drainAndResetMulticastCalls(ep, node)

	queueOutboundPacket(ep, buildIPv4IGMPv3Report(t, localPrefix.Addr(), groupAddr, header.IGMPv3ReportRecordChangeToIncludeMode))
	require.Eventually(t, func() bool {
		return containsMulticastCall(node.multicastUnsubscribeCalls(), multicastCall{nwid: ep.networkID, mac: group.mac, adi: group.adi})
	}, time.Second, 10*time.Millisecond)
}

func TestEndpointForwardOutboundIGMPv3ReportRespectsNetworkReadiness(t *testing.T) {
	t.Parallel()

	groupAddr := netip.MustParseAddr("224.0.0.251")
	ep := newTestEndpoint(t, nil)
	node := &fakeNode{}
	ep.node = node
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationDown, &zt.VirtualNetworkConfig{Status: zt.NetworkStatusRequestingConfiguration})
	ep.goManaged(ep.forwardOutbound)
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	queueOutboundPacket(ep, buildIPv4IGMPv3Report(t, netip.MustParseAddr("10.0.0.1"), groupAddr, header.IGMPv3ReportRecordChangeToExcludeMode))
	time.Sleep(100 * time.Millisecond)
	require.Empty(t, node.multicastSubscribeCalls())
	require.Empty(t, node.virtualNetworkFrames())
}

func TestEnsureManagedMulticastGroupsUsesPendingConfigReadiness(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	node := &fakeNode{}
	ep.node = node
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	ep.pendingConfigReady.Store(true)
	ep.pendingConfigNWMac.Store(0x112233445566)
	groups := ep.ensureManagedMulticastGroups([]zeroTierMulticastGroup{zeroTierIPv6AllNodesGroup})
	require.Equal(t, []zeroTierMulticastGroup{zeroTierIPv6AllNodesGroup}, groups)
	ep.waitForMulticastQueueDrain()
	require.Contains(t, node.multicastSubscribeCalls(), multicastCall{nwid: ep.networkID, mac: zeroTierIPv6AllNodesGroup.mac, adi: zeroTierIPv6AllNodesGroup.adi})
}

func TestEndpointForwardOutboundMLDv2ReportUpdatesSubscriptions(t *testing.T) {
	t.Parallel()

	localPrefix := netip.MustParsePrefix("fd00::1/64")
	groupAddr := netip.MustParseAddr("ff02::fb")
	ep := newTestEndpoint(t, []netip.Prefix{localPrefix})
	node := &fakeNode{}
	ep.node = node
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{localPrefix},
	})
	ep.goManaged(ep.forwardOutbound)
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	mldSource := netip.IPv6Unspecified()
	group, ok := zeroTierMulticastGroupFromAddr(groupAddr)
	require.True(t, ok)
	queueOutboundPacket(ep, buildIPv6MLDv2Report(t, mldSource, groupAddr, header.MLDv2ReportRecordChangeToExcludeMode))
	require.Eventually(t, func() bool {
		return containsMulticastCall(node.multicastSubscribeCalls(), multicastCall{nwid: ep.networkID, mac: group.mac, adi: group.adi})
	}, time.Second, 10*time.Millisecond)
	queueOutboundPacket(ep, buildIPv6MLDv2Report(t, mldSource, groupAddr, header.MLDv2ReportRecordChangeToExcludeMode))
	time.Sleep(50 * time.Millisecond)
	require.Len(t, node.multicastSubscribeCalls(), 1)

	drainAndResetMulticastCalls(ep, node)

	queueOutboundPacket(ep, buildIPv6MLDv2Report(t, mldSource, groupAddr, header.MLDv2ReportRecordChangeToIncludeMode))
	require.Eventually(t, func() bool {
		return containsMulticastCall(node.multicastUnsubscribeCalls(), multicastCall{nwid: ep.networkID, mac: group.mac, adi: group.adi})
	}, time.Second, 10*time.Millisecond)
}

func TestEndpointForwardOutboundMLDv2ReportRespectsNetworkReadiness(t *testing.T) {
	t.Parallel()

	groupAddr := netip.MustParseAddr("ff02::fb")
	ep := newTestEndpoint(t, nil)
	node := &fakeNode{}
	ep.node = node
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationDown, &zt.VirtualNetworkConfig{Status: zt.NetworkStatusRequestingConfiguration})
	ep.goManaged(ep.forwardOutbound)
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	queueOutboundPacket(ep, buildIPv6MLDv2Report(t, netip.IPv6Unspecified(), groupAddr, header.MLDv2ReportRecordChangeToExcludeMode))
	time.Sleep(100 * time.Millisecond)
	require.Empty(t, node.multicastSubscribeCalls())
	require.Empty(t, node.virtualNetworkFrames())
}

func TestHandleVirtualNetworkConfigReplaysSolicitedNodeGroupOnIPv6AddressChange(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	node := &fakeNode{}
	ep.node = node
	ep.multicastLifecycleReady.Store(true)
	oldGroup, _ := zeroTierSolicitedNodeGroup(netip.MustParseAddr("fd00::1234:5678"))
	newGroup, _ := zeroTierSolicitedNodeGroup(netip.MustParseAddr("fd00::1234:9abc"))

	ep.handleVirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("fd00::1234:5678/64")},
	})
	drainAndResetMulticastCalls(ep, node)

	ep.handleVirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("fd00::1234:9abc/64")},
	})

	require.Eventually(t, func() bool {
		var sawNew bool
		var sawBroadcast bool
		for _, call := range node.multicastSubscribeCalls() {
			if call == (multicastCall{nwid: ep.networkID, mac: newGroup.mac, adi: newGroup.adi}) {
				sawNew = true
			}
			if call == (multicastCall{nwid: ep.networkID, mac: zeroTierBroadcastGroup.mac, adi: zeroTierBroadcastGroup.adi}) {
				sawBroadcast = true
			}
		}
		return sawNew && sawBroadcast
	}, time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool {
		for _, call := range node.multicastUnsubscribeCalls() {
			if call == (multicastCall{nwid: ep.networkID, mac: oldGroup.mac, adi: oldGroup.adi}) {
				return true
			}
		}
		return false
	}, time.Second, 10*time.Millisecond)
	require.Contains(t, ep.multicastGroupsSnapshot(), newGroup)
	require.NotContains(t, ep.multicastGroupsSnapshot(), oldGroup)
}

func TestHandleVirtualNetworkConfigDoesNotTreatDynamic33ffGroupAsManaged(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	node := &fakeNode{}
	ep.node = node
	ep.multicastLifecycleReady.Store(true)
	dynamicGroup := zeroTierMulticastGroup{mac: 0x3333ff000001, adi: 0}
	ep.subscribeMulticastGroup(dynamicGroup)
	drainAndResetMulticastCalls(ep, node)

	ep.handleVirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("fd00::1234:5678/64")},
	})

	require.NotContains(t, node.multicastUnsubscribeCalls(), multicastCall{nwid: ep.networkID, mac: dynamicGroup.mac, adi: dynamicGroup.adi})
	require.Contains(t, ep.multicastGroupsSnapshot(), dynamicGroup)
}

func TestHandleVirtualNetworkConfigKeepsDynamicRefForManagedSameKey(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	node := &fakeNode{}
	ep.node = node
	ep.multicastLifecycleReady.Store(true)
	group, ok := zeroTierSolicitedNodeGroup(netip.MustParseAddr("fd00::1234:5678"))
	require.True(t, ok)
	ep.subscribeMulticastGroup(group)
	drainAndResetMulticastCalls(ep, node)

	ep.handleVirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("fd00::1234:5678/64")},
	})
	drainAndResetMulticastCalls(ep, node)

	ep.handleVirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
	})

	require.NotContains(t, node.multicastUnsubscribeCalls(), multicastCall{nwid: ep.networkID, mac: group.mac, adi: group.adi})
	require.Contains(t, ep.multicastGroupsSnapshot(), group)
}

func TestEndpointMulticastGroupKeyIncludesADI(t *testing.T) {
	t.Parallel()

	groups := map[zeroTierMulticastGroup]struct{}{
		{mac: 0x112233445566, adi: 0}: {},
		{mac: 0x112233445566, adi: 1}: {},
	}

	require.Len(t, groups, 2)
}

func TestEndpointSubscribeMulticastGroupDeduplicatesNodeCalls(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	node := &fakeNode{}
	ep.node = node

	group := zeroTierMulticastGroup{mac: 0xffffffffffff, adi: 0}
	ep.subscribeMulticastGroup(group)
	ep.subscribeMulticastGroup(group)

	require.Equal(t, []multicastCall{{nwid: ep.networkID, mac: group.mac, adi: group.adi}}, node.multicastSubscribeCalls())
	require.Equal(t, []zeroTierMulticastGroup{group}, ep.multicastGroupsSnapshot())
}

func TestEndpointUnsubscribeMulticastGroupSkipsUnknownGroup(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	node := &fakeNode{}
	ep.node = node

	group := zeroTierMulticastGroup{mac: 0xffffffffffff, adi: 0}
	ep.unsubscribeMulticastGroup(group)
	ep.subscribeMulticastGroup(group)
	ep.unsubscribeMulticastGroup(group)
	ep.unsubscribeMulticastGroup(group)

	require.Equal(t, []multicastCall{{nwid: ep.networkID, mac: group.mac, adi: group.adi}}, node.multicastUnsubscribeCalls())
	require.Empty(t, ep.multicastGroupsSnapshot())
}

func TestEndpointResubscribeMulticastGroupsReplaysCurrentGroups(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	node := &fakeNode{}
	ep.node = node
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
	})

	groupA := zeroTierMulticastGroup{mac: 0xffffffffffff, adi: 0}
	groupB := zeroTierMulticastGroup{mac: 0x334455667788, adi: 0x42}
	ep.subscribeMulticastGroup(groupA)
	ep.subscribeMulticastGroup(groupB)

	drainAndResetMulticastCalls(ep, node)
	ep.resubscribeMulticastGroupsIfActive()

	require.ElementsMatch(t, []multicastCall{
		{nwid: ep.networkID, mac: groupA.mac, adi: groupA.adi},
		{nwid: ep.networkID, mac: groupB.mac, adi: groupB.adi},
	}, node.multicastSubscribeCalls())
}

func TestEndpointStartRollsBackOnJoinSuccessCreateStackFailure(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	socket := &fakePacketConn{}
	node := &fakeNode{joinHook: func(n *fakeNode) error {
		n.callbacks.VirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
			Status:            zt.NetworkStatusOK,
			AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("10.0.1.5/24")},
		})
		return nil
	}}
	ep.listenUDP = func() (udpPacketConn, error) { return socket, nil }
	ep.newNode = func(callbacks zt.NodeCallbacks, _ *zt.NodeConfig) (zeroTierNode, error) {
		node.callbacks = callbacks
		return node, nil
	}
	ep.createStackFn = func() error { return errors.New("boom") }

	scope := adapter.NewScope(ep.ctx, ep.logger)
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	require.NoError(t, scope.Start(ep.Tag(), ep, adapter.StartStateInitialize))
	err := scope.Start(ep.Tag(), ep, adapter.StartStateStart)
	require.Error(t, err)
	require.ErrorContains(t, err, "create network stack")
	require.True(t, socket.closed.Load())
	require.True(t, node.closed.Load())
	select {
	case <-ep.done:
	default:
		t.Fatal("done channel must be closed after rollback")
	}
}

func TestEndpointStartReturnsPromptlyWhenClosedWhileWaitingForWireTargets(t *testing.T) {
	t.Parallel()

	endpoint, err := NewEndpoint(context.Background(), nil, logger.NOP(), fmt.Sprintf("test-%d", time.Now().UnixNano()), option.ZeroTierEndpointOptions{NetworkID: "0123456789abcdef", Address: []netip.Prefix{netip.MustParsePrefix("10.0.1.5/24")}})
	require.NoError(t, err)

	ep := endpoint.(*Endpoint)
	socket := &fakePacketConn{}
	node := &fakeNode{joinHook: func(n *fakeNode) error {
		n.callbacks.VirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
			Status:            zt.NetworkStatusOK,
			AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("10.0.1.5/24")},
		})
		return nil
	}}
	stackReady := make(chan struct{})
	ep.listenUDP = func() (udpPacketConn, error) { return socket, nil }
	ep.newNode = func(callbacks zt.NodeCallbacks, _ *zt.NodeConfig) (zeroTierNode, error) {
		node.callbacks = callbacks
		return node, nil
	}
	ep.createStackFn = func() error {
		close(stackReady)
		return nil
	}
	scope := adapter.NewScope(ep.ctx, ep.logger)
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	require.NoError(t, scope.Start(ep.Tag(), ep, adapter.StartStateInitialize))

	errCh := make(chan error, 1)
	go func() {
		errCh <- scope.Start(ep.Tag(), ep, adapter.StartStateStart)
	}()

	<-stackReady
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		require.NoError(t, ep.Close())
	}()

	select {
	case startErr := <-errCh:
		require.Error(t, startErr)
		require.ErrorContains(t, startErr, "closed while waiting for wire targets")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Start did not return promptly after Close while waiting for wire targets")
	}

	<-closed
}

func TestReceiveWirePacketsReturnsOnFatalUDPError(t *testing.T) {
	t.Parallel()

	socket := &fakePacketConn{}
	socket.closed.Store(true)
	ep := &Endpoint{
		done:    make(chan struct{}),
		udpConn: socket,
		logger:  logger.NOP(),
	}

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		ep.receiveWirePackets()
	}()

	select {
	case <-returned:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("receiveWirePackets did not return after fatal UDP error")
	}
}

func TestEndpointIPv4MalformedICMPFrameDoesNotPanic(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	require.NoError(t, ep.createStack())
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	frame := make([]byte, header.IPv4MinimumSize)
	frame[0] = (4 << 4) | 15
	frame[8] = 64
	frame[9] = uint8(header.ICMPv4ProtocolNumber)
	copy(frame[12:16], netip.MustParseAddr("10.0.0.2").AsSlice())
	copy(frame[16:20], netip.MustParseAddr("10.0.0.1").AsSlice())

	require.NotPanics(t, func() {
		ep.onVirtualNetworkFrame(ep.networkID, 0x010203040506, 0x0, 0x0800, 0, frame)
	})
}
func TestEndpointCreateStackRegistersICMPForwarders(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24"), netip.MustParsePrefix("fd00::1/64")})
	require.NoError(t, ep.createStack())
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	require.True(t, hasTransportProtocolHandler(ep.ipStack, icmp.ProtocolNumber4))
	require.True(t, hasTransportProtocolHandler(ep.ipStack, icmp.ProtocolNumber6))
}

func TestEndpointICMPv4ForwarderHandlesEchoRequestOnce(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	node := &fakeNode{}
	ep.node = node
	require.NoError(t, ep.createStack())
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
	})
	ep.goManaged(ep.forwardOutbound)
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	ep.onVirtualNetworkFrame(
		ep.networkID,
		0x010203040506,
		0,
		0x0800,
		0,
		buildIPv4ICMPEchoRequest(t, netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1")),
	)

	require.Eventually(t, func() bool {
		return len(node.virtualNetworkFrames()) == 1
	}, time.Second, 10*time.Millisecond)

	frames := node.virtualNetworkFrames()
	require.Len(t, frames, 1)
	frame := frames[0]
	require.Equal(t, uint(0x0800), frame.etherType)
	require.Equal(t, uint64(0x010203040506), frame.dstMAC)
	assertICMPEchoReplyPacket(t, frame.data, 0, netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"))
}

func TestEndpointICMPv4CallbackDoesNotSynchronouslyReenterNode(t *testing.T) {
	t.Parallel()

	processStarted := make(chan struct{})
	releaseProcess := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			close(releaseProcess)
		})
	}
	node := &fakeNode{
		processFrameHook: func() {
			close(processStarted)
			<-releaseProcess
		},
	}
	ep := newTestEndpoint(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	ep.node = node
	require.NoError(t, ep.createStack())
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
	})
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})
	t.Cleanup(release)

	callbackReturned := make(chan struct{})
	go func() {
		ep.onVirtualNetworkFrame(
			ep.networkID,
			0x010203040506,
			0,
			0x0800,
			0,
			buildIPv4ICMPEchoRequest(t, netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1")),
		)
		close(callbackReturned)
	}()

	select {
	case <-callbackReturned:
	case <-time.After(time.Second):
		release()
		<-callbackReturned
		t.Fatal("ICMP callback blocked on Node.ProcessVirtualNetworkFrame")
	}
	select {
	case <-processStarted:
	case <-time.After(time.Second):
		t.Fatal("Node.ProcessVirtualNetworkFrame was not called")
	}
	release()
	require.Eventually(t, func() bool {
		return len(node.virtualNetworkFrames()) == 1
	}, time.Second, 10*time.Millisecond)
}

func TestHandleICMPEchoUsesRuntimeIPv4AddressDuringReconfig(t *testing.T) {
	t.Parallel()

	oldPrefix := netip.MustParsePrefix("10.0.0.1/24")
	newPrefix := netip.MustParsePrefix("10.0.1.5/24")
	ep := newTestEndpoint(t, []netip.Prefix{oldPrefix})
	node := &fakeNode{}
	ep.node = node
	require.NoError(t, ep.createStack())
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{oldPrefix},
	})
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	require.NoError(t, ep.syncRuntimeAddresses([]netip.Prefix{oldPrefix}, []netip.Prefix{newPrefix}))
	handled := ep.handleICMPEcho(0x010203040506, buildIPv4ICMPEchoRequest(t, netip.MustParseAddr("10.0.0.2"), newPrefix.Addr()))
	require.True(t, handled)
	require.Eventually(t, func() bool {
		return len(node.virtualNetworkFrames()) == 1
	}, time.Second, 10*time.Millisecond)
}

func TestEndpointLearnsIPv6NeighborDiscoveryFrames(t *testing.T) {
	t.Parallel()

	t.Run("neighbor solicitation", func(t *testing.T) {
		ep := newTestEndpoint(t, []netip.Prefix{netip.MustParsePrefix("fd00::1/64")})
		require.NoError(t, ep.createStack())
		t.Cleanup(func() {
			require.NoError(t, ep.Close())
		})

		peerIP := netip.MustParseAddr("fd00::2")
		peerMAC := uint64(0x010203040506)
		ep.onVirtualNetworkFrame(ep.networkID, peerMAC, 0, 0x86DD, 0, buildIPv6NeighborSolicitation(t, peerIP, netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::1"), peerMAC))

		ep.macTableMu.RLock()
		learnedMAC, ok := ep.macTable[peerIP.String()]
		ep.macTableMu.RUnlock()
		require.True(t, ok)
		require.Equal(t, peerMAC, learnedMAC.mac)
	})

	t.Run("neighbor advertisement", func(t *testing.T) {
		ep := newTestEndpoint(t, []netip.Prefix{netip.MustParsePrefix("fd00::1/64")})
		require.NoError(t, ep.createStack())
		t.Cleanup(func() {
			require.NoError(t, ep.Close())
		})

		peerIP := netip.MustParseAddr("fd00::2")
		peerMAC := uint64(0x060504030201)
		ep.onVirtualNetworkFrame(ep.networkID, peerMAC, 0, 0x86DD, 0, buildIPv6NeighborAdvertisement(t, peerIP, netip.MustParseAddr("fd00::1"), peerIP, peerMAC, true))

		ep.macTableMu.RLock()
		learnedMAC, ok := ep.macTable[peerIP.String()]
		ep.macTableMu.RUnlock()
		require.True(t, ok)
		require.Equal(t, peerMAC, learnedMAC.mac)
	})
}

func TestEndpointRepliesToNeighborSolicitationForLocalIPv6(t *testing.T) {
	t.Parallel()

	localPrefix := netip.MustParsePrefix("fd00::1/64")
	ep := newTestEndpoint(t, []netip.Prefix{localPrefix})
	node := &fakeNode{}
	ep.node = node
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{localPrefix},
	})
	require.NoError(t, ep.createStack())
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	ep.tentativeIPv6Mu.Lock()
	delete(ep.tentativeIPv6, localPrefix.Addr().String())
	ep.tentativeIPv6Mu.Unlock()

	peerIP := netip.MustParseAddr("fd00::2")
	peerMAC := uint64(0x010203040506)
	ep.onVirtualNetworkFrame(ep.networkID, peerMAC, 0, 0x86DD, 0, buildIPv6NeighborSolicitation(t, peerIP, localPrefix.Addr(), localPrefix.Addr(), peerMAC))

	require.Eventually(t, func() bool {
		return len(node.virtualNetworkFrames()) == 1
	}, time.Second, 10*time.Millisecond)

	frames := node.virtualNetworkFrames()
	require.Len(t, frames, 1)
	frame := frames[0]
	require.Equal(t, uint(0x86DD), frame.etherType)
	require.Equal(t, peerMAC, frame.dstMAC)
	assertIPv6NeighborAdvertisementPacket(t, frame.data, localPrefix.Addr(), peerIP, localPrefix.Addr(), 0x112233445566, true)
}

func TestHandleICMPv6NeighborDiscoveryDoesNotConsumeDadNeighborSolicitation(t *testing.T) {
	t.Parallel()

	localPrefix := netip.MustParsePrefix("fd00::1/64")
	ep := newTestEndpoint(t, []netip.Prefix{localPrefix})
	node := &fakeNode{}
	ep.node = node
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{localPrefix},
	})
	require.NoError(t, ep.createStack())
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	handled := ep.handleICMPv6NeighborDiscovery(0x010203040506, buildIPv6DADNeighborSolicitation(t, localPrefix.Addr()))
	require.False(t, handled)
	require.Empty(t, node.virtualNetworkFrames())
}

func TestHandleICMPv6NeighborDiscoveryDoesNotReplyForInitialTentativeIPv6(t *testing.T) {
	t.Parallel()

	localPrefix := netip.MustParsePrefix("fd00::1/64")
	peerIP := netip.MustParseAddr("fd00::2")
	peerMAC := uint64(0x010203040506)
	ep := newTestEndpoint(t, []netip.Prefix{localPrefix})
	node := &fakeNode{}
	ep.node = node
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{localPrefix},
	})
	require.NoError(t, ep.createStack())
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})
	require.Eventually(t, func() bool {
		return ep.isTentativeRuntimeIPv6Address(localPrefix.Addr())
	}, time.Second, 10*time.Millisecond)

	handled := ep.handleICMPv6NeighborDiscovery(peerMAC, buildIPv6NeighborSolicitation(t, peerIP, localPrefix.Addr(), localPrefix.Addr(), peerMAC))
	require.False(t, handled)
	require.Empty(t, node.virtualNetworkFrames())
}

func TestHandleICMPv6NeighborDiscoveryDoesNotReplyForTentativeRuntimeIPv6(t *testing.T) {
	t.Parallel()

	newPrefix := netip.MustParsePrefix("fd00::2/64")
	peerIP := netip.MustParseAddr("fd00::3")
	peerMAC := uint64(0x010203040506)
	ep := newTestEndpoint(t, nil)
	node := &fakeNode{}
	ep.node = node
	require.NoError(t, ep.createStack())
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{newPrefix},
	})
	ep.tentativeIPv6Mu.Lock()
	ep.tentativeIPv6[newPrefix.Addr().String()] = true
	ep.tentativeIPv6Mu.Unlock()

	handled := ep.handleICMPv6NeighborDiscovery(peerMAC, buildIPv6NeighborSolicitation(t, peerIP, newPrefix.Addr(), newPrefix.Addr(), peerMAC))
	require.False(t, handled)
	require.Empty(t, node.virtualNetworkFrames())
}

func TestEndpointForwardOutboundAllowsDadNeighborSolicitation(t *testing.T) {
	t.Parallel()

	localPrefix := netip.MustParsePrefix("fd00::1/64")
	ep := newTestEndpoint(t, []netip.Prefix{localPrefix})
	node := &fakeNode{}
	ep.node = node
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{localPrefix},
	})
	ep.goManaged(ep.forwardOutbound)
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	queueOutboundPacket(ep, buildIPv6DADNeighborSolicitation(t, localPrefix.Addr()))
	require.Eventually(t, func() bool {
		return len(node.virtualNetworkFrames()) == 1
	}, time.Second, 10*time.Millisecond)
	group, ok := zeroTierSolicitedNodeGroup(localPrefix.Addr())
	require.True(t, ok)
	frame := node.virtualNetworkFrames()[0]
	require.Equal(t, group.mac, frame.dstMAC)
	require.Equal(t, uint(0x86DD), frame.etherType)
}

func TestEndpointForwardOutboundAllowsDadNeighborSolicitationInOddGeneration(t *testing.T) {
	t.Parallel()

	localPrefix := netip.MustParsePrefix("fd00::1/64")
	ep := newTestEndpoint(t, []netip.Prefix{localPrefix})
	node := &fakeNode{}
	ep.node = node
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{localPrefix},
	})
	ep.topologyGeneration.Store(3)
	ep.goManaged(ep.forwardOutbound)
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	queueOutboundPacket(ep, buildIPv6DADNeighborSolicitation(t, localPrefix.Addr()))
	require.Eventually(t, func() bool {
		return len(node.virtualNetworkFrames()) == 1
	}, time.Second, 10*time.Millisecond)
}

// TestEndpointForwardOutboundDadUsesNewMacDuringOddWindow covers the P1 bug:
// when forwardOutbound processes a DAD NS while still in the odd-generation
// window (networkState not yet updated), it must use pendingConfigNWMac, not
// the stale nwMac from the pre-transition published state.
func TestEndpointForwardOutboundDadUsesNewMacDuringOddWindow(t *testing.T) {
	t.Parallel()

	localPrefix := netip.MustParsePrefix("fd00::1/64")
	oldMAC := uint64(0xaabbccddeeff)
	newMAC := uint64(0x112233445566)

	ep := newTestEndpoint(t, []netip.Prefix{localPrefix})
	node := &fakeNode{}
	ep.node = node

	// Publish an old (valid) networkState with oldMAC, representing the
	// pre-transition state.
	ep.networkState.Store(&endpointNetworkState{
		hasConfig:      true,
		status:         zt.NetworkStatusOK,
		nwMac:          oldMAC,
		localAddresses: []netip.Prefix{localPrefix},
	})

	// Simulate being inside the odd-generation window: generation is odd,
	// pendingConfigReady is set to the new config, but networkState has NOT
	// been updated yet (as happens between syncRuntimeAddresses and
	// networkState.Store in applyVirtualNetworkConfig).
	ep.topologyGeneration.Store(3) // ODD
	ep.pendingConfigReady.Store(true)
	ep.pendingConfigNWMac.Store(newMAC)

	ep.goManaged(ep.forwardOutbound)
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	queueOutboundPacket(ep, buildIPv6DADNeighborSolicitation(t, localPrefix.Addr()))
	require.Eventually(t, func() bool {
		return len(node.virtualNetworkFrames()) == 1
	}, time.Second, 10*time.Millisecond)

	frame := node.virtualNetworkFrames()[0]
	require.Equal(t, newMAC, frame.srcMAC,
		"DAD NS in odd-generation window must use the pending new MAC, not the stale pre-transition MAC")
}

func TestEndpointRepliesToNeighborSolicitationForSecondLocalIPv6(t *testing.T) {
	t.Parallel()

	prefixes := []netip.Prefix{netip.MustParsePrefix("fd00::1/64"), netip.MustParsePrefix("fd00::2/64")}
	ep := newTestEndpoint(t, prefixes)
	node := &fakeNode{}
	ep.node = node
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: prefixes,
	})
	require.NoError(t, ep.createStack())
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	ep.tentativeIPv6Mu.Lock()
	delete(ep.tentativeIPv6, prefixes[0].Addr().String())
	delete(ep.tentativeIPv6, prefixes[1].Addr().String())
	ep.tentativeIPv6Mu.Unlock()

	peerIP := netip.MustParseAddr("fd00::3")
	peerMAC := uint64(0x010203040506)
	secondIP := prefixes[1].Addr()
	ep.onVirtualNetworkFrame(ep.networkID, peerMAC, 0, 0x86DD, 0, buildIPv6NeighborSolicitation(t, peerIP, secondIP, secondIP, peerMAC))

	require.Eventually(t, func() bool {
		return len(node.virtualNetworkFrames()) == 1
	}, time.Second, 10*time.Millisecond)
	frame := node.virtualNetworkFrames()[0]
	assertIPv6NeighborAdvertisementPacket(t, frame.data, secondIP, peerIP, secondIP, 0x112233445566, true)
}

func TestEndpointForwardOutboundIPv6UnknownNeighborSendsNeighborSolicitation(t *testing.T) {
	t.Parallel()

	localPrefix := netip.MustParsePrefix("fd00::1/64")
	peerIP := netip.MustParseAddr("fd00::2")
	ep := newTestEndpoint(t, []netip.Prefix{localPrefix})
	node := &fakeNode{}
	ep.node = node
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{localPrefix},
	})
	ep.goManaged(ep.forwardOutbound)
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	queueOutboundPacket(ep, buildIPv6ICMPEchoRequest(t, localPrefix.Addr(), peerIP))

	require.Eventually(t, func() bool {
		return len(node.virtualNetworkFrames()) == 1
	}, time.Second, 10*time.Millisecond)

	frames := node.virtualNetworkFrames()
	require.Len(t, frames, 1)
	frame := frames[0]
	require.Equal(t, uint(0x86DD), frame.etherType)
	require.NotEqual(t, uint64(0xffffffffffff), frame.dstMAC)
	group, ok := zeroTierSolicitedNodeGroup(peerIP)
	require.True(t, ok)
	require.Equal(t, group.mac, frame.dstMAC)
	assertIPv6NeighborSolicitationPacket(t, frame.data, localPrefix.Addr(), netip.MustParseAddr("ff02::1:ff00:2"), peerIP, 0x112233445566)
}

func TestEndpointForwardOutboundIPv6UnknownNeighborFlushesPendingPacketAfterAdvertisement(t *testing.T) {
	t.Parallel()

	localPrefix := netip.MustParsePrefix("fd00::1/64")
	peerIP := netip.MustParseAddr("fd00::2")
	peerMAC := uint64(0x010203040506)
	packet := buildIPv6ICMPEchoRequest(t, localPrefix.Addr(), peerIP)
	ep := newTestEndpoint(t, []netip.Prefix{localPrefix})
	node := &fakeNode{}
	ep.node = node
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{localPrefix},
	})
	require.NoError(t, ep.createStack())
	ep.goManaged(ep.forwardOutbound)
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	queueOutboundPacket(ep, packet)
	require.Eventually(t, func() bool {
		return len(node.virtualNetworkFrames()) == 1
	}, time.Second, 10*time.Millisecond)
	firstFrame := node.virtualNetworkFrames()[0]
	group, ok := zeroTierSolicitedNodeGroup(peerIP)
	require.True(t, ok)
	require.Equal(t, group.mac, firstFrame.dstMAC)
	assertIPv6NeighborSolicitationPacket(t, firstFrame.data, localPrefix.Addr(), netip.MustParseAddr("ff02::1:ff00:2"), peerIP, 0x112233445566)
	require.Eventually(t, func() bool {
		ep.ipv6PendingMu.Lock()
		defer ep.ipv6PendingMu.Unlock()
		state, ok := ep.ipv6Pending[peerIP.String()]
		return ok && len(state.packets) == 1
	}, time.Second, 10*time.Millisecond)

	ep.onVirtualNetworkFrame(ep.networkID, peerMAC, 0, 0x86DD, 0, buildIPv6NeighborAdvertisement(t, peerIP, localPrefix.Addr(), peerIP, peerMAC, true))
	require.Eventually(t, func() bool {
		return len(node.virtualNetworkFrames()) >= 2
	}, time.Second, 10*time.Millisecond)
	frames := node.virtualNetworkFrames()
	lastFrame := frames[len(frames)-1]
	require.Equal(t, peerMAC, lastFrame.dstMAC)
	assertICMPEchoReplyPacket(t, lastFrame.data, byte(header.ICMPv6EchoRequest), localPrefix.Addr(), peerIP)
}

func TestQueuePendingIPv6PacketCapsQueue(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	nextHop := netip.MustParseAddr("fd00::2")
	for i := 0; i < maxPendingIPv6PacketsPerNextHop+3; i++ {
		ep.queuePendingIPv6Packet(nextHop, []byte{byte(i)})
	}
	ep.ipv6PendingMu.Lock()
	defer ep.ipv6PendingMu.Unlock()
	state, ok := ep.ipv6Pending[nextHop.String()]
	require.True(t, ok)
	require.Len(t, state.packets, maxPendingIPv6PacketsPerNextHop)
	require.Equal(t, []byte{3}, state.packets[0])
}

func TestEndpointApplyVirtualNetworkConfigClearsPendingIPv6PacketsOnAddressChange(t *testing.T) {
	t.Parallel()

	oldPrefix := netip.MustParsePrefix("fd00::1/64")
	newPrefix := netip.MustParsePrefix("fd00::2/64")
	peerIP := netip.MustParseAddr("fd00::3")
	ep := newTestEndpoint(t, []netip.Prefix{oldPrefix})
	ep.queuePendingIPv6Packet(peerIP, buildIPv6ICMPEchoRequest(t, oldPrefix.Addr(), peerIP))
	ep.ipv6PendingMu.Lock()
	_, queuedBefore := ep.ipv6Pending[peerIP.String()]
	ep.ipv6PendingMu.Unlock()
	require.True(t, queuedBefore)

	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		AssignedAddresses: []netip.Prefix{newPrefix},
	})
	ep.ipv6PendingMu.Lock()
	defer ep.ipv6PendingMu.Unlock()
	require.Empty(t, ep.ipv6Pending)
}

func TestEndpointApplyVirtualNetworkConfigClearsPendingIPv6PacketsOnRouteChange(t *testing.T) {
	t.Parallel()

	localPrefix := netip.MustParsePrefix("fd00::1/64")
	oldGateway := netip.MustParseAddr("fd00::9")
	newGateway := netip.MustParseAddr("fd00::10")
	ep := newTestEndpoint(t, []netip.Prefix{localPrefix})
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		AssignedAddresses: []netip.Prefix{localPrefix},
		Routes:            []zt.Route{{Target: netip.MustParsePrefix("2001:db8::/64"), Via: oldGateway}},
	})
	ep.queuePendingIPv6Packet(oldGateway, buildIPv6ICMPEchoRequest(t, localPrefix.Addr(), netip.MustParseAddr("2001:db8::5")))
	ep.ipv6PendingMu.Lock()
	_, queuedBefore := ep.ipv6Pending[oldGateway.String()]
	ep.ipv6PendingMu.Unlock()
	require.True(t, queuedBefore)

	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		AssignedAddresses: []netip.Prefix{localPrefix},
		Routes:            []zt.Route{{Target: netip.MustParsePrefix("2001:db8::/64"), Via: newGateway}},
	})
	ep.ipv6PendingMu.Lock()
	defer ep.ipv6PendingMu.Unlock()
	require.Empty(t, ep.ipv6Pending)
}

func TestEndpointHandleVirtualNetworkConfigRouteChangeQueuesPendingForNewGateway(t *testing.T) {
	t.Parallel()

	localPrefix := netip.MustParsePrefix("fd00::1/64")
	dstIP := netip.MustParseAddr("2001:db8::5")
	oldGateway := netip.MustParseAddr("fd00::9")
	newGateway := netip.MustParseAddr("fd00::10")
	ep := newTestEndpoint(t, []netip.Prefix{localPrefix})
	node := &fakeNode{}
	ep.node = node
	ep.ipv6NeighborProbeRetryInterval = time.Hour
	ep.ipv6NeighborProbeTimeout = time.Hour
	ep.goManaged(ep.forwardOutbound)
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	ep.handleVirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{localPrefix},
		Routes:            []zt.Route{{Target: netip.MustParsePrefix("2001:db8::/64"), Via: oldGateway}},
	})
	queueOutboundPacket(ep, buildIPv6ICMPEchoRequest(t, localPrefix.Addr(), dstIP))
	require.Eventually(t, func() bool {
		ep.ipv6PendingMu.Lock()
		defer ep.ipv6PendingMu.Unlock()
		state, ok := ep.ipv6Pending[oldGateway.String()]
		return ok && len(state.packets) == 1
	}, time.Second, 10*time.Millisecond)

	ep.handleVirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{localPrefix},
		Routes:            []zt.Route{{Target: netip.MustParsePrefix("2001:db8::/64"), Via: newGateway}},
	})
	queueOutboundPacket(ep, buildIPv6ICMPEchoRequest(t, localPrefix.Addr(), dstIP))
	require.Eventually(t, func() bool {
		ep.ipv6PendingMu.Lock()
		defer ep.ipv6PendingMu.Unlock()
		_, oldQueued := ep.ipv6Pending[oldGateway.String()]
		state, newQueued := ep.ipv6Pending[newGateway.String()]
		return !oldQueued && newQueued && len(state.packets) == 1
	}, time.Second, 10*time.Millisecond)
}

func TestEndpointPendingIPv6NeighborRetriesAndExpires(t *testing.T) {
	t.Parallel()

	localPrefix := netip.MustParsePrefix("fd00::1/64")
	peerIP := netip.MustParseAddr("fd00::2")
	ep := newTestEndpoint(t, []netip.Prefix{localPrefix})
	node := &fakeNode{}
	ep.node = node
	ep.ipv6NeighborProbeRetryInterval = 20 * time.Millisecond
	ep.ipv6NeighborProbeTimeout = 100 * time.Millisecond
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{localPrefix},
	})
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	ep.queuePendingIPv6Packet(peerIP, buildIPv6ICMPEchoRequest(t, localPrefix.Addr(), peerIP))
	require.Eventually(t, func() bool {
		return len(node.virtualNetworkFrames()) == maxIPv6NeighborProbeAttempts
	}, time.Second, 10*time.Millisecond)
	time.Sleep(2 * ep.ipv6NeighborProbeRetryInterval)
	frames := node.virtualNetworkFrames()
	require.Len(t, frames, maxIPv6NeighborProbeAttempts)
	group, ok := zeroTierSolicitedNodeGroup(peerIP)
	require.True(t, ok)
	for _, frame := range frames {
		require.Equal(t, group.mac, frame.dstMAC)
		assertIPv6NeighborSolicitationPacket(t, frame.data, localPrefix.Addr(), netip.MustParseAddr("ff02::1:ff00:2"), peerIP, 0x112233445566)
	}
	require.Eventually(t, func() bool {
		ep.ipv6PendingMu.Lock()
		defer ep.ipv6PendingMu.Unlock()
		_, ok := ep.ipv6Pending[peerIP.String()]
		return !ok
	}, time.Second, 10*time.Millisecond)
}

func TestEndpointForwardOutboundDropsStaleFlushedIPv6PacketAfterReconfig(t *testing.T) {
	t.Parallel()

	oldPrefix := netip.MustParsePrefix("fd00::1/64")
	newPrefix := netip.MustParsePrefix("fd00::2/64")
	peerIP := netip.MustParseAddr("fd00::3")
	peerMAC := uint64(0x010203040506)
	ep := newTestEndpoint(t, []netip.Prefix{oldPrefix})
	node := &fakeNode{}
	ep.node = node
	ep.ipv6NeighborProbeRetryInterval = time.Hour
	ep.ipv6NeighborProbeTimeout = time.Hour
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{oldPrefix},
	})
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	ep.queuePendingIPv6Packet(peerIP, buildIPv6ICMPEchoRequest(t, oldPrefix.Addr(), peerIP))
	ep.learnMAC(peerIP, peerMAC)
	require.Eventually(t, func() bool {
		return len(ep.outbound) == 1
	}, time.Second, 10*time.Millisecond)
	baselineFrames := len(node.virtualNetworkFrames())

	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{newPrefix},
	})
	ep.goManaged(ep.forwardOutbound)
	require.Eventually(t, func() bool {
		return len(ep.outbound) == 0
	}, time.Second, 10*time.Millisecond)
	require.Len(t, node.virtualNetworkFrames(), baselineFrames)
}

func TestEndpointForwardOutboundDropsQueuedIPv6PacketWhileReconfigInProgress(t *testing.T) {
	t.Parallel()

	oldPrefix := netip.MustParsePrefix("fd00::1/64")
	newPrefix := netip.MustParsePrefix("fd00::2/64")
	peerIP := netip.MustParseAddr("fd00::3")
	ep := newTestEndpoint(t, []netip.Prefix{oldPrefix})
	node := &fakeNode{}
	ep.node = node
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{oldPrefix},
	})
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	queueOutboundPacket(ep, buildIPv6ICMPEchoRequest(t, oldPrefix.Addr(), peerIP))
	ep.runtimeStateMu.Lock()
	reconfigDone := make(chan struct{})
	go func() {
		defer close(reconfigDone)
		ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
			Status:            zt.NetworkStatusOK,
			MAC:               0x112233445566,
			AssignedAddresses: []netip.Prefix{newPrefix},
		})
	}()
	require.Eventually(t, func() bool {
		return ep.topologyGeneration.Load()%2 == 1
	}, time.Second, 10*time.Millisecond)
	ep.goManaged(ep.forwardOutbound)
	require.Eventually(t, func() bool {
		return len(ep.outbound) == 0
	}, time.Second, 10*time.Millisecond)
	require.Empty(t, node.virtualNetworkFrames())
	ep.runtimeStateMu.Unlock()
	<-reconfigDone
}

func TestEndpointForwardOutboundIPv6KnownNeighborUsesLearnedUnicastMAC(t *testing.T) {
	t.Parallel()

	localPrefix := netip.MustParsePrefix("fd00::1/64")
	peerIP := netip.MustParseAddr("fd00::2")
	peerMAC := uint64(0x010203040506)
	ep := newTestEndpoint(t, []netip.Prefix{localPrefix})
	node := &fakeNode{}
	ep.node = node
	ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status:            zt.NetworkStatusOK,
		MAC:               0x112233445566,
		AssignedAddresses: []netip.Prefix{localPrefix},
	})
	require.NoError(t, ep.createStack())
	ep.goManaged(ep.forwardOutbound)
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	ep.onVirtualNetworkFrame(ep.networkID, peerMAC, 0, 0x86DD, 0, buildIPv6NeighborAdvertisement(t, peerIP, localPrefix.Addr(), peerIP, peerMAC, true))
	queueOutboundPacket(ep, buildIPv6ICMPEchoRequest(t, localPrefix.Addr(), peerIP))

	require.Eventually(t, func() bool {
		return len(node.virtualNetworkFrames()) == 1
	}, time.Second, 10*time.Millisecond)

	frames := node.virtualNetworkFrames()
	require.Len(t, frames, 1)
	frame := frames[0]
	require.Equal(t, uint(0x86DD), frame.etherType)
	require.Equal(t, peerMAC, frame.dstMAC)
	assertICMPEchoReplyPacket(t, frame.data, byte(header.ICMPv6EchoRequest), localPrefix.Addr(), peerIP)
}

func TestBackgroundWaitDuration(t *testing.T) {
	t.Parallel()

	now := time.UnixMilli(10_000)
	require.Equal(t, defaultBackgroundPollInterval, backgroundWaitDuration(now, 0))
	require.Equal(t, 250*time.Millisecond, backgroundWaitDuration(now, now.Add(250*time.Millisecond).UnixMilli()))
	require.Zero(t, backgroundWaitDuration(now, now.Add(-time.Millisecond).UnixMilli()))
}

func TestEndpointCloseWaitsForManagedGoroutines(t *testing.T) {
	t.Parallel()

	ep := &Endpoint{done: make(chan struct{})}
	started := make(chan struct{})
	release := make(chan struct{})
	ep.goManaged(func() {
		<-ep.done
		close(started)
		<-release
	})

	closed := make(chan struct{})
	go func() {
		require.NoError(t, ep.Close())
		close(closed)
	}()

	select {
	case <-closed:
		t.Fatal("Close returned before managed goroutine exited")
	case <-started:
	}

	close(release)

	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not wait for managed goroutine completion")
	}
}

func TestNewEndpointDoesNotStartMulticastWorkerBeforeExplicitLaunch(t *testing.T) {
	t.Parallel()

	endpoint, err := NewEndpoint(context.Background(), nil, logger.NOP(), fmt.Sprintf("test-%d", time.Now().UnixNano()), option.ZeroTierEndpointOptions{NetworkID: "0123456789abcdef"})
	require.NoError(t, err)

	ep := endpoint.(*Endpoint)
	t.Cleanup(func() {
		require.NoError(t, ep.Close())
	})

	ran := make(chan struct{}, 1)
	ep.queueMulticastOperation(func() {
		ran <- struct{}{}
	})

	select {
	case <-ran:
		t.Fatal("multicast worker started before explicit launch")
	case <-time.After(50 * time.Millisecond):
	}

	ep.goManaged(ep.runMulticastOps)
	require.Eventually(t, func() bool {
		select {
		case <-ran:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
}

func TestRunMulticastOpsSkipsQueuedWorkAfterClose(t *testing.T) {
	t.Parallel()

	ep := newTestEndpoint(t, nil)
	node := &fakeNode{}
	ep.node = node
	started := make(chan struct{})
	release := make(chan struct{})
	ep.queueMulticastOperation(func() {
		close(started)
		<-release
		// Ensure ep.done is closed before op1 returns. This makes the
		// test deterministic: runMulticastOps will see ep.done closed
		// before it attempts to execute op2.
		<-ep.done
	})
	ep.queueMulticastOperation(func() {
		ep.subscribeMulticastGroupOnNode(zeroTierBroadcastGroup, "subscribe")
	})

	<-started
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		require.NoError(t, ep.Close())
	}()
	close(release)
	<-closed
	require.Empty(t, node.multicastSubscribeCalls())
}

type fakeNode struct {
	callbacks              zt.NodeCallbacks
	joinHook               func(*fakeNode) error
	config                 *zt.VirtualNetworkConfig
	multicastMu            sync.Mutex
	multicastSubscribe     []multicastCall
	multicastSubscribeHook func(multicastCall) error
	multicastUnsub         []multicastCall
	frameMu                sync.Mutex
	frames                 []virtualNetworkFrameCall
	processFrameHook       func()
	closed                 atomic.Bool
}

type multicastCall struct {
	nwid uint64
	mac  uint64
	adi  uint32
}

type virtualNetworkFrameCall struct {
	nwid      uint64
	srcMAC    uint64
	dstMAC    uint64
	etherType uint
	vlanID    uint
	data      []byte
}

func (n *fakeNode) Address() uint64 { return 1 }

func (n *fakeNode) Status() zt.NodeStatus {
	return zt.NodeStatus{Address: 1, Online: true}
}

func (n *fakeNode) NetworkConfig(uint64) *zt.VirtualNetworkConfig { return n.config }

func (n *fakeNode) Peers() []zt.Peer { return nil }

func (n *fakeNode) Join(uint64) error {
	if n.joinHook != nil {
		return n.joinHook(n)
	}
	return nil
}

func (n *fakeNode) MulticastSubscribe(nwid, mac uint64, adi uint32) error {
	call := multicastCall{nwid: nwid, mac: mac, adi: adi}
	n.multicastMu.Lock()
	n.multicastSubscribe = append(n.multicastSubscribe, call)
	hook := n.multicastSubscribeHook
	n.multicastMu.Unlock()
	if hook != nil {
		return hook(call)
	}
	return nil
}

func (n *fakeNode) MulticastUnsubscribe(nwid, mac uint64, adi uint32) error {
	n.multicastMu.Lock()
	n.multicastUnsub = append(n.multicastUnsub, multicastCall{nwid: nwid, mac: mac, adi: adi})
	n.multicastMu.Unlock()
	return nil
}

func (n *fakeNode) multicastSubscribeCalls() []multicastCall {
	n.multicastMu.Lock()
	defer n.multicastMu.Unlock()
	return append([]multicastCall(nil), n.multicastSubscribe...)
}

func (n *fakeNode) multicastUnsubscribeCalls() []multicastCall {
	n.multicastMu.Lock()
	defer n.multicastMu.Unlock()
	return append([]multicastCall(nil), n.multicastUnsub...)
}

func (n *fakeNode) resetMulticastCalls() {
	n.multicastMu.Lock()
	defer n.multicastMu.Unlock()
	n.multicastSubscribe = nil
	n.multicastUnsub = nil
}

func (n *fakeNode) ProcessWirePacket(int64, netip.AddrPort, []byte, *int64) error { return nil }

func (n *fakeNode) ProcessBackgroundTasks(nextDeadline *int64) error {
	if nextDeadline != nil {
		*nextDeadline = 0
	}
	return nil
}

func (n *fakeNode) ProcessVirtualNetworkFrame(nwid, srcMAC, dstMAC uint64, etherType, vlanID uint, data []byte, _ *int64) error {
	if n.processFrameHook != nil {
		n.processFrameHook()
	}
	n.frameMu.Lock()
	defer n.frameMu.Unlock()
	n.frames = append(n.frames, virtualNetworkFrameCall{
		nwid:      nwid,
		srcMAC:    srcMAC,
		dstMAC:    dstMAC,
		etherType: etherType,
		vlanID:    vlanID,
		data:      append([]byte(nil), data...),
	})
	return nil
}

func (n *fakeNode) virtualNetworkFrames() []virtualNetworkFrameCall {
	n.frameMu.Lock()
	defer n.frameMu.Unlock()
	return append([]virtualNetworkFrameCall(nil), n.frames...)
}

func (n *fakeNode) Close() { n.closed.Store(true) }

type closeSensitiveNode struct {
	*fakeNode
	closing      atomic.Bool
	closeStarted chan struct{}
	releaseClose chan struct{}
}

func (n *closeSensitiveNode) Status() zt.NodeStatus {
	if n.closing.Load() {
		panic("Status should not be called while Close is in progress")
	}
	return n.fakeNode.Status()
}

func (n *closeSensitiveNode) NetworkConfig(nwid uint64) *zt.VirtualNetworkConfig {
	if n.closing.Load() {
		panic("NetworkConfig should not be called while Close is in progress")
	}
	return n.fakeNode.NetworkConfig(nwid)
}

func (n *closeSensitiveNode) Peers() []zt.Peer {
	if n.closing.Load() {
		panic("Peers should not be called while Close is in progress")
	}
	return n.fakeNode.Peers()
}

func (n *closeSensitiveNode) Close() {
	n.closing.Store(true)
	close(n.closeStarted)
	<-n.releaseClose
	n.fakeNode.Close()
}

func containsMulticastCall(calls []multicastCall, want multicastCall) bool {
	for _, call := range calls {
		if call == want {
			return true
		}
	}
	return false
}

func drainAndResetMulticastCalls(ep *Endpoint, node *fakeNode) {
	ep.waitForMulticastQueueDrain()
	node.resetMulticastCalls()
}

type fakePacketConn struct {
	closed atomic.Bool
}

func (c *fakePacketConn) ReadFromUDP([]byte) (int, *net.UDPAddr, error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	return 0, nil, &net.DNSError{IsTimeout: true}
}

func (c *fakePacketConn) WriteTo([]byte, net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return 0, nil
}

func (c *fakePacketConn) Close() error {
	c.closed.Store(true)
	return nil
}

func (c *fakePacketConn) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (c *fakePacketConn) SetReadDeadline(time.Time) error { return nil }

type fakeNetworkDispatcher struct {
	deliveries atomic.Uint64
}

func (d *fakeNetworkDispatcher) DeliverNetworkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	d.deliveries.Add(1)
}

func (*fakeNetworkDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func queueOutboundPacket(ep *Endpoint, packet []byte) {
	packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	outbound := outboundPacket{packetBuffer: packetBuffer, generation: ep.topologyGeneration.Load()}
	select {
	case ep.outbound <- outbound:
	case <-time.After(time.Second):
		packetBuffer.DecRef()
		panic("timed out queueing outbound packet")
	}
}

func buildIPv6NeighborSolicitation(t *testing.T, source, destination, target netip.Addr, sourceMAC uint64) []byte {
	t.Helper()

	const optionLength = 8
	payloadLength := header.ICMPv6NeighborSolicitMinimumSize + optionLength
	packet := make([]byte, header.IPv6MinimumSize+payloadLength)
	ip := header.IPv6(packet)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(payloadLength),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          header.NDPHopLimit,
		SrcAddr:           tcpip.AddrFromSlice(source.AsSlice()),
		DstAddr:           tcpip.AddrFromSlice(destination.AsSlice()),
	})

	icmpPacket := header.ICMPv6(packet[header.IPv6MinimumSize:])
	icmpPacket.SetType(header.ICMPv6NeighborSolicit)
	icmpPacket.SetCode(0)
	ns := header.NDPNeighborSolicit(packet[header.IPv6MinimumSize+header.ICMPv6HeaderSize:])
	ns.SetTargetAddress(tcpip.AddrFromSlice(target.AsSlice()))
	option := ns.Options()[:optionLength]
	option[0] = 1
	option[1] = 1
	writeMAC(option[2:], sourceMAC)
	icmpPacket.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:     icmpPacket,
		Src:        tcpip.AddrFromSlice(source.AsSlice()),
		Dst:        tcpip.AddrFromSlice(destination.AsSlice()),
		PayloadLen: payloadLength,
	}))

	return packet
}

func buildIPv6DADNeighborSolicitation(t *testing.T, target netip.Addr) []byte {
	t.Helper()

	destination := netip.MustParseAddr("ff02::1:ff00:1")
	payloadLength := header.ICMPv6NeighborSolicitMinimumSize
	packet := make([]byte, header.IPv6MinimumSize+payloadLength)
	ip := header.IPv6(packet)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(payloadLength),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          header.NDPHopLimit,
		SrcAddr:           tcpip.AddrFromSlice(netip.IPv6Unspecified().AsSlice()),
		DstAddr:           tcpip.AddrFromSlice(destination.AsSlice()),
	})
	icmpPacket := header.ICMPv6(packet[header.IPv6MinimumSize:])
	icmpPacket.SetType(header.ICMPv6NeighborSolicit)
	icmpPacket.SetCode(0)
	ns := header.NDPNeighborSolicit(packet[header.IPv6MinimumSize+header.ICMPv6HeaderSize:])
	ns.SetTargetAddress(tcpip.AddrFromSlice(target.AsSlice()))
	icmpPacket.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:     icmpPacket,
		Src:        tcpip.AddrFromSlice(netip.IPv6Unspecified().AsSlice()),
		Dst:        tcpip.AddrFromSlice(destination.AsSlice()),
		PayloadLen: payloadLength,
	}))
	return packet
}

func buildIPv6NeighborAdvertisement(t *testing.T, source, destination, target netip.Addr, targetMAC uint64, solicited bool) []byte {
	t.Helper()

	const optionLength = 8
	payloadLength := header.ICMPv6NeighborAdvertMinimumSize + optionLength
	packet := make([]byte, header.IPv6MinimumSize+payloadLength)
	ip := header.IPv6(packet)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(payloadLength),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          header.NDPHopLimit,
		SrcAddr:           tcpip.AddrFromSlice(source.AsSlice()),
		DstAddr:           tcpip.AddrFromSlice(destination.AsSlice()),
	})

	icmpPacket := header.ICMPv6(packet[header.IPv6MinimumSize:])
	icmpPacket.SetType(header.ICMPv6NeighborAdvert)
	icmpPacket.SetCode(0)
	na := header.NDPNeighborAdvert(packet[header.IPv6MinimumSize+header.ICMPv6HeaderSize:])
	na.SetTargetAddress(tcpip.AddrFromSlice(target.AsSlice()))
	na.SetSolicitedFlag(solicited)
	na.SetOverrideFlag(true)
	option := na.Options()[:optionLength]
	option[0] = 2
	option[1] = 1
	writeMAC(option[2:], targetMAC)
	icmpPacket.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:     icmpPacket,
		Src:        tcpip.AddrFromSlice(source.AsSlice()),
		Dst:        tcpip.AddrFromSlice(destination.AsSlice()),
		PayloadLen: payloadLength,
	}))

	return packet
}

func assertIPv6NeighborSolicitationPacket(t *testing.T, packet []byte, wantSource, wantDestination, wantTarget netip.Addr, wantSourceMAC uint64) {
	t.Helper()

	ip := header.IPv6(packet)
	require.Equal(t, tcpip.AddrFromSlice(wantSource.AsSlice()), ip.SourceAddress())
	require.Equal(t, tcpip.AddrFromSlice(wantDestination.AsSlice()), ip.DestinationAddress())
	require.Equal(t, uint8(header.NDPHopLimit), ip.HopLimit())
	icmpPacket := header.ICMPv6(packet[header.IPv6MinimumSize:])
	require.Equal(t, header.ICMPv6NeighborSolicit, icmpPacket.Type())
	require.Equal(t, header.ICMPv6Code(0), icmpPacket.Code())
	ns := header.NDPNeighborSolicit(packet[header.IPv6MinimumSize+header.ICMPv6HeaderSize:])
	require.Equal(t, tcpip.AddrFromSlice(wantTarget.AsSlice()), ns.TargetAddress())
	require.Equal(t, wantSourceMAC, readMAC(ns.Options()[2:8]))
}

func assertIPv6NeighborAdvertisementPacket(t *testing.T, packet []byte, wantSource, wantDestination, wantTarget netip.Addr, wantTargetMAC uint64, wantSolicited bool) {
	t.Helper()

	ip := header.IPv6(packet)
	require.Equal(t, tcpip.AddrFromSlice(wantSource.AsSlice()), ip.SourceAddress())
	require.Equal(t, tcpip.AddrFromSlice(wantDestination.AsSlice()), ip.DestinationAddress())
	require.Equal(t, uint8(header.NDPHopLimit), ip.HopLimit())
	icmpPacket := header.ICMPv6(packet[header.IPv6MinimumSize:])
	require.Equal(t, header.ICMPv6NeighborAdvert, icmpPacket.Type())
	require.Equal(t, header.ICMPv6Code(0), icmpPacket.Code())
	na := header.NDPNeighborAdvert(packet[header.IPv6MinimumSize+header.ICMPv6HeaderSize:])
	require.Equal(t, tcpip.AddrFromSlice(wantTarget.AsSlice()), na.TargetAddress())
	require.Equal(t, wantSolicited, na.SolicitedFlag())
	require.Equal(t, wantTargetMAC, readMAC(na.Options()[2:8]))
}

func writeMAC(dst []byte, mac uint64) {
	dst[0] = byte(mac >> 40)
	dst[1] = byte(mac >> 32)
	dst[2] = byte(mac >> 24)
	dst[3] = byte(mac >> 16)
	dst[4] = byte(mac >> 8)
	dst[5] = byte(mac)
}

func readMAC(src []byte) uint64 {
	return uint64(src[0])<<40 | uint64(src[1])<<32 | uint64(src[2])<<24 | uint64(src[3])<<16 | uint64(src[4])<<8 | uint64(src[5])
}

func buildIPv4ICMPEchoRequest(t *testing.T, source, destination netip.Addr) []byte {
	t.Helper()

	packet := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize+4)
	ip := header.IPv4(packet)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFromSlice(source.AsSlice()),
		DstAddr:     tcpip.AddrFromSlice(destination.AsSlice()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	icmpPacket := header.ICMPv4(packet[header.IPv4MinimumSize:])
	icmpPacket.SetType(header.ICMPv4Echo)
	icmpPacket.SetCode(0)
	copy(packet[header.IPv4MinimumSize+header.ICMPv4MinimumSize:], []byte{0x12, 0x34, 0x56, 0x78})
	icmpPacket.SetChecksum(header.ICMPv4Checksum(icmpPacket, 0))

	return packet
}

func buildIPv6ICMPEchoRequest(t *testing.T, source, destination netip.Addr) []byte {
	t.Helper()

	packet := make([]byte, header.IPv6MinimumSize+header.ICMPv6MinimumSize+4)
	ip := header.IPv6(packet)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     header.ICMPv6MinimumSize + 4,
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFromSlice(source.AsSlice()),
		DstAddr:           tcpip.AddrFromSlice(destination.AsSlice()),
	})

	icmpPacket := header.ICMPv6(packet[header.IPv6MinimumSize:])
	icmpPacket.SetType(header.ICMPv6EchoRequest)
	icmpPacket.SetCode(0)
	copy(packet[header.IPv6MinimumSize+header.ICMPv6MinimumSize:], []byte{0x87, 0x65, 0x43, 0x21})
	icmpPacket.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmpPacket,
		Src:         tcpip.AddrFromSlice(source.AsSlice()),
		Dst:         tcpip.AddrFromSlice(destination.AsSlice()),
		PayloadCsum: 0,
		PayloadLen:  header.ICMPv6MinimumSize + 4,
	}))

	return packet
}

func buildIPv4UDPDatagram(t *testing.T, source, destination netip.Addr) []byte {
	t.Helper()

	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	packet := make([]byte, header.IPv4MinimumSize+len(payload))
	ip := header.IPv4(packet)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         1,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFromSlice(source.AsSlice()),
		DstAddr:     tcpip.AddrFromSlice(destination.AsSlice()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	copy(packet[header.IPv4MinimumSize:], payload)
	return packet
}

func buildIPv6UDPDatagram(t *testing.T, source, destination netip.Addr) []byte {
	t.Helper()

	payload := []byte{0xca, 0xfe, 0xba, 0xbe}
	packet := make([]byte, header.IPv6MinimumSize+len(payload))
	ip := header.IPv6(packet)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(payload)),
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          1,
		SrcAddr:           tcpip.AddrFromSlice(source.AsSlice()),
		DstAddr:           tcpip.AddrFromSlice(destination.AsSlice()),
	})
	copy(packet[header.IPv6MinimumSize:], payload)
	return packet
}

func buildIPv4IGMPv3Report(t *testing.T, source, group netip.Addr, recordType header.IGMPv3ReportRecordType) []byte {
	t.Helper()

	serializer := header.IGMPv3ReportSerializer{Records: []header.IGMPv3ReportGroupAddressRecordSerializer{{
		RecordType:   recordType,
		GroupAddress: tcpip.AddrFromSlice(group.AsSlice()),
	}}}
	payload := make([]byte, serializer.Length())
	serializer.SerializeInto(payload)
	destination := netip.MustParseAddr("224.0.0.22")
	packet := make([]byte, header.IPv4MinimumSize+len(payload))
	ip := header.IPv4(packet)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         1,
		Protocol:    uint8(header.IGMPProtocolNumber),
		SrcAddr:     tcpip.AddrFromSlice(source.AsSlice()),
		DstAddr:     tcpip.AddrFromSlice(destination.AsSlice()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	copy(packet[header.IPv4MinimumSize:], payload)
	return packet
}

func buildIPv6MLDv2Report(t *testing.T, source, group netip.Addr, recordType header.MLDv2ReportRecordType) []byte {
	t.Helper()

	serializer := header.MLDv2ReportSerializer{Records: []header.MLDv2ReportMulticastAddressRecordSerializer{{
		RecordType:       recordType,
		MulticastAddress: tcpip.AddrFromSlice(group.AsSlice()),
	}}}
	bodyLength := serializer.Length()
	icmpLength := header.ICMPv6HeaderSize + bodyLength
	const hopByHopLength = 8
	payloadLength := hopByHopLength + icmpLength
	destination := netip.MustParseAddr("ff02::16")
	packet := make([]byte, header.IPv6MinimumSize+payloadLength)
	ip := header.IPv6(packet)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(payloadLength),
		TransportProtocol: tcpip.TransportProtocolNumber(header.IPv6HopByHopOptionsExtHdrIdentifier),
		HopLimit:          header.MLDHopLimit,
		SrcAddr:           tcpip.AddrFromSlice(source.AsSlice()),
		DstAddr:           tcpip.AddrFromSlice(destination.AsSlice()),
	})
	hopByHop := packet[header.IPv6MinimumSize : header.IPv6MinimumSize+hopByHopLength]
	hopByHop[0] = byte(header.ICMPv6ProtocolNumber)
	hopByHop[1] = 0
	hopByHop[2] = 5
	hopByHop[3] = 2
	hopByHop[4] = 0
	hopByHop[5] = 0
	hopByHop[6] = 1
	hopByHop[7] = 0
	icmpPacket := header.ICMPv6(packet[header.IPv6MinimumSize+hopByHopLength:])
	icmpPacket.SetType(header.ICMPv6MulticastListenerV2Report)
	icmpPacket.SetCode(0)
	serializer.SerializeInto(icmpPacket[header.ICMPv6HeaderSize:])
	icmpPacket.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:     icmpPacket,
		Src:        tcpip.AddrFromSlice(source.AsSlice()),
		Dst:        tcpip.AddrFromSlice(destination.AsSlice()),
		PayloadLen: icmpLength,
	}))
	return packet
}

func hasTransportProtocolHandler(ipStack *stack.Stack, protocol tcpip.TransportProtocolNumber) bool {
	transportProtocols := reflect.ValueOf(ipStack).Elem().FieldByName("transportProtocols")
	state := transportProtocols.MapIndex(reflect.ValueOf(protocol))
	if !state.IsValid() || state.IsNil() {
		return false
	}

	defaultHandler := state.Elem().FieldByName("defaultHandler")
	defaultHandler = reflect.NewAt(defaultHandler.Type(), unsafe.Pointer(defaultHandler.UnsafeAddr())).Elem()
	return !defaultHandler.IsNil()
}

func assertICMPEchoReplyPacket(t *testing.T, packet []byte, wantType byte, wantSource, wantDestination netip.Addr) {
	t.Helper()

	version := header.IPVersion(packet)
	switch version {
	case header.IPv4Version:
		ip := header.IPv4(packet)
		require.Equal(t, tcpip.AddrFromSlice(wantSource.AsSlice()), ip.SourceAddress())
		require.Equal(t, tcpip.AddrFromSlice(wantDestination.AsSlice()), ip.DestinationAddress())
		require.Equal(t, wantType, packet[int(ip.HeaderLength())])
	case header.IPv6Version:
		ip := header.IPv6(packet)
		require.Equal(t, tcpip.AddrFromSlice(wantSource.AsSlice()), ip.SourceAddress())
		require.Equal(t, tcpip.AddrFromSlice(wantDestination.AsSlice()), ip.DestinationAddress())
		require.Equal(t, wantType, packet[header.IPv6MinimumSize])
	default:
		t.Fatalf("unexpected IP version %d", version)
	}
}

func TestForwardOutboundDrainsPendingOnClose(t *testing.T) {
	ep := newTestEndpoint(t, nil)
	close(ep.done)
	t.Cleanup(func() {
		for {
			select {
			case outbound := <-ep.outbound:
				if outbound.packetBuffer == nil {
					continue
				}
				for refs := outbound.packetBuffer.ReadRefs(); refs > 0; refs = outbound.packetBuffer.ReadRefs() {
					outbound.packetBuffer.DecRef()
				}
			default:
				ep.managed.Wait()
				return
			}
		}
	})

	packets := []*stack.PacketBuffer{
		stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{0x45, 0x00, 0x00, 0x14})}),
		stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{0x45, 0x00, 0x00, 0x14})}),
		stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{0x45, 0x00, 0x00, 0x14})}),
	}
	for _, packetBuffer := range packets {
		ep.outbound <- outboundPacket{packetBuffer: packetBuffer, generation: ep.topologyGeneration.Load()}
	}

	ep.forwardOutbound()

	require.Zero(t, len(ep.outbound))
	for _, packetBuffer := range packets {
		require.Zero(t, packetBuffer.ReadRefs())
	}
}

func TestZtLinkEndpointWritePacketsReleasesRefsOnClose(t *testing.T) {
	ep := newTestEndpoint(t, nil)
	close(ep.done)
	t.Cleanup(func() {
		ep.managed.Wait()
	})

	pbuf1 := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{0x45, 0x00})})
	pbuf2 := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{0x45, 0x00})})
	t.Cleanup(func() {
		for refs := pbuf1.ReadRefs(); refs > 0; refs = pbuf1.ReadRefs() {
			pbuf1.DecRef()
		}
		for refs := pbuf2.ReadRefs(); refs > 0; refs = pbuf2.ReadRefs() {
			pbuf2.DecRef()
		}
	})

	require.EqualValues(t, 1, pbuf1.ReadRefs())
	require.EqualValues(t, 1, pbuf2.ReadRefs())

	var list stack.PacketBufferList
	list.PushBack(pbuf1)
	list.PushBack(pbuf2)

	for i := len(ep.outbound); i < cap(ep.outbound); i++ {
		ep.outbound <- outboundPacket{}
	}
	queueLen := len(ep.outbound)

	le := (*ztLinkEndpoint)(ep)
	n, tErr := le.WritePackets(list)

	require.Equal(t, 0, n)
	require.IsType(t, &tcpip.ErrClosedForSend{}, tErr)
	require.Equal(t, queueLen, len(ep.outbound))
	require.EqualValues(t, 1, pbuf1.ReadRefs())
	require.EqualValues(t, 1, pbuf2.ReadRefs())
}

func newTestEndpoint(t *testing.T, addresses []netip.Prefix) *Endpoint {
	t.Helper()

	endpoint, err := NewEndpoint(context.Background(), nil, logger.NOP(), fmt.Sprintf("test-%d", time.Now().UnixNano()), option.ZeroTierEndpointOptions{NetworkID: "0123456789abcdef", Address: addresses})
	require.NoError(t, err)
	ep := endpoint.(*Endpoint)
	ep.goManaged(ep.runMulticastOps)
	ep.goManaged(ep.runPendingIPv6NeighborProbes)
	return ep
}

func requireProtocolAddresses(t *testing.T, ep *Endpoint, expected []netip.Prefix) {
	t.Helper()

	addresses := ep.ipStack.AllAddresses()[tun.DefaultNIC]
	actual := make([]netip.Prefix, 0, len(addresses))
	for _, address := range addresses {
		ip, ok := netip.AddrFromSlice(address.AddressWithPrefix.Address.AsSlice())
		require.True(t, ok)
		prefix := netip.PrefixFrom(ip, address.AddressWithPrefix.PrefixLen)
		if prefix == netip.MustParsePrefix("255.255.255.255/32") {
			continue
		}
		actual = append(actual, prefix)
	}
	require.ElementsMatch(t, expected, actual)
}

func requireProtocolAddressesContain(t *testing.T, ep *Endpoint, expected netip.Prefix) {
	t.Helper()
	addresses := ep.ipStack.AllAddresses()[tun.DefaultNIC]
	for _, address := range addresses {
		ip, ok := netip.AddrFromSlice(address.AddressWithPrefix.Address.AsSlice())
		require.True(t, ok)
		if netip.PrefixFrom(ip, address.AddressWithPrefix.PrefixLen) == expected {
			return
		}
	}
	t.Fatalf("expected protocol address %s to be present", expected)
}
