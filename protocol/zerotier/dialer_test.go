//go:build with_zerotier && with_gvisor

package zerotier

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	zt "github.com/scdhh/go-zt"
	"github.com/stretchr/testify/require"
)

func TestDialerRejectsNewCallsAfterCloseStarts(t *testing.T) {
	destination := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: 53}
	tests := []struct {
		name string
		call func(*Endpoint) (ioCloser, error)
	}{
		{
			name: "DialContext",
			call: func(ep *Endpoint) (ioCloser, error) {
				return ep.DialContext(context.Background(), N.NetworkUDP, destination)
			},
		},
		{
			name: "ListenPacket",
			call: func(ep *Endpoint) (ioCloser, error) {
				return ep.ListenPacket(context.Background(), destination)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ep := newTestEndpoint(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
			if err := ep.createStack(); err != nil {
				t.Fatal(err)
			}

			closeStarted := make(chan struct{})
			releaseClose := make(chan struct{})
			ep.goManaged(func() {
				<-ep.done
				close(closeStarted)
				<-releaseClose
			})
			closeResult := make(chan error, 1)
			go func() {
				closeResult <- ep.Close()
			}()
			<-closeStarted

			resource, err := test.call(ep)
			if resource != nil {
				_ = resource.Close()
			}
			if err == nil {
				close(releaseClose)
				<-closeResult
				t.Fatal("call succeeded after Close started")
			}
			if !isClosedError(err) {
				close(releaseClose)
				<-closeResult
				t.Fatalf("error = %v, want net.ErrClosed", err)
			}

			close(releaseClose)
			if err := <-closeResult; err != nil {
				t.Fatal(err)
			}
		})
	}
}

type ioCloser interface {
	Close() error
}

func isClosedError(err error) bool {
	return err == net.ErrClosed
}

type blockingInfoContextLogger struct {
	logger.ContextLogger
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (l *blockingInfoContextLogger) InfoContext(context.Context, ...any) {
	l.once.Do(func() {
		close(l.entered)
	})
	<-l.release
}

func TestEndpointCloseWaitsForEnteredDial(t *testing.T) {
	loggerEntered := make(chan struct{})
	releaseLogger := make(chan struct{})
	blockingLogger := &blockingInfoContextLogger{
		ContextLogger: logger.NOP(),
		entered:       loggerEntered,
		release:       releaseLogger,
	}
	endpoint, err := NewEndpoint(context.Background(), nil, blockingLogger, "dial-close-wait", option.ZeroTierEndpointOptions{
		NetworkID: "0123456789abcdef",
		Address:   []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
	})
	if err != nil {
		t.Fatal(err)
	}
	ep := endpoint.(*Endpoint)
	if err := ep.createStack(); err != nil {
		t.Fatal(err)
	}
	udpConn := &closeSignalingPacketConn{closed: make(chan struct{})}
	ep.udpConn = udpConn

	dialResult := make(chan error, 1)
	go func() {
		conn, err := ep.DialContext(context.Background(), N.NetworkUDP, M.Socksaddr{
			Addr: netip.MustParseAddr("192.0.2.1"),
			Port: 53,
		})
		if conn != nil {
			_ = conn.Close()
		}
		dialResult <- err
	}()
	<-loggerEntered

	closeResult := make(chan error, 1)
	go func() {
		closeResult <- ep.Close()
	}()
	<-udpConn.closed
	select {
	case err := <-closeResult:
		close(releaseLogger)
		t.Fatalf("Close returned before entered DialContext completed: %v", err)
	default:
	}

	close(releaseLogger)
	if err := <-dialResult; err != nil {
		t.Fatalf("entered DialContext failed: %v", err)
	}
	if err := <-closeResult; err != nil {
		t.Fatal(err)
	}
}

type tcpPeerNode struct {
	fakeNode
	send func([]byte)
}

func (n *tcpPeerNode) ProcessVirtualNetworkFrame(_, _, _ uint64, etherType, _ uint, data []byte, _ *int64) error {
	if etherType == uint(header.IPv4ProtocolNumber) {
		n.send(data)
	}
	return nil
}

// Only ZeroTier's frame transport is replaced; both endpoints use real TCP stacks.
func newTCPTestEndpoint(t *testing.T, forward bool) (*Endpoint, net.Listener, <-chan struct{}) {
	t.Helper()
	localPrefix := netip.MustParsePrefix("192.0.2.1/24")
	peerPrefix := netip.MustParsePrefix("192.0.2.2/24")
	peerLink := channel.New(256, 1500, "")
	t.Cleanup(peerLink.Close)
	peerStack, err := tun.NewGVisorStack(peerLink)
	require.NoError(t, err)
	t.Cleanup(func() { closeGVisorStack(peerStack) })
	require.Nil(t, peerStack.AddProtocolAddress(tun.DefaultNIC, protocolAddressFromPrefix(peerPrefix), stack.AddressProperties{}))
	listener, err := gonet.ListenTCP(peerStack, tcpip.FullAddress{
		NIC: tun.DefaultNIC, Addr: tun.AddressFromAddr(peerPrefix.Addr()), Port: 8080,
	}, header.IPv4ProtocolNumber)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })

	ep := newTestEndpoint(t, []netip.Prefix{localPrefix})
	t.Cleanup(func() { require.NoError(t, ep.Close()) })
	sent := make(chan struct{})
	var sentOnce sync.Once
	ep.node = &tcpPeerNode{send: func(data []byte) {
		if header.IPv4(data).Protocol() == uint8(header.TCPProtocolNumber) {
			sentOnce.Do(func() { close(sent) })
		}
		if forward {
			packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
			peerLink.InjectInbound(header.IPv4ProtocolNumber, packet)
			packet.DecRef()
		}
	}}
	_, err = ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{
		Status: zt.NetworkStatusOK, MAC: 0x020000000001, AssignedAddresses: []netip.Prefix{localPrefix},
	})
	require.NoError(t, err)
	require.NoError(t, ep.createStack())
	ep.learnMAC(peerPrefix.Addr(), 0x020000000002)
	ep.goManaged(ep.forwardOutbound)

	wireCtx, cancelWire := context.WithCancel(context.Background())
	var wire sync.WaitGroup
	wire.Go(func() {
		for {
			packet := peerLink.ReadContext(wireCtx)
			if packet == nil {
				return
			}
			var data []byte
			for _, part := range packet.AsSlices() {
				data = append(data, part...)
			}
			packet.DecRef()
			ep.withNode(func(zeroTierNode) {
				ep.onVirtualNetworkFrame(ep.networkID, 0x020000000002, 0x020000000001, 0x0800, 0, data)
			})
		}
	})
	t.Cleanup(func() {
		cancelWire()
		wire.Wait()
	})
	return ep, listener, sent
}

func TestEndpointTCPConnectionSurvivesDialContext(t *testing.T) {
	ep, listener, _ := newTCPTestEndpoint(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := ep.DialContext(ctx, N.NetworkTCP, M.SocksaddrFromNet(listener.Addr()))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	peer, err := listener.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, peer.Close()) })
	cancel()

	for range 2 {
		_, err = conn.Write([]byte("request"))
		require.NoError(t, err)
		request := make([]byte, len("request"))
		_, err = io.ReadFull(peer, request)
		require.NoError(t, err)
		require.Equal(t, "request", string(request))
		_, err = peer.Write([]byte("response"))
		require.NoError(t, err)
		response := make([]byte, len("response"))
		_, err = io.ReadFull(conn, response)
		require.NoError(t, err)
		require.Equal(t, "response", string(response))
	}
}

func TestEndpointTCPPendingDialCancellation(t *testing.T) {
	for _, name := range []string{"caller cancellation", "caller deadline", "endpoint close"} {
		t.Run(name, func(t *testing.T) {
			ep, listener, sent := newTCPTestEndpoint(t, false)
			var (
				ctx    context.Context
				cancel context.CancelFunc
			)
			wantError := context.Canceled
			if name == "caller deadline" {
				ctx, cancel = context.WithTimeout(context.Background(), time.Second)
				wantError = context.DeadlineExceeded
			} else {
				ctx, cancel = context.WithCancel(context.Background())
			}
			defer cancel()
			result := make(chan error, 1)
			go func() {
				conn, err := ep.DialContext(ctx, N.NetworkTCP, M.SocksaddrFromNet(listener.Addr()))
				if err == nil {
					_ = conn.Close()
				}
				result <- err
			}()
			select {
			case <-sent:
			case <-time.After(time.Second):
				t.Fatal("TCP connect did not send its first packet")
			}
			switch name {
			case "endpoint close":
				require.NoError(t, ep.Close())
			case "caller cancellation":
				cancel()
			}
			select {
			case err := <-result:
				require.ErrorIs(t, err, wantError)
			case <-time.After(3 * time.Second):
				t.Fatal("pending TCP dial ignored cancellation")
			}
		})
	}
}

func TestEndpointEstablishedTCPClosesWithItsOwners(t *testing.T) {
	for _, closeEndpoint := range []bool{false, true} {
		name := "caller close"
		if closeEndpoint {
			name = "endpoint close"
		}
		t.Run(name, func(t *testing.T) {
			ep, listener, _ := newTCPTestEndpoint(t, true)
			conn, err := ep.DialContext(context.Background(), N.NetworkTCP, M.SocksaddrFromNet(listener.Addr()))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, conn.Close()) })
			peer, err := listener.Accept()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, peer.Close()) })
			if closeEndpoint {
				result := make(chan error, 1)
				go func() {
					_, err := conn.Read(make([]byte, 1))
					result <- err
				}()
				require.NoError(t, ep.Close())
				select {
				case err := <-result:
					require.Error(t, err)
					if timeout, ok := err.(net.Error); ok {
						require.False(t, timeout.Timeout(), "endpoint shutdown must not rely on an expired dial deadline")
					}
				case <-time.After(time.Second):
					t.Fatal("endpoint close left TCP read blocked")
				}
			} else {
				require.NoError(t, conn.Close())
				require.NoError(t, conn.Close())
				require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
				_, err = peer.Read(make([]byte, 1))
				require.ErrorIs(t, err, io.EOF)
			}
		})
	}
}
