//go:build with_zerotier && with_gvisor

package zerotier

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestZtLinkEndpointAttachNilClearsDispatcher(t *testing.T) {
	ep := &Endpoint{}
	linkEndpoint := (*ztLinkEndpoint)(ep)
	linkEndpoint.Attach(&fakeNetworkDispatcher{})
	if !linkEndpoint.IsAttached() {
		t.Fatal("link endpoint did not attach dispatcher")
	}

	linkEndpoint.Attach(nil)
	if linkEndpoint.IsAttached() {
		t.Fatal("Attach(nil) left link endpoint attached")
	}
}

func TestEndpointReceiveFrameIgnoresNilDispatcher(t *testing.T) {
	ep := &Endpoint{}
	linkEndpoint := (*ztLinkEndpoint)(ep)
	linkEndpoint.Attach(nil)

	defer func() {
		if panicValue := recover(); panicValue != nil {
			t.Fatalf("frame delivery panicked with nil dispatcher: %v", panicValue)
		}
	}()
	ep.onVirtualNetworkFrame(0, 0, 0, 0x0800, 0, []byte{0})
}

func TestCreateStackCleansPartialInitializationFailure(t *testing.T) {
	address := netip.MustParsePrefix("10.0.0.1/24")
	ep := newTestEndpoint(t, []netip.Prefix{address, address})
	defer ep.Close()

	if err := ep.createStack(); err == nil {
		t.Fatal("createStack succeeded with duplicate protocol addresses")
	}
	if (*ztLinkEndpoint)(ep).IsAttached() {
		t.Fatal("failed stack initialization left link dispatcher attached")
	}
	addr4, addr6 := ep.runtimeBindAddresses()
	if addr4.Len() != 0 || addr6.Len() != 0 {
		t.Fatalf("failed stack initialization left runtime addresses: IPv4=%s IPv6=%s", addr4, addr6)
	}
	if ep.udpForwarder != nil || ep.icmpForwarder != nil {
		t.Fatal("failed stack initialization left forwarders published")
	}
}

type forwardedUDPPacket struct {
	payload  []byte
	metadata adapter.InboundContext
	err      error
}

type forwarderTestRouter struct {
	adapter.Router
	action   adapter.PreMatchAction
	received chan forwardedUDPPacket
}

func (r *forwarderTestRouter) PreMatch(adapter.InboundContext, []byte) adapter.PreMatchResult {
	return adapter.PreMatchResult{Action: r.action}
}

func (r *forwarderTestRouter) RoutePacketConnectionEx(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, _ N.CloseHandlerFunc) {
	defer conn.Close()
	packet := buf.NewPacket()
	defer packet.Release()
	_, err := conn.ReadPacket(packet)
	r.received <- forwardedUDPPacket{payload: append([]byte(nil), packet.Bytes()...), metadata: metadata, err: err}
}

func (r *forwarderTestRouter) HijackDNSPacket(_ context.Context, payload []byte, _ N.PacketWriter, metadata adapter.InboundContext) {
	r.received <- forwardedUDPPacket{payload: append([]byte(nil), payload...), metadata: metadata}
}

func TestEndpointUDPForwarderDispatchesIncomingPackets(t *testing.T) {
	for _, test := range []struct {
		name        string
		action      adapter.PreMatchAction
		destination string
		protocol    string
	}{
		{name: "route", action: adapter.PreMatchContinue, destination: "127.0.0.1:53"},
		{name: "hijack_dns", action: adapter.PreMatchHijackDNS, destination: "10.0.0.1:53", protocol: C.ProtocolDNS},
	} {
		t.Run(test.name, func(t *testing.T) {
			ep := newTestEndpoint(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
			t.Cleanup(func() { require.NoError(t, ep.Close()) })
			router := &forwarderTestRouter{action: test.action, received: make(chan forwardedUDPPacket, 1)}
			ep.router = router
			require.NoError(t, ep.createStack())

			source := netip.MustParseAddrPort("10.0.0.2:12345")
			destination := netip.MustParseAddrPort("10.0.0.1:53")
			payload := []byte("zerotier-packet")
			frame := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
			ipHeader := header.IPv4(frame)
			ipHeader.Encode(&header.IPv4Fields{
				TotalLength: uint16(len(frame)),
				TTL:         64,
				Protocol:    uint8(header.UDPProtocolNumber),
				SrcAddr:     tun.AddressFromAddr(source.Addr()),
				DstAddr:     tun.AddressFromAddr(destination.Addr()),
			})
			ipHeader.SetChecksum(^ipHeader.CalculateChecksum())
			udpHeader := header.UDP(frame[header.IPv4MinimumSize:])
			udpHeader.Encode(&header.UDPFields{
				SrcPort: source.Port(),
				DstPort: destination.Port(),
				Length:  uint16(header.UDPMinimumSize + len(payload)),
			})
			copy(frame[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)
			ep.onVirtualNetworkFrame(ep.networkID, 0x010203040506, 0, 0x0800, 0, frame)

			select {
			case packet := <-router.received:
				require.NoError(t, packet.err)
				require.Equal(t, payload, packet.payload)
				require.Equal(t, ep.Tag(), packet.metadata.Inbound)
				require.Equal(t, C.TypeZeroTier, packet.metadata.InboundType)
				require.Equal(t, source, packet.metadata.Source.AddrPort())
				require.Equal(t, netip.MustParseAddrPort(test.destination), packet.metadata.Destination.AddrPort())
				require.Equal(t, test.protocol, packet.metadata.Protocol)
			case <-time.After(time.Second):
				t.Fatal("incoming UDP packet did not reach the router")
			}
		})
	}
}

func TestEndpointJudgeFlowLocalICMPUsesRuntimeAddress(t *testing.T) {
	for _, test := range []struct {
		name     string
		network  uint8
		previous string
		next     string
		peer     string
	}{
		{name: "ipv4", network: uint8(header.ICMPv4ProtocolNumber), previous: "10.0.0.1/24", next: "10.0.0.3/24", peer: "10.0.0.2"},
		{name: "ipv6", network: uint8(header.ICMPv6ProtocolNumber), previous: "fd00::1/64", next: "fd00::3/64", peer: "fd00::2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			previous := netip.MustParsePrefix(test.previous)
			next := netip.MustParsePrefix(test.next)
			ep := newTestEndpoint(t, []netip.Prefix{previous})
			t.Cleanup(func() { require.NoError(t, ep.Close()) })
			ep.router = &forwarderTestRouter{action: adapter.PreMatchReject}
			require.NoError(t, ep.createStack())
			source := netip.AddrPortFrom(netip.MustParseAddr(test.peer), 42)

			require.Equal(t, tun.ActionAccept, ep.JudgeFlow(test.network, source, netip.AddrPortFrom(previous.Addr(), 42), nil).Action)
			require.Equal(t, tun.ActionReject, ep.JudgeFlow(test.network, source, source, nil).Action)
			require.NoError(t, ep.syncRuntimeAddresses([]netip.Prefix{previous}, []netip.Prefix{next}))
			require.Equal(t, tun.ActionAccept, ep.JudgeFlow(test.network, source, netip.AddrPortFrom(next.Addr(), 42), nil).Action)
			require.Equal(t, tun.ActionReject, ep.JudgeFlow(test.network, source, netip.AddrPortFrom(previous.Addr(), 42), nil).Action)
		})
	}
}
