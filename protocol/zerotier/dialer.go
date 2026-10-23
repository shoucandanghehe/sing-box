//go:build with_zerotier && with_gvisor

package zerotier

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (ep *Endpoint) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	if network == uint8(header.ICMPv4ProtocolNumber) || network == uint8(header.ICMPv6ProtocolNumber) {
		addr4, addr6 := ep.runtimeBindAddresses()
		destinationAddr := tun.AddressFromAddr(destination.Addr())
		if destinationAddr == addr4 || destinationAddr == addr6 {
			return tun.FlowVerdict{Action: tun.ActionAccept}
		}
	}
	return adapter.JudgeFlow(ep.router, ep.Tag(), ep.Type(), network, source, destination, firstPacket)
}

func (ep *Endpoint) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	ctx := log.ContextWithNewID(ep.ctx)
	ep.router.HijackDNSPacket(ctx, payload, writer, adapter.InboundContext{
		Inbound:     ep.Tag(),
		InboundType: ep.Type(),
		Network:     N.NetworkUDP,
		Source:      source,
		Destination: destination,
		Protocol:    C.ProtocolDNS,
	})
}

func (ep *Endpoint) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = ep.Tag()
	metadata.InboundType = ep.Type()
	metadata.Source = source
	for _, localPrefix := range ep.currentNetworkState().localAddresses {
		if localPrefix.Contains(destination.Addr) {
			metadata.OriginDestination = destination
			if destination.Addr.Is4() {
				destination.Addr = netip.AddrFrom4([4]uint8{127, 0, 0, 1})
			} else {
				destination.Addr = netip.IPv6Loopback()
			}
			break
		}
	}
	metadata.Destination = destination
	ep.logger.InfoContext(ctx, "inbound connection from ", source)
	ep.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	ep.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (ep *Endpoint) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = ep.Tag()
	metadata.InboundType = ep.Type()
	metadata.Source = source
	metadata.Destination = destination
	for _, localPrefix := range ep.currentNetworkState().localAddresses {
		if localPrefix.Contains(destination.Addr) {
			metadata.OriginDestination = destination
			if destination.Addr.Is4() {
				metadata.Destination.Addr = netip.AddrFrom4([4]uint8{127, 0, 0, 1})
			} else {
				metadata.Destination.Addr = netip.IPv6Loopback()
			}
			conn = bufio.NewNATPacketConn(bufio.NewNetPacketConn(conn), metadata.OriginDestination, metadata.Destination)
		}
	}
	ep.logger.InfoContext(ctx, "inbound packet connection from ", source)
	ep.logger.InfoContext(ctx, "inbound packet connection to ", destination)
	ep.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

// --- Outbound ---
func (ep *Endpoint) beginStackCall() (*stack.Stack, bool) {
	ep.lifecycleMu.Lock()
	defer ep.lifecycleMu.Unlock()
	if ep.closed.Load() || ep.ipStack == nil {
		return nil, false
	}
	ep.stackCalls.Add(1)
	return ep.ipStack, true
}

func (ep *Endpoint) stackCallContext(ctx context.Context) (context.Context, context.CancelFunc) {
	callCtx, cancel := context.WithCancel(ctx)
	if ep.closeCtx == nil {
		return callCtx, cancel
	}
	stop := context.AfterFunc(ep.closeCtx, cancel)
	return callCtx, func() {
		stop()
		cancel()
	}
}

func (ep *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ipStack, admitted := ep.beginStackCall()
	if !admitted {
		return nil, net.ErrClosed
	}
	defer ep.stackCalls.Done()
	ctx, cancel := ep.stackCallContext(ctx)
	defer cancel()
	switch network {
	case N.NetworkTCP:
		ep.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		ep.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}

	if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}

	addr := tcpip.FullAddress{
		NIC:  tun.DefaultNIC,
		Port: destination.Port,
		Addr: tun.AddressFromAddr(destination.Addr),
	}
	bind := tcpip.FullAddress{NIC: tun.DefaultNIC}
	bindAddr4, bindAddr6 := ep.runtimeBindAddresses()
	var networkProtocol tcpip.NetworkProtocolNumber
	if destination.IsIPv4() {
		networkProtocol = header.IPv4ProtocolNumber
		bind.Addr = bindAddr4
	} else {
		networkProtocol = header.IPv6ProtocolNumber
		bind.Addr = bindAddr6
	}

	switch N.NetworkName(network) {
	case N.NetworkTCP:
		// Pre-resolve MAC via ARP before TCP connect to avoid broadcast SYN.
		if destination.IsIPv4() {
			dstIP := destination.Addr.String()
			_, known, nextHop := ep.resolveNextHopMAC(dstIP)
			if !known {
				ep.logger.Debug(fmt.Sprintf("pre-ARP for %s (next hop: %s)", dstIP, nextHop))
				ep.sendARPRequest(nextHop)
				for i := 0; i < 20; i++ {
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(100 * time.Millisecond):
					}
					_, known, _ = ep.resolveNextHopMAC(dstIP)
					if known {
						ep.logger.Debug(fmt.Sprintf("ARP resolved %s before TCP connect", nextHop))
						break
					}
					if i%5 == 4 {
						ep.sendARPRequest(nextHop)
					}
				}
			}
		}
		return dialTCPWithBind(ctx, ipStack, bind, addr, networkProtocol)
	case N.NetworkUDP:
		return gonet.DialUDP(ipStack, &bind, &addr, networkProtocol)
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (ep *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ipStack, admitted := ep.beginStackCall()
	if !admitted {
		return nil, net.ErrClosed
	}
	defer ep.stackCalls.Done()
	ep.logger.InfoContext(ctx, "outbound packet connection to ", destination)

	bind := tcpip.FullAddress{NIC: tun.DefaultNIC}
	bindAddr4, bindAddr6 := ep.runtimeBindAddresses()
	var networkProtocol tcpip.NetworkProtocolNumber
	if destination.IsIPv4() {
		networkProtocol = header.IPv4ProtocolNumber
		bind.Addr = bindAddr4
	} else {
		networkProtocol = header.IPv6ProtocolNumber
		bind.Addr = bindAddr6
	}

	return gonet.DialUDP(ipStack, &bind, nil, networkProtocol)
}
