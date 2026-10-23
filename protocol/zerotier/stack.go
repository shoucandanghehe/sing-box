//go:build with_zerotier && with_gvisor

package zerotier

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/icmp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/gvisor/pkg/waiter"
	"github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
)

func closeGVisorStack(ipStack *stack.Stack) {
	ipStack.Close()
	for _, endpoint := range ipStack.CleanupEndpoints() {
		endpoint.Abort()
	}
	ipStack.Wait()
}

func (ep *Endpoint) createStack() error {
	ep.runtimeStateMu.Lock()
	defer ep.runtimeStateMu.Unlock()

	ipStack, err := tun.NewGVisorStack((*ztLinkEndpoint)(ep))
	if err != nil {
		return err
	}
	initialized := false
	var udpForwarder *tun.UDPForwarder
	var icmpForwarder *tun.ICMPForwarder
	defer func() {
		if initialized {
			return
		}
		if icmpForwarder != nil {
			_ = icmpForwarder.Close()
		}
		if udpForwarder != nil {
			_ = udpForwarder.Close()
		}
		closeGVisorStack(ipStack)
		ep.addr4 = tcpip.Address{}
		ep.addr6 = tcpip.Address{}
		ep.tentativeIPv6Mu.Lock()
		clear(ep.tentativeIPv6)
		ep.tentativeIPv6Mu.Unlock()
	}()

	for _, prefix := range ep.currentNetworkState().localAddresses {
		addr := tun.AddressFromAddr(prefix.Addr())
		protoAddr := protocolAddressFromPrefix(prefix)
		if prefix.Addr().Is4() {
			ep.addr4 = addr
		} else {
			ep.addr6 = addr
		}
		if gErr := ipStack.AddProtocolAddress(tun.DefaultNIC, protoAddr, ep.runtimeAddressProperties(prefix)); gErr != nil {
			return E.New("add address ", protoAddr.AddressWithPrefix, ": ", gErr.String())
		}
		ep.markTentativeRuntimeIPv6Address(prefix.Addr())
	}

	ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tun.NewTCPForwarder(ep.ctx, ipStack, ep).HandlePacket)
	udpForwarder = tun.NewUDPForwarder(ep.ctx, ipStack, ep, tun.UDPNatOptions{
		Timeout: ep.udpTimeout,
		Shared:  true,
	})
	if err = udpForwarder.Start(); err != nil {
		return E.Cause(err, "start UDP forwarder")
	}
	ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	icmpForwarder = tun.NewICMPForwarder(ipStack, ep, ep.logger)
	ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber4, icmpForwarder.HandlePacket)
	ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber6, icmpForwarder.HandlePacket)

	ep.lifecycleMu.Lock()
	if ep.closed.Load() {
		ep.lifecycleMu.Unlock()
		return net.ErrClosed
	}
	ep.ipStack = ipStack
	ep.udpForwarder = udpForwarder
	ep.icmpForwarder = icmpForwarder
	ep.lifecycleMu.Unlock()
	initialized = true
	return nil
}

var _ stack.LinkEndpoint = (*ztLinkEndpoint)(nil)

type ztLinkEndpoint Endpoint

func (le *ztLinkEndpoint) MTU() uint32                      { return le.mtu.Load() }
func (le *ztLinkEndpoint) SetMTU(uint32)                    {}
func (le *ztLinkEndpoint) MaxHeaderLength() uint16          { return 0 }
func (le *ztLinkEndpoint) LinkAddress() tcpip.LinkAddress   { return "" }
func (le *ztLinkEndpoint) SetLinkAddress(tcpip.LinkAddress) {}
func (le *ztLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}
func (le *ztLinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	if dispatcher == nil {
		le.dispatcher.Store(nil)
		return
	}
	le.dispatcher.Store(&dispatcherHolder{value: dispatcher})
}
func (le *ztLinkEndpoint) IsAttached() bool                        { return le.dispatcher.Load() != nil }
func (le *ztLinkEndpoint) Wait()                                   {}
func (le *ztLinkEndpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }
func (le *ztLinkEndpoint) AddHeader(*stack.PacketBuffer)           {}
func (le *ztLinkEndpoint) ParseHeader(*stack.PacketBuffer) bool    { return true }
func (le *ztLinkEndpoint) Close()                                  {}
func (le *ztLinkEndpoint) SetOnCloseAction(func())                 {}

func (le *ztLinkEndpoint) beginPacketWrite() bool {
	le.lifecycleMu.Lock()
	defer le.lifecycleMu.Unlock()
	if le.closed.Load() {
		return false
	}
	select {
	case <-le.done:
		return false
	default:
	}
	le.enqueueCalls.Add(1)
	return true
}

func (le *ztLinkEndpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	if !le.beginPacketWrite() {
		return 0, &tcpip.ErrClosedForSend{}
	}
	defer le.enqueueCalls.Done()
	sent := 0
	for _, packetBuffer := range list.AsSlice() {
		if le.closed.Load() {
			return sent, &tcpip.ErrClosedForSend{}
		}
		packetBuffer.IncRef()
		outbound := outboundPacket{packetBuffer: packetBuffer, generation: le.topologyGeneration.Load()}
		select {
		case <-le.done:
			packetBuffer.DecRef()
			return sent, &tcpip.ErrClosedForSend{}
		case le.outbound <- outbound:
			sent++
		}
	}
	return sent, nil
}

func dialTCPWithBind(ctx context.Context, s *stack.Stack, localAddr, remoteAddr tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*gonet.TCPConn, error) {
	var wq waiter.Queue
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, network, &wq)
	if err != nil {
		return nil, E.New(err.String())
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	if localAddr != (tcpip.FullAddress{}) {
		if err = ep.Bind(localAddr); err != nil {
			return nil, E.New("bind: ", err.String())
		}
	}

	err = ep.Connect(remoteAddr)
	if _, ok := err.(*tcpip.ErrConnectStarted); ok {
		select {
		case <-ctx.Done():
			ep.Close()
			return nil, ctx.Err()
		case <-notifyCh:
		}
		err = ep.LastError()
	}
	if err != nil {
		ep.Close()
		return nil, &net.OpError{
			Op:   "connect",
			Net:  "tcp",
			Addr: &net.TCPAddr{IP: net.IP(remoteAddr.Addr.AsSlice()), Port: int(remoteAddr.Port)},
			Err:  E.New(err.String()),
		}
	}
	conn := gonet.NewTCPConn(&wq, ep)
	go func() {
		<-ctx.Done()
		conn.SetDeadline(time.Now())
	}()
	return conn, nil
}
