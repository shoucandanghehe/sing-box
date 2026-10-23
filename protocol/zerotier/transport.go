//go:build with_zerotier && with_gvisor

package zerotier

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
	zt "github.com/scdhh/go-zt"
)

func backgroundWaitDuration(now time.Time, nextDeadline int64) time.Duration {
	if nextDeadline <= 0 {
		return defaultBackgroundPollInterval
	}
	wait := time.UnixMilli(nextDeadline).Sub(now)
	if wait < 0 {
		return 0
	}
	return wait
}

func (ep *Endpoint) listenWirePacket() (udpPacketConn, error) {
	if ep.listenUDP != nil {
		return ep.listenUDP()
	}

	listenConfig := net.ListenConfig{}
	networkManager := service.FromContext[adapter.NetworkManager](ep.ctx)
	if networkManager != nil {
		protectFunc := networkManager.ProtectFunc()
		if protectFunc != nil {
			listenConfig.Control = func(network, address string, c syscall.RawConn) error {
				return protectFunc(network, address, c)
			}
			ep.logger.Info("UDP socket will be VPN-protected")
		} else if bindFunc := networkManager.AutoDetectInterfaceFunc(); bindFunc != nil {
			listenConfig.Control = func(network, address string, c syscall.RawConn) error {
				return bindFunc(network, address, c)
			}
			ep.logger.Info("UDP socket will use auto-detect interface")
		}
	}
	udpConn, err := listenConfig.ListenPacket(ep.ctx, "udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	return udpConn.(*net.UDPConn), nil
}

func (ep *Endpoint) createZeroTierNode(callbacks zt.NodeCallbacks) (zeroTierNode, error) {
	if ep.newNode != nil {
		return ep.newNode(callbacks, nil)
	}
	return zt.NewNode(callbacks, nil)
}

func (ep *Endpoint) createManagedStack() error {
	if ep.createStackFn != nil {
		return ep.createStackFn()
	}
	return ep.createStack()
}

func (ep *Endpoint) receiveWirePackets() {
	buf := make([]byte, 16384)
	for {
		select {
		case <-ep.done:
			return
		default:
		}
		ep.udpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, remoteAddr, err := ep.udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-ep.done:
				return
			default:
				ep.logger.Debug("UDP read error: ", err)
				return
			}
		}
		packet := make([]byte, n)
		copy(packet, buf[:n])
		ep.logger.Debug(fmt.Sprintf("wire recv: %d bytes <- %s", n, remoteAddr))
		if !ep.withNode(func(node zeroTierNode) {
			_ = node.ProcessWirePacket(0, remoteAddr.AddrPort(), packet, nil)
		}) {
			return
		}
	}
}

func (ep *Endpoint) backgroundLoop() {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ep.done:
			return
		case <-timer.C:
			var nextDeadline int64
			if !ep.withNode(func(node zeroTierNode) {
				_ = node.ProcessBackgroundTasks(&nextDeadline)
			}) {
				return
			}
			timer.Reset(backgroundWaitDuration(time.Now(), nextDeadline))
		}
	}
}

func (ep *Endpoint) onVirtualNetworkFrame(nwid uint64, srcMAC, dstMAC uint64, etherType, vlanID uint, data []byte) {
	holder := ep.dispatcher.Load()
	if holder == nil || holder.value == nil || len(data) == 0 {
		return
	}
	dispatcher := holder.value

	switch etherType {
	case 0x0806: // ARP
		ep.handleARP(srcMAC, data)
		return
	case 0x0800: // IPv4
		if len(data) >= 20 {
			iph := header.IPv4(data)
			ep.logger.Debug(fmt.Sprintf("vnet IN: %s -> %s proto=%d len=%d srcMAC=%012x", iph.SourceAddress(), iph.DestinationAddress(), iph.Protocol(), len(data), srcMAC))
			if srcIPAddr, ok := tcpipAddressToNetip(iph.SourceAddress()); ok {
				ep.learnMAC(srcIPAddr, srcMAC)
			}
			if iph.Protocol() == uint8(header.ICMPv4ProtocolNumber) {
				ihl := int(iph.HeaderLength())
				if len(data) > ihl {
					ep.logger.Debug(fmt.Sprintf("ICMP IN: %s -> %s type=%d len=%d srcMAC=%012x", iph.SourceAddress(), iph.DestinationAddress(), data[ihl], len(data), srcMAC))
				}
				if ep.handleICMPEcho(srcMAC, data) {
					return
				}
			}
		}
		packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
		dispatcher.DeliverNetworkPacket(header.IPv4ProtocolNumber, packetBuffer)
		packetBuffer.DecRef()
		return
	case 0x86DD: // IPv6
		if len(data) >= header.IPv6MinimumSize {
			iph := header.IPv6(data)
			ep.logger.Debug(fmt.Sprintf("vnet IN: %s -> %s proto=%d len=%d srcMAC=%012x dstMAC=%012x", iph.SourceAddress(), iph.DestinationAddress(), iph.TransportProtocol(), len(data), srcMAC, dstMAC))
			if srcIP, ok := tcpipAddressToNetip(iph.SourceAddress()); ok {
				ep.learnMAC(srcIP, srcMAC)
			}
			if iph.TransportProtocol() == header.ICMPv6ProtocolNumber && ep.handleICMPv6NeighborDiscovery(srcMAC, data) {
				return
			}
		}
		packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
		dispatcher.DeliverNetworkPacket(header.IPv6ProtocolNumber, packetBuffer)
		packetBuffer.DecRef()
		return
	}
}

func (ep *Endpoint) drainOutboundPackets() {
	for {
		select {
		case outbound := <-ep.outbound:
			if outbound.packetBuffer != nil {
				outbound.packetBuffer.DecRef()
			}
		default:
			return
		}
	}
}

func (ep *Endpoint) forwardOutbound() {
	defer ep.drainOutboundPackets()
	for {
		select {
		case outbound, ok := <-ep.outbound:
			if !ok {
				return
			}
			packetBuffer := outbound.packetBuffer
			packetGeneration := outbound.generation
			var data []byte
			for _, slice := range packetBuffer.AsSlices() {
				data = append(data, slice...)
			}
			packetBuffer.DecRef()
			select {
			case <-ep.done:
				return
			default:
			}
			if len(data) == 0 {
				continue
			}
			isDADNS := isIPv6DADNeighborSolicitation(data)
			currentGeneration := ep.topologyGeneration.Load()
			if !packetGenerationMatchesCurrent(packetGeneration, currentGeneration, isDADNS) || (currentGeneration%2 != 0 && !isDADNS) {
				continue
			}

			var etherType uint
			var dstMAC uint64
			var multicastUpdates []multicastMembershipUpdate
			switch header.IPVersion(data) {
			case header.IPv4Version:
				etherType = 0x0800
				if len(data) >= 20 {
					iph := header.IPv4(data)
					multicastUpdates = observeIPv4MulticastControl(data)
					dstNetIP, dstOK := tcpipAddressToNetip(iph.DestinationAddress())
					dstIP := iph.DestinationAddress().String()
					ep.logger.Debug(fmt.Sprintf("vnet OUT: %s -> %s proto=%d len=%d", iph.SourceAddress(), iph.DestinationAddress(), iph.Protocol(), len(data)))
					if dstOK && dstNetIP.IsMulticast() {
						if group, ok := zeroTierMulticastGroupFromAddr(dstNetIP); ok {
							dstMAC = group.mac
						} else {
							dstMAC = zeroTierBroadcastMAC
						}
					} else {
						mac, ok, nextHop := ep.resolveNextHopMAC(dstIP)
						if ok {
							dstMAC = mac
						} else {
							dstMAC = zeroTierBroadcastMAC
							if ep.shouldSendNeighborProbe(nextHop) {
								ep.sendARPRequest(nextHop)
							}
						}
					}
				} else {
					dstMAC = zeroTierBroadcastMAC
				}
			case header.IPv6Version:
				etherType = 0x86DD
				if len(data) < header.IPv6MinimumSize {
					continue
				}
				iph := header.IPv6(data)
				if !ep.canSendIPv6Packet() && !(isDADNS && ep.pendingConfigReady.Load()) {
					continue
				}
				var isMLD bool
				multicastUpdates, isMLD = observeIPv6MulticastControl(data)
				if !isMLD && !isDADNS && !ep.hasLocalIPv6PacketSource(iph) {
					continue
				}
				if isDADNS {
					ep.waitForMulticastQueueDrain()
				}
				if dstIP, ok := tcpipAddressToNetip(iph.DestinationAddress()); ok {
					if dstIP.IsMulticast() {
						if group, ok := zeroTierMulticastGroupFromAddr(dstIP); ok {
							dstMAC = group.mac
						} else {
							dstMAC = zeroTierBroadcastMAC
						}
					} else {
						ep.routesMu.RLock()
						mac, found, nextHop := ep.resolveNextHopMACLocked(dstIP.String())
						if found {
							ep.routesMu.RUnlock()
							if nextHopIP, err := netip.ParseAddr(nextHop); err == nil && nextHopIP.Is6() && !nextHopIP.Is4In6() {
								ep.flushPendingIPv6Packets(nextHopIP)
							}
							dstMAC = mac
						} else if nextHopIP, err := netip.ParseAddr(nextHop); err == nil && nextHopIP.Is6() && !nextHopIP.Is4In6() {
							ep.queuePendingIPv6Packet(nextHopIP, data)
							ep.routesMu.RUnlock()
							continue
						} else {
							ep.routesMu.RUnlock()
							dstMAC = zeroTierBroadcastMAC
						}
					}
				} else {
					dstMAC = zeroTierBroadcastMAC
				}
			default:
				continue
			}

			currentGeneration = ep.topologyGeneration.Load()
			if !packetGenerationMatchesCurrent(packetGeneration, currentGeneration, isDADNS) || (currentGeneration%2 != 0 && !isDADNS) {
				continue
			}
			state := ep.currentNetworkState()
			nwMac := state.nwMac
			dadNSInOddWindow := isDADNS && packetGeneration%2 != 0 && currentGeneration == packetGeneration && ep.pendingConfigReady.Load()
			if dadNSInOddWindow {
				// In the odd-generation window, networkState may not yet reflect the
				// incoming config (networkState.Store happens after syncRuntimeAddresses).
				// Always use pendingConfigNWMac to avoid sending DAD probes with a stale
				// source MAC from the pre-transition state.
				nwMac = ep.pendingConfigNWMac.Load()
				if nwMac == 0 {
					continue
				}
			} else if state.networkClosed || state.status != zt.NetworkStatusOK || state.nwMac == 0 {
				continue
			}
			ep.logger.Debug(fmt.Sprintf("ProcessVNF: srcMAC=%012x dstMAC=%012x etherType=%04x len=%d", nwMac, dstMAC, etherType, len(data)))
			var processErr error
			if ep.withNode(func(node zeroTierNode) {
				processErr = node.ProcessVirtualNetworkFrame(ep.networkID, nwMac, dstMAC, etherType, 0, data, nil)
			}) {
				if processErr != nil {
					ep.logger.Warn(fmt.Sprintf("ProcessVNF error: %v", processErr))
				} else {
					ep.applyMulticastMembershipUpdatesIfCurrent(multicastUpdates, packetGeneration)
				}
			}
		case <-ep.done:
			return
		}
	}
}

// logPeers logs the current peer status.
func (ep *Endpoint) logPeers() {
	ep.withNode(func(node zeroTierNode) {
		peers := node.Peers()
		ep.logger.Debug(fmt.Sprintf("peers: %d total", len(peers)))
		for _, peer := range peers {
			pathInfo := ""
			for _, path := range peer.Paths {
				pathInfo += fmt.Sprintf(" [%s send=%d recv=%d]", path.Address, path.LastSend, path.LastReceive)
			}
			ep.logger.Debug(fmt.Sprintf("  peer %010x: role=%s latency=%dms alive=%d total=%d%s", peer.Address, peer.Role, peer.Latency, peer.NumAliveLinks, peer.NumTotalLinks, pathInfo))
		}
	})
}
