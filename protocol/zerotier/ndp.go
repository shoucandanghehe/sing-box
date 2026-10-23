//go:build with_zerotier && with_gvisor

package zerotier

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing-tun"
	zt "github.com/scdhh/go-zt"
)

func (ep *Endpoint) currentNDPMAC() (uint64, bool) {
	state := ep.currentNetworkState()
	if state.networkClosed || state.status != zt.NetworkStatusOK || state.nwMac == 0 {
		return 0, false
	}
	return state.nwMac, true
}

func (ep *Endpoint) currentNDPAnnouncementState() (netip.Addr, uint64, bool) {
	state := ep.currentNetworkState()
	if state.networkClosed || state.status != zt.NetworkStatusOK || state.nwMac == 0 {
		return netip.Addr{}, 0, false
	}
	for _, prefix := range state.localAddresses {
		if prefix.Addr().Is6() && !prefix.Addr().Is4In6() {
			return prefix.Addr(), state.nwMac, true
		}
	}
	return netip.Addr{}, 0, false
}

func (ep *Endpoint) notifyPendingIPv6Packets() {
	if ep.ipv6PendingWake == nil {
		return
	}
	select {
	case ep.ipv6PendingWake <- struct{}{}:
	default:
	}
}

func (ep *Endpoint) queuePendingIPv6Packet(nextHop netip.Addr, packet []byte) {
	if !nextHop.Is6() || nextHop.Is4In6() || len(packet) == 0 {
		return
	}
	now := time.Now()
	generation := ep.topologyGeneration.Load()
	ep.ipv6PendingMu.Lock()
	key := nextHop.String()
	state := ep.ipv6Pending[key]
	if state.generation != generation {
		state = pendingIPv6Neighbor{generation: generation}
	}
	state.packets = append(state.packets, append([]byte(nil), packet...))
	if len(state.packets) > maxPendingIPv6PacketsPerNextHop {
		state.packets = state.packets[len(state.packets)-maxPendingIPv6PacketsPerNextHop:]
	}
	if state.firstQueuedAt.IsZero() {
		state.firstQueuedAt = now
	}
	ep.ipv6Pending[key] = state
	ep.ipv6PendingMu.Unlock()
	ep.notifyPendingIPv6Packets()
}

func (ep *Endpoint) takePendingIPv6Packets(nextHop netip.Addr) ([][]byte, uint64) {
	ep.ipv6PendingMu.Lock()
	defer ep.ipv6PendingMu.Unlock()
	key := nextHop.String()
	state := ep.ipv6Pending[key]
	delete(ep.ipv6Pending, key)
	return state.packets, state.generation
}

func (ep *Endpoint) clearPendingIPv6Packets() {
	ep.ipv6PendingMu.Lock()
	clear(ep.ipv6Pending)
	ep.ipv6PendingMu.Unlock()
	ep.notifyPendingIPv6Packets()
}

func (ep *Endpoint) collectPendingIPv6NeighborProbes(now time.Time) ([]netip.Addr, time.Duration, bool) {
	ep.ipv6PendingMu.Lock()
	defer ep.ipv6PendingMu.Unlock()

	var (
		targets  []netip.Addr
		nextWait time.Duration
		haveWait bool
	)
	for key, state := range ep.ipv6Pending {
		if len(state.packets) == 0 {
			delete(ep.ipv6Pending, key)
			continue
		}
		if state.firstQueuedAt.IsZero() {
			state.firstQueuedAt = now
		}
		if ep.ipv6NeighborProbeTimeout > 0 && now.Sub(state.firstQueuedAt) >= ep.ipv6NeighborProbeTimeout {
			delete(ep.ipv6Pending, key)
			continue
		}
		if state.probeAttempts < maxIPv6NeighborProbeAttempts {
			if state.lastProbeAt.IsZero() || now.Sub(state.lastProbeAt) >= ep.ipv6NeighborProbeRetryInterval {
				target, err := netip.ParseAddr(key)
				if err != nil || !target.Is6() || target.Is4In6() {
					delete(ep.ipv6Pending, key)
					continue
				}
				state.lastProbeAt = now
				state.probeAttempts++
				ep.ipv6Pending[key] = state
				targets = append(targets, target)
				if !haveWait || ep.ipv6NeighborProbeRetryInterval < nextWait {
					nextWait = ep.ipv6NeighborProbeRetryInterval
					haveWait = true
				}
				continue
			}
			wait := state.lastProbeAt.Add(ep.ipv6NeighborProbeRetryInterval).Sub(now)
			if wait < 0 {
				wait = 0
			}
			if !haveWait || wait < nextWait {
				nextWait = wait
				haveWait = true
			}
			ep.ipv6Pending[key] = state
			continue
		}
		wait := state.lastProbeAt.Add(ep.ipv6NeighborProbeRetryInterval).Sub(now)
		if wait <= 0 {
			delete(ep.ipv6Pending, key)
			continue
		}
		if !haveWait || wait < nextWait {
			nextWait = wait
			haveWait = true
		}
		ep.ipv6Pending[key] = state
	}
	if !haveWait {
		nextWait = 0
	}
	return targets, nextWait, len(ep.ipv6Pending) > 0
}

func (ep *Endpoint) runPendingIPv6NeighborProbes() {
	for {
		targets, wait, hasPending := ep.collectPendingIPv6NeighborProbes(time.Now())
		for _, target := range targets {
			ep.sendNeighborSolicitation(target)
		}

		var (
			timer  *time.Timer
			timerC <-chan time.Time
		)
		if hasPending {
			if wait < 0 {
				wait = 0
			}
			timer = time.NewTimer(wait)
			timerC = timer.C
		}

		select {
		case <-ep.done:
			if timer != nil {
				timer.Stop()
			}
			return
		case <-ep.ipv6PendingWake:
			if timer != nil && !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timerC:
		}
	}
}

func (ep *Endpoint) flushPendingIPv6Packets(nextHop netip.Addr) {
	packets, generation := ep.takePendingIPv6Packets(nextHop)
	if len(packets) == 0 {
		return
	}
	ep.goManaged(func() {
		for _, packet := range packets {
			packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(packet),
			})
			select {
			case <-ep.done:
				packetBuffer.DecRef()
				return
			case ep.outbound <- outboundPacket{packetBuffer: packetBuffer, generation: generation}:
			}
		}
	})
}

func (ep *Endpoint) isLocalIPv6Address(addr netip.Addr) bool {
	if !addr.Is6() || addr.Is4In6() {
		return false
	}
	for _, prefix := range ep.currentNetworkState().localAddresses {
		if prefix.Addr() == addr {
			return true
		}
	}
	return false
}

func (ep *Endpoint) canSendIPv6Packet() bool {
	state := ep.currentNetworkState()
	return !state.networkClosed && state.status == zt.NetworkStatusOK && state.nwMac != 0
}

func (ep *Endpoint) hasLocalIPv6PacketSource(iph header.IPv6) bool {
	state := ep.currentNetworkState()
	srcIP, ok := tcpipAddressToNetip(iph.SourceAddress())
	if !ok || !srcIP.Is6() || srcIP.Is4In6() {
		return false
	}
	for _, prefix := range state.localAddresses {
		if prefix.Addr() == srcIP {
			return true
		}
	}
	return false
}

func (ep *Endpoint) shouldForwardIPv6Packet(iph header.IPv6) bool {
	return ep.canSendIPv6Packet() && ep.hasLocalIPv6PacketSource(iph)
}

func ndpLinkLayerAddressOptionMAC(options header.NDPOptions) (uint64, bool) {
	iter, err := options.Iter(true)
	if err != nil {
		return 0, false
	}
	for {
		opt, done, err := iter.Next()
		if err != nil || done {
			return 0, false
		}
		switch option := opt.(type) {
		case header.NDPSourceLinkLayerAddressOption:
			return macFromLinkAddress(option.EthernetAddress())
		case header.NDPTargetLinkLayerAddressOption:
			return macFromLinkAddress(option.EthernetAddress())
		}
	}
}

func isIPv6DADNeighborSolicitation(data []byte) bool {
	if len(data) < header.IPv6MinimumSize+header.ICMPv6HeaderSize {
		return false
	}
	iph := header.IPv6(data)
	if iph.TransportProtocol() != header.ICMPv6ProtocolNumber || iph.HopLimit() != header.NDPHopLimit {
		return false
	}
	srcIP, ok := tcpipAddressToNetip(iph.SourceAddress())
	if !ok || !srcIP.IsUnspecified() {
		return false
	}
	payloadLength := int(iph.PayloadLength())
	if payloadLength < header.ICMPv6NeighborSolicitMinimumSize || len(data) < header.IPv6MinimumSize+payloadLength {
		return false
	}
	packet := header.ICMPv6(data[header.IPv6MinimumSize : header.IPv6MinimumSize+payloadLength])
	return packet.Type() == header.ICMPv6NeighborSolicit
}

func packetGenerationMatchesCurrent(packetGeneration, currentGeneration uint64, isDADNS bool) bool {
	if packetGeneration == currentGeneration {
		return true
	}
	return isDADNS && packetGeneration%2 != 0 && currentGeneration == packetGeneration+1
}

func (ep *Endpoint) handleICMPv6NeighborDiscovery(srcMAC uint64, data []byte) bool {
	if len(data) < header.IPv6MinimumSize+header.ICMPv6HeaderSize {
		return false
	}
	iph := header.IPv6(data)
	if iph.TransportProtocol() != header.ICMPv6ProtocolNumber || iph.HopLimit() != header.NDPHopLimit {
		return false
	}
	payloadLength := int(iph.PayloadLength())
	if payloadLength < header.ICMPv6HeaderSize || len(data) < header.IPv6MinimumSize+payloadLength {
		return false
	}
	icmpPacket := header.ICMPv6(data[header.IPv6MinimumSize : header.IPv6MinimumSize+payloadLength])
	srcIP, _ := tcpipAddressToNetip(iph.SourceAddress())
	switch icmpPacket.Type() {
	case header.ICMPv6NeighborSolicit:
		if len(icmpPacket) < header.ICMPv6NeighborSolicitMinimumSize {
			return false
		}
		ns := header.NDPNeighborSolicit(icmpPacket.MessageBody())
		if mac, ok := ndpLinkLayerAddressOptionMAC(ns.Options()); ok {
			ep.learnMAC(srcIP, mac)
		} else {
			ep.learnMAC(srcIP, srcMAC)
		}
		targetIP, ok := tcpipAddressToNetip(ns.TargetAddress())
		if !ok {
			return true
		}
		if ep.isLocalIPv6Address(targetIP) {
			if srcIP.IsValid() && !srcIP.IsUnspecified() {
				if ep.isTentativeRuntimeIPv6Address(targetIP) {
					return false
				}
				ep.sendNeighborAdvertisement(srcMAC, srcIP, targetIP, true)
				return true
			}
			return false
		}
		return true
	case header.ICMPv6NeighborAdvert:
		if len(icmpPacket) < header.ICMPv6NeighborAdvertMinimumSize {
			return false
		}
		na := header.NDPNeighborAdvert(icmpPacket.MessageBody())
		targetIP, ok := tcpipAddressToNetip(na.TargetAddress())
		if !ok {
			return true
		}
		if mac, ok := ndpLinkLayerAddressOptionMAC(na.Options()); ok {
			ep.learnMAC(targetIP, mac)
			ep.flushPendingIPv6Packets(targetIP)
		} else {
			ep.learnMAC(targetIP, srcMAC)
			ep.flushPendingIPv6Packets(targetIP)
		}
		return false
	default:
		return false
	}
}

func (ep *Endpoint) sendNeighborAdvertisement(dstMAC uint64, dstIP, srcIP netip.Addr, solicited bool) {
	nwMac, ok := ep.currentNDPMAC()
	if !ok || !ep.isLocalIPv6Address(srcIP) {
		return
	}
	generation := ep.topologyGeneration.Load()
	const optionLength = 8
	payloadLength := header.ICMPv6NeighborAdvertMinimumSize + optionLength
	reply := make([]byte, header.IPv6MinimumSize+payloadLength)
	ip := header.IPv6(reply)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(payloadLength),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          header.NDPHopLimit,
		SrcAddr:           tun.AddressFromAddr(srcIP),
		DstAddr:           tun.AddressFromAddr(dstIP),
	})
	icmpPacket := header.ICMPv6(reply[header.IPv6MinimumSize:])
	icmpPacket.SetType(header.ICMPv6NeighborAdvert)
	icmpPacket.SetCode(0)
	na := header.NDPNeighborAdvert(reply[header.IPv6MinimumSize+header.ICMPv6HeaderSize:])
	na.SetTargetAddress(tun.AddressFromAddr(srcIP))
	na.SetSolicitedFlag(solicited)
	na.SetOverrideFlag(true)
	option := na.Options()[:optionLength]
	option[0] = 2
	option[1] = 1
	option[2] = byte(nwMac >> 40)
	option[3] = byte(nwMac >> 32)
	option[4] = byte(nwMac >> 24)
	option[5] = byte(nwMac >> 16)
	option[6] = byte(nwMac >> 8)
	option[7] = byte(nwMac)
	icmpPacket.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:     icmpPacket,
		Src:        tun.AddressFromAddr(srcIP),
		Dst:        tun.AddressFromAddr(dstIP),
		PayloadLen: payloadLength,
	}))
	ep.goManaged(func() {
		select {
		case <-ep.done:
			return
		default:
		}
		currentGeneration := ep.topologyGeneration.Load()
		currentMAC, ok := ep.currentNDPMAC()
		if !ok || currentGeneration != generation || currentGeneration%2 != 0 || !ep.isLocalIPv6Address(srcIP) {
			return
		}
		ep.withNode(func(node zeroTierNode) {
			if err := node.ProcessVirtualNetworkFrame(ep.networkID, currentMAC, dstMAC, 0x86DD, 0, reply, nil); err != nil {
				ep.logger.Warn("failed to send IPv6 neighbor advertisement: ", err)
			}
		})
	})
}

func (ep *Endpoint) sendNeighborSolicitation(targetIP netip.Addr) {
	srcIP, nwMac, ok := ep.currentNDPAnnouncementState()
	if !ok || !targetIP.Is6() || targetIP.Is4In6() {
		return
	}
	generation := ep.topologyGeneration.Load()
	group, ok := zeroTierSolicitedNodeGroup(targetIP)
	if !ok {
		return
	}
	dstAddr, ok := tcpipAddressToNetip(header.SolicitedNodeAddr(tun.AddressFromAddr(targetIP)))
	if !ok {
		return
	}
	const optionLength = 8
	payloadLength := header.ICMPv6NeighborSolicitMinimumSize + optionLength
	request := make([]byte, header.IPv6MinimumSize+payloadLength)
	ip := header.IPv6(request)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(payloadLength),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          header.NDPHopLimit,
		SrcAddr:           tun.AddressFromAddr(srcIP),
		DstAddr:           tun.AddressFromAddr(dstAddr),
	})
	icmpPacket := header.ICMPv6(request[header.IPv6MinimumSize:])
	icmpPacket.SetType(header.ICMPv6NeighborSolicit)
	icmpPacket.SetCode(0)
	ns := header.NDPNeighborSolicit(request[header.IPv6MinimumSize+header.ICMPv6HeaderSize:])
	ns.SetTargetAddress(tun.AddressFromAddr(targetIP))
	option := ns.Options()[:optionLength]
	option[0] = 1
	option[1] = 1
	option[2] = byte(nwMac >> 40)
	option[3] = byte(nwMac >> 32)
	option[4] = byte(nwMac >> 24)
	option[5] = byte(nwMac >> 16)
	option[6] = byte(nwMac >> 8)
	option[7] = byte(nwMac)
	icmpPacket.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:     icmpPacket,
		Src:        tun.AddressFromAddr(srcIP),
		Dst:        tun.AddressFromAddr(dstAddr),
		PayloadLen: payloadLength,
	}))
	select {
	case <-ep.done:
		return
	default:
	}
	currentSrcIP, currentMAC, ok := ep.currentNDPAnnouncementState()
	currentGeneration := ep.topologyGeneration.Load()
	if !ok || currentGeneration != generation || currentGeneration%2 != 0 || currentSrcIP != srcIP || currentMAC != nwMac {
		return
	}
	ep.withNode(func(node zeroTierNode) {
		if err := node.ProcessVirtualNetworkFrame(ep.networkID, currentMAC, group.mac, 0x86DD, 0, request, nil); err != nil {
			ep.logger.Warn("failed to send IPv6 neighbor solicitation: ", err)
			return
		}
		ep.logger.Debug(fmt.Sprintf("NDP solicit: who-has %s tell %s via %012x", targetIP, srcIP, group.mac))
	})
}
