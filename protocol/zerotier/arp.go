//go:build with_zerotier && with_gvisor

package zerotier

import (
	"fmt"
	"net/netip"
	"time"

	zt "github.com/scdhh/go-zt"
)

func (ep *Endpoint) currentARPAnnouncementState() (netip.Addr, uint64, bool) {
	state := ep.currentNetworkState()
	if state.networkClosed || state.status != zt.NetworkStatusOK || state.nwMac == 0 {
		return netip.Addr{}, 0, false
	}
	for _, prefix := range state.localAddresses {
		if prefix.Addr().Is4() {
			return prefix.Addr(), state.nwMac, true
		}
	}
	return netip.Addr{}, 0, false
}

// handleARP processes incoming ARP frames and learns MAC-IP mappings.
// Also responds to ARP requests for our own IP addresses.
func (ep *Endpoint) handleARP(srcMAC uint64, data []byte) {
	// ARP packet: 28 bytes for IPv4.
	if len(data) < 28 {
		return
	}
	htype := uint16(data[0])<<8 | uint16(data[1])
	ptype := uint16(data[2])<<8 | uint16(data[3])
	hlen := data[4]
	plen := data[5]
	oper := uint16(data[6])<<8 | uint16(data[7])

	if htype != 1 || ptype != 0x0800 || hlen != 6 || plen != 4 {
		return // Only handle Ethernet + IPv4.
	}

	// Parse sender IP (offset 14-17) and target IP (offset 24-27).
	senderIP := netip.AddrFrom4([4]byte{data[14], data[15], data[16], data[17]})
	targetIP := netip.AddrFrom4([4]byte{data[24], data[25], data[26], data[27]})

	// Learn sender MAC-IP mapping.

	ep.learnMAC(senderIP, srcMAC)

	// If this is an ARP request (oper=1) for our address, send a reply.
	if oper == 1 {
		for _, prefix := range ep.currentNetworkState().localAddresses {
			if prefix.Addr() == targetIP {
				ep.sendARPReply(srcMAC, senderIP, targetIP)
				return
			}
		}
	}
}

// sendARPReply sends an ARP reply to the given MAC address.
func (ep *Endpoint) sendARPReply(dstMAC uint64, dstIP, srcIP netip.Addr) {
	nwMac := ep.currentNetworkState().nwMac
	reply := make([]byte, 28)
	reply[0] = 0x00
	reply[1] = 0x01
	reply[2] = 0x08
	reply[3] = 0x00
	reply[4] = 6
	reply[5] = 4
	reply[6] = 0x00
	reply[7] = 0x02

	reply[8] = byte(nwMac >> 40)
	reply[9] = byte(nwMac >> 32)
	reply[10] = byte(nwMac >> 24)
	reply[11] = byte(nwMac >> 16)
	reply[12] = byte(nwMac >> 8)
	reply[13] = byte(nwMac)

	src4 := srcIP.As4()
	copy(reply[14:18], src4[:])

	reply[18] = byte(dstMAC >> 40)
	reply[19] = byte(dstMAC >> 32)
	reply[20] = byte(dstMAC >> 24)
	reply[21] = byte(dstMAC >> 16)
	reply[22] = byte(dstMAC >> 8)
	reply[23] = byte(dstMAC)

	dst4 := dstIP.As4()
	copy(reply[24:28], dst4[:])

	ep.goManaged(func() {
		select {
		case <-ep.done:
			return
		default:
		}
		ep.withNode(func(node zeroTierNode) {
			node.ProcessVirtualNetworkFrame(ep.networkID, nwMac, dstMAC, 0x0806, 0, reply, nil)
			ep.logger.Debug(fmt.Sprintf("ARP reply: %s is-at %012x -> %012x", srcIP, nwMac, dstMAC))
		})
	})
}

// sendARPRequest sends an ARP request for the given IP address as a broadcast.
func (ep *Endpoint) sendARPRequest(targetIPStr string) {
	targetIP, err := netip.ParseAddr(targetIPStr)
	if err != nil || !targetIP.Is4() {
		return
	}
	srcIP, nwMac, ok := ep.currentARPAnnouncementState()
	if !ok {
		return
	}
	generation := ep.topologyGeneration.Load()
	request := make([]byte, 28)
	request[0] = 0x00
	request[1] = 0x01
	request[2] = 0x08
	request[3] = 0x00
	request[4] = 6
	request[5] = 4
	request[6] = 0x00
	request[7] = 0x01

	request[8] = byte(nwMac >> 40)
	request[9] = byte(nwMac >> 32)
	request[10] = byte(nwMac >> 24)
	request[11] = byte(nwMac >> 16)
	request[12] = byte(nwMac >> 8)
	request[13] = byte(nwMac)

	src4 := srcIP.As4()
	copy(request[14:18], src4[:])
	dst4 := targetIP.As4()
	copy(request[24:28], dst4[:])
	select {
	case <-ep.done:
		return
	default:
	}
	currentSrcIP, currentMAC, ok := ep.currentARPAnnouncementState()
	currentGeneration := ep.topologyGeneration.Load()
	if !ok || currentGeneration != generation || currentGeneration%2 != 0 || currentSrcIP != srcIP || currentMAC != nwMac {
		return
	}
	ep.withNode(func(node zeroTierNode) {
		node.ProcessVirtualNetworkFrame(ep.networkID, currentMAC, zeroTierBroadcastMAC, 0x0806, 0, request, nil)
		ep.logger.Debug(fmt.Sprintf("ARP request: who-has %s tell %s", targetIPStr, srcIP))
	})
}

// announceARP sends gratuitous ARP announcements periodically to trigger
// multicast GATHER early and prime peers' ARP caches.
func (ep *Endpoint) announceARP() {
	for i := 0; i < 50; i++ {
		if _, _, ok := ep.currentARPAnnouncementState(); ok {
			break
		}
		select {
		case <-ep.done:
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
	srcIP, _, ok := ep.currentARPAnnouncementState()
	if !ok {
		return
	}

	for i := 0; i < 5; i++ {
		select {
		case <-ep.done:
			return
		default:
		}
		srcIP, _, ok = ep.currentARPAnnouncementState()
		if !ok {
			return
		}
		ep.sendGratuitousARP(srcIP)
		if i < 4 {
			select {
			case <-ep.done:
				return
			case <-time.After(2 * time.Second):
			}
		}
	}
}

// sendGratuitousARP sends a gratuitous ARP announcement (ARP reply for our own IP).
func (ep *Endpoint) sendGratuitousARP(srcIP netip.Addr) {
	currentSrcIP, nwMac, ok := ep.currentARPAnnouncementState()
	if !ok || currentSrcIP != srcIP {
		return
	}
	generation := ep.topologyGeneration.Load()
	reply := make([]byte, 28)
	reply[0] = 0x00
	reply[1] = 0x01
	reply[2] = 0x08
	reply[3] = 0x00
	reply[4] = 6
	reply[5] = 4
	reply[6] = 0x00
	reply[7] = 0x02

	reply[8] = byte(nwMac >> 40)
	reply[9] = byte(nwMac >> 32)
	reply[10] = byte(nwMac >> 24)
	reply[11] = byte(nwMac >> 16)
	reply[12] = byte(nwMac >> 8)
	reply[13] = byte(nwMac)

	src4 := srcIP.As4()
	copy(reply[14:18], src4[:])
	reply[18] = 0xff
	reply[19] = 0xff
	reply[20] = 0xff
	reply[21] = 0xff
	reply[22] = 0xff
	reply[23] = 0xff
	copy(reply[24:28], src4[:])
	select {
	case <-ep.done:
		return
	default:
	}
	currentSrcIP, currentMAC, ok := ep.currentARPAnnouncementState()
	currentGeneration := ep.topologyGeneration.Load()
	if !ok || currentGeneration != generation || currentGeneration%2 != 0 || currentSrcIP != srcIP || currentMAC != nwMac {
		return
	}
	ep.withNode(func(node zeroTierNode) {
		node.ProcessVirtualNetworkFrame(ep.networkID, currentMAC, zeroTierBroadcastMAC, 0x0806, 0, reply, nil)
		ep.logger.Debug(fmt.Sprintf("gratuitous ARP: %s is-at %012x", srcIP, currentMAC))
	})
}
