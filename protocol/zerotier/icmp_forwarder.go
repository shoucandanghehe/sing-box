//go:build with_zerotier && with_gvisor

package zerotier

import (
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

// handleICMPEcho queues local IPv4 echo replies outside the synchronous Node callback.
func (ep *Endpoint) handleICMPEcho(srcMAC uint64, data []byte) bool {
	if len(data) < header.IPv4MinimumSize+header.ICMPv4MinimumSize {
		return false
	}
	iph := header.IPv4(data)
	if iph.Protocol() != uint8(header.ICMPv4ProtocolNumber) {
		return false
	}
	ihl := int(iph.HeaderLength())
	if ihl < header.IPv4MinimumSize || len(data) < ihl+header.ICMPv4MinimumSize {
		return false
	}
	dstAddr := iph.DestinationAddress()
	runtimeAddr4, _ := ep.runtimeBindAddresses()
	if runtimeAddr4 == (tcpip.Address{}) || runtimeAddr4 != dstAddr {
		return false
	}
	icmpPacket := header.ICMPv4(data[ihl:])
	if icmpPacket.Type() != header.ICMPv4Echo || icmpPacket.Code() != 0 {
		return false
	}
	reply := append([]byte(nil), data...)
	replyIP := header.IPv4(reply)
	sourceAddress := replyIP.SourceAddress()
	replyIP.SetSourceAddress(dstAddr)
	replyIP.SetDestinationAddress(sourceAddress)
	replyIP.SetChecksum(0)
	replyIP.SetChecksum(^replyIP.CalculateChecksum())
	replyICMP := header.ICMPv4(reply[ihl:])
	replyICMP.SetType(header.ICMPv4EchoReply)
	replyICMP.SetChecksum(0)
	replyICMP.SetChecksum(header.ICMPv4Checksum(replyICMP, 0))
	nwMac := ep.currentNetworkState().nwMac
	if nwMac == 0 {
		return false
	}
	ep.goManaged(func() {
		select {
		case <-ep.done:
			return
		default:
		}
		ep.withNode(func(node zeroTierNode) {
			if err := node.ProcessVirtualNetworkFrame(ep.networkID, nwMac, srcMAC, 0x0800, 0, reply, nil); err != nil {
				ep.logger.Warn("failed to send ICMP echo reply: ", err)
			}
		})
	})
	return true
}
