//go:build with_zerotier && with_gvisor

package zerotier

import (
	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	zt "github.com/scdhh/go-zt"
)

type multicastMembershipUpdate struct {
	group  zeroTierMulticastGroup
	joined bool
}

func appendMulticastMembershipUpdate(updates []multicastMembershipUpdate, addr tcpip.Address, joined bool) []multicastMembershipUpdate {
	netipAddr, ok := tcpipAddressToNetip(addr)
	if !ok {
		return updates
	}
	group, ok := zeroTierMulticastGroupFromAddr(netipAddr)
	if !ok {
		return updates
	}
	return append(updates, multicastMembershipUpdate{group: group, joined: joined})
}

func (ep *Endpoint) applyMulticastMembershipUpdatesIfCurrent(updates []multicastMembershipUpdate, packetGeneration uint64) {
	if len(updates) == 0 {
		return
	}
	ep.topologyMu.RLock()
	defer ep.topologyMu.RUnlock()
	currentGeneration := ep.topologyGeneration.Load()
	state := ep.currentNetworkState()
	if packetGeneration != currentGeneration || currentGeneration%2 != 0 || state.networkClosed || state.status != zt.NetworkStatusOK || state.nwMac == 0 {
		return
	}
	for _, update := range updates {
		ep.setReportedMulticastGroupMembership(update.group, update.joined)
	}
}

func appendIGMPv3RecordUpdates(updates []multicastMembershipUpdate, record header.IGMPv3ReportGroupAddressRecord) []multicastMembershipUpdate {
	switch record.RecordType() {
	case header.IGMPv3ReportRecordModeIsInclude, header.IGMPv3ReportRecordChangeToIncludeMode:
		sources, ok := record.Sources()
		return appendMulticastMembershipUpdate(updates, record.GroupAddress(), ok && !sources.Done())
	default:
		return appendMulticastMembershipUpdate(updates, record.GroupAddress(), true)
	}
}

func observeIPv4MulticastControl(data []byte) []multicastMembershipUpdate {
	if len(data) < header.IPv4MinimumSize+header.IGMPMinimumSize {
		return nil
	}
	iph := header.IPv4(data)
	ihl := int(iph.HeaderLength())
	if ihl < header.IPv4MinimumSize || len(data) < ihl+header.IGMPMinimumSize || iph.Protocol() != uint8(header.IGMPProtocolNumber) {
		return nil
	}
	payload := data[ihl:]
	packet := header.IGMP(payload)
	var updates []multicastMembershipUpdate
	switch packet.Type() {
	case header.IGMPv1MembershipReport, header.IGMPv2MembershipReport:
		updates = appendMulticastMembershipUpdate(updates, packet.GroupAddress(), true)
	case header.IGMPLeaveGroup:
		updates = appendMulticastMembershipUpdate(updates, packet.GroupAddress(), false)
	case header.IGMPv3MembershipReport:
		report := header.IGMPv3Report(payload)
		iter := report.GroupAddressRecords()
		for {
			record, disposition := iter.Next()
			switch disposition {
			case header.IGMPv3ReportGroupAddressRecordIteratorNextOk:
				updates = appendIGMPv3RecordUpdates(updates, record)
			case header.IGMPv3ReportGroupAddressRecordIteratorNextDone:
				return updates
			default:
				return nil
			}
		}
	}
	return updates
}

func appendMLDv2RecordUpdates(updates []multicastMembershipUpdate, record header.MLDv2ReportMulticastAddressRecord) []multicastMembershipUpdate {
	switch record.RecordType() {
	case header.MLDv2ReportRecordModeIsInclude, header.MLDv2ReportRecordChangeToIncludeMode:
		sources, ok := record.Sources()
		return appendMulticastMembershipUpdate(updates, record.MulticastAddress(), ok && !sources.Done())
	default:
		return appendMulticastMembershipUpdate(updates, record.MulticastAddress(), true)
	}
}

func observeIPv6MulticastControl(data []byte) ([]multicastMembershipUpdate, bool) {
	if len(data) < header.IPv6MinimumSize+header.ICMPv6HeaderSize {
		return nil, false
	}
	iph := header.IPv6(data)
	payloadLength := int(iph.PayloadLength())
	if payloadLength < header.ICMPv6HeaderSize || len(data) < header.IPv6MinimumSize+payloadLength {
		return nil, false
	}
	payloadBuffer := buffer.MakeWithData(data[header.IPv6MinimumSize : header.IPv6MinimumSize+payloadLength])
	it := header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(iph.NextHeader()), payloadBuffer)
	defer it.Release()

	sawRouterAlert := false
	for {
		payloadHeader, done, err := it.Next()
		if err != nil || done {
			return nil, false
		}
		switch headerValue := payloadHeader.(type) {
		case header.IPv6HopByHopOptionsExtHdr:
			iter := headerValue.Iter()
			for {
				option, done, err := iter.Next()
				if err != nil || done {
					break
				}
				if routerAlert, ok := option.(*header.IPv6RouterAlertOption); ok && routerAlert.Value == header.IPv6RouterAlertMLD {
					sawRouterAlert = true
				}
			}
			headerValue.Release()
		case header.IPv6RawPayloadHeader:
			if headerValue.Identifier != header.IPv6ExtensionHeaderIdentifier(header.ICMPv6ProtocolNumber) || iph.HopLimit() != header.MLDHopLimit || !sawRouterAlert {
				headerValue.Release()
				return nil, false
			}
			payload := headerValue.Buf.Flatten()
			headerValue.Release()
			if len(payload) < header.ICMPv6HeaderSize {
				return nil, false
			}
			packet := header.ICMPv6(payload)
			body := packet.MessageBody()
			var updates []multicastMembershipUpdate
			switch packet.Type() {
			case header.ICMPv6MulticastListenerReport:
				if len(body) < header.MLDMinimumSize {
					return nil, false
				}
				updates = appendMulticastMembershipUpdate(updates, header.MLD(body).MulticastAddress(), true)
				return updates, true
			case header.ICMPv6MulticastListenerDone:
				if len(body) < header.MLDMinimumSize {
					return nil, false
				}
				updates = appendMulticastMembershipUpdate(updates, header.MLD(body).MulticastAddress(), false)
				return updates, true
			case header.ICMPv6MulticastListenerV2Report:
				if len(body) < header.MLDv2ReportMinimumSize {
					return nil, false
				}
				report := header.MLDv2Report(body)
				iter := report.MulticastAddressRecords()
				for {
					record, disposition := iter.Next()
					switch disposition {
					case header.MLDv2ReportMulticastAddressRecordIteratorNextOk:
						updates = appendMLDv2RecordUpdates(updates, record)
					case header.MLDv2ReportMulticastAddressRecordIteratorNextDone:
						return updates, true
					default:
						return nil, false
					}
				}
			default:
				return nil, false
			}
		default:
			payloadHeader.Release()
		}
	}
}
