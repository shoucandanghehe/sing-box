//go:build with_zerotier && with_gvisor

package zerotier

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
)

const (
	maxMACTableEntries = 1024
	macTableEntryTTL   = 10 * time.Minute
)

type macTableEntry struct {
	mac       uint64
	learnedAt time.Time
}

func tcpipAddressToNetip(addr tcpip.Address) (netip.Addr, bool) {
	if addr.Len() == 0 {
		return netip.Addr{}, false
	}
	return netip.AddrFromSlice(addr.AsSlice())
}

func macFromLinkAddress(addr tcpip.LinkAddress) (uint64, bool) {
	if len(addr) < 6 {
		return 0, false
	}
	b := []byte(addr)
	return uint64(b[0])<<40 | uint64(b[1])<<32 | uint64(b[2])<<24 | uint64(b[3])<<16 | uint64(b[4])<<8 | uint64(b[5]), true
}

func (ep *Endpoint) macTableTime() time.Time {
	if ep.macTableNow != nil {
		return ep.macTableNow()
	}
	return time.Now()
}

func (ep *Endpoint) canLearnMAC(addr netip.Addr) bool {
	if addr.Is6() && !addr.Is4In6() && addr.IsLinkLocalUnicast() {
		return true
	}
	for _, prefix := range ep.currentNetworkState().localAddresses {
		if prefix.Contains(addr) {
			return true
		}
	}
	ep.routesMu.RLock()
	defer ep.routesMu.RUnlock()
	for _, route := range ep.routes {
		if route.Via == addr {
			return true
		}
	}
	return false
}

func (ep *Endpoint) pruneExpiredMACEntriesLocked(now time.Time) {
	for ip, entry := range ep.macTable {
		if !now.Before(entry.learnedAt.Add(macTableEntryTTL)) {
			delete(ep.macTable, ip)
		}
	}
}

func (ep *Endpoint) lookupMAC(ip string) (uint64, bool) {
	now := ep.macTableTime()
	ep.macTableMu.Lock()
	defer ep.macTableMu.Unlock()
	entry, found := ep.macTable[ip]
	if !found {
		return 0, false
	}
	if !now.Before(entry.learnedAt.Add(macTableEntryTTL)) {
		delete(ep.macTable, ip)
		return 0, false
	}
	return entry.mac, true
}

func (ep *Endpoint) learnMAC(addr netip.Addr, mac uint64) {
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || mac == 0 || !ep.canLearnMAC(addr) {
		return
	}
	ip := addr.String()
	now := ep.macTableTime()
	ep.macTableMu.Lock()
	ep.pruneExpiredMACEntriesLocked(now)
	previous, exists := ep.macTable[ip]
	if !exists && len(ep.macTable) >= maxMACTableEntries {
		var oldestIP string
		var oldestTime time.Time
		for candidateIP, entry := range ep.macTable {
			if oldestIP == "" || entry.learnedAt.Before(oldestTime) {
				oldestIP = candidateIP
				oldestTime = entry.learnedAt
			}
		}
		delete(ep.macTable, oldestIP)
	}
	ep.macTable[ip] = macTableEntry{mac: mac, learnedAt: now}
	ep.macTableMu.Unlock()
	if !exists || previous.mac != mac {
		ep.logger.Debug(fmt.Sprintf("MAC learned: %s -> %012x", ip, mac))
	}
	if addr.Is6() && !addr.Is4In6() {
		ep.flushPendingIPv6Packets(addr)
	}
}

func (ep *Endpoint) shouldSendNeighborProbe(nextHop string) bool {
	ep.arpPendingMu.Lock()
	defer ep.arpPendingMu.Unlock()

	lastReq := ep.arpPending[nextHop]
	now := time.Now()
	if now.Sub(lastReq) <= time.Second {
		return false
	}
	ep.arpPending[nextHop] = now
	return true
}
