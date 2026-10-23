//go:build with_zerotier && with_gvisor

package zerotier

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	zt "github.com/scdhh/go-zt"
)

// Global registry for active ZeroTier endpoints.
var (
	activeEndpointsMu sync.RWMutex
	activeEndpoints   = make(map[string]*Endpoint)
)

// StatusInfo holds the current status of a ZeroTier endpoint.
type StatusInfo struct {
	Tag           string      `json:"tag"`
	NodeID        string      `json:"node_id"`
	Online        bool        `json:"online"`
	NetworkID     string      `json:"network_id"`
	NetworkStatus string      `json:"network_status"`
	Addresses     []string    `json:"addresses"`
	Peers         []PeerInfo  `json:"peers"`
	Routes        []RouteInfo `json:"routes"`
}

// PeerInfo holds information about a ZeroTier peer.
type PeerInfo struct {
	Address   string `json:"address"`
	Role      string `json:"role"`
	Latency   int    `json:"latency"`
	Version   string `json:"version"`
	PathCount int    `json:"path_count"`
}

// RouteInfo holds information about a ZeroTier managed route.
type RouteInfo struct {
	Target string `json:"target"`
	Via    string `json:"via,omitempty"`
}

// GetAllStatus returns the status of all active ZeroTier endpoints as JSON.
func GetAllStatus() string {
	activeEndpointsMu.RLock()
	defer activeEndpointsMu.RUnlock()

	statuses := make([]StatusInfo, 0, len(activeEndpoints))
	for _, ep := range activeEndpoints {
		statuses = append(statuses, ep.getStatus())
	}
	data, _ := json.Marshal(statuses)
	return string(data)
}

// GetPlanetIPs returns a comma-separated list of planet server IP addresses
// from all active ZeroTier endpoints. Used by VPN service to exclude these
// IPs from VPN routing (excludeRoute).
func GetPlanetIPs() string {
	activeEndpointsMu.RLock()
	defer activeEndpointsMu.RUnlock()

	seen := make(map[string]bool)
	var ips []string
	for _, ep := range activeEndpoints {
		hasPlanetPath := false
		ep.withNode(func(node zeroTierNode) {
			for _, peer := range node.Peers() {
				if peer.Role != zt.PeerRolePlanet {
					continue
				}
				for _, path := range peer.Paths {
					ip := path.Address.Addr().String()
					if !seen[ip] {
						seen[ip] = true
						ips = append(ips, ip)
					}
					hasPlanetPath = true
				}
			}
		})
		if hasPlanetPath {
			continue
		}
		ep.wireTargetsMu.RLock()
		for ip := range ep.wireTargets {
			if !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
		ep.wireTargetsMu.RUnlock()
	}
	return strings.Join(ips, ",")
}

func (ep *Endpoint) getStatus() StatusInfo {
	info := StatusInfo{
		Tag:       ep.Tag(),
		NetworkID: fmt.Sprintf("%016x", ep.networkID),
	}
	if ep.closed.Load() {
		return info
	}
	ep.withNode(func(node zeroTierNode) {
		status := node.Status()
		info.NodeID = fmt.Sprintf("%010x", status.Address)
		info.Online = status.Online

		if nwConfig := node.NetworkConfig(ep.networkID); nwConfig != nil {
			info.NetworkStatus = nwConfig.Status.String()
			for _, addr := range nwConfig.AssignedAddresses {
				info.Addresses = append(info.Addresses, addr.String())
			}
		}

		for _, peer := range node.Peers() {
			version := ""
			if peer.VersionMajor > 0 {
				version = fmt.Sprintf("%d.%d.%d", peer.VersionMajor, peer.VersionMinor, peer.VersionRev)
			}
			info.Peers = append(info.Peers, PeerInfo{
				Address:   fmt.Sprintf("%010x", peer.Address),
				Role:      peer.Role.String(),
				Latency:   peer.Latency,
				Version:   version,
				PathCount: len(peer.Paths),
			})
		}
	})

	// Routes.
	ep.routesMu.RLock()
	for _, r := range ep.routes {
		ri := RouteInfo{Target: r.Target.String()}
		if r.Via.IsValid() {
			ri.Via = r.Via.String()
		}
		info.Routes = append(info.Routes, ri)
	}
	ep.routesMu.RUnlock()

	return info
}
