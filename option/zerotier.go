package option

import "net/netip"

type ZeroTierEndpointOptions struct {
	DialerOptions
	NetworkID   string           `json:"network_id"`
	StoragePath string           `json:"storage_path,omitempty"`
	Address     []netip.Prefix   `json:"address,omitempty"`
	MTU         uint32           `json:"mtu,omitempty"`
	UDPTimeout  UDPTimeoutCompat `json:"udp_timeout,omitempty"`
}
