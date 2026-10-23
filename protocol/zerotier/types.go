//go:build with_zerotier && with_gvisor

package zerotier

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	zt "github.com/scdhh/go-zt"
)

const defaultBackgroundPollInterval = 200 * time.Millisecond

type endpointNetworkState struct {
	hasConfig      bool
	networkClosed  bool
	status         zt.VirtualNetworkStatus
	localAddresses []netip.Prefix
	routes         []zt.Route
	nwMac          uint64
	mtu            uint32
}

var emptyEndpointNetworkState = &endpointNetworkState{}

const (
	zeroTierBroadcastMAC                   = 0xffffffffffff
	zeroTierSolicitedNodeMACPrefix  uint64 = 0x3333ff000000
	maxPendingIPv6PacketsPerNextHop        = 8
	maxIPv6NeighborProbeAttempts           = 3
)

type outboundPacket struct {
	packetBuffer *stack.PacketBuffer
	generation   uint64
}

type pendingIPv6Neighbor struct {
	packets       [][]byte
	generation    uint64
	firstQueuedAt time.Time
	lastProbeAt   time.Time
	probeAttempts int
}

type zeroTierMulticastGroup struct {
	mac uint64
	adi uint32
}

type zeroTierMulticastGroupRef struct {
	managed  int
	dynamic  int
	reported bool
}

func (r zeroTierMulticastGroupRef) active() bool {
	return r.managed > 0 || r.dynamic > 0 || r.reported
}

func (g zeroTierMulticastGroup) String() string {
	return fmt.Sprintf("mac=%012x adi=%08x", g.mac, g.adi)
}

var (
	zeroTierBroadcastGroup    = zeroTierMulticastGroup{mac: zeroTierBroadcastMAC}
	zeroTierIPv6AllNodesAddr  = netip.MustParseAddr("ff02::1")
	zeroTierIPv6AllNodesGroup = zeroTierMulticastGroup{mac: 0x333300000001}
)

type zeroTierNode interface {
	Address() uint64
	Status() zt.NodeStatus
	NetworkConfig(uint64) *zt.VirtualNetworkConfig
	Peers() []zt.Peer
	Join(uint64) error
	MulticastSubscribe(uint64, uint64, uint32) error
	MulticastUnsubscribe(uint64, uint64, uint32) error
	ProcessWirePacket(int64, netip.AddrPort, []byte, *int64) error
	ProcessBackgroundTasks(*int64) error
	ProcessVirtualNetworkFrame(uint64, uint64, uint64, uint, uint, []byte, *int64) error
	Close()
}

type udpPacketConn interface {
	ReadFromUDP([]byte) (int, *net.UDPAddr, error)
	WriteTo([]byte, net.Addr) (int, error)
	Close() error
	LocalAddr() net.Addr
	SetReadDeadline(time.Time) error
}
