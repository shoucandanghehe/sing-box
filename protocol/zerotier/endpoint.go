//go:build with_zerotier && with_gvisor

package zerotier

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service/filemanager"
	zt "github.com/scdhh/go-zt"
)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.ZeroTierEndpointOptions](registry, C.TypeZeroTier, NewEndpoint)
}

type Endpoint struct {
	endpoint.Adapter
	ctx          context.Context
	closeCtx     context.Context
	cancelClose  context.CancelFunc
	router       adapter.Router
	logger       logger.ContextLogger
	networkState atomic.Pointer[endpointNetworkState]
	networkID    uint64
	storagePath  string
	defaultMTU   uint32
	mtu          atomic.Uint32
	udpTimeout   time.Duration

	staticAddresses []netip.Prefix

	// ZeroTier core
	node    zeroTierNode
	udpConn udpPacketConn

	// test seams
	newNode       func(zt.NodeCallbacks, *zt.NodeConfig) (zeroTierNode, error)
	macTableNow   func() time.Time
	listenUDP     func() (udpPacketConn, error)
	createStackFn func() error

	// gVisor stack
	ipStack            *stack.Stack
	dispatcher         atomic.Pointer[dispatcherHolder]
	runtimeStateMu     sync.Mutex
	addr4              tcpip.Address
	addr6              tcpip.Address
	udpForwarder       *tun.UDPForwarder
	icmpForwarder      *tun.ICMPForwarder
	outbound           chan outboundPacket
	topologyGeneration atomic.Uint64
	topologyMu         sync.RWMutex
	pendingConfigReady atomic.Bool
	pendingConfigNWMac atomic.Uint64
	done               chan struct{}
	closed             atomic.Bool
	closeOnce          sync.Once
	lifecycleMu        sync.Mutex
	managed            sync.WaitGroup
	nodeCalls          sync.WaitGroup
	stackCalls         sync.WaitGroup
	enqueueCalls       sync.WaitGroup

	// Wire send targets (for excludeRoute)
	wireTargetsMu sync.RWMutex
	wireTargets   map[string]bool

	// MAC address table: maps IP → ZeroTier MAC for unicast frames
	macTableMu sync.RWMutex
	macTable   map[string]macTableEntry

	// ARP/NDP probe and pending packet tracking
	arpPendingMu                   sync.Mutex
	arpPending                     map[string]time.Time
	ipv6NeighborProbeRetryInterval time.Duration
	ipv6NeighborProbeTimeout       time.Duration
	ipv6PendingMu                  sync.Mutex
	ipv6Pending                    map[string]pendingIPv6Neighbor
	ipv6PendingWake                chan struct{}
	tentativeIPv6Mu                sync.Mutex
	tentativeIPv6                  map[string]bool
	multicastGroupsMu              sync.Mutex
	multicastGroups                map[zeroTierMulticastGroup]zeroTierMulticastGroupRef
	multicastOpsMu                 sync.Mutex
	multicastOps                   []func()
	multicastWake                  chan struct{}
	multicastLifecycleReady        atomic.Bool
	// ZeroTier managed routes
	routesMu sync.RWMutex
	routes   []zt.Route
}

type dispatcherHolder struct {
	value stack.NetworkDispatcher
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ZeroTierEndpointOptions) (adapter.Endpoint, error) {
	networkID, err := strconv.ParseUint(options.NetworkID, 16, 64)
	if err != nil {
		return nil, E.Cause(err, "parse network_id")
	}

	storagePath := options.StoragePath
	if storagePath == "" {
		storagePath = "zerotier"
	}
	storagePath = filemanager.BasePath(ctx, os.ExpandEnv(storagePath))
	storagePath, _ = filepath.Abs(storagePath)

	var mtu uint32 = 2800
	if options.MTU != 0 {
		mtu = options.MTU
	}

	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}

	closeCtx, cancelClose := context.WithCancel(ctx)
	ep := &Endpoint{
		Adapter:                        endpoint.NewAdapterWithDialerOptions(C.TypeZeroTier, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		ctx:                            ctx,
		closeCtx:                       closeCtx,
		cancelClose:                    cancelClose,
		router:                         router,
		logger:                         logger,
		networkID:                      networkID,
		storagePath:                    storagePath,
		defaultMTU:                     mtu,
		udpTimeout:                     udpTimeout,
		staticAddresses:                clonePrefixes(options.Address),
		outbound:                       make(chan outboundPacket, 256),
		done:                           make(chan struct{}),
		wireTargets:                    make(map[string]bool),
		macTable:                       make(map[string]macTableEntry),
		arpPending:                     make(map[string]time.Time),
		ipv6NeighborProbeRetryInterval: time.Second,
		ipv6NeighborProbeTimeout:       4 * time.Second,
		ipv6Pending:                    make(map[string]pendingIPv6Neighbor),
		ipv6PendingWake:                make(chan struct{}, 1),
		tentativeIPv6:                  make(map[string]bool),
		multicastGroups:                make(map[zeroTierMulticastGroup]zeroTierMulticastGroupRef),
		multicastWake:                  make(chan struct{}, 1),
	}
	ep.mtu.Store(mtu)
	ep.topologyGeneration.Store(2)
	ep.initializeNetworkState(options.Address)
	return ep, nil
}

func (ep *Endpoint) beginManaged() bool {
	ep.lifecycleMu.Lock()
	defer ep.lifecycleMu.Unlock()
	if ep.closed.Load() {
		return false
	}
	ep.managed.Add(1)
	return true
}

func (ep *Endpoint) goManaged(fn func()) {
	if !ep.beginManaged() {
		return
	}
	go func() {
		defer ep.managed.Done()
		fn()
	}()
}

func (ep *Endpoint) withNode(fn func(zeroTierNode)) bool {
	ep.lifecycleMu.Lock()
	if ep.closed.Load() || ep.node == nil {
		ep.lifecycleMu.Unlock()
		return false
	}
	node := ep.node
	ep.nodeCalls.Add(1)
	ep.lifecycleMu.Unlock()
	defer ep.nodeCalls.Done()
	fn(node)
	return true
}

func (ep *Endpoint) Start(stage adapter.StartStage, scope *adapter.Scope) (err error) {
	if stage == adapter.StartStateInitialize {
		scope.Add(ep.Close)
		return nil
	}
	if stage != adapter.StartStateStart {
		return nil
	}
	ep.goManaged(ep.runMulticastOps)
	ep.goManaged(ep.runPendingIPv6NeighborProbes)
	defer func() {
		if err == nil {
			return
		}
		if closeErr := ep.Close(); closeErr != nil {
			ep.logger.Warn("failed to rollback ZeroTier endpoint start: ", closeErr)
		}
	}()

	if err = os.MkdirAll(ep.storagePath, 0o700); err != nil {
		return E.Cause(err, "create storage directory")
	}
	ep.udpConn, err = ep.listenWirePacket()
	if err != nil {
		return E.Cause(err, "listen UDP")
	}
	ep.logger.Info(fmt.Sprintf("UDP socket bound to %s", ep.udpConn.LocalAddr()))

	major, minor, rev := zt.Version()
	ep.logger.Info(fmt.Sprintf("ZeroTier Core v%d.%d.%d", major, minor, rev))

	node, err := ep.createZeroTierNode(zt.NodeCallbacks{
		StatePut: ep.statePut,
		StateGet: ep.stateGet,
		WirePacketSend: func(localSocket int64, addr netip.AddrPort, data []byte, ttl uint) error {
			ip := addr.Addr().String()
			ep.wireTargetsMu.RLock()
			known := ep.wireTargets[ip]
			ep.wireTargetsMu.RUnlock()
			if !known {
				ep.wireTargetsMu.Lock()
				ep.wireTargets[ip] = true
				ep.wireTargetsMu.Unlock()
			}
			target := net.UDPAddrFromAddrPort(addr)
			ep.logger.Debug(fmt.Sprintf("wire send: %d bytes -> %s", len(data), target))
			_, writeErr := ep.udpConn.WriteTo(data, target)
			return writeErr
		},
		VirtualNetworkFrame:  ep.onVirtualNetworkFrame,
		VirtualNetworkConfig: ep.handleVirtualNetworkConfig,
		Event: func(event zt.Event, data any) {
			ep.logger.Info(fmt.Sprint("event: ", event))
			if event == zt.EventOnline {
				ep.goManaged(func() {
					timer := time.NewTimer(100 * time.Millisecond)
					defer timer.Stop()
					select {
					case <-ep.done:
						return
					case <-timer.C:
					}
					if ep.multicastLifecycleReady.Load() {
						ep.queueMulticastGroupsResubscribe(0)
						ep.queueMulticastOperation(func() {
							ep.goManaged(ep.announceARP)
						})
					}
					ep.logPeers()
				})
			}
		},
		PathCheck: func(ztAddress uint64, localSocket int64, addr netip.AddrPort) bool {
			return true
		},
		Logger: func(msg string) {
			ep.logger.Warn("go-zt: ", msg)
		},
	})
	if err != nil {
		return E.Cause(err, "create ZeroTier node")
	}
	ep.lifecycleMu.Lock()
	if ep.closed.Load() {
		ep.lifecycleMu.Unlock()
		node.Close()
		return E.New("closed while creating ZeroTier node")
	}
	ep.node = node
	ep.lifecycleMu.Unlock()
	var nodeAddress uint64
	if !ep.withNode(func(node zeroTierNode) {
		nodeAddress = node.Address()
	}) {
		return E.New("closed before reading ZeroTier node address")
	}
	ep.logger.Info(fmt.Sprintf("node address: %010x", nodeAddress))

	ep.goManaged(ep.receiveWirePackets)
	ep.goManaged(ep.backgroundLoop)

	if !ep.withNode(func(node zeroTierNode) {
		err = node.Join(ep.networkID)
	}) {
		return E.New("closed before joining ZeroTier network")
	}
	if err != nil {
		return E.Cause(err, "join network")
	}
	ep.logger.Info(fmt.Sprintf("joining network %016x", ep.networkID))

	if err = ep.waitForNetworkReady(); err != nil {
		return err
	}
	ep.logger.Info(fmt.Sprint("addresses: ", ep.currentNetworkState().localAddresses))

	ep.multicastLifecycleReady.Store(true)
	ep.syncManagedMulticastGroups(ep.currentNetworkState())
	for _, group := range ep.multicastGroupsSnapshot() {
		ep.subscribeMulticastGroupOnNode(group, "subscribe")
	}

	if err = ep.createManagedStack(); err != nil {
		return E.Cause(err, "create network stack")
	}
	ep.goManaged(ep.forwardOutbound)
	ep.goManaged(ep.announceARP)

	wireWait := time.NewTimer(100 * time.Millisecond)
	defer wireWait.Stop()
	for i := 0; i < 30; i++ {
		ep.wireTargetsMu.RLock()
		count := len(ep.wireTargets)
		ep.wireTargetsMu.RUnlock()
		if count > 0 {
			break
		}
		wireWait.Reset(100 * time.Millisecond)
		select {
		case <-ep.done:
			return E.New("closed while waiting for wire targets")
		case <-ep.ctx.Done():
			return ep.ctx.Err()
		case <-wireWait.C:
		}
	}

	activeEndpointsMu.Lock()
	activeEndpoints[ep.Tag()] = ep
	activeEndpointsMu.Unlock()
	return nil
}
func (ep *Endpoint) Close() error {
	if !ep.closed.CompareAndSwap(false, true) {
		return nil
	}
	if ep.cancelClose != nil {
		ep.cancelClose()
	}
	ep.closeOnce.Do(func() {
		select {
		case <-ep.done:
		default:
			close(ep.done)
		}
	})

	activeEndpointsMu.Lock()
	if activeEndpoints[ep.Tag()] == ep {
		delete(activeEndpoints, ep.Tag())
	}
	activeEndpointsMu.Unlock()

	if ep.udpConn != nil {
		_ = ep.udpConn.Close()
	}

	ep.lifecycleMu.Lock()
	ep.lifecycleMu.Unlock()
	ep.managed.Wait()
	ep.nodeCalls.Wait()
	ep.stackCalls.Wait()
	ep.enqueueCalls.Wait()
	if ep.icmpForwarder != nil {
		_ = ep.icmpForwarder.Close()
	}
	if ep.udpForwarder != nil {
		_ = ep.udpForwarder.Close()
	}
	ep.drainOutboundPackets()

	if ep.ipStack != nil {
		closeGVisorStack(ep.ipStack)
		ep.ipStack = nil
	}

	ep.lifecycleMu.Lock()
	node := ep.node
	ep.node = nil
	ep.lifecycleMu.Unlock()
	if node != nil {
		node.Close()
	}

	ep.clearMulticastOperations()
	ep.runtimeStateMu.Lock()
	ep.addr4 = tcpip.Address{}
	ep.addr6 = tcpip.Address{}
	ep.runtimeStateMu.Unlock()
	return nil
}
