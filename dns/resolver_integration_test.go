package dns_test

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// All routing, managers and dialers are production implementations. Only DNS
// transport I/O is replaced; TCP connections go to an actual loopback listener.
type resolverTestTransport struct {
	dns.TransportAdapter
	queries atomic.Int32
}

func (*resolverTestTransport) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (*resolverTestTransport) Reset()                                         {}
func (t *resolverTestTransport) Exchange(_ context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.queries.Add(1)
	return dns.FixedResponse(message.Id, message.Question[0], []netip.Addr{netip.MustParseAddr("127.0.0.1")}, 60), nil
}

func (t *resolverTestTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	callback(t.Exchange(ctx, message))
}

func resolverTestContext(t *testing.T, defaultResolver *option.DomainResolveOptions, rawRules string, tags ...string) (context.Context, *dns.TransportManager, *outbound.Manager, *adapter.Scope) {
	t.Helper()
	ctx := context.Background()
	logger := log.NewNOPFactory().Logger()
	registry := dns.NewTransportRegistry()
	dns.RegisterTransport(registry, "test", func(_ context.Context, _ log.ContextLogger, tag string, _ struct{}) (adapter.DNSTransport, error) {
		return &resolverTestTransport{TransportAdapter: dns.NewTransportAdapter("test", tag, nil)}, nil
	})
	transports := dns.NewTransportManager(registry, nil, "final")
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, transports)
	if len(tags) == 0 {
		tags = []string{"final", "global", "member", "rule"}
	}
	for _, tag := range tags {
		require.NoError(t, transports.Create(ctx, logger, tag, "test", nil))
	}
	outboundRegistry := outbound.NewRegistry()
	direct.RegisterOutbound(outboundRegistry)
	group.RegisterSelector(outboundRegistry)
	outbounds := outbound.NewManager(outboundRegistry, endpoint.NewManager(endpoint.NewRegistry()), "")
	ctx = service.ContextWith[adapter.OutboundManager](ctx, outbounds)
	network, err := route.NewNetworkManager(ctx, logger, option.RouteOptions{DefaultDomainResolver: defaultResolver}, option.DNSOptions{})
	require.NoError(t, err)
	ctx = service.ContextWith[adapter.NetworkManager](ctx, network)
	var rules []option.DNSRule
	require.NoError(t, json.Unmarshal([]byte(rawRules), &rules))
	router, err := dns.NewRouter(ctx, log.NewNOPFactory(), option.DNSOptions{RawDNSOptions: option.RawDNSOptions{DNSClientOptions: option.DNSClientOptions{DisableCache: true}}})
	require.NoError(t, err)
	require.NoError(t, router.Initialize(rules))
	ctx = service.ContextWith[adapter.DNSRouter](ctx, router)
	scope := adapter.NewScope(ctx, logger)
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	require.NoError(t, router.Start(adapter.StartStateStart, scope))
	return ctx, transports, outbounds, scope
}

func resolverQueryCount(t *testing.T, transports *dns.TransportManager, tag string) int32 {
	t.Helper()
	transport, loaded := transports.Transport(tag)
	require.True(t, loaded)
	return transport.(*resolverTestTransport).queries.Load()
}

func TestSelectorSelectedDirectFallbackResolver(t *testing.T) {
	ctx, transports, outbounds, scope := resolverTestContext(t,
		&option.DomainResolveOptions{Server: "global", Strategy: option.DomainStrategy(C.DomainStrategyIPv4Only)},
		`[{"domain":"private.example","action":"route","server":"rule"}]`)
	logger := log.NewNOPFactory().Logger()
	for _, member := range []struct{ tag, resolver string }{
		{"DIRECT", `{"fallback_server":"member","strategy":"ipv4_only"}`},
		{"FIXED", `{"server":"global","strategy":"ipv4_only"}`},
	} {
		var resolver option.DomainResolveOptions
		require.NoError(t, json.Unmarshal([]byte(member.resolver), &resolver))
		require.NoError(t, outbounds.Create(ctx, nil, logger, member.tag, C.TypeDirect, &option.DirectOutboundOptions{
			DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{DomainResolver: &resolver}},
		}))
	}
	require.NoError(t, outbounds.Create(ctx, nil, logger, "select", C.TypeSelector, &option.SelectorOutboundOptions{Outbounds: []string{"FIXED", "DIRECT"}, Default: "DIRECT"}))
	selected, loaded := outbounds.Outbound("select")
	require.True(t, loaded)
	selector := selected.(*group.Selector)
	require.NoError(t, selector.Start(adapter.StartStateStart, scope))
	require.Equal(t, "DIRECT", selector.Now())
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	for _, testCase := range []struct {
		domain string
		server string
	}{
		{"private.example", "rule"},
		{"public.example", "member"},
	} {
		t.Run(testCase.domain, func(t *testing.T) {
			before := resolverQueryCount(t, transports, testCase.server)
			dialCtx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			conn, dialErr := selector.DialContext(dialCtx, "tcp", M.Socksaddr{Fqdn: testCase.domain, Port: M.SocksaddrFromNet(listener.Addr()).Port})
			require.NoError(t, dialErr)
			require.NoError(t, conn.Close())
			accepted, acceptErr := listener.Accept()
			require.NoError(t, acceptErr)
			require.NoError(t, accepted.Close())
			require.Equal(t, before+1, resolverQueryCount(t, transports, testCase.server))
		})
	}
	require.Zero(t, resolverQueryCount(t, transports, "global"), "member fallback must override global fixed resolver")
	require.Zero(t, resolverQueryCount(t, transports, "final"))
	require.True(t, selector.SelectOutbound("FIXED"))
	conn, err := selector.DialContext(ctx, "tcp", M.Socksaddr{Fqdn: "private.example", Port: M.SocksaddrFromNet(listener.Addr()).Port})
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	accepted, err := listener.Accept()
	require.NoError(t, err)
	require.NoError(t, accepted.Close())
	require.EqualValues(t, 1, resolverQueryCount(t, transports, "global"))
	require.EqualValues(t, 1, resolverQueryCount(t, transports, "rule"), "fixed member must bypass the matching DNS rule")
}

func TestDomainResolverPrecedenceAndUnknownReferences(t *testing.T) {
	for _, testCase := range []struct {
		name            string
		global, member  *option.DomainResolveOptions
		want, wantError string
	}{
		{"global fallback", &option.DomainResolveOptions{FallbackServer: "global"}, nil, "global", ""},
		{"member fixed over fallback", &option.DomainResolveOptions{FallbackServer: "global"}, &option.DomainResolveOptions{Server: "member"}, "member", ""},
		{"member fallback over fixed", &option.DomainResolveOptions{Server: "global"}, &option.DomainResolveOptions{FallbackServer: "member"}, "member", ""},
		{"unknown member", &option.DomainResolveOptions{Server: "global"}, &option.DomainResolveOptions{FallbackServer: "missing"}, "", "domain resolver not found: missing"},
		{"unknown global", &option.DomainResolveOptions{FallbackServer: "missing"}, nil, "", "default domain resolver not found: missing"},
		{"conflicting member", nil, &option.DomainResolveOptions{Server: "global", FallbackServer: "member"}, "", "mutually exclusive"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, transports, _, _ := resolverTestContext(t, testCase.global, `[{"domain":"routed.example","action":"route","server":"rule"}]`)
			options, err := dialer.NewDNSQueryOptions(ctx, testCase.member, true)
			if testCase.wantError != "" {
				require.ErrorContains(t, err, testCase.wantError)
				return
			}
			require.NoError(t, err)
			options.Strategy = C.DomainStrategyIPv4Only
			addresses, err := service.FromContext[adapter.DNSRouter](ctx).Lookup(ctx, "example", options)
			require.NoError(t, err)
			require.Equal(t, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, addresses)
			require.EqualValues(t, 1, resolverQueryCount(t, transports, testCase.want))
			require.Zero(t, resolverQueryCount(t, transports, "final"))
			_, err = service.FromContext[adapter.DNSRouter](ctx).Lookup(ctx, "routed.example", options)
			require.NoError(t, err)
			resolver := testCase.member
			if resolver == nil {
				resolver = testCase.global
			}
			if resolver.FallbackServer != "" {
				require.EqualValues(t, 1, resolverQueryCount(t, transports, "rule"))
				require.EqualValues(t, 1, resolverQueryCount(t, transports, testCase.want))
			} else {
				require.Zero(t, resolverQueryCount(t, transports, "rule"))
				require.EqualValues(t, 2, resolverQueryCount(t, transports, testCase.want))
			}
		})
	}
}

func TestDirectResolverFallbackLateBinding(t *testing.T) {
	ctx, transports, _, _ := resolverTestContext(t, nil, `[]`)
	resolver, err := dialer.NewWithOptions(dialer.Options{
		Context: ctx, RemoteIsDomain: true, DirectResolver: true, NewDialer: true,
		Options: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{
			DomainResolver: &option.DomainResolveOptions{FallbackServer: "late", Strategy: option.DomainStrategy(C.DomainStrategyIPv4Only)},
		}},
	})
	require.NoError(t, err, "DNS transports can refer to a server constructed later")
	require.NoError(t, transports.Create(ctx, log.NewNOPFactory().Logger(), "late", "test", nil))
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	conn, err := resolver.DialContext(ctx, "tcp", M.Socksaddr{Fqdn: "bootstrap.example", Port: M.SocksaddrFromNet(listener.Addr()).Port})
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	accepted, err := listener.Accept()
	require.NoError(t, err)
	require.NoError(t, accepted.Close())
	require.EqualValues(t, 1, resolverQueryCount(t, transports, "late"))
	options := resolver.(dialer.ParallelInterfaceResolveDialer).QueryOptions()
	require.Nil(t, options.Transport, "late binding must not turn fallback into fixed transport")
	require.Equal(t, "late", options.FallbackTransport.Tag())
}

func TestExplicitFallbackResolverOnDetour(t *testing.T) {
	ctx, transports, outbounds, _ := resolverTestContext(t, nil, `[]`)
	require.NoError(t, outbounds.Create(ctx, nil, log.NewNOPFactory().Logger(), "detour", C.TypeDirect, &option.DirectOutboundOptions{
		DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{
			DomainResolver: &option.DomainResolveOptions{Server: "global", Strategy: option.DomainStrategy(C.DomainStrategyIPv4Only)},
		}},
	}))
	resolver, err := dialer.NewWithOptions(dialer.Options{
		Context: ctx, RemoteIsDomain: true, NewDialer: true,
		Options: option.DialerOptions{
			Detour: "detour",
			AbstractDialerOptions: option.AbstractDialerOptions{
				DomainResolver: &option.DomainResolveOptions{FallbackServer: "member", Strategy: option.DomainStrategy(C.DomainStrategyIPv4Only)},
			},
		},
	})
	require.NoError(t, err)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	conn, err := resolver.DialContext(ctx, "tcp", M.Socksaddr{Fqdn: "detour.example", Port: M.SocksaddrFromNet(listener.Addr()).Port})
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	accepted, err := listener.Accept()
	require.NoError(t, err)
	require.NoError(t, accepted.Close())
	require.EqualValues(t, 1, resolverQueryCount(t, transports, "member"))
	require.Zero(t, resolverQueryCount(t, transports, "global"), "explicit resolver must resolve before passing the IP to the detour")
}

func TestDomainResolverFallbackWithSingleTransport(t *testing.T) {
	ctx, transports, _, _ := resolverTestContext(t, nil, `[{"action":"reject"}]`, "final")
	options, err := dialer.NewDNSQueryOptions(ctx, &option.DomainResolveOptions{FallbackServer: "final"}, true)
	require.NoError(t, err)
	options.Strategy = C.DomainStrategyIPv4Only
	_, err = service.FromContext[adapter.DNSRouter](ctx).Lookup(ctx, "example", options)
	require.Error(t, err, "an explicit fallback must still run rules with only one transport")
	require.Zero(t, resolverQueryCount(t, transports, "final"))
}
