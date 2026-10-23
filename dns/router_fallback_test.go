package dns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Only the transport boundary is fake; Lookup, DNS rules and the DNS client are real.
type fallbackTestFakeIP struct {
	*fakeDNSTransport
}

func (*fallbackTestFakeIP) Type() string {
	return C.DNSTypeFakeIP
}

func TestDNSLookupFallbackTransport(t *testing.T) {
	t.Parallel()
	for _, legacy := range []bool{false, true} {
		name := "rules"
		if legacy {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			final := &fakeDNSTransport{tag: "final", address: netip.MustParseAddr("192.0.2.1")}
			fallback := &fakeDNSTransport{tag: "fallback", address: netip.MustParseAddr("192.0.2.2")}
			routed := &fakeDNSTransport{tag: "routed", address: netip.MustParseAddr("192.0.2.3")}
			fakeIP := &fallbackTestFakeIP{&fakeDNSTransport{tag: "fakeip", address: netip.MustParseAddr("198.18.0.1")}}
			router := raceTestRouter(t, final, fallback, routed)
			router.legacyDNSMode = legacy
			router.transport.(*fakeDNSTransportManager).transports["fakeip"] = fakeIP
			rule := routeRule("routed", false)
			rule.DefaultOptions.Domain = []string{"rule.example"}
			router.rules = raceTestRules(t, []option.DNSRule{routeRule("fakeip", false), rule})
			options := adapter.DNSQueryOptions{FallbackTransport: fallback, Strategy: C.DomainStrategyIPv4Only}
			addresses, err := router.Lookup(context.Background(), "rule.example", options)
			require.NoError(t, err)
			require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.3")}, addresses)
			addresses, err = router.Lookup(context.Background(), "unmatched.example", options)
			require.NoError(t, err)
			require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.2")}, addresses)
			require.Zero(t, fakeIP.queryCount.Load(), "internal lookup must skip FakeIP rules")
			require.Zero(t, final.queryCount.Load())
			options.Transport = final
			addresses, err = router.Lookup(context.Background(), "rule.example", options)
			require.NoError(t, err)
			require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, addresses, "fixed server still bypasses DNS rules")
			require.EqualValues(t, 1, routed.queryCount.Load())
			require.EqualValues(t, 1, fallback.queryCount.Load())
			addresses, err = router.Lookup(context.Background(), "unmatched.example", adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only})
			require.NoError(t, err)
			require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, addresses, "absent fallback preserves the default")
		})
	}
}

func TestDNSFallbackPreservesTerminalActions(t *testing.T) {
	t.Parallel()
	for _, legacy := range []bool{false, true} {
		for _, action := range []string{"route-error", "reject", "predefined"} {
			t.Run(action+map[bool]string{false: "/rules", true: "/legacy"}[legacy], func(t *testing.T) {
				fallback := &fakeDNSTransport{tag: "fallback", address: netip.MustParseAddr("192.0.2.2")}
				routed := &fakeDNSTransport{tag: "routed", exchangeErr: context.DeadlineExceeded}
				router := raceTestRouter(t, fallback, routed)
				router.legacyDNSMode = legacy
				rule := routeRule("routed", false)
				switch action {
				case "reject":
					rule.DefaultOptions.DNSRuleAction = option.DNSRuleAction{
						Action:        C.RuleActionTypeReject,
						RejectOptions: option.RejectActionOptions{Method: C.RuleActionRejectMethodDefault},
					}
				case "predefined":
					record, parseErr := mDNS.NewRR("example. 60 IN A 192.0.2.9")
					require.NoError(t, parseErr)
					record.(*mDNS.A).A = record.(*mDNS.A).A.To4()
					rcode := option.DNSRCode(mDNS.RcodeSuccess)
					rule.DefaultOptions.DNSRuleAction = option.DNSRuleAction{
						Action:            C.RuleActionTypePredefined,
						PredefinedOptions: option.DNSRouteActionPredefined{Rcode: &rcode, Answer: []option.DNSRecordOptions{{RR: record}}},
					}
				}
				router.rules = raceTestRules(t, []option.DNSRule{rule})
				addresses, err := router.Lookup(context.Background(), "example", adapter.DNSQueryOptions{FallbackTransport: fallback, Strategy: C.DomainStrategyIPv4Only})
				if action == "predefined" {
					require.NoError(t, err)
					require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.9")}, addresses)
				} else {
					require.Error(t, err)
				}
				require.Zero(t, fallback.queryCount.Load(), "fallback must not retry a terminal action")
			})
		}
	}
}

func TestDNSFallbackPreservesEvaluateRespond(t *testing.T) {
	t.Parallel()
	fallback := &fakeDNSTransport{tag: "fallback", address: netip.MustParseAddr("192.0.2.2")}
	routed := &fakeDNSTransport{tag: "routed", address: netip.MustParseAddr("192.0.2.3"), immediate: true}
	router := raceTestRouter(t, fallback, routed)
	router.rules = raceTestRules(t, []option.DNSRule{evaluateRule("routed", "answer", false), respondRule("answer", false, true)})
	addresses, err := router.Lookup(context.Background(), "example", adapter.DNSQueryOptions{FallbackTransport: fallback, Strategy: C.DomainStrategyIPv4Only})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.3")}, addresses)
	require.Zero(t, fallback.queryCount.Load())
}

func TestDNSFallbackCacheUsesSelectedTransport(t *testing.T) {
	t.Parallel()
	final := &fakeDNSTransport{tag: "final", address: netip.MustParseAddr("192.0.2.1")}
	fallback := &fakeDNSTransport{tag: "fallback", address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, final, fallback)
	router.client = NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
	for range 2 {
		for _, testCase := range []struct {
			fallback adapter.DNSTransport
			want     string
		}{{nil, "192.0.2.1"}, {fallback, "192.0.2.2"}} {
			addresses, err := router.Lookup(context.Background(), "same.example", adapter.DNSQueryOptions{FallbackTransport: testCase.fallback, Strategy: C.DomainStrategyIPv4Only})
			require.NoError(t, err)
			require.Equal(t, []netip.Addr{netip.MustParseAddr(testCase.want)}, addresses)
		}
	}
	require.EqualValues(t, 1, final.queryCount.Load())
	require.EqualValues(t, 1, fallback.queryCount.Load())
}

func TestDNSExchangeFallbackTransport(t *testing.T) {
	t.Parallel()
	for _, legacy := range []bool{false, true} {
		final := &fakeDNSTransport{tag: "final", address: netip.MustParseAddr("192.0.2.1")}
		fallback := &fakeDNSTransport{tag: "fallback", address: netip.MustParseAddr("192.0.2.2"), immediate: true}
		router := raceTestRouter(t, final, fallback)
		router.legacyDNSMode = legacy
		message := new(mDNS.Msg).SetQuestion("example.", mDNS.TypeA)
		options := adapter.DNSQueryOptions{FallbackTransport: fallback}
		response, err := router.Exchange(context.Background(), message, options)
		require.NoError(t, err)
		require.Equal(t, netip.MustParseAddr("192.0.2.2"), responseAddress(t, response))
		type result struct {
			response *mDNS.Msg
			err      error
		}
		done := make(chan result, 1)
		router.ExchangeAsync(context.Background(), message, options, func(response *mDNS.Msg, err error) { done <- result{response, err} })
		actual := <-done
		require.NoError(t, actual.err)
		require.Equal(t, netip.MustParseAddr("192.0.2.2"), responseAddress(t, actual.response))
		require.Zero(t, final.queryCount.Load())
	}
}
