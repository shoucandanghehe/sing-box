package box_test

import (
	"context"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// CLI check and libbox.CheckConfig both validate through box.New without Start.
func TestDNSFallbackReferencesAtConstruction(t *testing.T) {
	for _, testCase := range []struct {
		name, config, wantError string
	}{
		{
			"unused global",
			`{"dns":{"servers":[{"type":"hosts","tag":"fixed"}]},"route":{"default_domain_resolver":{"fallback_server":"missing"}},"outbounds":[{"type":"direct","tag":"direct","domain_resolver":"fixed"}]}`,
			"default domain resolver not found: missing",
		},
		{
			"bootstrap missing",
			`{"dns":{"servers":[{"type":"udp","tag":"remote","server":"dns.example","domain_resolver":{"fallback_server":"missing"}},{"type":"hosts","tag":"fixed"}]},"outbounds":[{"type":"direct","tag":"direct","domain_resolver":"fixed"}]}`,
			"domain resolver not found: missing",
		},
		{
			"bootstrap forward reference",
			`{"dns":{"servers":[{"type":"udp","tag":"remote","server":"dns.example","domain_resolver":{"fallback_server":"bootstrap"}},{"type":"hosts","tag":"bootstrap"}]},"route":{"default_domain_resolver":{"fallback_server":"bootstrap"}},"outbounds":[{"type":"direct","tag":"direct","domain_resolver":"bootstrap"}]}`,
			"",
		},
		{
			"member missing",
			`{"dns":{"servers":[{"type":"hosts","tag":"fixed"}]},"outbounds":[{"type":"direct","tag":"direct","domain_resolver":{"fallback_server":"missing"}}]}`,
			"domain resolver not found: missing",
		},
		{
			"IP member missing fallback",
			`{"dns":{"servers":[{"type":"hosts","tag":"fixed"}]},"outbounds":[{"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1080,"domain_resolver":{"fallback_server":"missing"}}]}`,
			"domain resolver not found: missing",
		},
		{
			"IP member fallback",
			`{"dns":{"servers":[{"type":"hosts","tag":"fixed"}]},"outbounds":[{"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1080,"domain_resolver":{"fallback_server":"fixed"}}]}`,
			"",
		},
		{
			"IP member unused fixed resolver",
			`{"dns":{"servers":[{"type":"hosts","tag":"fixed"}]},"outbounds":[{"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1080,"domain_resolver":{"server":"missing"}}]}`,
			"",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(include.Context(context.Background()))
			defer cancel()
			var options option.Options
			require.NoError(t, json.UnmarshalContext(ctx, []byte(testCase.config), &options))
			instance, err := box.New(box.Options{Context: ctx, Options: options})
			if testCase.wantError != "" {
				require.ErrorContains(t, err, testCase.wantError)
				return
			}
			require.NoError(t, err)
			require.NoError(t, instance.Close())
		})
	}
}
