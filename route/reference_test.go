package route

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestDomainResolverReferences(t *testing.T) {
	t.Parallel()
	manager := NewReferenceManager(context.Background(), log.NewNOPFactory().Logger(), option.Options{
		Outbounds: []option.Outbound{
			{Options: &option.DirectOutboundOptions{DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{
				DomainResolver: &option.DomainResolveOptions{Server: "fixed"},
			}}}},
			{Options: &option.DirectOutboundOptions{DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{
				DomainResolver: &option.DomainResolveOptions{FallbackServer: "fallback"},
			}}}},
		},
	})
	require.Equal(t, []string{"fixed", "fallback"}, manager.staticTransports)
}
