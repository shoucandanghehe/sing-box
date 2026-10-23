package dns

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

type fallbackDependencyTransport struct {
	*fakeDNSTransport
	dependencies []string
	startOrder   *[]string
}

func (t *fallbackDependencyTransport) Dependencies() []string { return t.dependencies }
func (t *fallbackDependencyTransport) Start(stage adapter.StartStage, _ *adapter.Scope) error {
	if stage == adapter.StartStateStart {
		*t.startOrder = append(*t.startOrder, t.tag)
	}
	return nil
}

func TestDNSFallbackStartupDependencies(t *testing.T) {
	t.Parallel()
	resolverOptions := option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{DomainResolver: &option.DomainResolveOptions{FallbackServer: "bootstrap"}}}
	local := NewTransportAdapterWithLocalOptions(C.DNSTypeLocal, "local", option.LocalDNSServerOptions{RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{DialerOptions: resolverOptions}})
	remote := NewTransportAdapterWithRemoteOptions(C.DNSTypeUDP, "remote", option.RemoteDNSServerOptions{RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{DialerOptions: resolverOptions}})
	for _, transportAdapter := range []TransportAdapter{local, remote} {
		t.Run(transportAdapter.Tag(), func(t *testing.T) {
			require.Equal(t, []string{"bootstrap"}, transportAdapter.Dependencies())
			for _, dependency := range []string{"bootstrap", "missing", transportAdapter.Tag()} {
				t.Run(dependency, func(t *testing.T) {
					var order []string
					transport := &fallbackDependencyTransport{fakeDNSTransport: &fakeDNSTransport{tag: transportAdapter.Tag()}, dependencies: []string{dependency}, startOrder: &order}
					bootstrap := &fallbackDependencyTransport{fakeDNSTransport: &fakeDNSTransport{tag: "bootstrap"}, startOrder: &order}
					manager := NewTransportManager(nil, nil, "")
					manager.transports = []adapter.DNSTransport{transport, bootstrap}
					manager.transportByTag = map[string]adapter.DNSTransport{transport.Tag(): transport, bootstrap.Tag(): bootstrap}
					scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
					defer scope.Close()
					err := manager.Start(adapter.StartStateStart, scope)
					switch dependency {
					case "bootstrap":
						require.NoError(t, err)
						require.Equal(t, []string{"bootstrap", transportAdapter.Tag()}, order)
					case "missing":
						require.ErrorContains(t, err, "dependency[missing] not found")
					default:
						require.ErrorContains(t, err, "circular server dependency")
					}
				})
			}
		})
	}
}
