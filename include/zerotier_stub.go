//go:build !with_zerotier || !with_gvisor

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerZeroTierEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.ZeroTierEndpointOptions](registry, C.TypeZeroTier, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ZeroTierEndpointOptions) (adapter.Endpoint, error) {
		return nil, E.New(`ZeroTier is not included in this build, rebuild with -tags with_zerotier`)
	})
}
