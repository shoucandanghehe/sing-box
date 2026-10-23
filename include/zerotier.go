//go:build with_zerotier && with_gvisor

package include

import (
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/protocol/zerotier"
)

func registerZeroTierEndpoint(registry *endpoint.Registry) {
	zerotier.RegisterEndpoint(registry)
}
