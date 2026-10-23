//go:build with_zerotier && with_gvisor

package libbox

import (
	"github.com/sagernet/sing-box/protocol/zerotier"
)

func GetZeroTierStatus() string {
	return zerotier.GetAllStatus()
}

func GetZeroTierPlanetIPs() string {
	return zerotier.GetPlanetIPs()
}
