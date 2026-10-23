//go:build !with_zerotier || !with_gvisor

package libbox

func GetZeroTierStatus() string {
	return "[]"
}

func GetZeroTierPlanetIPs() string {
	return ""
}
