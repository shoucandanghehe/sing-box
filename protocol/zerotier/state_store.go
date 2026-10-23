//go:build with_zerotier && with_gvisor

package zerotier

import (
	"fmt"
	"os"
	"path/filepath"

	zt "github.com/scdhh/go-zt"
)

// State persistence.
func (ep *Endpoint) statePut(objType zt.StateObjectType, id [2]uint64, data []byte) {
	path := ep.statePath(objType, id)
	if path == "" {
		return
	}
	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0o700)
	if data == nil {
		os.Remove(path)
	} else {
		os.WriteFile(path, data, 0o600)
	}
}

func (ep *Endpoint) stateGet(objType zt.StateObjectType, id [2]uint64) ([]byte, bool) {
	path := ep.statePath(objType, id)
	if path == "" {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return data, true
}

func (ep *Endpoint) statePath(objType zt.StateObjectType, id [2]uint64) string {
	switch objType {
	case zt.StateObjectIdentityPublic:
		return filepath.Join(ep.storagePath, "identity.public")
	case zt.StateObjectIdentitySecret:
		return filepath.Join(ep.storagePath, "identity.secret")
	case zt.StateObjectPlanet:
		return filepath.Join(ep.storagePath, "planet")
	case zt.StateObjectMoon:
		return filepath.Join(ep.storagePath, "moons.d", fmt.Sprintf("%016x.moon", id[0]))
	case zt.StateObjectPeer:
		return filepath.Join(ep.storagePath, "peers.d", fmt.Sprintf("%010x", id[0]))
	case zt.StateObjectNetworkConfig:
		return filepath.Join(ep.storagePath, "networks.d", fmt.Sprintf("%016x.conf", id[0]))
	default:
		return ""
	}
}
