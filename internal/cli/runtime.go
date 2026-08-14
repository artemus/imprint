package cli

import (
	"path/filepath"

	"github.com/artemus/imprint/internal/config"
	"github.com/artemus/imprint/internal/identity"
	"github.com/artemus/imprint/internal/paths"
	"github.com/artemus/imprint/internal/store"
)

type runtimeState struct {
	Config     config.Config
	Root       string
	OperatorID string
}

func loadRuntime(configPath string, withIdentity bool) (runtimeState, error) {
	value, err := config.Load(configPath)
	if err != nil {
		return runtimeState{}, err
	}
	root, err := paths.OperatorRoot(value)
	if err != nil {
		return runtimeState{}, err
	}
	state := runtimeState{Config: value, Root: root}
	if withIdentity {
		state.OperatorID, err = identity.LoadOrCreate(root)
	}
	return state, err
}

func (r runtimeState) openStore() (*store.Store, error) {
	return store.Open(filepath.Join(r.Root, "imprint.db"), r.OperatorID, r.Config.NodeID)
}
