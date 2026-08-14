// Package identity owns the installation-local opaque operator identity.
package identity

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/artemus/imprint/internal/canonical"
	"github.com/artemus/imprint/internal/privateio"
	"github.com/artemus/imprint/internal/urn"
)

type file struct {
	Version    string `json:"identity_schema_version"`
	OperatorID string `json:"operator_id"`
}

func LoadOrCreate(root string) (string, error) {
	path := filepath.Join(root, "identity.json")
	for attempts := 0; attempts < 2; attempts++ {
		raw, err := os.ReadFile(path)
		if err == nil {
			var value file
			decoderErr := json.Unmarshal(raw, &value)
			if decoderErr != nil {
				return "", errors.New("operator identity is corrupt")
			}
			if value.Version != "1.0.0" || urn.Require(value.OperatorID, "operator") != nil {
				return "", errors.New("operator identity is corrupt")
			}
			return value.OperatorID, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		id, err := urn.New("operator")
		if err != nil {
			return "", err
		}
		encoded, err := canonical.JSON(file{Version: "1.0.0", OperatorID: id})
		if err != nil {
			return "", err
		}
		encoded = append(encoded, '\n')
		if err = privateio.PublishNew(path, encoded); err == nil {
			return id, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
	return "", errors.New("operator identity publication raced repeatedly")
}
