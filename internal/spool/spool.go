// Package spool persists immutable raw capture before any derivation.
package spool

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/artemus/imprint/internal/canonical"
	"github.com/artemus/imprint/internal/capture"
	"github.com/artemus/imprint/internal/privateio"
)

func Write(root string, envelope capture.Envelope) (string, error) {
	if err := envelope.Validate(); err != nil {
		return "", err
	}
	uuid := envelope.InputEventID[strings.LastIndex(envelope.InputEventID, ":")+1:]
	path := filepath.Join(root, "spool", envelope.NodeID, uuid+".json")
	encoded, err := canonical.JSON(envelope)
	if err != nil {
		return "", err
	}
	encoded = append(encoded, '\n')
	if err = privateio.PublishNew(path, encoded); err == nil {
		return path, nil
	}
	if errors.Is(err, os.ErrExist) {
		existing, readErr := os.ReadFile(path)
		if readErr == nil && bytes.Equal(existing, encoded) {
			return path, nil
		}
		return "", errors.New("same spool event path contains different bytes")
	}
	return "", fmt.Errorf("publish spool event: %w", err)
}
