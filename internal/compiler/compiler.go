// Package compiler is the sole spool-to-SQLite writer.
package compiler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/artemus/imprint/internal/canonical"
	"github.com/artemus/imprint/internal/capture"
	"github.com/artemus/imprint/internal/privateio"
	"github.com/artemus/imprint/internal/store"
)

type Counts struct {
	Captured    int `json:"captured"`
	Duplicate   int `json:"duplicate"`
	Quarantined int `json:"quarantined"`
}
type input struct {
	capturedAt, eventID, path string
	envelope                  capture.Envelope
}

func Compile(ctx context.Context, root string, database *store.Store) (counts Counts, returned error) {
	lock := filepath.Join(root, "compiler.lock")
	if err := privateio.EnsureDir(root); err != nil {
		return counts, err
	}
	if err := os.Mkdir(lock, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return counts, errors.New("compiler lock already held; refusing a second writer")
		}
		return counts, err
	}
	defer func() { _ = os.Remove(filepath.Join(lock, "owner.json")); _ = os.Remove(lock) }()
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return counts, err
	}
	owner := map[string]any{"lock_schema_version": "1.0.0", "nonce": hex.EncodeToString(nonceBytes), "pid": os.Getpid(), "host": hostname(), "created_at": now(), "heartbeat_at": now()}
	ownerJSON, _ := canonical.JSON(owner)
	if err := privateio.PublishNew(filepath.Join(lock, "owner.json"), append(ownerJSON, '\n')); err != nil {
		return counts, err
	}
	paths, err := filepath.Glob(filepath.Join(root, "spool", "*", "*.json"))
	if err != nil {
		return counts, err
	}
	items := make([]input, 0, len(paths))
	for _, path := range paths {
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return counts, readErr
		}
		envelope, decodeErr := capture.Decode(raw)
		if decodeErr != nil {
			if err = quarantine(root, path); err != nil {
				return counts, err
			}
			counts.Quarantined++
			continue
		}
		committed, checkErr := acknowledged(root, path, envelope)
		if checkErr != nil {
			return counts, checkErr
		}
		if committed {
			continue
		}
		items = append(items, input{envelope.CapturedAt, envelope.InputEventID, path, envelope})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].capturedAt != items[j].capturedAt {
			return items[i].capturedAt < items[j].capturedAt
		}
		return items[i].eventID < items[j].eventID
	})
	for _, item := range items {
		relative, err := filepath.Rel(root, item.path)
		if err != nil {
			return counts, err
		}
		result, applyErr := database.ApplyCapture(ctx, item.envelope, filepath.ToSlash(relative))
		if applyErr != nil {
			if err = quarantine(root, item.path); err != nil {
				return counts, err
			}
			counts.Quarantined++
			continue
		}
		if err = writeAcknowledgement(root, item.path, item.envelope, result); err != nil {
			return counts, err
		}
		if result == "captured" {
			counts.Captured++
		} else {
			counts.Duplicate++
		}
	}
	return counts, nil
}

func acknowledged(root, path string, envelope capture.Envelope) (bool, error) {
	ackPath := ackPath(root, envelope)
	raw, err := os.ReadFile(ackPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var ack map[string]any
	if json.Unmarshal(raw, &ack) != nil {
		return false, errors.New("acknowledgement is corrupt")
	}
	relative, _ := filepath.Rel(root, path)
	payload, _ := canonical.JSON(envelope)
	source, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	return ack["ack_schema_version"] == "1.0.0" && ack["input_event_id"] == envelope.InputEventID && ack["node_id"] == envelope.NodeID && ack["payload_sha256"] == hash(payload) && ack["source_file_sha256"] == hash(source) && ack["source_path"] == filepath.ToSlash(relative) && ack["committed"] == true, nil
}

func writeAcknowledgement(root, path string, envelope capture.Envelope, result string) error {
	target := ackPath(root, envelope)
	relative, _ := filepath.Rel(root, path)
	payload, _ := canonical.JSON(envelope)
	source, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	body := map[string]any{"ack_schema_version": "1.0.0", "input_event_id": envelope.InputEventID, "node_id": envelope.NodeID, "payload_sha256": hash(payload), "source_file_sha256": hash(source), "source_path": filepath.ToSlash(relative), "committed": true, "compiler_result": result, "acknowledged_at": now()}
	encoded, _ := canonical.JSON(body)
	err = privateio.PublishNew(target, append(encoded, '\n'))
	if errors.Is(err, os.ErrExist) {
		matched, checkErr := acknowledged(root, path, envelope)
		if checkErr != nil {
			return checkErr
		}
		if matched {
			return nil
		}
		return errors.New("acknowledgement identity conflicts with committed input")
	}
	return err
}
func quarantine(root, path string) error {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}
	receiptID := hash([]byte(filepath.ToSlash(relative)))
	target := filepath.Join(root, "quarantine", receiptID+".json")
	body := map[string]any{"quarantine_schema_version": "1.0.0", "receipt_id": receiptID, "error_type": "ValidationError", "content_included": false, "recorded_at": now()}
	encoded, _ := canonical.JSON(body)
	err = privateio.PublishNew(target, append(encoded, '\n'))
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	return err
}
func ackPath(root string, envelope capture.Envelope) string {
	uuid := envelope.InputEventID[strings.LastIndex(envelope.InputEventID, ":")+1:]
	return filepath.Join(root, "runtime", "acknowledgements", envelope.NodeID, uuid+".json")
}
func hash(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
func now() string              { return time.Now().UTC().Format(time.RFC3339Nano) }
func hostname() string {
	value, err := os.Hostname()
	if err != nil || strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}
