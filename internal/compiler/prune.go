package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/artemus/imprint/internal/canonical"
	"github.com/artemus/imprint/internal/capture"
	"github.com/artemus/imprint/internal/urn"
)

type PruneCounts struct {
	Deleted                 int `json:"deleted"`
	Retained                int `json:"retained"`
	AlreadyPruned           int `json:"already_pruned"`
	AcknowledgementsDeleted int `json:"acknowledgements_deleted"`
	QuarantineDeleted       int `json:"quarantine_deleted"`
	Invalid                 int `json:"invalid"`
}

type acknowledgement struct {
	SchemaVersion    string `json:"ack_schema_version"`
	InputEventID     string `json:"input_event_id"`
	NodeID           string `json:"node_id"`
	PayloadSHA256    string `json:"payload_sha256"`
	SourceFileSHA256 string `json:"source_file_sha256"`
	SourcePath       string `json:"source_path"`
	Committed        bool   `json:"committed"`
	CompilerResult   string `json:"compiler_result"`
	AcknowledgedAt   string `json:"acknowledged_at"`
}

// PruneAcknowledged removes only inputs whose exact committed bytes are proven
// by an old acknowledgement belonging to this producer.
func PruneAcknowledged(root, nodeID string, retentionDays int, clock time.Time) (PruneCounts, error) {
	var counts PruneCounts
	if retentionDays < 1 {
		return counts, errors.New("spool retention must be at least one day")
	}
	if !safeNodeID(nodeID) {
		return counts, errors.New("source node identity is unsafe")
	}
	if clock.Location() == nil {
		return counts, errors.New("retention clock must be timezone-aware")
	}
	threshold := clock.UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	ackRoot := filepath.Join(root, "runtime", "acknowledgements", nodeID)
	entries, err := os.ReadDir(ackRoot)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return counts, err
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(ackRoot, entry.Name())
		if err := pruneAcknowledgement(root, nodeID, path, threshold, &counts); err != nil {
			counts.Invalid++
		}
	}
	if err := pruneQuarantine(root, threshold, &counts); err != nil {
		return counts, err
	}
	return counts, nil
}

func pruneAcknowledgement(root, nodeID, path string, threshold time.Time, counts *PruneCounts) error {
	if err := regularFile(path); err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	var ack acknowledgement
	ackFields := []string{"ack_schema_version", "input_event_id", "node_id", "payload_sha256", "source_file_sha256", "source_path", "committed", "compiler_result", "acknowledged_at"}
	if json.Unmarshal(raw, &fields) != nil || !exactFields(fields, ackFields) || json.Unmarshal(raw, &ack) != nil || ack.SchemaVersion != "1.0.0" || !ack.Committed || ack.NodeID != nodeID {
		return errors.New("acknowledgement contract is invalid")
	}
	acknowledged, err := time.Parse(time.RFC3339Nano, ack.AcknowledgedAt)
	if err != nil {
		return errors.New("acknowledgement timestamp is invalid")
	}
	if urn.Require(ack.InputEventID, "event") != nil {
		return errors.New("acknowledgement event identity is invalid")
	}
	event := ack.InputEventID[strings.LastIndex(ack.InputEventID, ":")+1:]
	expected := "spool/" + nodeID + "/" + event + ".json"
	if ack.SourcePath != expected {
		return errors.New("acknowledgement source escapes its producer spool")
	}
	source := filepath.Join(root, filepath.FromSlash(ack.SourcePath))
	if _, err := os.Lstat(source); errors.Is(err, os.ErrNotExist) {
		if err = os.Remove(path); err != nil {
			return err
		}
		counts.AlreadyPruned++
		counts.AcknowledgementsDeleted++
		return nil
	} else if err != nil {
		return err
	}
	if err := regularFile(source); err != nil {
		return errors.New("acknowledgement source escapes its producer spool")
	}
	resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(source))
	if err != nil {
		return err
	}
	expectedParent, err := filepath.EvalSymlinks(filepath.Join(root, "spool", nodeID))
	if err != nil || resolvedParent != expectedParent {
		return errors.New("acknowledgement source escapes its producer spool")
	}
	sourceRaw, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	envelope, err := capture.Decode(sourceRaw)
	if err != nil || envelope.InputEventID != ack.InputEventID {
		return errors.New("acknowledgement event does not match source")
	}
	payload, err := canonical.JSON(envelope)
	if err != nil || digest(payload) != ack.PayloadSHA256 || digest(sourceRaw) != ack.SourceFileSHA256 {
		return errors.New("acknowledgement hash does not match source")
	}
	if acknowledged.UTC().After(threshold) {
		counts.Retained++
		return nil
	}
	if err := os.Remove(source); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	counts.Deleted++
	counts.AcknowledgementsDeleted++
	return nil
}

func pruneQuarantine(root string, threshold time.Time, counts *PruneCounts) error {
	directory := filepath.Join(root, "quarantine")
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		if err := pruneQuarantineReceipt(path, threshold, counts); err != nil {
			counts.Invalid++
		}
	}
	return nil
}

func pruneQuarantineReceipt(path string, threshold time.Time, counts *PruneCounts) error {
	if err := regularFile(path); err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil || value["quarantine_schema_version"] != "1.0.0" || value["content_included"] != false {
		return errors.New("quarantine receipt contract is invalid")
	}
	fields := []string{"quarantine_schema_version", "receipt_id", "error_type", "content_included"}
	if _, ok := value["recorded_at"]; ok {
		fields = append(fields, "recorded_at")
	}
	if !exactAnyFields(value, fields) {
		return errors.New("quarantine receipt contract is invalid")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	recorded := info.ModTime()
	if rawTime, ok := value["recorded_at"]; ok {
		text, ok := rawTime.(string)
		if !ok {
			return errors.New("quarantine receipt timestamp is invalid")
		}
		recorded, err = time.Parse(time.RFC3339Nano, text)
		if err != nil {
			return errors.New("quarantine receipt timestamp is invalid")
		}
	}
	if !recorded.UTC().After(threshold) {
		if err := os.Remove(path); err != nil {
			return err
		}
		counts.QuarantineDeleted++
	}
	return nil
}

func regularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("path is not a regular non-symlink file")
	}
	return nil
}

func safeNodeID(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func exactFields(value map[string]json.RawMessage, expected []string) bool {
	if len(value) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, ok := value[key]; !ok {
			return false
		}
	}
	return true
}

func exactAnyFields(value map[string]any, expected []string) bool {
	if len(value) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, ok := value[key]; !ok {
			return false
		}
	}
	return true
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
