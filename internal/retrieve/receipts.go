package retrieve

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/artemus/imprint/internal/canonical"
	"github.com/artemus/imprint/internal/privateio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var safeID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func ReceiptPaths(root, session, snapshot, scope string) (string, string, error) {
	if !safeID.MatchString(session) {
		return "", "", errors.New("unsafe session id")
	}
	snapshotRef := shortHash(snapshot, 24)
	suffix := "session-start"
	if scope != "" {
		if !safeID.MatchString(scope) {
			return "", "", errors.New("unsafe receipt scope")
		}
		suffix = "domain-" + scope
	}
	directory := filepath.Join(root, "receipts", session)
	final := filepath.Join(directory, snapshotRef+"-"+suffix+".json")
	return strings.TrimSuffix(final, ".json") + ".pending.json", final, nil
}
func Existing(root, session, snapshot, scope string) (map[string]any, bool, error) {
	pending, final, err := ReceiptPaths(root, session, snapshot, scope)
	if err != nil {
		return nil, false, err
	}
	if _, err = os.Stat(final); err == nil {
		return nil, true, nil
	}
	raw, err := os.ReadFile(pending)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	response, err := decodePrepared(raw)
	return response, false, err
}
func Prepare(root, session, snapshot, scope string, response map[string]any) (map[string]any, error) {
	pending, final, err := ReceiptPaths(root, session, snapshot, scope)
	if err != nil {
		return nil, err
	}
	if _, err = os.Stat(final); err == nil {
		return nil, os.ErrExist
	}
	canonicalResponse, err := canonical.JSON(response)
	if err != nil {
		return nil, err
	}
	envelope := map[string]any{"receipt_schema_version": "1.1.0", "response": response, "response_sha256": hashBytes(canonicalResponse)}
	raw, _ := canonical.JSON(envelope)
	err = privateio.PublishNew(pending, raw)
	if errors.Is(err, os.ErrExist) {
		existing, readErr := os.ReadFile(pending)
		if readErr != nil {
			return nil, readErr
		}
		return decodePrepared(existing)
	}
	if err != nil {
		return nil, err
	}
	return decodePrepared(raw)
}
func Commit(root, session, snapshot, scope string) (bool, error) {
	pending, final, err := ReceiptPaths(root, session, snapshot, scope)
	if err != nil {
		return false, err
	}
	if _, err = os.Stat(final); err == nil {
		return false, nil
	}
	raw, err := os.ReadFile(pending)
	if err != nil {
		return false, err
	}
	if _, err = decodePrepared(raw); err != nil {
		return false, err
	}
	err = privateio.PublishNew(final, raw)
	if errors.Is(err, os.ErrExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_ = os.Remove(pending)
	return true, nil
}
func decodePrepared(raw []byte) (map[string]any, error) {
	var envelope struct {
		Version  string         `json:"receipt_schema_version"`
		Response map[string]any `json:"response"`
		Hash     string         `json:"response_sha256"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Version != "1.1.0" {
		return nil, errors.New("prepared delivery receipt is corrupt")
	}
	encoded, _ := canonical.JSON(envelope.Response)
	if hashBytes(encoded) != envelope.Hash {
		return nil, errors.New("prepared delivery response hash mismatch")
	}
	payload, ok := envelope.Response["payload"].(string)
	if !ok {
		return nil, errors.New("prepared delivery response is invalid")
	}
	budget, ok := envelope.Response["budget_bytes"].(float64)
	if !ok || len([]byte(payload)) > int(budget) {
		return nil, errors.New("prepared delivery exceeds retrieval budget")
	}
	return envelope.Response, nil
}
func SafeSession(value string) string { return shortHash(value, 24) }
func shortHash(value string, length int) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:length]
}
func hashBytes(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
