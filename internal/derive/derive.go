// Package derive manages immutable, non-authoritative proposal inputs.
package derive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/artemus/imprint/internal/canonical"
	"github.com/artemus/imprint/internal/privateio"
	"github.com/artemus/imprint/internal/proposal"
	"github.com/artemus/imprint/internal/store"
)

type Counts struct {
	Applied    int       `json:"applied"`
	Duplicates int       `json:"duplicates"`
	Rejected   int       `json:"rejected"`
	Skipped    int       `json:"skipped"`
	Failures   []Failure `json:"failures"`
}
type Failure struct {
	File      string `json:"file"`
	ErrorType string `json:"error_type"`
	Error     string `json:"error"`
}

func Submit(root string, value proposal.Proposal) (string, error) {
	if err := value.Validate(); err != nil {
		return "", err
	}
	uuid := value.ID[strings.LastIndex(value.ID, ":")+1:]
	encoded, err := canonical.JSON(value)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, "proposal-spool", "pending", uuid+".json")
	if err = publishImmutable(path, append(encoded, '\n')); err != nil {
		return "", err
	}
	return value.ID, nil
}

func Compile(ctx context.Context, root string, database *store.Store) (Counts, error) {
	counts := Counts{Failures: []Failure{}}
	pending := filepath.Join(root, "proposal-spool", "pending")
	if err := privateio.EnsureDir(pending); err != nil {
		return counts, err
	}
	entries, err := os.ReadDir(pending)
	if err != nil {
		return counts, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		source := filepath.Join(pending, entry.Name())
		if err := regular(source); err != nil {
			counts.reject(entry.Name(), "SafetyError", "proposal source is not a regular file")
			continue
		}
		raw, err := os.ReadFile(source)
		if err != nil {
			return counts, err
		}
		sourceHash := hash(raw)
		receipt := filepath.Join(root, "proposal-spool", "receipts", strings.TrimSuffix(entry.Name(), ".json")+".receipt.json")
		if _, err := os.Lstat(receipt); err == nil {
			current, checkErr := acceptedReceiptCurrent(ctx, receipt, sourceHash, raw, database)
			if checkErr != nil {
				counts.reject(entry.Name(), "SafetyError", checkErr.Error())
				continue
			}
			if current {
				counts.Skipped++
				continue
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return counts, err
		}
		value, decodeErr := proposal.Decode(raw)
		if decodeErr == nil && entry.Name() != value.ID[strings.LastIndex(value.ID, ":")+1:]+".json" {
			decodeErr = errors.New("proposal filename does not match proposal_id")
		}
		var receiptValue map[string]any
		if decodeErr == nil {
			result, applyErr := database.ApplyProposal(ctx, value)
			if applyErr == nil {
				if result == "applied" {
					counts.Applied++
				} else {
					counts.Duplicates++
				}
				receiptValue = map[string]any{"receipt_schema_version": "1.0.0", "proposal_id": value.ID, "source_sha256": sourceHash, "status": "accepted"}
			} else {
				decodeErr = applyErr
			}
		}
		if decodeErr != nil {
			counts.reject(entry.Name(), "ValidationError", decodeErr.Error())
			receiptValue = map[string]any{"receipt_schema_version": "1.0.0", "proposal_file": entry.Name(), "source_sha256": sourceHash, "status": "rejected", "error_type": "ValidationError", "error": decodeErr.Error()}
		}
		encoded, _ := canonical.JSON(receiptValue)
		if err = publishImmutable(receipt, append(encoded, '\n')); err != nil {
			return counts, err
		}
	}
	return counts, nil
}

func acceptedReceiptCurrent(ctx context.Context, path, sourceHash string, source []byte, database *store.Store) (bool, error) {
	if err := regular(path); err != nil {
		return false, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil || len(value) != 4 || value["receipt_schema_version"] != "1.0.0" || value["status"] != "accepted" || value["source_sha256"] != sourceHash {
		return false, errors.New("proposal receipt does not prove accepted canonical state")
	}
	parsed, err := proposal.Decode(source)
	if err != nil || value["proposal_id"] != parsed.ID {
		return false, errors.New("proposal receipt identity does not match its source")
	}
	payload, _ := canonical.JSON(parsed)
	knownHash, known, err := database.CurrentNodeHash(ctx, parsed.ID, "Proposal")
	return known && knownHash == hash(payload), err
}

func publishImmutable(path string, content []byte) error {
	err := privateio.PublishNew(path, content)
	if errors.Is(err, os.ErrExist) {
		if regular(path) != nil {
			return errors.New("immutable proposal target is not a regular file")
		}
		prior, readErr := os.ReadFile(path)
		if readErr == nil && bytes.Equal(prior, content) {
			return nil
		}
		return errors.New("immutable proposal identity contains different bytes")
	}
	return err
}

func regular(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("not a regular non-symlink file")
	}
	return nil
}

func (c *Counts) reject(file, kind, message string) {
	c.Rejected++
	c.Failures = append(c.Failures, Failure{file, kind, message})
}
func hash(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
