package authority

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoveryPublicationJournalRetainsExternalBundleUntilExplicitClear(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	dataRoot := filepath.Join(root, "data")
	destination := filepath.Join(root, "offline", "recovery.json")
	raw, _ := recoveryBundleFixture(t)
	digest := sha256.Sum256(raw)
	journal, err := CreateRecoveryPublicationJournal(dataRoot, destination, "urn:imprint:authority-key:recovery", hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateRecoveryPublicationJournal(dataRoot, destination, journal.RecoveryKeyID, journal.LedgerHeadSHA256); !errors.Is(err, os.ErrExist) {
		t.Fatalf("duplicate journal err=%v", err)
	}
	stored, err := LoadRecoveryPublicationJournal(dataRoot)
	if err != nil || stored == nil || *stored != journal {
		t.Fatalf("stored=%#v err=%v", stored, err)
	}
	published, err := PublishRecoveryBundle(destination, RecoveryBundleArtifact{
		Bytes: raw, BundleSHA256: hex.EncodeToString(digest[:]),
	})
	if err != nil || published.Path != destination {
		t.Fatalf("published=%#v err=%v", published, err)
	}
	if err := ClearRecoveryPublicationJournal(dataRoot, journal); err != nil {
		t.Fatal(err)
	}
	if loaded, err := LoadRecoveryPublicationJournal(dataRoot); err != nil || loaded != nil {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}
	if _, err := os.Stat(destination); err != nil {
		t.Fatal("clearing journal removed retained bundle:", err)
	}
}

func TestRecoveryPublicationRejectsDestinationInsideDataRoot(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	dataRoot := filepath.Join(root, "data")
	if _, err := CreateRecoveryPublicationJournal(dataRoot, filepath.Join(dataRoot, "recovery.json"), "key", strings.Repeat("a", 64)); err == nil {
		t.Fatal("accepted recovery bundle inside ordinary data root")
	}
}
