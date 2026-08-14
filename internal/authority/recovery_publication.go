package authority

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/artemus/imprint/internal/privateio"
)

const RecoveryPublicationJournalVersion = "imprint.authority.recovery-publication/1.0.0"

type RecoveryPublicationJournal struct {
	JournalVersion   string `json:"journal_version"`
	OperationID      string `json:"operation_id"`
	Destination      string `json:"destination"`
	RecoveryKeyID    string `json:"recovery_key_id"`
	LedgerHeadSHA256 string `json:"ledger_head_sha256"`
	State            string `json:"state"`
}

type PublishedRecoveryBundle struct {
	Path         string
	Manifest     RecoveryManifest
	BundleSHA256 string
}

var recoveryPublicationJournalFields = []string{"journal_version", "operation_id", "destination", "recovery_key_id", "ledger_head_sha256", "state"}

func CanonicalRecoveryPublicationJournal(journal RecoveryPublicationJournal) ([]byte, error) {
	return canonicalContract(journal)
}

func CreateRecoveryPublicationJournal(dataRoot, destination, recoveryKeyID, ledgerHeadSHA256 string) (RecoveryPublicationJournal, error) {
	root := filepath.Clean(dataRoot)
	absoluteDestination, err := filepath.Abs(destination)
	if strings.TrimSpace(dataRoot) == "" || !filepath.IsAbs(root) || err != nil || strings.TrimSpace(recoveryKeyID) == "" || !lowercaseSHA256.MatchString(ledgerHeadSHA256) {
		return RecoveryPublicationJournal{}, errors.New("recovery publication journal is invalid")
	}
	relative, err := filepath.Rel(root, absoluteDestination)
	if err == nil && (relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		return RecoveryPublicationJournal{}, errors.New("recovery bundle must be stored outside the ordinary data root")
	}
	journal := RecoveryPublicationJournal{
		JournalVersion: RecoveryPublicationJournalVersion,
		OperationID:    "urn:imprint:recovery-publication:" + uuid.NewString(),
		Destination:    absoluteDestination, RecoveryKeyID: recoveryKeyID,
		LedgerHeadSHA256: ledgerHeadSHA256, State: "prepared-before-external-publication",
	}
	encoded, err := canonicalContract(journal)
	if err != nil {
		return RecoveryPublicationJournal{}, err
	}
	if err := privateio.PublishNew(recoveryPublicationJournalPath(root), append(encoded, '\n')); err != nil {
		return RecoveryPublicationJournal{}, err
	}
	return journal, nil
}

func LoadRecoveryPublicationJournal(dataRoot string) (*RecoveryPublicationJournal, error) {
	path := recoveryPublicationJournalPath(filepath.Clean(dataRoot))
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("interrupted recovery publication journal must be a regular non-symlink file")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return nil, errors.New("interrupted recovery publication journal is malformed")
	}
	var journal RecoveryPublicationJournal
	body := raw[:len(raw)-1]
	if decodeExactObject(body, &journal, recoveryPublicationJournalFields) != nil {
		return nil, errors.New("interrupted recovery publication journal is malformed")
	}
	canonical, canonicalErr := canonicalContract(journal)
	if canonicalErr != nil || !bytes.Equal(canonical, body) || journal.JournalVersion != RecoveryPublicationJournalVersion ||
		journal.State != "prepared-before-external-publication" || journal.OperationID == "" || journal.Destination == "" || journal.RecoveryKeyID == "" || !lowercaseSHA256.MatchString(journal.LedgerHeadSHA256) {
		return nil, errors.New("interrupted recovery publication journal is malformed")
	}
	return &journal, nil
}

func PublishRecoveryBundle(destination string, artifact RecoveryBundleArtifact) (PublishedRecoveryBundle, error) {
	absolute, err := filepath.Abs(destination)
	if err != nil || len(artifact.Bytes) == 0 || !lowercaseSHA256.MatchString(artifact.BundleSHA256) {
		return PublishedRecoveryBundle{}, errors.New("recovery bundle publication is invalid")
	}
	digest := sha256.Sum256(artifact.Bytes)
	if hex.EncodeToString(digest[:]) != artifact.BundleSHA256 {
		return PublishedRecoveryBundle{}, errors.New("recovery bundle publication digest mismatch")
	}
	verified, err := VerifyRecoveryBundle(artifact.Bytes, time.Now().UTC(), false)
	if err != nil {
		return PublishedRecoveryBundle{}, err
	}
	if err := privateio.PublishNew(absolute, artifact.Bytes); err != nil {
		return PublishedRecoveryBundle{}, err
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return PublishedRecoveryBundle{}, errors.New("published recovery bundle is not a regular file")
	}
	raw, err := os.ReadFile(absolute)
	if err != nil || !bytes.Equal(raw, artifact.Bytes) {
		return PublishedRecoveryBundle{}, errors.New("published recovery bundle failed verification")
	}
	return PublishedRecoveryBundle{Path: absolute, Manifest: verified.Manifest, BundleSHA256: artifact.BundleSHA256}, nil
}

func ClearRecoveryPublicationJournal(dataRoot string, expected RecoveryPublicationJournal) error {
	stored, err := LoadRecoveryPublicationJournal(dataRoot)
	if err != nil {
		return err
	}
	if stored == nil || *stored != expected {
		return errors.New("recovery publication journal changed before completion")
	}
	path := recoveryPublicationJournalPath(filepath.Clean(dataRoot))
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectories(filepath.Dir(path))
}

func recoveryPublicationJournalPath(dataRoot string) string {
	return filepath.Join(dataRoot, "authority", "recovery-publication.journal")
}
