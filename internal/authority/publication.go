package authority

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/uuid"

	"github.com/artemus/imprint/internal/privateio"
)

// PublishedKey is a verified key blob that has reached its final create-only
// path but whose database transaction may not yet have committed.
type PublishedKey struct {
	dataRoot string
	target   string
}

// PublishKeyBlob validates and durably publishes an enrollment key blob. The
// signed genesis event is the source of truth for its path, digest, size, and
// encryption AAD.
func PublishKeyBlob(dataRoot string, event GenesisEvent, blob []byte) (PublishedKey, error) {
	target, err := enrollmentKeyPath(dataRoot, event)
	if err != nil {
		return PublishedKey{}, err
	}
	validated, err := ValidateEncryptedKeyBlob(blob)
	if err != nil {
		return PublishedKey{}, err
	}
	aad, err := canonicalContract(KeyAAD{
		OperatorID: event.OperatorID, InstallID: event.InstallID,
		StoreIdentity: event.StoreIdentity, KeyID: event.KeyID,
		PublicKeyB64: event.PublicKeyB64, PublicKeyFingerprint: event.PublicKeyFingerprint,
		CreatedAt: event.CreatedAt, AlgorithmSuite: event.AlgorithmSuite,
		LedgerSequence: event.Sequence, EnrollmentNonce: event.EnrollmentNonce,
	})
	if err != nil {
		return PublishedKey{}, err
	}
	aadDigest := sha256.Sum256(aad)
	blobDigest := sha256.Sum256(blob)
	if validated.AlgorithmSuite != event.AlgorithmSuite || validated.AADSHA256 != hex.EncodeToString(aadDigest[:]) ||
		int64(len(blob)) != event.BlobSize || hex.EncodeToString(blobDigest[:]) != event.BlobSHA256 {
		return PublishedKey{}, errors.New("authority key blob binding is invalid")
	}
	if err := privateio.PublishNew(target, blob); err != nil {
		return PublishedKey{}, err
	}
	published := PublishedKey{dataRoot: filepath.Clean(dataRoot), target: target}
	if err := published.verify(event); err != nil {
		_, _ = published.Quarantine()
		return PublishedKey{}, err
	}
	return published, nil
}

// Quarantine removes a published blob from its active path after a failed
// database commit while retaining the bytes for diagnosis and recovery.
func (published PublishedKey) Quarantine() (string, error) {
	if published.target == "" || published.dataRoot == "" {
		return "", errors.New("authority key publication is invalid")
	}
	info, err := os.Lstat(published.target)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("published authority key is not a regular file")
	}
	quarantine := filepath.Join(published.dataRoot, "authority", "quarantine")
	if err := privateio.EnsureDir(quarantine); err != nil {
		return "", err
	}
	destination := filepath.Join(quarantine, "orphan-"+uuid.NewString()+".blob")
	if err := os.Rename(published.target, destination); err != nil {
		return "", fmt.Errorf("quarantine authority key: %w", err)
	}
	if err := syncDirectories(filepath.Dir(published.target), quarantine); err != nil {
		return "", err
	}
	return destination, nil
}

func (published PublishedKey) verify(event GenesisEvent) error {
	info, err := os.Lstat(published.target)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("published authority key is not a regular file")
	}
	raw, err := os.ReadFile(published.target)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	if int64(len(raw)) != event.BlobSize || hex.EncodeToString(digest[:]) != event.BlobSHA256 {
		return errors.New("published authority key failed verification")
	}
	return nil
}

func enrollmentKeyPath(dataRoot string, event GenesisEvent) (string, error) {
	if strings.TrimSpace(dataRoot) == "" || !strings.HasPrefix(event.PublicKeyFingerprint, "sha256:") || !lowercaseSHA256.MatchString(strings.TrimPrefix(event.PublicKeyFingerprint, "sha256:")) {
		return "", errors.New("authority key publication path is invalid")
	}
	portable := strings.ReplaceAll(event.BlobRelativePath, `\`, "/")
	expected := "authority/keys/" + strings.TrimPrefix(event.PublicKeyFingerprint, "sha256:") + ".blob"
	if !safeRelativeBlobPath(portable) || portable != expected {
		return "", errors.New("authority key publication path is invalid")
	}
	return filepath.Join(filepath.Clean(dataRoot), filepath.FromSlash(portable)), nil
}

func syncDirectories(paths ...string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	for _, item := range paths {
		directory, err := os.Open(item)
		if err != nil {
			return err
		}
		err = directory.Sync()
		closeErr := directory.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
