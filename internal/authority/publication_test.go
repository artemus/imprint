package authority

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishKeyBlobVerifiesBindingAndQuarantinesRollback(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	event, _ := signedGenesis(t)
	event.BlobRelativePath = "authority/keys/" + stringsTrimSHA256(event.PublicKeyFingerprint) + ".blob"
	blob := enrollmentBlob(t, event)
	digest := sha256.Sum256(blob)
	event.BlobSHA256, event.BlobSize = hex.EncodeToString(digest[:]), int64(len(blob))
	published, err := PublishKeyBlob(root, event, blob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublishKeyBlob(root, event, blob); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second publication err=%v", err)
	}
	quarantined, err := published.Quarantine()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, event.BlobRelativePath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active key remains: %v", err)
	}
	if raw, err := os.ReadFile(quarantined); err != nil || string(raw) != string(blob) {
		t.Fatalf("quarantine err=%v content=%q", err, raw)
	}
}

func TestPublishKeyBlobRejectsWrongAADAndPath(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	event, _ := signedGenesis(t)
	event.BlobRelativePath = "authority/keys/" + stringsTrimSHA256(event.PublicKeyFingerprint) + ".blob"
	blob := enrollmentBlob(t, event)
	digest := sha256.Sum256(blob)
	event.BlobSHA256, event.BlobSize = hex.EncodeToString(digest[:]), int64(len(blob))
	tampered := event
	tampered.OperatorID = "urn:imprint:operator:other"
	if _, err := PublishKeyBlob(root, tampered, blob); err == nil {
		t.Fatal("accepted a blob bound to different enrollment metadata")
	}
	tampered = event
	tampered.BlobRelativePath = "authority/keys/../escaped.blob"
	if _, err := PublishKeyBlob(root, tampered, blob); err == nil {
		t.Fatal("accepted an unsafe enrollment key path")
	}
	tampered = event
	tampered.PublicKeyFingerprint = stringsTrimSHA256(event.PublicKeyFingerprint)
	if _, err := PublishKeyBlob(root, tampered, blob); err == nil {
		t.Fatal("accepted a fingerprint without its digest scheme")
	}
}

func enrollmentBlob(t *testing.T, event GenesisEvent) []byte {
	t.Helper()
	aad, err := canonicalContract(KeyAAD{
		OperatorID: event.OperatorID, InstallID: event.InstallID,
		StoreIdentity: event.StoreIdentity, KeyID: event.KeyID,
		PublicKeyB64: event.PublicKeyB64, PublicKeyFingerprint: event.PublicKeyFingerprint,
		CreatedAt: event.CreatedAt, AlgorithmSuite: event.AlgorithmSuite,
		LedgerSequence: event.Sequence, EnrollmentNonce: event.EnrollmentNonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(aad)
	encoded, err := canonicalContract(EncryptedKeyBlob{
		BlobVersion: KeyBlobVersion, AlgorithmSuite: AlgorithmSuite,
		SaltB64:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		NonceB64:      "AAAAAAAAAAAAAAAA",
		CiphertextB64: "AAAAAAAAAAAAAAAAAAAAAAAA",
		AADSHA256:     hex.EncodeToString(digest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

func stringsTrimSHA256(value string) string {
	return value[len("sha256:"):]
}
