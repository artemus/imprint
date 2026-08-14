package authority

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func TestVerifyRecoveryBundleBindsManifestLedgerAndEncryptedKey(t *testing.T) {
	raw, bundle := recoveryBundleFixture(t)
	staleNow := time.Date(2026, 8, 16, 12, 30, 0, 0, time.UTC)
	verified, err := VerifyRecoveryBundle(raw, staleNow, false)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Chain.HeadSequence != 1 || len(verified.EncryptedRecoveryKey) == 0 || verified.Manifest.RecoveryKeyID == "" {
		t.Fatalf("verified=%#v", verified)
	}
	if _, err = VerifyRecoveryBundle(raw, staleNow, true); err == nil {
		t.Fatal("accepted stale required creation checkpoint")
	}

	tampered := bundle
	tampered.EncryptedRecoveryKeyB64 = base64.StdEncoding.EncodeToString([]byte("different encrypted key"))
	if _, err = VerifyRecoveryBundle(canonicalRecoveryBundle(t, tampered), staleNow, false); err == nil {
		t.Fatal("accepted encrypted recovery key with another digest")
	}
	tampered = bundle
	tampered.SignatureB64 = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if _, err = VerifyRecoveryBundle(canonicalRecoveryBundle(t, tampered), staleNow, false); err == nil {
		t.Fatal("accepted unsigned recovery manifest")
	}
}

func TestVerifyRecoveryBundleRejectsAnotherLedgerHead(t *testing.T) {
	_, bundle := recoveryBundleFixture(t)
	var manifest RecoveryManifest
	if err := json.Unmarshal(bundle.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.LedgerHeadSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	manifestRaw, _ := canonicalContract(manifest)
	bundle.Manifest = manifestRaw
	signature, err := recoverySignature(fixturePrivateKey(0), manifest)
	if err != nil {
		t.Fatal(err)
	}
	bundle.SignatureB64 = signature
	now := time.Date(2026, 8, 14, 12, 30, 0, 0, time.UTC)
	if _, err = VerifyRecoveryBundle(canonicalRecoveryBundle(t, bundle), now, false); err == nil {
		t.Fatal("accepted manifest naming another ledger head")
	}
}

func TestBuildRecoveryBundleMatchesCanonicalFixture(t *testing.T) {
	expected, bundle := recoveryBundleFixture(t)
	var manifest RecoveryManifest
	if err := json.Unmarshal(bundle.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	_, rows, err := decodePortableLedger(bundle.Ledger)
	if err != nil {
		t.Fatal(err)
	}
	history := make([]Checkpoint, len(manifest.CheckpointHistory))
	for index, raw := range manifest.CheckpointHistory {
		if history[index], err = decodeCheckpoint(raw); err != nil {
			t.Fatal(err)
		}
	}
	creation, err := decodeCheckpoint(manifest.CreationCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, _ := base64.StdEncoding.DecodeString(bundle.EncryptedRecoveryKeyB64)
	artifact, err := BuildRecoveryBundle(rows, encrypted, RecoveryBundleMetadata{
		CreatedAt: manifest.CreatedAt,
		Recovery: KeyCertificate{
			KeyID: manifest.RecoveryKeyID, PublicKeyB64: manifest.RecoveryPublicKeyB64,
			PublicKeyFingerprint: manifest.RecoveryPublicKeyFingerprint, InstallID: manifest.RecoveryInstallID,
		},
		SignerKeyID: manifest.SignerKeyID, CheckpointHistory: history,
		CreationCheckpoint: creation,
	}, fixturePrivateKey(0), time.Date(2026, 8, 14, 12, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(artifact.Bytes, expected) || artifact.BundleSHA256 == "" || artifact.Manifest.LedgerSHA256 != manifest.LedgerSHA256 {
		t.Fatalf("artifact=%#v", artifact)
	}
	if _, err := BuildRecoveryBundle(rows, encrypted, RecoveryBundleMetadata{
		CreatedAt: manifest.CreatedAt, Recovery: KeyCertificate{
			KeyID: manifest.RecoveryKeyID, PublicKeyB64: manifest.RecoveryPublicKeyB64,
			PublicKeyFingerprint: manifest.RecoveryPublicKeyFingerprint, InstallID: manifest.RecoveryInstallID,
		}, SignerKeyID: manifest.SignerKeyID, CheckpointHistory: history, CreationCheckpoint: creation,
	}, fixturePrivateKey(1), time.Date(2026, 8, 14, 12, 30, 0, 0, time.UTC)); err == nil {
		t.Fatal("built a recovery bundle with a mismatched signer")
	}
}

func recoveryBundleFixture(t *testing.T) ([]byte, recoveryBundle) {
	t.Helper()
	genesis, _ := signedGenesis(t)
	recoveryPrivate := fixturePrivateKey(255)
	recoveryPublic := recoveryPrivate.Public().(ed25519.PublicKey)
	recoveryDigest := sha256.Sum256(recoveryPublic)
	recoveryID := "urn:imprint:authority-key:" + hex.EncodeToString(recoveryDigest[:16])
	genesis.RecoveryBinding = &KeyCertificate{
		KeyID: recoveryID, PublicKeyB64: base64.StdEncoding.EncodeToString(recoveryPublic),
		PublicKeyFingerprint: "sha256:" + hex.EncodeToString(recoveryDigest[:]),
		InstallID:            "urn:imprint:recovery:fixture",
	}
	row := signGenesisEvent(t, genesis)
	chain, err := VerifyChain([]LedgerRow{row}, genesis.OperatorID, genesis.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := signedCheckpoint(t, chain, 1, genesis.KeyID, fixturePrivateKey(0))
	checkpointRaw, _ := canonicalContract(checkpoint)
	portable := []PortableLedgerRow{portableRow(row)}
	ledgerSHA, err := LedgerSHA256(portable)
	if err != nil {
		t.Fatal(err)
	}
	rowRaw, _ := canonicalContract(portable[0])
	encrypted := []byte("opaque encrypted recovery key fixture\n")
	manifest := RecoveryManifest{
		ManifestVersion: RecoveryManifestVersion, OperatorID: chain.OperatorID,
		StoreIdentity: chain.StoreIdentity, CreatedAt: "2026-08-14T12:10:00.000000Z",
		RecoveryKeyID: recoveryID, RecoveryPublicKeyB64: genesis.RecoveryBinding.PublicKeyB64,
		RecoveryPublicKeyFingerprint: genesis.RecoveryBinding.PublicKeyFingerprint,
		RecoveryInstallID:            genesis.RecoveryBinding.InstallID,
		LedgerSequence:               1, LedgerHeadSHA256: chain.HeadSHA256, LedgerSHA256: ledgerSHA,
		AuthorityLedgerGenesisSHA256: chain.GenesisSHA256,
		EncryptedRecoveryKeySHA256:   recoveryEncryptedDigest(encrypted),
		SignerKeyID:                  genesis.KeyID, SignerInstallID: genesis.InstallID,
		CheckpointHistory: []json.RawMessage{checkpointRaw}, CreationCheckpoint: checkpointRaw,
	}
	manifestRaw, _ := canonicalContract(manifest)
	signature, err := recoverySignature(fixturePrivateKey(0), manifest)
	if err != nil {
		t.Fatal(err)
	}
	bundle := recoveryBundle{
		BundleVersion: RecoveryBundleVersion, Manifest: manifestRaw,
		Ledger: []json.RawMessage{rowRaw}, EncryptedRecoveryKeyB64: base64.StdEncoding.EncodeToString(encrypted),
		SignatureB64: signature,
	}
	return canonicalRecoveryBundle(t, bundle), bundle
}

func canonicalRecoveryBundle(t *testing.T, bundle recoveryBundle) []byte {
	t.Helper()
	encoded, err := canonicalContract(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}
