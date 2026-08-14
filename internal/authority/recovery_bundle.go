package authority

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

const (
	RecoveryBundleVersion   = "imprint.authority.recovery-bundle/1.0.0"
	RecoveryManifestVersion = "imprint.authority.recovery-manifest/1.1.0"
	RecoveryManifestDomain  = "imprint-authority-recovery-manifest-v1"
)

type RecoveryManifest struct {
	ManifestVersion              string            `json:"manifest_version"`
	OperatorID                   string            `json:"operator_id"`
	StoreIdentity                string            `json:"store_identity"`
	CreatedAt                    string            `json:"created_at"`
	RecoveryKeyID                string            `json:"recovery_key_id"`
	RecoveryPublicKeyB64         string            `json:"recovery_public_key_b64"`
	RecoveryPublicKeyFingerprint string            `json:"recovery_public_key_fingerprint"`
	RecoveryInstallID            string            `json:"recovery_install_id"`
	LedgerSequence               int64             `json:"ledger_sequence"`
	LedgerHeadSHA256             string            `json:"ledger_head_sha256"`
	LedgerSHA256                 string            `json:"ledger_sha256"`
	AuthorityLedgerGenesisSHA256 string            `json:"authority_ledger_genesis_sha256"`
	EncryptedRecoveryKeySHA256   string            `json:"encrypted_recovery_key_sha256"`
	SignerKeyID                  string            `json:"signer_key_id"`
	SignerInstallID              string            `json:"signer_install_id"`
	CheckpointHistory            []json.RawMessage `json:"checkpoint_history"`
	CreationCheckpoint           json.RawMessage   `json:"creation_checkpoint"`
}

type recoveryBundle struct {
	BundleVersion           string            `json:"bundle_version"`
	Manifest                json.RawMessage   `json:"manifest"`
	Ledger                  []json.RawMessage `json:"ledger"`
	EncryptedRecoveryKeyB64 string            `json:"encrypted_recovery_key_b64"`
	SignatureB64            string            `json:"signature_b64"`
}

type VerifiedRecoveryBundle struct {
	Manifest             RecoveryManifest
	Ledger               []PortableLedgerRow
	EncryptedRecoveryKey []byte
	Chain                VerifiedChain
}

var recoveryBundleFields = []string{"bundle_version", "manifest", "ledger", "encrypted_recovery_key_b64", "signature_b64"}
var recoveryManifestFields = []string{"manifest_version", "operator_id", "store_identity", "created_at", "recovery_key_id", "recovery_public_key_b64", "recovery_public_key_fingerprint", "recovery_install_id", "ledger_sequence", "ledger_head_sha256", "ledger_sha256", "authority_ledger_genesis_sha256", "encrypted_recovery_key_sha256", "signer_key_id", "signer_install_id", "checkpoint_history", "creation_checkpoint"}

// VerifyRecoveryBundle verifies the canonical signed artifact without exposing
// or decrypting its embedded private key.
func VerifyRecoveryBundle(raw []byte, now time.Time, requireFreshCheckpoint bool) (VerifiedRecoveryBundle, error) {
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return VerifiedRecoveryBundle{}, errors.New("recovery bundle is not canonical")
	}
	body := raw[:len(raw)-1]
	var bundle recoveryBundle
	if decodeExactObject(body, &bundle, recoveryBundleFields) != nil || bundle.BundleVersion != RecoveryBundleVersion {
		return VerifiedRecoveryBundle{}, errors.New("recovery bundle has unknown fields or version")
	}
	canonical, err := canonicalContract(bundle)
	if err != nil || !bytes.Equal(canonical, body) {
		return VerifiedRecoveryBundle{}, errors.New("recovery bundle is not canonical")
	}
	var manifest RecoveryManifest
	if decodeExactObject(bundle.Manifest, &manifest, recoveryManifestFields) != nil {
		return VerifiedRecoveryBundle{}, errors.New("recovery manifest or ledger is malformed")
	}
	if manifest.ManifestVersion != RecoveryManifestVersion {
		return VerifiedRecoveryBundle{}, errors.New("recovery manifest ledger digest mismatch")
	}
	portableRows, rows, err := decodePortableLedger(bundle.Ledger)
	if err != nil {
		return VerifiedRecoveryBundle{}, err
	}
	ledgerSHA, err := rawLedgerSHA256(bundle.Ledger)
	if err != nil || ledgerSHA != manifest.LedgerSHA256 {
		return VerifiedRecoveryBundle{}, errors.New("recovery manifest ledger digest mismatch")
	}
	if len(manifest.CheckpointHistory) == 0 {
		return VerifiedRecoveryBundle{}, errors.New("recovery manifest checkpoint history is absent or inconsistent")
	}
	latest, latestErr := canonicalContract(json.RawMessage(manifest.CheckpointHistory[len(manifest.CheckpointHistory)-1]))
	creation, creationErr := canonicalContract(json.RawMessage(manifest.CreationCheckpoint))
	if latestErr != nil || creationErr != nil || !bytes.Equal(latest, creation) {
		return VerifiedRecoveryBundle{}, errors.New("recovery manifest checkpoint history is absent or inconsistent")
	}
	encrypted, err := canonicalBase64(bundle.EncryptedRecoveryKeyB64)
	if err != nil {
		return VerifiedRecoveryBundle{}, errors.New("recovery key encoding is invalid")
	}
	encryptedDigest := sha256.Sum256(encrypted)
	if hex.EncodeToString(encryptedDigest[:]) != manifest.EncryptedRecoveryKeySHA256 {
		return VerifiedRecoveryBundle{}, errors.New("recovery encrypted-key digest mismatch")
	}
	chain, err := VerifyChain(rows, manifest.OperatorID, manifest.StoreIdentity)
	if err != nil {
		return VerifiedRecoveryBundle{}, err
	}
	if _, err := verifyCheckpointHistory(chain, manifest.CheckpointHistory, nil, now, false); err != nil {
		return VerifiedRecoveryBundle{}, err
	}
	if requireFreshCheckpoint {
		if _, err := VerifyCheckpoint(chain, manifest.CreationCheckpoint, now, MaxCheckpointAge, true); err != nil {
			return VerifiedRecoveryBundle{}, err
		}
	}
	if chain.HeadSequence != manifest.LedgerSequence || chain.HeadSHA256 != manifest.LedgerHeadSHA256 {
		return VerifiedRecoveryBundle{}, errors.New("recovery manifest names another ledger head")
	}
	if chain.GenesisSHA256 != manifest.AuthorityLedgerGenesisSHA256 {
		return VerifiedRecoveryBundle{}, errors.New("recovery manifest genesis binding mismatch")
	}
	signer, signerExists := chain.Keys[manifest.SignerKeyID]
	recovery, recoveryExists := chain.Keys[manifest.RecoveryKeyID]
	if !signerExists || signer.Status != "active" || signer.Kind != "installation" || signer.InstallID != manifest.SignerInstallID {
		return VerifiedRecoveryBundle{}, errors.New("recovery manifest signer is not active and paired")
	}
	if !recoveryExists || recovery.Status != "active" || recovery.Kind != "recovery" {
		return VerifiedRecoveryBundle{}, errors.New("recovery key is absent or inactive")
	}
	manifestCanonical, err := canonicalContract(manifest)
	signature, signatureErr := canonicalBase64(bundle.SignatureB64)
	publicKey, publicKeyErr := PublicKeyFromBase64(signer.PublicKeyB64)
	if err != nil || signatureErr != nil || publicKeyErr != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, append([]byte(RecoveryManifestDomain+"\x00"), manifestCanonical...), signature) {
		return VerifiedRecoveryBundle{}, errors.New("recovery manifest signature is invalid")
	}
	return VerifiedRecoveryBundle{Manifest: manifest, Ledger: portableRows, EncryptedRecoveryKey: encrypted, Chain: chain}, nil
}

func recoveryEncryptedDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func recoverySignature(privateKey ed25519.PrivateKey, manifest RecoveryManifest) (string, error) {
	encoded, err := canonicalContract(manifest)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, append([]byte(RecoveryManifestDomain+"\x00"), encoded...))), nil
}
