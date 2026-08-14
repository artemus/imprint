package authority

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

const (
	RecoveryKeyBlobVersion = "imprint.authority.recovery-key/1.0.0"
	RecoveryAlgorithm      = "Ed25519+PKCS8-DER+AES-256-GCM+scrypt-N262144-r8-p1+recovery-v1"
	RecoveryWrapDomain     = "imprint-authority-recovery-wrap-v1"
)

type RecoveryKeyAAD struct {
	Domain                       string `json:"domain"`
	OperatorID                   string `json:"operator_id"`
	StoreIdentity                string `json:"store_identity"`
	RecoveryKeyID                string `json:"recovery_key_id"`
	RecoveryPublicKeyB64         string `json:"recovery_public_key_b64"`
	RecoveryPublicKeyFingerprint string `json:"recovery_public_key_fingerprint"`
	RecoveryInstallID            string `json:"recovery_install_id"`
	CreatedAt                    string `json:"created_at"`
	Algorithm                    string `json:"algorithm"`
}

type EncryptedRecoveryKey struct {
	RecoveryBlobVersion string `json:"recovery_blob_version"`
	Algorithm           string `json:"algorithm"`
	SaltB64             string `json:"salt_b64"`
	NonceB64            string `json:"nonce_b64"`
	CiphertextB64       string `json:"ciphertext_b64"`
	AADSHA256           string `json:"aad_sha256"`
}

var encryptedRecoveryKeyFields = []string{"recovery_blob_version", "algorithm", "salt_b64", "nonce_b64", "ciphertext_b64", "aad_sha256"}

func RecoveryAAD(manifest RecoveryManifest) RecoveryKeyAAD {
	return RecoveryKeyAAD{
		Domain: RecoveryWrapDomain, OperatorID: manifest.OperatorID,
		StoreIdentity: manifest.StoreIdentity, RecoveryKeyID: manifest.RecoveryKeyID,
		RecoveryPublicKeyB64:         manifest.RecoveryPublicKeyB64,
		RecoveryPublicKeyFingerprint: manifest.RecoveryPublicKeyFingerprint,
		RecoveryInstallID:            manifest.RecoveryInstallID, CreatedAt: manifest.CreatedAt,
		Algorithm: RecoveryAlgorithm,
	}
}

func EncryptRecoveryKey(privateKey ed25519.PrivateKey, passphrase string, manifest RecoveryManifest, random io.Reader) ([]byte, error) {
	aadBytes, err := canonicalContract(RecoveryAAD(manifest))
	if err != nil {
		return nil, err
	}
	authenticatedData := append([]byte(RecoveryWrapDomain+"\x00"), aadBytes...)
	salt, nonce, ciphertext, err := wrapEd25519(privateKey, passphrase, authenticatedData, random, recoveryCryptoMessages)
	if err != nil {
		return nil, err
	}
	aadDigest := sha256.Sum256(aadBytes)
	blob := EncryptedRecoveryKey{
		RecoveryBlobVersion: RecoveryKeyBlobVersion, Algorithm: RecoveryAlgorithm,
		SaltB64: base64.StdEncoding.EncodeToString(salt), NonceB64: base64.StdEncoding.EncodeToString(nonce),
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext), AADSHA256: hex.EncodeToString(aadDigest[:]),
	}
	encoded, err := canonicalContract(blob)
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func DecryptRecoveryKey(raw []byte, passphrase string, manifest RecoveryManifest) (ed25519.PrivateKey, error) {
	blob, err := ValidateEncryptedRecoveryKey(raw)
	if err != nil {
		return nil, err
	}
	aadBytes, err := canonicalContract(RecoveryAAD(manifest))
	if err != nil {
		return nil, err
	}
	aadDigest := sha256.Sum256(aadBytes)
	if blob.AADSHA256 != hex.EncodeToString(aadDigest[:]) {
		return nil, errors.New("recovery key binding is invalid")
	}
	salt, _ := canonicalBase64(blob.SaltB64)
	nonce, _ := canonicalBase64(blob.NonceB64)
	ciphertext, _ := canonicalBase64(blob.CiphertextB64)
	authenticatedData := append([]byte(RecoveryWrapDomain+"\x00"), aadBytes...)
	copyKey, err := unwrapEd25519(passphrase, salt, nonce, ciphertext, authenticatedData, recoveryCryptoMessages)
	if err != nil {
		return nil, err
	}
	if err := VerifyPublicBinding(copyKey, manifest.RecoveryPublicKeyB64); err != nil {
		clear(copyKey)
		return nil, errors.New("recovery private key does not match the manifest")
	}
	return copyKey, nil
}

func ValidateEncryptedRecoveryKey(raw []byte) (EncryptedRecoveryKey, error) {
	var blob EncryptedRecoveryKey
	if decodeExactObject(raw, &blob, encryptedRecoveryKeyFields) != nil {
		return EncryptedRecoveryKey{}, errors.New("recovery key blob is malformed")
	}
	canonical, err := canonicalContract(blob)
	if err != nil || !bytes.Equal(append(canonical, '\n'), raw) {
		return EncryptedRecoveryKey{}, errors.New("recovery key blob is malformed or non-canonical")
	}
	if blob.RecoveryBlobVersion != RecoveryKeyBlobVersion || blob.Algorithm != RecoveryAlgorithm {
		return EncryptedRecoveryKey{}, errors.New("recovery key algorithm is unsupported")
	}
	if !lowercaseSHA256.MatchString(blob.AADSHA256) {
		return EncryptedRecoveryKey{}, errors.New("recovery key binding is invalid")
	}
	salt, saltErr := canonicalBase64(blob.SaltB64)
	nonce, nonceErr := canonicalBase64(blob.NonceB64)
	ciphertext, ciphertextErr := canonicalBase64(blob.CiphertextB64)
	if saltErr != nil || nonceErr != nil || ciphertextErr != nil {
		return EncryptedRecoveryKey{}, errors.New("recovery key encoding is invalid")
	}
	if len(salt) != 32 || len(nonce) != 12 || len(ciphertext) < 17 {
		return EncryptedRecoveryKey{}, errors.New("recovery key lengths are invalid")
	}
	return blob, nil
}
