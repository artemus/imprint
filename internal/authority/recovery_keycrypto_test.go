package authority

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestRecoveryKeyBlobRoundTripAndDomainBinding(t *testing.T) {
	privateKey := fixturePrivateKey(255)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(publicKey)
	manifest := RecoveryManifest{
		OperatorID: "urn:imprint:operator:fixture", StoreIdentity: "urn:imprint:store:fixture",
		CreatedAt:                    "2026-08-14T12:00:00.000000Z",
		RecoveryKeyID:                "urn:imprint:authority-key:" + hex.EncodeToString(digest[:16]),
		RecoveryPublicKeyB64:         base64.StdEncoding.EncodeToString(publicKey),
		RecoveryPublicKeyFingerprint: "sha256:" + hex.EncodeToString(digest[:]),
		RecoveryInstallID:            "urn:imprint:recovery:fixture",
	}
	randomness := bytes.NewReader(bytes.Repeat([]byte{0xa5}, 44))
	raw, err := EncryptRecoveryKey(privateKey, "separate recovery passphrase", manifest, randomness)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ValidateEncryptedRecoveryKey(raw); err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptRecoveryKey(raw, "separate recovery passphrase", manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, privateKey) {
		t.Fatal("decrypted another recovery key")
	}
	tampered := manifest
	tampered.RecoveryInstallID = "urn:imprint:recovery:other"
	if _, err = DecryptRecoveryKey(raw, "separate recovery passphrase", tampered); err == nil {
		t.Fatal("accepted recovery key under another manifest binding")
	}
	if _, err = ValidateEncryptedRecoveryKey(raw[:len(raw)-1]); err == nil {
		t.Fatal("accepted recovery key blob without canonical newline")
	}
}
