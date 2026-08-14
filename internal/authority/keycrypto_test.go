package authority

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestPrivateKeyBlobRoundTripAndAADBinding(t *testing.T) {
	privateKey := fixturePrivateKey(0)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	aad := KeyAAD{
		OperatorID: "urn:imprint:operator:fixture", InstallID: "urn:imprint:install:fixture",
		StoreIdentity: "urn:imprint:store:fixture", KeyID: "urn:imprint:authority-key:fixture",
		PublicKeyB64:         base64.StdEncoding.EncodeToString(publicKey),
		PublicKeyFingerprint: "sha256:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c",
		CreatedAt:            "2026-08-14T12:00:00.000000Z", AlgorithmSuite: AlgorithmSuite,
		LedgerSequence: 1, EnrollmentNonce: "fixture-nonce",
	}
	randomness := bytes.NewReader(bytes.Repeat([]byte{0x5a}, 44))
	raw, err := EncryptPrivateKey(privateKey, "correct horse battery", aad, randomness)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ValidateEncryptedKeyBlob(raw); err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptPrivateKey(raw, "correct horse battery", aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, privateKey) {
		t.Fatal("decrypted another private key")
	}
	if err := VerifyPublicBinding(decrypted, aad.PublicKeyB64); err != nil {
		t.Fatal(err)
	}
	tamperedAAD := aad
	tamperedAAD.LedgerSequence = 2
	if _, err = DecryptPrivateKey(raw, "correct horse battery", tamperedAAD); err == nil {
		t.Fatal("accepted key blob under another AAD binding")
	}
}

func TestGenerateKeyDerivesStableIdentityAndRejectsShortPassphrase(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	generated, err := GenerateKey(bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	if generated.KeyID != "urn:imprint:authority-key:56475aa75463474c0285df5dbf2bcab7" || generated.Fingerprint != "sha256:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c" {
		t.Fatalf("generated=%#v", generated)
	}
	aad := KeyAAD{AlgorithmSuite: AlgorithmSuite}
	if _, err = EncryptPrivateKey(generated.PrivateKey, "too short", aad, bytes.NewReader(make([]byte, 44))); err == nil {
		t.Fatal("accepted short authority passphrase")
	}
	wrongPublic := base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	if err = VerifyPublicBinding(generated.PrivateKey, wrongPublic); err == nil {
		t.Fatal("accepted another public key binding")
	}
}
