package authority

import (
	"encoding/base64"
	"testing"
)

func TestEncryptedKeyBlobValidationIsClosedAndCanonical(t *testing.T) {
	value := EncryptedKeyBlob{
		BlobVersion: KeyBlobVersion, AlgorithmSuite: AlgorithmSuite,
		SaltB64:       base64.StdEncoding.EncodeToString(make([]byte, 32)),
		NonceB64:      base64.StdEncoding.EncodeToString(make([]byte, 12)),
		CiphertextB64: base64.StdEncoding.EncodeToString(make([]byte, 17)),
		AADSHA256:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	encoded, err := canonicalContract(value)
	if err != nil {
		t.Fatal(err)
	}
	raw := append(encoded, '\n')
	if _, err = ValidateEncryptedKeyBlob(raw); err != nil {
		t.Fatal(err)
	}
	if _, err = ValidateEncryptedKeyBlob(encoded); err == nil {
		t.Fatal("accepted blob without canonical trailing newline")
	}
	unknown := append([]byte(`{"unknown":true,`), encoded[1:]...)
	unknown = append(unknown, '\n')
	if _, err = ValidateEncryptedKeyBlob(unknown); err == nil {
		t.Fatal("accepted unknown blob field")
	}
}

func TestPublicKeyRequiresCanonicalRawEd25519Bytes(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if key, err := PublicKeyFromBase64(encoded); err != nil || len(key) != 32 {
		t.Fatalf("key=%x err=%v", key, err)
	}
	if _, err := PublicKeyFromBase64(base64.StdEncoding.EncodeToString(make([]byte, 31))); err == nil {
		t.Fatal("accepted short Ed25519 public key")
	}
}
