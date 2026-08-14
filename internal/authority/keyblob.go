package authority

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
)

const (
	KeyBlobVersion = "imprint.authority.key-blob/1.0.0"
	AlgorithmSuite = "Ed25519+PKCS8-DER+AES-256-GCM+scrypt-N262144-r8-p1"
)

var lowercaseSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

type EncryptedKeyBlob struct {
	BlobVersion    string `json:"blob_version"`
	AlgorithmSuite string `json:"algorithm_suite"`
	SaltB64        string `json:"salt_b64"`
	NonceB64       string `json:"nonce_b64"`
	CiphertextB64  string `json:"ciphertext_b64"`
	AADSHA256      string `json:"aad_sha256"`
}

// ValidateEncryptedKeyBlob validates the closed Python-compatible envelope
// without decrypting, repairing, or normalizing it.
func ValidateEncryptedKeyBlob(raw []byte) (EncryptedKeyBlob, error) {
	var value EncryptedKeyBlob
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return EncryptedKeyBlob{}, errors.New("authority key blob is malformed")
	}
	if value.BlobVersion != KeyBlobVersion || value.AlgorithmSuite != AlgorithmSuite {
		return EncryptedKeyBlob{}, errors.New("authority key blob algorithm is unsupported")
	}
	if !lowercaseSHA256.MatchString(value.AADSHA256) {
		return EncryptedKeyBlob{}, errors.New("authority key blob binding digest is invalid")
	}
	salt, saltErr := canonicalBase64(value.SaltB64)
	nonce, nonceErr := canonicalBase64(value.NonceB64)
	ciphertext, ciphertextErr := canonicalBase64(value.CiphertextB64)
	if saltErr != nil || nonceErr != nil || ciphertextErr != nil {
		return EncryptedKeyBlob{}, errors.New("authority key blob encoding is invalid")
	}
	if len(salt) != 32 || len(nonce) != 12 || len(ciphertext) < 17 {
		return EncryptedKeyBlob{}, errors.New("authority key blob lengths are invalid")
	}
	canonical, err := canonicalContract(value)
	if err != nil || !bytes.Equal(append(canonical, '\n'), raw) {
		return EncryptedKeyBlob{}, errors.New("authority key blob is not canonical")
	}
	return value, nil
}

func PublicKeyFromBase64(value string) (ed25519.PublicKey, error) {
	raw, err := canonicalBase64(value)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("authority public key is invalid")
	}
	return ed25519.PublicKey(raw), nil
}

func canonicalBase64(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != value {
		return nil, errors.New("noncanonical base64")
	}
	return raw, nil
}
