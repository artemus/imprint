package authority

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"
)

const (
	ScryptN = 1 << 18
	ScryptR = 8
	ScryptP = 1
)

type GeneratedKey struct {
	PrivateKey  ed25519.PrivateKey
	PublicKey   ed25519.PublicKey
	KeyID       string
	Fingerprint string
}

type KeyAAD struct {
	OperatorID           string `json:"operator_id"`
	InstallID            string `json:"install_id"`
	StoreIdentity        string `json:"store_identity"`
	KeyID                string `json:"key_id"`
	PublicKeyB64         string `json:"public_key_b64"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	CreatedAt            string `json:"created_at"`
	AlgorithmSuite       string `json:"algorithm_suite"`
	LedgerSequence       int64  `json:"ledger_sequence"`
	EnrollmentNonce      string `json:"enrollment_nonce"`
}

func GenerateKey(random io.Reader) (GeneratedKey, error) {
	if random == nil {
		random = rand.Reader
	}
	publicKey, privateKey, err := ed25519.GenerateKey(random)
	if err != nil {
		return GeneratedKey{}, errors.New("authority key generation failed")
	}
	digest := sha256.Sum256(publicKey)
	digestText := hex.EncodeToString(digest[:])
	return GeneratedKey{
		PrivateKey: privateKey, PublicKey: publicKey,
		KeyID:       "urn:imprint:authority-key:" + digestText[:32],
		Fingerprint: "sha256:" + digestText,
	}, nil
}

func EncryptPrivateKey(privateKey ed25519.PrivateKey, passphrase string, aad KeyAAD, random io.Reader) ([]byte, error) {
	aadBytes, err := canonicalContract(aad)
	if err != nil {
		return nil, err
	}
	salt, nonce, ciphertext, err := wrapEd25519(privateKey, passphrase, aadBytes, random, authorityCryptoMessages)
	if err != nil {
		return nil, err
	}
	aadDigest := sha256.Sum256(aadBytes)
	blob := EncryptedKeyBlob{
		BlobVersion: KeyBlobVersion, AlgorithmSuite: AlgorithmSuite,
		SaltB64:       base64.StdEncoding.EncodeToString(salt),
		NonceB64:      base64.StdEncoding.EncodeToString(nonce),
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
		AADSHA256:     hex.EncodeToString(aadDigest[:]),
	}
	encoded, err := canonicalContract(blob)
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func DecryptPrivateKey(raw []byte, passphrase string, aad KeyAAD) (ed25519.PrivateKey, error) {
	blob, err := ValidateEncryptedKeyBlob(raw)
	if err != nil {
		return nil, err
	}
	aadBytes, err := canonicalContract(aad)
	if err != nil {
		return nil, err
	}
	aadDigest := sha256.Sum256(aadBytes)
	if blob.AADSHA256 != hex.EncodeToString(aadDigest[:]) {
		return nil, errors.New("authority key blob binding is invalid")
	}
	salt, _ := canonicalBase64(blob.SaltB64)
	nonce, _ := canonicalBase64(blob.NonceB64)
	ciphertext, _ := canonicalBase64(blob.CiphertextB64)
	return unwrapEd25519(passphrase, salt, nonce, ciphertext, aadBytes, authorityCryptoMessages)
}

func VerifyPublicBinding(privateKey ed25519.PrivateKey, publicKeyB64 string) error {
	expected, err := PublicKeyFromBase64(publicKeyB64)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize || !privateKey.Public().(ed25519.PublicKey).Equal(expected) {
		return errors.New("authority private key does not match public binding")
	}
	return nil
}

func deriveScryptKey(passphrase string, salt []byte, shortMessage, failureMessage string) ([]byte, error) {
	if utf8.RuneCountInString(passphrase) < 12 {
		return nil, errors.New(shortMessage)
	}
	derived, err := scrypt.Key([]byte(passphrase), salt, ScryptN, ScryptR, ScryptP, 32)
	if err != nil {
		return nil, errors.New(failureMessage)
	}
	return derived, nil
}

type cryptoMessages struct {
	invalidPrivate, nonEd25519, randomness      string
	shortPassphrase, derivation, authentication string
}

var authorityCryptoMessages = cryptoMessages{
	invalidPrivate: "authority private key is invalid", nonEd25519: "authority private key is not Ed25519",
	randomness:      "authority key encryption randomness failed",
	shortPassphrase: "authority passphrase must contain at least 12 characters",
	derivation:      "authority key derivation failed", authentication: "authority passphrase or key blob is invalid",
}

var recoveryCryptoMessages = cryptoMessages{
	invalidPrivate: "recovery private key is invalid", nonEd25519: "recovery private key is not Ed25519",
	randomness:      "recovery key encryption randomness failed",
	shortPassphrase: "recovery passphrase must contain at least 12 characters",
	derivation:      "recovery key derivation failed", authentication: "recovery passphrase or bundle is invalid",
}

func wrapEd25519(privateKey ed25519.PrivateKey, passphrase string, authenticatedData []byte, random io.Reader, messages cryptoMessages) ([]byte, []byte, []byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, nil, nil, errors.New(messages.invalidPrivate)
	}
	if random == nil {
		random = rand.Reader
	}
	salt, nonce := make([]byte, 32), make([]byte, 12)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, nil, nil, errors.New(messages.randomness)
	}
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, nil, nil, errors.New(messages.randomness)
	}
	wrappingKey, err := deriveScryptKey(passphrase, salt, messages.shortPassphrase, messages.derivation)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(wrappingKey)
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, nil, errors.New(messages.invalidPrivate)
	}
	defer clear(privateDER)
	gcm, err := aesGCM(wrappingKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return salt, nonce, gcm.Seal(nil, nonce, privateDER, authenticatedData), nil
}

func unwrapEd25519(passphrase string, salt, nonce, ciphertext, authenticatedData []byte, messages cryptoMessages) (ed25519.PrivateKey, error) {
	wrappingKey, err := deriveScryptKey(passphrase, salt, messages.shortPassphrase, messages.derivation)
	if err != nil {
		return nil, err
	}
	defer clear(wrappingKey)
	gcm, err := aesGCM(wrappingKey)
	if err != nil {
		return nil, err
	}
	privateDER, err := gcm.Open(nil, nonce, ciphertext, authenticatedData)
	if err != nil {
		return nil, errors.New(messages.authentication)
	}
	defer clear(privateDER)
	parsed, err := x509.ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		return nil, errors.New(messages.invalidPrivate)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New(messages.nonEd25519)
	}
	return append(ed25519.PrivateKey(nil), privateKey...), nil
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("authority key encryption failed")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("authority key encryption failed")
	}
	return gcm, nil
}
