package authority

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestCanonicalChallengeMatchesPythonRFC8785Fixture(t *testing.T) {
	challenge := fixtureChallenge(t)
	encoded, err := CanonicalChallenge(challenge)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	if got := hex.EncodeToString(digest[:]); got != "7e1086a67f5d9c200af6e496d1730ed5a15222791e15f4e13cd2b1066f723fb0" {
		t.Fatalf("RFC 8785 mismatch: %s\n%s", got, encoded)
	}
}

func TestApprovalTokenSignatureAndTime(t *testing.T) {
	challenge := fixtureChallenge(t)
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	message, err := SignatureMessage(challenge)
	if err != nil {
		t.Fatal(err)
	}
	token := ApprovalToken{Challenge: challenge, SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, message))}
	raw, _ := json.Marshal(token)
	decoded, err := DecodeApprovalToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyApproval(decoded, privateKey.Public().(ed25519.PublicKey), time.Date(2026, 8, 14, 12, 0, 30, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if err = VerifyApproval(decoded, privateKey.Public().(ed25519.PublicKey), time.Date(2026, 8, 14, 12, 1, 30, 0, time.UTC)); err == nil {
		t.Fatal("accepted expired approval")
	}
	decoded.Challenge.Purpose = "A different mutation"
	if err = VerifyApproval(decoded, privateKey.Public().(ed25519.PublicKey), time.Date(2026, 8, 14, 12, 0, 30, 0, time.UTC)); err == nil {
		t.Fatal("accepted signature after challenge mutation")
	}
}

func TestChallengeRejectsDuplicateListsAndNoncanonicalNonce(t *testing.T) {
	challenge := fixtureChallenge(t)
	challenge.Scope = []string{"review", "review"}
	if err := challenge.Validate(); err == nil {
		t.Fatal("accepted duplicate scope")
	}
	challenge = fixtureChallenge(t)
	challenge.Nonce += "="
	if err := challenge.Validate(); err == nil {
		t.Fatal("accepted padded nonce")
	}
}

func fixtureChallenge(t *testing.T) Challenge {
	t.Helper()
	raw, err := os.ReadFile("testdata/challenge.json")
	if err != nil {
		t.Fatal(err)
	}
	var value Challenge
	if err = json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}
