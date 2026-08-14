package authority

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestVerifyGenesisBindsRowDigestSignatureAndIdentity(t *testing.T) {
	event, row := signedGenesis(t)
	state, err := VerifyGenesis(row, event.OperatorID, event.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if state.HeadSHA256 != row.EventSHA256 || state.Installation.KeyID != event.KeyID || state.HasRecovery {
		t.Fatalf("state=%#v", state)
	}
	tampered := row
	tampered.EventType = "key_rotated"
	if _, err = VerifyGenesis(tampered, event.OperatorID, event.StoreIdentity); err == nil {
		t.Fatal("accepted row/event disagreement")
	}
	tampered = row
	tampered.EventJSON = tampered.EventJSON[:len(tampered.EventJSON)-1] + " "
	if _, err = VerifyGenesis(tampered, event.OperatorID, event.StoreIdentity); err == nil {
		t.Fatal("accepted malformed event JSON")
	}
	tampered = row
	signature, _ := base64.StdEncoding.DecodeString(tampered.SignatureB64)
	signature[0] ^= 1
	tampered.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	if _, err = VerifyGenesis(tampered, event.OperatorID, event.StoreIdentity); err == nil {
		t.Fatal("accepted invalid genesis signature")
	}
}

func TestVerifyGenesisAcceptsBoundRecoveryCertificate(t *testing.T) {
	event, _ := signedGenesis(t)
	recoverySeed := make([]byte, ed25519.SeedSize)
	for index := range recoverySeed {
		recoverySeed[index] = byte(255 - index)
	}
	recoveryPublic := ed25519.NewKeyFromSeed(recoverySeed).Public().(ed25519.PublicKey)
	recoveryDigest := sha256.Sum256(recoveryPublic)
	event.RecoveryBinding = &KeyCertificate{KeyID: "urn:imprint:authority-key:" + hex.EncodeToString(recoveryDigest[:16]), PublicKeyB64: base64.StdEncoding.EncodeToString(recoveryPublic), PublicKeyFingerprint: "sha256:" + hex.EncodeToString(recoveryDigest[:]), InstallID: "urn:imprint:recovery:fixture"}
	row := signGenesisEvent(t, event)
	state, err := VerifyGenesis(row, event.OperatorID, event.StoreIdentity)
	if err != nil || !state.HasRecovery || state.Recovery.KeyID != event.RecoveryBinding.KeyID {
		t.Fatalf("state=%#v err=%v", state, err)
	}
}

func signedGenesis(t *testing.T) (GenesisEvent, LedgerRow) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	digest := sha256.Sum256(public)
	event := GenesisEvent{
		ContractVersion: GenesisEventVersion, DomainSeparator: LedgerDomain,
		Sequence: 1, EventID: "urn:imprint:authority-event:fixture", EventType: "enrollment",
		OperatorID: "urn:imprint:operator:fixture", InstallID: "urn:imprint:install:fixture",
		StoreIdentity: "urn:imprint:store:fixture", KeyID: "urn:imprint:authority-key:" + hex.EncodeToString(digest[:16]),
		PublicKeyB64: base64.StdEncoding.EncodeToString(public), PublicKeyFingerprint: "sha256:" + hex.EncodeToString(digest[:]),
		AlgorithmSuite: AlgorithmSuite, EnrollmentNonce: "fixture-nonce", BlobRelativePath: "authority/keys/fixture.enc",
		BlobSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", BlobSize: 128,
		Status: "active", CreatedAt: "2026-08-14T12:00:00.000000Z",
	}
	return event, signGenesisEvent(t, event)
}

func signGenesisEvent(t *testing.T, event GenesisEvent) LedgerRow {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	encoded, err := canonicalContract(event)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return LedgerRow{Sequence: 1, EventID: event.EventID, EventType: event.EventType, OperatorID: event.OperatorID, InstallID: event.InstallID, KeyID: event.KeyID, EventJSON: string(encoded), EventSHA256: hex.EncodeToString(digest[:]), SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, append([]byte(LedgerDomain+"\x00"), encoded...))), CreatedAt: event.CreatedAt}
}
