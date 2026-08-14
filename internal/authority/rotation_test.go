package authority

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestVerifyRotationContinuesActiveInstallationKey(t *testing.T) {
	genesisEvent, genesisRow := signedGenesis(t)
	prior, err := BeginChain(genesisRow, genesisEvent.OperatorID, genesisEvent.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	row, newKeyID := signedRotation(t, prior)
	next, err := VerifyRotation(prior, row)
	if err != nil {
		t.Fatal(err)
	}
	if next.HeadSequence != 2 || next.HeadSHA256 != row.EventSHA256 || next.Keys[genesisEvent.KeyID].Status != "retired" || next.Keys[newKeyID].Status != "active" {
		t.Fatalf("next=%#v", next)
	}
	if prior.Keys[genesisEvent.KeyID].Status != "active" {
		t.Fatal("verification mutated prior state")
	}
	tampered := row
	wrong := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	tampered.PreviousEventSHA256 = &wrong
	if _, err = VerifyRotation(prior, tampered); err == nil {
		t.Fatal("accepted rotation row with another prior head")
	}
	tampered = row
	tampered.SignatureB64 = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if _, err = VerifyRotation(prior, tampered); err == nil {
		t.Fatal("accepted unsigned rotation")
	}
}

func signedRotation(t *testing.T, prior ChainState) (LedgerRow, string) {
	t.Helper()
	oldSeed := make([]byte, ed25519.SeedSize)
	for index := range oldSeed {
		oldSeed[index] = byte(index)
	}
	oldPrivate := ed25519.NewKeyFromSeed(oldSeed)
	newSeed := make([]byte, ed25519.SeedSize)
	for index := range newSeed {
		newSeed[index] = byte(index + 32)
	}
	newPublic := ed25519.NewKeyFromSeed(newSeed).Public().(ed25519.PublicKey)
	newDigest := sha256.Sum256(newPublic)
	newKeyID := "urn:imprint:authority-key:" + hex.EncodeToString(newDigest[:16])
	var oldKey ChainKey
	for _, candidate := range prior.Keys {
		if candidate.Kind == "installation" && candidate.Status == "active" {
			oldKey = candidate
		}
	}
	details := rotationDetails{KeyID: newKeyID, PublicKeyB64: base64.StdEncoding.EncodeToString(newPublic), PublicKeyFingerprint: "sha256:" + hex.EncodeToString(newDigest[:]), InstallID: oldKey.InstallID, BlobRelativePath: "authority/keys/rotated.enc", BlobSHA256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", BlobSize: 144, AlgorithmSuite: AlgorithmSuite, OldKeyID: oldKey.KeyID}
	detailsRaw, _ := json.Marshal(details)
	previous := prior.HeadSHA256
	event := lifecycleEvent{ContractVersion: LifecycleEventVersion, DomainSeparator: LedgerDomain, Sequence: 2, EventID: "urn:imprint:authority-event:rotation-fixture", EventType: "key_rotated", OperatorID: prior.OperatorID, InstallID: oldKey.InstallID, KeyID: newKeyID, SignedByKeyID: oldKey.KeyID, Details: detailsRaw, CreatedAt: "2026-08-14T12:05:00.000000Z", PreviousEventSHA256: &previous}
	encoded, err := canonicalContract(event)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	row := LedgerRow{Sequence: 2, EventID: event.EventID, EventType: event.EventType, OperatorID: event.OperatorID, InstallID: event.InstallID, KeyID: event.KeyID, EventJSON: string(encoded), EventSHA256: hex.EncodeToString(digest[:]), SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(oldPrivate, append([]byte(LedgerDomain+"\x00"), encoded...))), PreviousEventSHA256: &previous, CreatedAt: event.CreatedAt}
	return row, newKeyID
}
