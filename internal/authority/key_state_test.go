package authority

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestVerifyKeyStateRevokesWithoutMutatingPrior(t *testing.T) {
	event, genesisRow := signedGenesis(t)
	prior, err := BeginChain(genesisRow, event.OperatorID, event.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := fixturePrivateKey(0)
	details := keyStateDetails{
		TargetKeyID: event.KeyID, EffectiveAt: "2026-08-14T12:10:00.000000Z",
		Reason: "operator retired this key", AffectedInstallationIDs: []string{event.InstallID},
		EvidenceSHA256s: []string{}, RequiredRevocationKeyIDs: []string{event.KeyID},
	}
	row := signedKeyState(t, prior, "key_revoked", event.KeyID, event.InstallID, event.KeyID, details, privateKey)
	next, err := VerifyKeyState(prior, row)
	if err != nil {
		t.Fatal(err)
	}
	if next.Keys[event.KeyID].Status != "revoked" || next.HeadSequence != 2 || prior.Keys[event.KeyID].Status != "active" {
		t.Fatalf("prior=%#v next=%#v", prior, next)
	}
}

func TestVerifyKeyStateCompromiseRequiresAnotherActiveSigner(t *testing.T) {
	event, genesisRow := signedGenesis(t)
	prior, err := BeginChain(genesisRow, event.OperatorID, event.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	recoveryPrivate := fixturePrivateKey(255)
	recoveryPublic := recoveryPrivate.Public().(ed25519.PublicKey)
	recoveryDigest := sha256.Sum256(recoveryPublic)
	recoveryID := "urn:imprint:authority-key:" + hex.EncodeToString(recoveryDigest[:16])
	prior.Keys[recoveryID] = ChainKey{KeyCertificate: KeyCertificate{
		KeyID: recoveryID, PublicKeyB64: base64.StdEncoding.EncodeToString(recoveryPublic),
		PublicKeyFingerprint: "sha256:" + hex.EncodeToString(recoveryDigest[:]), InstallID: "urn:imprint:recovery:fixture",
	}, Kind: "recovery", Status: "active", EffectiveAt: event.CreatedAt}
	details := keyStateDetails{
		TargetKeyID: event.KeyID, EffectiveAt: "2026-08-14T12:10:00.000000Z",
		Reason: "key material exposed", AffectedInstallationIDs: []string{event.InstallID},
		EvidenceSHA256s:          []string{"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},
		RequiredRevocationKeyIDs: []string{event.KeyID},
	}
	row := signedKeyState(t, prior, "key_compromised", event.KeyID, event.InstallID, recoveryID, details, recoveryPrivate)
	next, err := VerifyKeyState(prior, row)
	if err != nil {
		t.Fatal(err)
	}
	if next.Keys[event.KeyID].Status != "compromised" || next.Keys[event.KeyID].CompromisedAt == nil || *next.Keys[event.KeyID].CompromisedAt != details.EffectiveAt {
		t.Fatalf("next=%#v", next)
	}
	selfSigned := signedKeyState(t, prior, "key_compromised", event.KeyID, event.InstallID, event.KeyID, details, fixturePrivateKey(0))
	if _, err = VerifyKeyState(prior, selfSigned); err == nil {
		t.Fatal("accepted a compromise event signed by its target")
	}
	details.CompromisedAt = stringPointer("2026-08-14T12:11:00.000000Z")
	lateBoundary := signedKeyState(t, prior, "key_compromised", event.KeyID, event.InstallID, recoveryID, details, recoveryPrivate)
	if _, err = VerifyKeyState(prior, lateBoundary); err == nil {
		t.Fatal("accepted a compromise boundary after its effective time")
	}
	details.CompromisedAt = nil
	details.ReplacementKeyID = stringPointer("urn:imprint:authority-key:unknown")
	unknownReplacement := signedKeyState(t, prior, "key_compromised", event.KeyID, event.InstallID, recoveryID, details, recoveryPrivate)
	if _, err = VerifyKeyState(prior, unknownReplacement); err == nil {
		t.Fatal("accepted an unknown replacement key")
	}

	recoveryDetails := keyStateDetails{
		TargetKeyID: recoveryID, EffectiveAt: "2026-08-14T12:10:00.000000Z",
		Reason: "recovery authority withdrawn", AffectedInstallationIDs: []string{"urn:imprint:recovery:fixture"},
		EvidenceSHA256s: []string{}, RequiredRevocationKeyIDs: []string{recoveryID},
	}
	recoveryRevoked := signedKeyState(t, prior, "recovery_revoked", recoveryID, "urn:imprint:recovery:fixture", event.KeyID, recoveryDetails, fixturePrivateKey(0))
	next, err = VerifyKeyState(prior, recoveryRevoked)
	if err != nil || next.Keys[recoveryID].Status != "revoked" {
		t.Fatalf("recovery revocation: next=%#v err=%v", next, err)
	}
}

func signedKeyState(t *testing.T, prior ChainState, eventType, targetID, installID, signerID string, details keyStateDetails, privateKey ed25519.PrivateKey) LedgerRow {
	t.Helper()
	detailsRaw, err := json.Marshal(details)
	if err != nil {
		t.Fatal(err)
	}
	previous := prior.HeadSHA256
	event := lifecycleEvent{
		ContractVersion: LifecycleEventVersion, DomainSeparator: LedgerDomain,
		Sequence: prior.HeadSequence + 1, EventID: "urn:imprint:authority-event:" + eventType,
		EventType: eventType, OperatorID: prior.OperatorID, InstallID: installID,
		KeyID: targetID, SignedByKeyID: signerID, Details: detailsRaw,
		CreatedAt: "2026-08-14T12:09:00.000000Z", PreviousEventSHA256: &previous,
	}
	encoded, err := canonicalContract(event)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return LedgerRow{
		Sequence: event.Sequence, EventID: event.EventID, EventType: event.EventType,
		OperatorID: event.OperatorID, InstallID: event.InstallID, KeyID: event.KeyID,
		EventJSON: string(encoded), EventSHA256: hex.EncodeToString(digest[:]),
		SignatureB64:        base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, append([]byte(LedgerDomain+"\x00"), encoded...))),
		PreviousEventSHA256: &previous, CreatedAt: event.CreatedAt,
	}
}

func fixturePrivateKey(start int) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		if start == 255 {
			seed[index] = byte(255 - index)
		} else {
			seed[index] = byte(index + start)
		}
	}
	return ed25519.NewKeyFromSeed(seed)
}

func stringPointer(value string) *string { return &value }
