package authority

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestVerifyConflictAdjudicatedRequiresRecoverySignature(t *testing.T) {
	prior, recoveryID := chainWithRecovery(t)
	details := adjudicationDetails{
		ProofID:                "urn:imprint:authority-proof:fixture",
		ChosenCheckpointSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RejectedProofSHA256:    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Reason:                 "retain the physically pinned checkpoint", EffectiveAt: "2026-08-14T12:45:00.000000Z",
	}
	row := signedAdjudication(t, prior, recoveryID, fixturePrivateKey(255), details)
	next, err := VerifyConflictAdjudicated(prior, row)
	if err != nil {
		t.Fatal(err)
	}
	if next.HeadSequence != 2 || next.HeadSHA256 != row.EventSHA256 || len(next.Keys) != len(prior.Keys) {
		t.Fatalf("next=%#v", next)
	}
	installation := activeInstallationKey(prior)
	wrongSigner := signedAdjudication(t, prior, installation.KeyID, fixturePrivateKey(0), details)
	if _, err = VerifyConflictAdjudicated(prior, wrongSigner); err == nil {
		t.Fatal("accepted installation-signed conflict adjudication")
	}
	details.RejectedProofSHA256 = "not-a-digest"
	if _, err = VerifyConflictAdjudicated(prior, signedAdjudication(t, prior, recoveryID, fixturePrivateKey(255), details)); err == nil {
		t.Fatal("accepted malformed adjudication digest")
	}
}

func chainWithRecovery(t *testing.T) (ChainState, string) {
	t.Helper()
	genesis, _ := signedGenesis(t)
	recoveryPrivate := fixturePrivateKey(255)
	recoveryPublic := recoveryPrivate.Public().(ed25519.PublicKey)
	recoveryDigest := sha256.Sum256(recoveryPublic)
	recoveryID := "urn:imprint:authority-key:" + hex.EncodeToString(recoveryDigest[:16])
	genesis.RecoveryBinding = &KeyCertificate{
		KeyID: recoveryID, PublicKeyB64: base64.StdEncoding.EncodeToString(recoveryPublic),
		PublicKeyFingerprint: "sha256:" + hex.EncodeToString(recoveryDigest[:]),
		InstallID:            "urn:imprint:recovery:fixture",
	}
	state, err := BeginChain(signGenesisEvent(t, genesis), genesis.OperatorID, genesis.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	return state, recoveryID
}

func signedAdjudication(t *testing.T, prior ChainState, signerID string, privateKey ed25519.PrivateKey, details adjudicationDetails) LedgerRow {
	t.Helper()
	detailsRaw, err := json.Marshal(details)
	if err != nil {
		t.Fatal(err)
	}
	previous := prior.HeadSHA256
	signer := prior.Keys[signerID]
	event := lifecycleEvent{
		ContractVersion: LifecycleEventVersion, DomainSeparator: LedgerDomain,
		Sequence: prior.HeadSequence + 1, EventID: "urn:imprint:authority-event:conflict-adjudicated",
		EventType: "authority_conflict_adjudicated", OperatorID: prior.OperatorID,
		InstallID: signer.InstallID, KeyID: signer.KeyID, SignedByKeyID: signer.KeyID,
		Details: detailsRaw, CreatedAt: "2026-08-14T12:44:00.000000Z", PreviousEventSHA256: &previous,
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
