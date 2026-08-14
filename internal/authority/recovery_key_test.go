package authority

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestVerifyRecoveryCreatedCertifiesDistinctKey(t *testing.T) {
	genesis, genesisRow := signedGenesis(t)
	prior, err := BeginChain(genesisRow, genesis.OperatorID, genesis.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	recoveryPrivate := fixturePrivateKey(64)
	recoveryPublic := recoveryPrivate.Public().(ed25519.PublicKey)
	recoveryDigest := sha256.Sum256(recoveryPublic)
	certificate := KeyCertificate{
		KeyID:                "urn:imprint:authority-key:" + hex.EncodeToString(recoveryDigest[:16]),
		PublicKeyB64:         base64.StdEncoding.EncodeToString(recoveryPublic),
		PublicKeyFingerprint: "sha256:" + hex.EncodeToString(recoveryDigest[:]),
		InstallID:            "urn:imprint:recovery:new-fixture",
	}
	row := signedRecoveryCreated(t, prior, certificate)
	next, err := VerifyRecoveryCreated(prior, row)
	if err != nil {
		t.Fatal(err)
	}
	created := next.Keys[certificate.KeyID]
	if created.Kind != "recovery" || created.Status != "active" || created.Paired || created.CertificateSequence != 2 || prior.Keys[certificate.KeyID].KeyID != "" {
		t.Fatalf("created=%#v", created)
	}
	duplicate := signedRecoveryCreated(t, next, certificate)
	if _, err = VerifyRecoveryCreated(next, duplicate); err == nil {
		t.Fatal("accepted a recovery key certified twice")
	}
	tampered := row
	tampered.KeyID = genesis.KeyID
	if _, err = VerifyRecoveryCreated(prior, tampered); err == nil {
		t.Fatal("accepted a row that names another recovery subject")
	}
}

func signedRecoveryCreated(t *testing.T, prior ChainState, certificate KeyCertificate) LedgerRow {
	t.Helper()
	details, err := json.Marshal(certificate)
	if err != nil {
		t.Fatal(err)
	}
	previous := prior.HeadSHA256
	event := lifecycleEvent{
		ContractVersion: LifecycleEventVersion, DomainSeparator: LedgerDomain,
		Sequence: prior.HeadSequence + 1, EventID: "urn:imprint:authority-event:recovery-created",
		EventType: "recovery_created", OperatorID: prior.OperatorID,
		InstallID: certificate.InstallID, KeyID: certificate.KeyID,
		SignedByKeyID: activeInstallationKey(prior).KeyID, Details: details,
		CreatedAt: "2026-08-14T12:20:00.000000Z", PreviousEventSHA256: &previous,
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
		SignatureB64:        base64.StdEncoding.EncodeToString(ed25519.Sign(fixturePrivateKey(0), append([]byte(LedgerDomain+"\x00"), encoded...))),
		PreviousEventSHA256: &previous, CreatedAt: event.CreatedAt,
	}
}

func activeInstallationKey(state ChainState) ChainKey {
	for _, key := range state.Keys {
		if key.Kind == "installation" && key.Status == "active" {
			return key
		}
	}
	return ChainKey{}
}
