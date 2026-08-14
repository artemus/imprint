package authority

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestVerifyInstallationPairedBindsAuthorizationAndBlob(t *testing.T) {
	genesis, genesisRow := signedGenesis(t)
	prior, err := BeginChain(genesisRow, genesis.OperatorID, genesis.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	newPublic := fixturePrivateKey(96).Public().(ed25519.PublicKey)
	newDigest := sha256.Sum256(newPublic)
	details := pairingDetails{
		KeyID:                "urn:imprint:authority-key:" + hex.EncodeToString(newDigest[:16]),
		PublicKeyB64:         base64.StdEncoding.EncodeToString(newPublic),
		PublicKeyFingerprint: "sha256:" + hex.EncodeToString(newDigest[:]),
		InstallID:            "urn:imprint:install:paired", BlobRelativePath: "authority/keys/paired.enc",
		BlobSHA256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		BlobSize:   160, AlgorithmSuite: AlgorithmSuite,
	}
	details.Authorization = installationAuthorization{
		CertificateVersion: InstallationAuthorizationVersion,
		OperatorID:         prior.OperatorID, StoreIdentity: prior.StoreIdentity,
		NewInstallID: details.InstallID, NewKeyID: details.KeyID,
		NewPublicKeyB64: details.PublicKeyB64, PairingNonce: "pairing-fixture",
		PairingRequestSHA256:         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PrecedingAuthorityHeadSHA256: prior.HeadSHA256, ExpiresAt: "2026-08-14T12:30:00.000000Z",
	}
	row := signedPairing(t, prior, details)
	next, err := VerifyInstallationPaired(prior, row)
	if err != nil {
		t.Fatal(err)
	}
	paired := next.Keys[details.KeyID]
	if !paired.Paired || paired.Kind != "installation" || paired.Status != "active" || paired.BlobSHA256 != details.BlobSHA256 || prior.Keys[details.KeyID].KeyID != "" {
		t.Fatalf("paired=%#v", paired)
	}

	tampered := details
	tampered.Authorization.PrecedingAuthorityHeadSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err = VerifyInstallationPaired(prior, signedPairing(t, prior, tampered)); err == nil {
		t.Fatal("accepted authorization for another authority head")
	}
	tampered = details
	tampered.InstallID = genesis.InstallID
	tampered.Authorization.NewInstallID = genesis.InstallID
	if _, err = VerifyInstallationPaired(prior, signedPairing(t, prior, tampered)); err == nil {
		t.Fatal("accepted a second active key for one installation")
	}
}

func signedPairing(t *testing.T, prior ChainState, details pairingDetails) LedgerRow {
	t.Helper()
	detailsRaw, err := json.Marshal(details)
	if err != nil {
		t.Fatal(err)
	}
	previous := prior.HeadSHA256
	event := lifecycleEvent{
		ContractVersion: LifecycleEventVersion, DomainSeparator: LedgerDomain,
		Sequence: prior.HeadSequence + 1, EventID: "urn:imprint:authority-event:installation-paired",
		EventType: "installation_paired", OperatorID: prior.OperatorID,
		InstallID: details.InstallID, KeyID: details.KeyID,
		SignedByKeyID: activeInstallationKey(prior).KeyID, Details: detailsRaw,
		CreatedAt: "2026-08-14T12:21:00.000000Z", PreviousEventSHA256: &previous,
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
