package authority

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestVerifyInstallationReboundRetiresExactlyOneSource(t *testing.T) {
	genesis, genesisRow := signedGenesis(t)
	prior, err := BeginChain(genesisRow, genesis.OperatorID, genesis.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	newPublic := fixturePrivateKey(128).Public().(ed25519.PublicKey)
	newDigest := sha256.Sum256(newPublic)
	details := rebindDetails{
		KeyID:                "urn:imprint:authority-key:" + hex.EncodeToString(newDigest[:16]),
		PublicKeyB64:         base64.StdEncoding.EncodeToString(newPublic),
		PublicKeyFingerprint: "sha256:" + hex.EncodeToString(newDigest[:]),
		InstallID:            "urn:imprint:install:rebound", OldInstallID: genesis.InstallID,
		BlobRelativePath: "authority/keys/rebound.enc",
		BlobSHA256:       "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		BlobSize:         176, AlgorithmSuite: AlgorithmSuite,
	}
	details.Authorization = installationAuthorization{
		CertificateVersion: InstallationAuthorizationVersion,
		OperatorID:         prior.OperatorID, StoreIdentity: prior.StoreIdentity,
		NewInstallID: details.InstallID, NewKeyID: details.KeyID,
		NewPublicKeyB64: details.PublicKeyB64, PairingNonce: "rebind-fixture",
		PairingRequestSHA256:         "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		PrecedingAuthorityHeadSHA256: prior.HeadSHA256, ExpiresAt: "2026-08-14T12:40:00.000000Z",
	}
	row := signedRebind(t, prior, details)
	next, err := VerifyInstallationRebound(prior, row)
	if err != nil {
		t.Fatal(err)
	}
	if next.Keys[genesis.KeyID].Status != "retired" || next.Keys[details.KeyID].Status != "active" || prior.Keys[genesis.KeyID].Status != "active" {
		t.Fatalf("prior=%#v next=%#v", prior, next)
	}

	ambiguous := prior
	ambiguous.Keys = cloneKeys(prior.Keys)
	ambiguous.Keys["recovery-on-source"] = ChainKey{KeyCertificate: KeyCertificate{KeyID: "recovery-on-source", InstallID: genesis.InstallID}, Kind: "recovery", Status: "active"}
	if _, err = VerifyInstallationRebound(ambiguous, signedRebind(t, ambiguous, details)); err == nil {
		t.Fatal("accepted an ambiguous source installation")
	}

	targetActive := details
	targetActive.InstallID = genesis.InstallID
	targetActive.Authorization.NewInstallID = genesis.InstallID
	if _, err = VerifyInstallationRebound(prior, signedRebind(t, prior, targetActive)); err == nil {
		t.Fatal("accepted a rebind onto an active installation")
	}
}

func signedRebind(t *testing.T, prior ChainState, details rebindDetails) LedgerRow {
	t.Helper()
	detailsRaw, err := json.Marshal(details)
	if err != nil {
		t.Fatal(err)
	}
	previous := prior.HeadSHA256
	event := lifecycleEvent{
		ContractVersion: LifecycleEventVersion, DomainSeparator: LedgerDomain,
		Sequence: prior.HeadSequence + 1, EventID: "urn:imprint:authority-event:installation-rebound",
		EventType: "installation_rebound", OperatorID: prior.OperatorID,
		InstallID: details.InstallID, KeyID: details.KeyID,
		SignedByKeyID: activeInstallationKey(prior).KeyID, Details: detailsRaw,
		CreatedAt: "2026-08-14T12:31:00.000000Z", PreviousEventSHA256: &previous,
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
