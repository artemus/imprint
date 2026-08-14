package authority

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

func TestVerifyCheckpointAcceptsHistoricalActiveSigner(t *testing.T) {
	genesis, genesisRow := signedGenesis(t)
	prior, err := BeginChain(genesisRow, genesis.OperatorID, genesis.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	rotation, _ := signedRotation(t, prior)
	chain, err := VerifyChain([]LedgerRow{genesisRow, rotation}, genesis.OperatorID, genesis.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := signedCheckpoint(t, chain, 1, genesis.KeyID, fixturePrivateKey(0))
	raw, err := canonicalContract(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 14, 12, 30, 0, 0, time.UTC)
	result, err := VerifyCheckpoint(chain, raw, now, MaxCheckpointAge, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.Sequence != 1 || result.SignerCurrentStatus != "retired" || result.CheckpointSHA256 == "" {
		t.Fatalf("result=%#v", result)
	}

	tampered := checkpoint
	tampered.KeyStateSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tampered = resignCheckpoint(t, tampered, fixturePrivateKey(0))
	raw, _ = canonicalContract(tampered)
	if _, err = VerifyCheckpoint(chain, raw, now, MaxCheckpointAge, true); err == nil {
		t.Fatal("accepted a checkpoint with another key-state digest")
	}

	staleNow := time.Date(2026, 8, 15, 13, 0, 0, 0, time.UTC)
	raw, _ = canonicalContract(checkpoint)
	if _, err = VerifyCheckpoint(chain, raw, staleNow, MaxCheckpointAge, true); err == nil {
		t.Fatal("accepted stale checkpoint when freshness was enforced")
	}
	if _, err = VerifyCheckpoint(chain, raw, staleNow, MaxCheckpointAge, false); err != nil {
		t.Fatalf("offline historical verification failed: %v", err)
	}
}

func TestVerifyCheckpointRejectsCertificateAndPriorHashTampering(t *testing.T) {
	genesis, row := signedGenesis(t)
	chain, err := VerifyChain([]LedgerRow{row}, genesis.OperatorID, genesis.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := signedCheckpoint(t, chain, 1, genesis.KeyID, fixturePrivateKey(0))
	checkpoint.SignerCertificate.Paired = false
	checkpoint = resignCheckpoint(t, checkpoint, fixturePrivateKey(0))
	raw, _ := canonicalContract(checkpoint)
	now := time.Date(2026, 8, 14, 12, 30, 0, 0, time.UTC)
	if _, err = VerifyCheckpoint(chain, raw, now, MaxCheckpointAge, true); err == nil {
		t.Fatal("accepted a mismatched signer certificate")
	}
	checkpoint = signedCheckpoint(t, chain, 1, genesis.KeyID, fixturePrivateKey(0))
	checkpoint.PriorCheckpointSHA256 = stringPointer("not-a-digest")
	checkpoint = resignCheckpoint(t, checkpoint, fixturePrivateKey(0))
	raw, _ = canonicalContract(checkpoint)
	if _, err = VerifyCheckpoint(chain, raw, now, MaxCheckpointAge, true); err == nil {
		t.Fatal("accepted a malformed prior checkpoint hash")
	}
}

func TestSignCheckpointMatchesCanonicalContractAndKeyBinding(t *testing.T) {
	genesis, row := signedGenesis(t)
	chain, err := VerifyChain([]LedgerRow{row}, genesis.OperatorID, genesis.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 14, 12, 15, 0, 0, time.UTC)
	checkpoint, err := SignCheckpoint(chain, genesis.KeyID, fixturePrivateKey(0), nil, now, MaxCheckpointAge)
	if err != nil {
		t.Fatal(err)
	}
	expected := signedCheckpoint(t, chain, 1, genesis.KeyID, fixturePrivateKey(0))
	if checkpoint != expected {
		t.Fatalf("checkpoint=%#v expected=%#v", checkpoint, expected)
	}
	if _, err := SignCheckpoint(chain, genesis.KeyID, fixturePrivateKey(1), nil, now, MaxCheckpointAge); err == nil {
		t.Fatal("signed a checkpoint with a mismatched private key")
	}
	if _, err := SignCheckpoint(chain, genesis.KeyID, fixturePrivateKey(0), nil, now, MaxCheckpointAge+time.Second); err == nil {
		t.Fatal("accepted an excessive checkpoint TTL")
	}
}

func signedCheckpoint(t *testing.T, chain VerifiedChain, sequence int64, signerID string, privateKey ed25519.PrivateKey) Checkpoint {
	t.Helper()
	snapshot := chain.Snapshots[sequence]
	checkpoint := Checkpoint{CheckpointUnsigned: CheckpointUnsigned{
		CheckpointVersion: CheckpointVersion, DomainSeparator: CheckpointDomain,
		OperatorID: chain.OperatorID, StoreIdentity: chain.StoreIdentity,
		Sequence: sequence, EventSHA256: snapshot.EventSHA256,
		GenesisEventSHA256: chain.GenesisSHA256, KeyStateSHA256: snapshot.KeyStateSHA256,
		SignerKeyID: signerID, SignerCertificate: signerCertificate(snapshot.Keys[signerID]),
		IssuedAt: "2026-08-14T12:15:00.000000Z", ExpiresAt: "2026-08-15T12:15:00.000000Z",
	}}
	return resignCheckpoint(t, checkpoint, privateKey)
}

func resignCheckpoint(t *testing.T, checkpoint Checkpoint, privateKey ed25519.PrivateKey) Checkpoint {
	t.Helper()
	encoded, err := canonicalContract(checkpoint.CheckpointUnsigned)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, append([]byte(CheckpointDomain+"\x00"), encoded...)))
	return checkpoint
}
