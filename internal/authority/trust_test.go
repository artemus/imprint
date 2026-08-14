package authority

import (
	"strings"
	"testing"
	"time"
)

func TestAuthorityTrustAnchorDigestMatchesLegacyContract(t *testing.T) {
	anchor := AuthorityTrustAnchor{
		OperatorID: "op", StoreIdentity: "store", GenesisEventSHA256: strings.Repeat("a", 64),
		PinnedSequence: 2, PinnedHeadSHA256: strings.Repeat("b", 64),
		KeyStateSHA256: strings.Repeat("c", 64),
	}
	digest, err := anchor.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if digest != "8a0b63d070cda50c6abfef2026449a3cb4affc72af9f5d1e135db13b83d3acb2" {
		t.Fatalf("digest=%s", digest)
	}
}

func TestVerifyTransferExtendsDestinationCheckpointHistory(t *testing.T) {
	genesis, genesisRow := signedGenesis(t)
	prior, err := BeginChain(genesisRow, genesis.OperatorID, genesis.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	rotation, newKeyID := signedRotation(t, prior)
	chain, err := VerifyChain([]LedgerRow{genesisRow, rotation}, genesis.OperatorID, genesis.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint1 := signedCheckpoint(t, chain, 1, genesis.KeyID, fixturePrivateKey(0))
	raw1, _ := canonicalContract(checkpoint1)
	digest1, err := canonicalValueSHA256(checkpoint1)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint2 := signedCheckpoint(t, chain, 2, newKeyID, fixturePrivateKey(32))
	checkpoint2.PriorCheckpointSHA256 = &digest1
	checkpoint2 = resignCheckpoint(t, checkpoint2, fixturePrivateKey(32))
	raw2, _ := canonicalContract(checkpoint2)
	certificateSHA, _ := canonicalValueSHA256(checkpoint1.SignerCertificate)
	anchor := AuthorityTrustAnchor{
		OperatorID: chain.OperatorID, StoreIdentity: chain.StoreIdentity,
		GenesisEventSHA256: chain.GenesisSHA256, PinnedSequence: 1,
		PinnedHeadSHA256: chain.Snapshots[1].EventSHA256,
		KeyStateSHA256:   chain.Snapshots[1].KeyStateSHA256,
		CheckpointSHA256: &digest1, SignerCertificateSHA256: &certificateSHA,
	}
	now := time.Date(2026, 8, 14, 12, 30, 0, 0, time.UTC)
	transfer, err := VerifyTransfer(chain, anchor, [][]byte{raw1, raw2}, now)
	if err != nil {
		t.Fatal(err)
	}
	if transfer.Checkpoint.Sequence != 2 || transfer.CheckpointSHA256 == digest1 || transfer.PriorAnchorSHA256 == "" {
		t.Fatalf("transfer=%#v", transfer)
	}
	if _, err = VerifyTransfer(chain, anchor, [][]byte{raw2}, now); err == nil {
		t.Fatal("accepted history that omitted the destination pin")
	}
	checkpoint2.PriorCheckpointSHA256 = nil
	checkpoint2 = resignCheckpoint(t, checkpoint2, fixturePrivateKey(32))
	brokenRaw, _ := canonicalContract(checkpoint2)
	if _, err = VerifyTransfer(chain, anchor, [][]byte{raw1, brokenRaw}, now); err == nil {
		t.Fatal("accepted checkpoint history with a broken link")
	}
	anchor.PinnedHeadSHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, err = VerifyTransfer(chain, anchor, [][]byte{raw1, raw2}, now); err == nil {
		t.Fatal("accepted a chain that forked from the pinned head")
	}
}

func TestVerifyCheckpointHistoryBootstrapsOnlyClosedHistory(t *testing.T) {
	genesis, row := signedGenesis(t)
	chain, err := VerifyChain([]LedgerRow{row}, genesis.OperatorID, genesis.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := signedCheckpoint(t, chain, 1, genesis.KeyID, fixturePrivateKey(0))
	raw, _ := canonicalContract(checkpoint)
	now := time.Date(2026, 8, 14, 12, 30, 0, 0, time.UTC)
	results, err := VerifyCheckpointHistory(chain, [][]byte{raw}, nil, now)
	if err != nil || len(results) != 1 || results[0].Sequence != 1 {
		t.Fatalf("results=%#v err=%v", results, err)
	}
	checkpoint.PriorCheckpointSHA256 = stringPointer("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	checkpoint = resignCheckpoint(t, checkpoint, fixturePrivateKey(0))
	raw, _ = canonicalContract(checkpoint)
	if _, err = VerifyCheckpointHistory(chain, [][]byte{raw}, nil, now); err == nil {
		t.Fatal("accepted bootstrap history that did not start at nil")
	}
}

func TestValidateRecoveryAnchorRequiresActiveExactBinding(t *testing.T) {
	chain, recoveryID := chainWithRecovery(t)
	publicKey := chain.Keys[recoveryID].PublicKeyB64
	if err := ValidateRecoveryAnchor(VerifiedChain{ChainState: chain}, &recoveryID, &publicKey); err != nil {
		t.Fatal(err)
	}
	wrong := "wrong"
	if err := ValidateRecoveryAnchor(VerifiedChain{ChainState: chain}, &recoveryID, &wrong); err == nil {
		t.Fatal("accepted a different recovery public key")
	}
	if err := ValidateRecoveryAnchor(VerifiedChain{ChainState: chain}, &recoveryID, nil); err == nil {
		t.Fatal("accepted incomplete recovery trust")
	}
}
