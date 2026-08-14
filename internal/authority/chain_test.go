package authority

import "testing"

func TestVerifyChainRetainsImmutableSequenceSnapshots(t *testing.T) {
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
	if chain.HeadSequence != 2 || len(chain.Snapshots) != 2 || chain.Snapshots[1].EventSHA256 != genesisRow.EventSHA256 || chain.Snapshots[2].EventSHA256 != rotation.EventSHA256 {
		t.Fatalf("chain=%#v", chain)
	}
	if chain.Snapshots[1].Keys[genesis.KeyID].Status != "active" || chain.Snapshots[2].Keys[genesis.KeyID].Status != "retired" || chain.Snapshots[2].Keys[newKeyID].Status != "active" {
		t.Fatalf("snapshots=%#v", chain.Snapshots)
	}
	current := chain.Keys[newKeyID]
	current.Status = "revoked"
	chain.Keys[newKeyID] = current
	if chain.Snapshots[2].Keys[newKeyID].Status != "active" {
		t.Fatal("current-state mutation changed a historical snapshot")
	}
}

func TestVerifyChainRejectsUnsupportedLifecycleEvent(t *testing.T) {
	genesis, row := signedGenesis(t)
	unsupported := row
	unsupported.Sequence = 2
	unsupported.EventType = "unknown"
	if _, err := VerifyChain([]LedgerRow{row, unsupported}, genesis.OperatorID, genesis.StoreIdentity); err == nil {
		t.Fatal("accepted unsupported lifecycle event")
	}
}
