package authority

import (
	"context"
	"testing"
)

func TestLoadVerifiedChainFromCanonicalStore(t *testing.T) {
	db, genesis, _ := approvalDatabase(t)
	defer db.Close()
	chain, err := LoadVerifiedChain(context.Background(), db, genesis.OperatorID, genesis.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if chain.HeadSequence != 1 || chain.HeadSHA256 == "" || chain.GenesisSHA256 != chain.HeadSHA256 {
		t.Fatalf("chain=%#v", chain)
	}
}

func TestLoadVerifiedChainRejectsStoredTampering(t *testing.T) {
	db, genesis, _ := approvalDatabase(t)
	defer db.Close()
	if _, err := db.Exec(`UPDATE authority_ledger SET event_sha256=? WHERE sequence=1`, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err == nil {
		t.Fatal("immutability trigger unexpectedly allowed ledger tampering")
	}
	if _, err := db.Exec(`DROP TRIGGER authority_ledger_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE authority_ledger SET event_sha256=? WHERE sequence=1`, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVerifiedChain(context.Background(), db, genesis.OperatorID, genesis.StoreIdentity); err == nil {
		t.Fatal("accepted a tampered stored ledger")
	}
}
