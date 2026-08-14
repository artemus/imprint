package authority

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestInitializeSchemaCreatesCompleteAuthorityStoreIdempotently(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for attempt := 0; attempt < 2; attempt++ {
		if err := InitializeSchema(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	for _, table := range []string{
		"authority_keys", "authority_ledger", "authority_trust_anchor",
		"authority_checkpoint_pins", "authority_transfer_intents",
		"authority_pairing_requests", "authority_equivocation_proofs",
		"authority_challenges", "authority_prepared_mutations", "authority_provenance",
	} {
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)`, table).Scan(&exists); err != nil || !exists {
			t.Fatalf("table=%s exists=%t err=%v", table, exists, err)
		}
	}
}
