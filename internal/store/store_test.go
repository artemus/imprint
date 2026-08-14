package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/artemus/imprint/internal/capture"
	"github.com/artemus/imprint/internal/urn"
)

func TestApplyCaptureCreatesCompatibleGraphAndDeduplicates(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	operator, _ := urn.New("operator")
	session, _ := urn.New("session")
	value, err := capture.Build(capture.BuildOptions{OperatorID: operator, SessionID: session, NodeID: "primary", CaseDescription: "Reviewed a draft", RawOperatorText: "No, use the compact version.", CallType: "correct", CaptureMechanism: "explicit_cli", CapturedBy: "test", Chosen: []capture.AlternativeInput{{Description: "compact"}}, Rejected: []capture.AlternativeInput{{Description: "large"}}})
	if err != nil {
		t.Fatal(err)
	}
	database, err := Open(filepath.Join(root, "imprint.db"), operator, "primary")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	result, err := database.ApplyCapture(context.Background(), value, "spool/primary/event.json")
	if err != nil || result != "captured" {
		t.Fatalf("result=%q err=%v", result, err)
	}
	result, err = database.ApplyCapture(context.Background(), value, "spool/primary/event.json")
	if err != nil || result != "duplicate" {
		t.Fatalf("result=%q err=%v", result, err)
	}
	var nodes, edges int
	if err = database.db.QueryRow("SELECT COUNT(*) FROM nodes").Scan(&nodes); err != nil {
		t.Fatal(err)
	}
	if err = database.db.QueryRow("SELECT COUNT(*) FROM edges").Scan(&edges); err != nil {
		t.Fatal(err)
	}
	if nodes != 6 || edges != 5 {
		t.Fatalf("nodes=%d edges=%d", nodes, edges)
	}
}

func TestOpenRejectsIncompatibleStore(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	operator, _ := urn.New("operator")
	path := filepath.Join(root, "imprint.db")
	database, err := Open(path, operator, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.db.Exec("UPDATE meta SET value='99' WHERE key='store_schema_version'"); err != nil {
		t.Fatal(err)
	}
	database.Close()
	if _, err = Open(path, operator, "primary"); err == nil {
		t.Fatal("accepted incompatible schema")
	}
}

func TestOpenInitializesAuthoritySchemaAndRollsBackFailedMutation(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	operator, _ := urn.New("operator")
	path := filepath.Join(root, "imprint.db")
	database, err := Open(path, operator, "primary")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var table string
	if err := database.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='authority_provenance'`).Scan(&table); err != nil || table != "authority_provenance" {
		t.Fatalf("table=%s err=%v", table, err)
	}
	want := errors.New("mutation failed")
	err = database.AuthorityTransaction(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO authority_challenges VALUES('nonce','operation','challenge','issued','expires',NULL,NULL)`)
		if err != nil {
			return err
		}
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("err=%v", err)
	}
	var count int
	if err := database.db.QueryRow(`SELECT COUNT(*) FROM authority_challenges`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}
