package authority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestConsumeApprovalIsAtomicWithCallerTransaction(t *testing.T) {
	ctx := context.Background()
	db, genesis, privateKey := approvalDatabase(t)
	defer db.Close()
	execution := map[string]any{"event_id": "urn:imprint:event:approved"}
	_, executionSHA, _ := canonicalJSONDigest(execution)
	request := ChallengeRequest{
		OperationID: "urn:imprint:operation:atomic", Purpose: "ratify exact proposal",
		PayloadSHA256:         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PriorStateSHA256:      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ExecutionFieldsSHA256: executionSHA, AuthorityTransition: "proposal_to_ratified_knowledge",
		SubjectIDs: []string{"urn:imprint:node:subject"}, ProposalIDs: []string{"urn:imprint:proposal:source"},
		Scope: []string{"operator"}, FieldPaths: []string{"/authority_tier"},
	}
	prepared, err := PrepareMutation("proposal-accept", request, map[string]any{"proposal": "source"}, map[string]any{}, execution, genesis.OperatorID, time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	tx, _ := db.BeginTx(ctx, nil)
	if err := InsertPreparedMutation(ctx, tx, prepared); err != nil {
		t.Fatal(err)
	}
	challenge, _, err := IssueChallenge(ctx, tx, request, genesis.OperatorID, 90*time.Second, time.Date(2026, 8, 14, 12, 1, 0, 0, time.UTC), bytes.NewReader(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	message, _ := SignatureMessage(challenge)
	token := ApprovalToken{Challenge: challenge, SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, message))}

	tx, _ = db.BeginTx(ctx, nil)
	provenanceID, err := ConsumeApproval(ctx, tx, token, request, genesis.OperatorID, time.Date(2026, 8, 14, 12, 1, 30, 0, time.UTC))
	if err != nil || provenanceID == "" {
		t.Fatalf("provenance=%s err=%v", provenanceID, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var count int
	var consumed sql.NullString
	if err := db.QueryRow(`SELECT COUNT(*) FROM authority_provenance`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if err := db.QueryRow(`SELECT consumed_at FROM authority_challenges WHERE operation_id=?`, request.OperationID).Scan(&consumed); err != nil || consumed.Valid {
		t.Fatalf("consumed=%#v err=%v", consumed, err)
	}

	tx, _ = db.BeginTx(ctx, nil)
	provenanceID, err = ConsumeApproval(ctx, tx, token, request, genesis.OperatorID, time.Date(2026, 8, 14, 12, 1, 30, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := MarkPreparedExecuted(ctx, tx, request.OperationID, provenanceID, time.Date(2026, 8, 14, 12, 1, 30, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx, _ = db.BeginTx(ctx, nil)
	if _, err = ConsumeApproval(ctx, tx, token, request, genesis.OperatorID, time.Date(2026, 8, 14, 12, 1, 31, 0, time.UTC)); err == nil {
		t.Fatal("consumed one nonce twice")
	}
	_ = tx.Rollback()
}

func TestPreparedMutationStorageRejectsTamperingAndDuplicateOperation(t *testing.T) {
	ctx := context.Background()
	db, genesis, _ := approvalDatabase(t)
	defer db.Close()
	execution := map[string]any{}
	_, executionSHA, _ := canonicalJSONDigest(execution)
	request := RequestFromChallenge(fixtureChallenge(t))
	request.ExecutionFieldsSHA256 = executionSHA
	prepared, err := PrepareMutation("authority-test", request, map[string]any{"operation_id": request.OperationID}, map[string]any{}, execution, genesis.OperatorID, time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	tx, _ := db.BeginTx(ctx, nil)
	if err := InsertPreparedMutation(ctx, tx, prepared); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx, _ = db.BeginTx(ctx, nil)
	stored, err := LoadPreparedMutation(ctx, tx, request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = stored.Verify("authority-test", genesis.OperatorID, map[string]any{"operation_id": request.OperationID}, map[string]any{}, time.Date(2026, 8, 14, 13, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	_ = tx.Rollback()
	tx, _ = db.BeginTx(ctx, nil)
	if err = InsertPreparedMutation(ctx, tx, prepared); err == nil {
		t.Fatal("accepted duplicate prepared operation")
	}
	_ = tx.Rollback()
}

func TestLoadVerifiedPreparedMutationMarksExpiry(t *testing.T) {
	ctx := context.Background()
	db, genesis, _ := approvalDatabase(t)
	defer db.Close()
	execution := map[string]any{}
	_, executionSHA, _ := canonicalJSONDigest(execution)
	request := RequestFromChallenge(fixtureChallenge(t))
	request.OperationID = "urn:imprint:operation:expires"
	request.ExecutionFieldsSHA256 = executionSHA
	created := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	prepared, err := PrepareMutation("authority-test", request, map[string]any{}, map[string]any{}, execution, genesis.OperatorID, created)
	if err != nil {
		t.Fatal(err)
	}
	tx, _ := db.BeginTx(ctx, nil)
	if err = InsertPreparedMutation(ctx, tx, prepared); err != nil {
		t.Fatal(err)
	}
	if _, _, err = LoadVerifiedPreparedMutation(ctx, tx, request.OperationID, "authority-test", genesis.OperatorID, map[string]any{}, map[string]any{}, created.Add(PreparedMutationTTL)); err == nil {
		t.Fatal("accepted expired prepared mutation")
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var status string
	if err = db.QueryRow(`SELECT status FROM authority_prepared_mutations WHERE operation_id=?`, request.OperationID).Scan(&status); err != nil || status != "expired" {
		t.Fatalf("status=%s err=%v", status, err)
	}
}

func approvalDatabase(t *testing.T) (*sql.DB, GenesisEvent, ed25519.PrivateKey) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if err := InitializeSchema(context.Background(), db); err != nil {
		db.Close()
		t.Fatal(err)
	}
	genesis, row := signedGenesis(t)
	_, err = db.Exec(`INSERT INTO authority_keys VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		genesis.KeyID, genesis.OperatorID, genesis.InstallID, genesis.StoreIdentity,
		genesis.PublicKeyB64, genesis.PublicKeyFingerprint, "active", 1,
		genesis.BlobRelativePath, genesis.BlobSHA256, genesis.BlobSize,
		genesis.AlgorithmSuite, genesis.EnrollmentNonce, genesis.CreatedAt)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO authority_ledger VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		row.Sequence, row.EventID, row.EventType, row.OperatorID, row.InstallID, row.KeyID,
		row.EventJSON, row.EventSHA256, row.SignatureB64, row.PreviousEventSHA256, row.CreatedAt)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	return db, genesis, fixturePrivateKey(0)
}
