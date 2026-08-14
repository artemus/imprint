package authority

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
)

const ApprovalSchema = `
CREATE TABLE IF NOT EXISTS authority_keys (
 key_id TEXT PRIMARY KEY,operator_id TEXT NOT NULL,install_id TEXT NOT NULL,
 store_identity TEXT NOT NULL,public_key_b64 TEXT NOT NULL,public_key_fingerprint TEXT NOT NULL UNIQUE,
 status TEXT NOT NULL CHECK(status IN ('active','retired','revoked','compromised')),
 ledger_sequence INTEGER NOT NULL,blob_rel_path TEXT NOT NULL UNIQUE,blob_sha256 TEXT NOT NULL,
 blob_size INTEGER NOT NULL CHECK(blob_size>0),algorithm_suite TEXT NOT NULL,
 enrollment_nonce TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_authority_key_per_install ON authority_keys(operator_id,install_id) WHERE status='active';
CREATE TABLE IF NOT EXISTS authority_ledger (
 sequence INTEGER PRIMARY KEY CHECK(sequence>0),event_id TEXT NOT NULL UNIQUE,event_type TEXT NOT NULL,
 operator_id TEXT NOT NULL,install_id TEXT NOT NULL,key_id TEXT NOT NULL,event_json TEXT NOT NULL,
 event_sha256 TEXT NOT NULL,signature_b64 TEXT NOT NULL,previous_event_sha256 TEXT,created_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS authority_ledger_no_update BEFORE UPDATE ON authority_ledger BEGIN SELECT RAISE(ABORT,'authority ledger is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_ledger_no_delete BEFORE DELETE ON authority_ledger BEGIN SELECT RAISE(ABORT,'authority ledger is immutable'); END;
CREATE TABLE IF NOT EXISTS authority_challenges (
 nonce_sha256 TEXT PRIMARY KEY,operation_id TEXT NOT NULL,challenge_sha256 TEXT NOT NULL,
 issued_at TEXT NOT NULL,expires_at TEXT NOT NULL,consumed_at TEXT,consumed_provenance_id TEXT
);
CREATE TABLE IF NOT EXISTS authority_prepared_mutations (
 operation_id TEXT PRIMARY KEY,command_name TEXT NOT NULL,operator_id TEXT NOT NULL,
 request_json TEXT NOT NULL,request_sha256 TEXT NOT NULL,intent_json TEXT NOT NULL,intent_sha256 TEXT NOT NULL,
 prior_state_json TEXT NOT NULL,prior_state_sha256 TEXT NOT NULL,
 execution_fields_json TEXT NOT NULL,execution_fields_sha256 TEXT NOT NULL,
 created_at TEXT NOT NULL,expires_at TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','executed','expired','cancelled')),
 executed_at TEXT,provenance_id TEXT
);
CREATE TRIGGER IF NOT EXISTS authority_prepared_content_immutable BEFORE UPDATE ON authority_prepared_mutations
WHEN OLD.operation_id!=NEW.operation_id OR OLD.command_name!=NEW.command_name OR OLD.operator_id!=NEW.operator_id
 OR OLD.request_json!=NEW.request_json OR OLD.request_sha256!=NEW.request_sha256
 OR OLD.intent_json!=NEW.intent_json OR OLD.intent_sha256!=NEW.intent_sha256
 OR OLD.prior_state_json!=NEW.prior_state_json OR OLD.prior_state_sha256!=NEW.prior_state_sha256
 OR OLD.execution_fields_json!=NEW.execution_fields_json OR OLD.execution_fields_sha256!=NEW.execution_fields_sha256
 OR OLD.created_at!=NEW.created_at OR OLD.expires_at!=NEW.expires_at
BEGIN SELECT RAISE(ABORT,'prepared mutation content is immutable'); END;
CREATE TABLE IF NOT EXISTS authority_provenance (
 provenance_id TEXT PRIMARY KEY,operation_id TEXT NOT NULL UNIQUE,operator_id TEXT NOT NULL,
 install_id TEXT NOT NULL,key_id TEXT NOT NULL,ledger_sequence INTEGER NOT NULL,
 challenge_json TEXT NOT NULL,challenge_sha256 TEXT NOT NULL,signature_b64 TEXT NOT NULL,
 authority_transition TEXT NOT NULL,committed_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS authority_provenance_no_update BEFORE UPDATE ON authority_provenance BEGIN SELECT RAISE(ABORT,'authority provenance is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_provenance_no_delete BEFORE DELETE ON authority_provenance BEGIN SELECT RAISE(ABORT,'authority provenance is immutable'); END;
`

type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func InitializeApprovalSchema(ctx context.Context, executor sqlExecutor) error {
	_, err := executor.ExecContext(ctx, ApprovalSchema)
	return err
}

func InsertPreparedMutation(ctx context.Context, tx *sql.Tx, prepared PreparedMutation) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO authority_prepared_mutations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,? ,NULL,NULL)`,
		prepared.OperationID, prepared.CommandName, prepared.OperatorID,
		prepared.RequestJSON, prepared.RequestSHA256, prepared.IntentJSON, prepared.IntentSHA256,
		prepared.PriorStateJSON, prepared.PriorStateSHA256,
		prepared.ExecutionFieldsJSON, prepared.ExecutionFieldsSHA256,
		prepared.CreatedAt, prepared.ExpiresAt, prepared.Status)
	if err != nil {
		return errors.New("prepared mutation operation already exists")
	}
	return nil
}

func LoadPreparedMutation(ctx context.Context, tx *sql.Tx, operationID string) (PreparedMutation, error) {
	var prepared PreparedMutation
	var executedAt, provenanceID sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT operation_id,command_name,operator_id,request_json,request_sha256,intent_json,intent_sha256,prior_state_json,prior_state_sha256,execution_fields_json,execution_fields_sha256,created_at,expires_at,status,executed_at,provenance_id FROM authority_prepared_mutations WHERE operation_id=?`, operationID).Scan(
		&prepared.OperationID, &prepared.CommandName, &prepared.OperatorID,
		&prepared.RequestJSON, &prepared.RequestSHA256, &prepared.IntentJSON, &prepared.IntentSHA256,
		&prepared.PriorStateJSON, &prepared.PriorStateSHA256,
		&prepared.ExecutionFieldsJSON, &prepared.ExecutionFieldsSHA256,
		&prepared.CreatedAt, &prepared.ExpiresAt, &prepared.Status, &executedAt, &provenanceID)
	if errors.Is(err, sql.ErrNoRows) {
		return PreparedMutation{}, errors.New("authority token does not name a stored prepared mutation")
	}
	if err != nil {
		return PreparedMutation{}, err
	}
	if executedAt.Valid {
		prepared.ExecutedAt = &executedAt.String
	}
	if provenanceID.Valid {
		prepared.ProvenanceID = &provenanceID.String
	}
	return prepared, nil
}

func LoadVerifiedPreparedMutation(ctx context.Context, tx *sql.Tx, operationID, commandName, operatorID string, intent, priorState any, now time.Time) (ChallengeRequest, []byte, error) {
	prepared, err := LoadPreparedMutation(ctx, tx, operationID)
	if err != nil {
		return ChallengeRequest{}, nil, err
	}
	expires, parseErr := utcTimestamp(prepared.ExpiresAt)
	if parseErr == nil && !now.UTC().Before(expires) && prepared.Status == "pending" {
		if _, err := tx.ExecContext(ctx, `UPDATE authority_prepared_mutations SET status='expired' WHERE operation_id=? AND status='pending'`, operationID); err != nil {
			return ChallengeRequest{}, nil, err
		}
		return ChallengeRequest{}, nil, errors.New("prepared mutation has expired")
	}
	request, execution, err := prepared.Verify(commandName, operatorID, intent, priorState, now)
	return request, []byte(execution), err
}

func MarkPreparedExecuted(ctx context.Context, tx *sql.Tx, operationID, provenanceID string, now time.Time) error {
	result, err := tx.ExecContext(ctx, `UPDATE authority_prepared_mutations SET status='executed',executed_at=?,provenance_id=? WHERE operation_id=? AND status='pending'`, utcText(now), provenanceID, operationID)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return errors.New("prepared mutation was already executed or expired")
	}
	return nil
}

func IssueChallenge(ctx context.Context, tx *sql.Tx, request ChallengeRequest, expectedOperatorID string, ttl time.Duration, now time.Time, random io.Reader) (Challenge, ActiveBinding, error) {
	binding, err := activeSQLBinding(ctx, tx, expectedOperatorID)
	if err != nil {
		return Challenge{}, ActiveBinding{}, err
	}
	var sequence sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(sequence) FROM authority_ledger`).Scan(&sequence); err != nil || !sequence.Valid {
		return Challenge{}, ActiveBinding{}, errors.New("authority ledger is absent")
	}
	challenge, err := BuildChallenge(request, binding, sequence.Int64, ttl, now, random)
	if err != nil {
		return Challenge{}, ActiveBinding{}, err
	}
	encoded, err := CanonicalChallenge(challenge)
	if err != nil {
		return Challenge{}, ActiveBinding{}, err
	}
	nonceDigest := sha256.Sum256([]byte(challenge.Nonce))
	challengeDigest := sha256.Sum256(encoded)
	_, err = tx.ExecContext(ctx, `INSERT INTO authority_challenges VALUES(?,?,?,?,?,NULL,NULL)`,
		hex.EncodeToString(nonceDigest[:]), challenge.OperationID, hex.EncodeToString(challengeDigest[:]), challenge.IssuedAt, challenge.ExpiresAt)
	if err != nil {
		return Challenge{}, ActiveBinding{}, errors.New("authority nonce or operation collision")
	}
	return challenge, binding, nil
}

func ConsumeApproval(ctx context.Context, tx *sql.Tx, token ApprovalToken, expected ChallengeRequest, expectedOperatorID string, now time.Time) (string, error) {
	if !expected.Matches(token.Challenge) {
		return "", errors.New("authority token does not match the exact mutation")
	}
	binding, err := activeSQLBinding(ctx, tx, expectedOperatorID)
	if err != nil {
		return "", err
	}
	challenge := token.Challenge
	if challenge.OperatorID != binding.OperatorID || challenge.InstallID != binding.InstallID || challenge.KeyID != binding.KeyID || challenge.StoreIdentity != binding.StoreIdentity {
		return "", errors.New("authority token is bound to another operator or installation")
	}
	var head sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(sequence) FROM authority_ledger`).Scan(&head); err != nil || !head.Valid || challenge.LedgerSequence != head.Int64 {
		return "", errors.New("authority token is stale relative to the ledger")
	}
	encoded, err := CanonicalChallenge(challenge)
	if err != nil {
		return "", err
	}
	challengeDigest := sha256.Sum256(encoded)
	nonceDigest := sha256.Sum256([]byte(challenge.Nonce))
	var storedChallengeSHA, operationID string
	var consumedAt sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT challenge_sha256,operation_id,consumed_at FROM authority_challenges WHERE nonce_sha256=?`, hex.EncodeToString(nonceDigest[:])).Scan(&storedChallengeSHA, &operationID, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("authority nonce was not issued by this store")
	}
	if err != nil {
		return "", err
	}
	if storedChallengeSHA != hex.EncodeToString(challengeDigest[:]) || operationID != challenge.OperationID {
		return "", errors.New("authority nonce was not issued by this store")
	}
	if consumedAt.Valid {
		return "", errors.New("authority nonce has already been consumed")
	}
	publicKey, err := PublicKeyFromBase64(binding.PublicKeyB64)
	if err != nil {
		return "", errors.New("authority signature is invalid")
	}
	if err := VerifyApproval(token, publicKey, now); err != nil {
		return "", err
	}
	provenanceID := "urn:imprint:authority-provenance:" + uuid.NewString()
	committedAt := utcText(now)
	_, err = tx.ExecContext(ctx, `INSERT INTO authority_provenance VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		provenanceID, challenge.OperationID, binding.OperatorID, binding.InstallID, binding.KeyID,
		head.Int64, string(encoded), hex.EncodeToString(challengeDigest[:]), token.SignatureB64,
		challenge.AuthorityTransition, committedAt)
	if err != nil {
		return "", errors.New("authority operation or provenance already exists")
	}
	result, err := tx.ExecContext(ctx, `UPDATE authority_challenges SET consumed_at=?,consumed_provenance_id=? WHERE nonce_sha256=? AND consumed_at IS NULL`, committedAt, provenanceID, hex.EncodeToString(nonceDigest[:]))
	if err != nil {
		return "", err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return "", errors.New("authority nonce was consumed concurrently")
	}
	return provenanceID, nil
}

func activeSQLBinding(ctx context.Context, tx *sql.Tx, expectedOperatorID string) (ActiveBinding, error) {
	rows, err := tx.QueryContext(ctx, `SELECT operator_id,install_id,key_id,store_identity,public_key_b64 FROM authority_keys WHERE status='active' ORDER BY ledger_sequence DESC`)
	if err != nil {
		return ActiveBinding{}, err
	}
	defer rows.Close()
	bindings := []ActiveBinding{}
	for rows.Next() {
		var binding ActiveBinding
		if err := rows.Scan(&binding.OperatorID, &binding.InstallID, &binding.KeyID, &binding.StoreIdentity, &binding.PublicKeyB64); err != nil {
			return ActiveBinding{}, err
		}
		bindings = append(bindings, binding)
	}
	if err := rows.Err(); err != nil {
		return ActiveBinding{}, err
	}
	if len(bindings) != 1 {
		return ActiveBinding{}, errors.New("authority requires exactly one active local key")
	}
	if expectedOperatorID != "" && bindings[0].OperatorID != expectedOperatorID {
		return ActiveBinding{}, errors.New("authority key does not match configured operator")
	}
	return bindings[0], nil
}
