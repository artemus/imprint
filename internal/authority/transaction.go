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
