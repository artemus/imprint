package authority

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// LoadTrustAnchor loads the destination-owned monotonic authority pin. A nil
// result means this store has not established local trust yet.
func LoadTrustAnchor(ctx context.Context, queryer rowQuerier) (*AuthorityTrustAnchor, error) {
	var anchor AuthorityTrustAnchor
	var recoveryKeyID, recoveryPublicKeyB64 sql.NullString
	var checkpointSHA256, checkpointJSON, certificateSHA256 sql.NullString
	var blocked int
	var blockReason sql.NullString
	err := queryer.QueryRowContext(ctx, `SELECT operator_id,store_identity,genesis_event_sha256,recovery_key_id,recovery_public_key_b64,pinned_sequence,pinned_head_sha256,key_state_sha256,checkpoint_sha256,checkpoint_json,signer_certificate_sha256,updated_at,writes_blocked,block_reason FROM authority_trust_anchor WHERE anchor_id=1`).Scan(
		&anchor.OperatorID, &anchor.StoreIdentity, &anchor.GenesisEventSHA256,
		&recoveryKeyID, &recoveryPublicKeyB64, &anchor.PinnedSequence,
		&anchor.PinnedHeadSHA256, &anchor.KeyStateSHA256, &checkpointSHA256,
		&checkpointJSON, &certificateSHA256, &anchor.UpdatedAt, &blocked, &blockReason,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if recoveryKeyID.Valid {
		anchor.RecoveryKeyID = &recoveryKeyID.String
	}
	if recoveryPublicKeyB64.Valid {
		anchor.RecoveryPublicKeyB64 = &recoveryPublicKeyB64.String
	}
	if checkpointSHA256.Valid {
		anchor.CheckpointSHA256 = &checkpointSHA256.String
	}
	if certificateSHA256.Valid {
		anchor.SignerCertificateSHA256 = &certificateSHA256.String
	}
	if blockReason.Valid {
		anchor.BlockReason = &blockReason.String
	}
	anchor.WritesBlocked = blocked != 0
	if checkpointJSON.Valid {
		checkpoint, decodeErr := decodeCheckpoint([]byte(checkpointJSON.String))
		if decodeErr != nil {
			return nil, errors.New("local authority trust anchor is corrupt")
		}
		anchor.Checkpoint = &checkpoint
	}
	if (anchor.RecoveryKeyID == nil) != (anchor.RecoveryPublicKeyB64 == nil) ||
		(anchor.CheckpointSHA256 == nil) != (anchor.Checkpoint == nil) ||
		(anchor.CheckpointSHA256 == nil) != (anchor.SignerCertificateSHA256 == nil) ||
		anchor.PinnedSequence < 1 || !lowercaseSHA256.MatchString(anchor.GenesisEventSHA256) ||
		!lowercaseSHA256.MatchString(anchor.PinnedHeadSHA256) || !lowercaseSHA256.MatchString(anchor.KeyStateSHA256) ||
		(anchor.WritesBlocked != (anchor.BlockReason != nil)) {
		return nil, errors.New("local authority trust anchor is corrupt")
	}
	if _, err := utcTimestamp(anchor.UpdatedAt); err != nil {
		return nil, errors.New("local authority trust anchor is corrupt")
	}
	if anchor.Checkpoint != nil {
		checkpointSHA, err := canonicalValueSHA256(*anchor.Checkpoint)
		certificateSHA, certificateErr := canonicalValueSHA256(anchor.Checkpoint.SignerCertificate)
		if err != nil || certificateErr != nil || checkpointSHA != *anchor.CheckpointSHA256 || certificateSHA != *anchor.SignerCertificateSHA256 {
			return nil, errors.New("local authority trust anchor is corrupt")
		}
	}
	return &anchor, nil
}

// EstablishEnrollmentTrust pins the first verified chain head and its initial
// checkpoint. The caller owns the enrollment transaction.
func EstablishEnrollmentTrust(ctx context.Context, tx *sql.Tx, chain VerifiedChain, recoveryKeyID, recoveryPublicKeyB64 *string, checkpoint Checkpoint, now time.Time) (AuthorityTrustAnchor, error) {
	existing, err := LoadTrustAnchor(ctx, tx)
	if err != nil {
		return AuthorityTrustAnchor{}, err
	}
	if existing != nil {
		return AuthorityTrustAnchor{}, errors.New("authority trust anchor already exists")
	}
	if err := ValidateRecoveryAnchor(chain, recoveryKeyID, recoveryPublicKeyB64); err != nil {
		return AuthorityTrustAnchor{}, err
	}
	if checkpoint.PriorCheckpointSHA256 != nil {
		return AuthorityTrustAnchor{}, errors.New("trust bootstrap checkpoint history is not closed")
	}
	raw, err := canonicalContract(checkpoint)
	if err != nil {
		return AuthorityTrustAnchor{}, err
	}
	verified, err := VerifyCheckpoint(chain, raw, now.UTC(), MaxCheckpointAge, true)
	if err != nil {
		return AuthorityTrustAnchor{}, err
	}
	snapshot, exists := chain.Snapshots[chain.HeadSequence]
	if !exists || verified.Sequence != chain.HeadSequence || verified.EventSHA256 != chain.HeadSHA256 || verified.KeyStateSHA256 != snapshot.KeyStateSHA256 {
		return AuthorityTrustAnchor{}, errors.New("enrollment checkpoint does not pin the verified head")
	}
	certificateSHA, err := canonicalValueSHA256(checkpoint.SignerCertificate)
	if err != nil {
		return AuthorityTrustAnchor{}, err
	}
	accepted := utcText(now)
	if _, err = tx.ExecContext(ctx, `INSERT INTO authority_trust_anchor(anchor_id,operator_id,store_identity,genesis_event_sha256,recovery_key_id,recovery_public_key_b64,pinned_sequence,pinned_head_sha256,key_state_sha256,checkpoint_sha256,checkpoint_json,signer_certificate_sha256,updated_at,writes_blocked,block_reason) VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?,0,NULL)`,
		chain.OperatorID, chain.StoreIdentity, chain.GenesisSHA256, recoveryKeyID,
		recoveryPublicKeyB64, chain.HeadSequence, chain.HeadSHA256, snapshot.KeyStateSHA256,
		verified.CheckpointSHA256, string(raw), certificateSHA, accepted); err != nil {
		return AuthorityTrustAnchor{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO authority_checkpoint_pins(checkpoint_sha256,operator_id,store_identity,sequence,event_sha256,key_state_sha256,prior_checkpoint_sha256,signer_certificate_sha256,checkpoint_json,accepted_at,operation_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		verified.CheckpointSHA256, chain.OperatorID, chain.StoreIdentity, chain.HeadSequence,
		chain.HeadSHA256, snapshot.KeyStateSHA256, nil, certificateSHA, string(raw), accepted,
		"trust-bootstrap"); err != nil {
		return AuthorityTrustAnchor{}, err
	}
	stored, err := LoadTrustAnchor(ctx, tx)
	if err != nil {
		return AuthorityTrustAnchor{}, err
	}
	if stored == nil {
		return AuthorityTrustAnchor{}, errors.New("authority trust anchor was not persisted")
	}
	return *stored, nil
}

func AssertAuthorityWritesAllowed(ctx context.Context, queryer rowQuerier) (AuthorityTrustAnchor, error) {
	anchor, err := LoadTrustAnchor(ctx, queryer)
	if err != nil {
		return AuthorityTrustAnchor{}, err
	}
	if anchor == nil {
		return AuthorityTrustAnchor{}, errors.New("authority writes require a destination-owned trust anchor")
	}
	if anchor.WritesBlocked {
		return AuthorityTrustAnchor{}, errors.New("authority writes are blocked pending native signed adjudication: " + *anchor.BlockReason)
	}
	return *anchor, nil
}

// PinLocalCheckpoint advances the destination-owned trust anchor to a locally
// verified checkpoint. The pin and anchor update share the caller's transaction.
func PinLocalCheckpoint(ctx context.Context, tx *sql.Tx, chain VerifiedChain, checkpoint Checkpoint, operationDigest string, now time.Time) (AuthorityTrustAnchor, error) {
	anchor, err := AssertAuthorityWritesAllowed(ctx, tx)
	if err != nil {
		return AuthorityTrustAnchor{}, err
	}
	if operationDigest == "" {
		return AuthorityTrustAnchor{}, errors.New("local checkpoint operation digest is empty")
	}
	if chain.OperatorID != anchor.OperatorID || chain.StoreIdentity != anchor.StoreIdentity || chain.GenesisSHA256 != anchor.GenesisEventSHA256 {
		return AuthorityTrustAnchor{}, errors.New("local checkpoint belongs to another trust genesis")
	}
	if err := VerifyPinnedHead(chain, anchor.PinnedSequence, anchor.PinnedHeadSHA256); err != nil {
		return AuthorityTrustAnchor{}, err
	}
	raw, err := canonicalContract(checkpoint)
	if err != nil {
		return AuthorityTrustAnchor{}, err
	}
	verified, err := VerifyCheckpoint(chain, raw, now.UTC(), MaxCheckpointAge, true)
	if err != nil {
		return AuthorityTrustAnchor{}, err
	}
	if verified.Sequence < anchor.PinnedSequence {
		return AuthorityTrustAnchor{}, errors.New("local checkpoint would roll back the trusted head")
	}
	if verified.Sequence == anchor.PinnedSequence && verified.EventSHA256 != anchor.PinnedHeadSHA256 {
		return AuthorityTrustAnchor{}, errors.New("local checkpoint equivocates at the trusted sequence")
	}
	if !equalOptionalString(checkpoint.PriorCheckpointSHA256, anchor.CheckpointSHA256) {
		return AuthorityTrustAnchor{}, errors.New("local checkpoint does not extend the pinned checkpoint")
	}
	certificateSHA, err := canonicalValueSHA256(checkpoint.SignerCertificate)
	if err != nil {
		return AuthorityTrustAnchor{}, err
	}
	accepted := utcText(now)
	if _, err = tx.ExecContext(ctx, `INSERT INTO authority_checkpoint_pins(checkpoint_sha256,operator_id,store_identity,sequence,event_sha256,key_state_sha256,prior_checkpoint_sha256,signer_certificate_sha256,checkpoint_json,accepted_at,operation_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		verified.CheckpointSHA256, chain.OperatorID, chain.StoreIdentity, verified.Sequence,
		verified.EventSHA256, verified.KeyStateSHA256, checkpoint.PriorCheckpointSHA256,
		certificateSHA, string(raw), accepted, operationDigest); err != nil {
		return AuthorityTrustAnchor{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE authority_trust_anchor SET pinned_sequence=?,pinned_head_sha256=?,key_state_sha256=?,checkpoint_sha256=?,checkpoint_json=?,signer_certificate_sha256=?,updated_at=? WHERE anchor_id=1`,
		verified.Sequence, verified.EventSHA256, verified.KeyStateSHA256,
		verified.CheckpointSHA256, string(raw), certificateSHA, accepted); err != nil {
		return AuthorityTrustAnchor{}, err
	}
	stored, err := LoadTrustAnchor(ctx, tx)
	if err != nil {
		return AuthorityTrustAnchor{}, err
	}
	if stored == nil || stored.CheckpointSHA256 == nil || *stored.CheckpointSHA256 != verified.CheckpointSHA256 {
		return AuthorityTrustAnchor{}, errors.New("local checkpoint trust anchor was not persisted")
	}
	return *stored, nil
}
