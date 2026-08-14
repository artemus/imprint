package authority

import (
	"context"
	"database/sql"
)

// Schema is the canonical authority subset shared with the Python 3.1 store.
const Schema = `
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
CREATE TABLE IF NOT EXISTS authority_trust_anchor (
 anchor_id INTEGER PRIMARY KEY CHECK(anchor_id=1),operator_id TEXT NOT NULL,store_identity TEXT NOT NULL,
 genesis_event_sha256 TEXT NOT NULL,recovery_key_id TEXT,recovery_public_key_b64 TEXT,
 pinned_sequence INTEGER NOT NULL CHECK(pinned_sequence>0),pinned_head_sha256 TEXT NOT NULL,
 key_state_sha256 TEXT NOT NULL,checkpoint_sha256 TEXT,checkpoint_json TEXT,
 signer_certificate_sha256 TEXT,updated_at TEXT NOT NULL,
 writes_blocked INTEGER NOT NULL DEFAULT 0 CHECK(writes_blocked IN (0,1)),block_reason TEXT,
 CHECK((writes_blocked=0 AND block_reason IS NULL) OR (writes_blocked=1 AND block_reason IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS authority_checkpoint_pins (
 checkpoint_sha256 TEXT PRIMARY KEY,operator_id TEXT NOT NULL,store_identity TEXT NOT NULL,
 sequence INTEGER NOT NULL CHECK(sequence>0),event_sha256 TEXT NOT NULL,key_state_sha256 TEXT NOT NULL,
 prior_checkpoint_sha256 TEXT,signer_certificate_sha256 TEXT NOT NULL,checkpoint_json TEXT NOT NULL,
 accepted_at TEXT NOT NULL,operation_digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS authority_transfer_intents (
 ticket_id TEXT PRIMARY KEY,checkpoint_sha256 TEXT NOT NULL,checkpoint_json TEXT NOT NULL,
 operation_digest TEXT NOT NULL,prior_anchor_sha256 TEXT NOT NULL,source_store_identity TEXT NOT NULL,
 destination_store_identity TEXT NOT NULL,prior_sequence INTEGER NOT NULL CHECK(prior_sequence>0),
 prior_head_sha256 TEXT NOT NULL,candidate_sequence INTEGER NOT NULL CHECK(candidate_sequence>0),
 candidate_head_sha256 TEXT NOT NULL,prepared_at TEXT NOT NULL,expires_at TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('prepared','finalized','cancelled')),finalized_at TEXT
);
CREATE TABLE IF NOT EXISTS authority_pairing_requests (
 request_id TEXT PRIMARY KEY,request_json TEXT NOT NULL,request_sha256 TEXT NOT NULL UNIQUE,
 key_id TEXT NOT NULL UNIQUE,install_id TEXT NOT NULL UNIQUE,blob_rel_path TEXT NOT NULL UNIQUE,
 blob_sha256 TEXT NOT NULL,blob_size INTEGER NOT NULL CHECK(blob_size>0),
 enrollment_nonce TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL,expires_at TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','finalized','cancelled')),finalized_at TEXT
);
CREATE TABLE IF NOT EXISTS authority_equivocation_proofs (
 proof_id TEXT PRIMARY KEY,conflict_class TEXT NOT NULL,local_proof_json TEXT NOT NULL,
 candidate_proof_json TEXT NOT NULL,local_proof_sha256 TEXT NOT NULL,candidate_proof_sha256 TEXT NOT NULL,
 detected_at TEXT NOT NULL,adjudication_event_sha256 TEXT
);
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
CREATE TABLE IF NOT EXISTS authority_provenance (
 provenance_id TEXT PRIMARY KEY,operation_id TEXT NOT NULL UNIQUE,operator_id TEXT NOT NULL,
 install_id TEXT NOT NULL,key_id TEXT NOT NULL,ledger_sequence INTEGER NOT NULL,
 challenge_json TEXT NOT NULL,challenge_sha256 TEXT NOT NULL,signature_b64 TEXT NOT NULL,
 authority_transition TEXT NOT NULL,committed_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS authority_ledger_no_update BEFORE UPDATE ON authority_ledger BEGIN SELECT RAISE(ABORT,'authority ledger is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_ledger_no_delete BEFORE DELETE ON authority_ledger BEGIN SELECT RAISE(ABORT,'authority ledger is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_checkpoint_pins_no_update BEFORE UPDATE ON authority_checkpoint_pins BEGIN SELECT RAISE(ABORT,'authority checkpoint pins are immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_checkpoint_pins_no_delete BEFORE DELETE ON authority_checkpoint_pins BEGIN SELECT RAISE(ABORT,'authority checkpoint pins are immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_equivocation_proofs_no_update BEFORE UPDATE ON authority_equivocation_proofs
WHEN OLD.proof_id!=NEW.proof_id OR OLD.conflict_class!=NEW.conflict_class OR OLD.local_proof_json!=NEW.local_proof_json
 OR OLD.candidate_proof_json!=NEW.candidate_proof_json OR OLD.local_proof_sha256!=NEW.local_proof_sha256
 OR OLD.candidate_proof_sha256!=NEW.candidate_proof_sha256 OR OLD.detected_at!=NEW.detected_at
BEGIN SELECT RAISE(ABORT,'authority equivocation evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_equivocation_proofs_no_delete BEFORE DELETE ON authority_equivocation_proofs BEGIN SELECT RAISE(ABORT,'authority equivocation evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_prepared_content_immutable BEFORE UPDATE ON authority_prepared_mutations
WHEN OLD.operation_id!=NEW.operation_id OR OLD.command_name!=NEW.command_name OR OLD.operator_id!=NEW.operator_id
 OR OLD.request_json!=NEW.request_json OR OLD.request_sha256!=NEW.request_sha256
 OR OLD.intent_json!=NEW.intent_json OR OLD.intent_sha256!=NEW.intent_sha256
 OR OLD.prior_state_json!=NEW.prior_state_json OR OLD.prior_state_sha256!=NEW.prior_state_sha256
 OR OLD.execution_fields_json!=NEW.execution_fields_json OR OLD.execution_fields_sha256!=NEW.execution_fields_sha256
 OR OLD.created_at!=NEW.created_at OR OLD.expires_at!=NEW.expires_at
BEGIN SELECT RAISE(ABORT,'prepared mutation content is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_provenance_no_update BEFORE UPDATE ON authority_provenance BEGIN SELECT RAISE(ABORT,'authority provenance is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_provenance_no_delete BEFORE DELETE ON authority_provenance BEGIN SELECT RAISE(ABORT,'authority provenance is immutable'); END;
`

type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func InitializeSchema(ctx context.Context, executor sqlExecutor) error {
	_, err := executor.ExecContext(ctx, Schema)
	return err
}
