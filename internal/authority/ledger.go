package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
)

const (
	LedgerDomain        = "imprint-authority-ledger-v1"
	GenesisEventVersion = "imprint.authority.ledger-event/1.0.0"
)

type KeyCertificate struct {
	KeyID                string `json:"key_id"`
	PublicKeyB64         string `json:"public_key_b64"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	InstallID            string `json:"install_id"`
}

type GenesisEvent struct {
	ContractVersion      string          `json:"contract_version"`
	DomainSeparator      string          `json:"domain_separator"`
	Sequence             int64           `json:"sequence"`
	EventID              string          `json:"event_id"`
	EventType            string          `json:"event_type"`
	OperatorID           string          `json:"operator_id"`
	InstallID            string          `json:"install_id"`
	StoreIdentity        string          `json:"store_identity"`
	KeyID                string          `json:"key_id"`
	PublicKeyB64         string          `json:"public_key_b64"`
	PublicKeyFingerprint string          `json:"public_key_fingerprint"`
	AlgorithmSuite       string          `json:"algorithm_suite"`
	EnrollmentNonce      string          `json:"enrollment_nonce"`
	BlobRelativePath     string          `json:"blob_rel_path"`
	BlobSHA256           string          `json:"blob_sha256"`
	BlobSize             int64           `json:"blob_size"`
	Status               string          `json:"status"`
	CreatedAt            string          `json:"created_at"`
	PreviousEventSHA256  *string         `json:"previous_event_sha256"`
	RecoveryBinding      *KeyCertificate `json:"recovery_binding,omitempty"`
}

type LedgerRow struct {
	Sequence            int64
	EventID, EventType  string
	OperatorID          string
	InstallID, KeyID    string
	EventJSON           string
	EventSHA256         string
	SignatureB64        string
	PreviousEventSHA256 *string
	CreatedAt           string
}

type GenesisState struct {
	OperatorID, StoreIdentity, HeadSHA256 string
	CreatedAt                             string
	AlgorithmSuite, BlobRelativePath      string
	BlobSHA256                            string
	BlobSize                              int64
	Installation, Recovery                KeyCertificate
	HasRecovery                           bool
}

// CanonicalGenesisTransition returns the exact bytes shown to the operator
// before a recovery-bound genesis is signed and committed.
func CanonicalGenesisTransition(event GenesisEvent) ([]byte, error) {
	return canonicalContract(event)
}

// SignGenesis creates the exact canonical row committed at enrollment. The
// result is verified before it can reach SQLite, including the private/public
// key binding carried by the signature.
func SignGenesis(event GenesisEvent, privateKey ed25519.PrivateKey) (LedgerRow, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return LedgerRow{}, errors.New("authority private key is invalid")
	}
	encoded, err := canonicalContract(event)
	if err != nil {
		return LedgerRow{}, err
	}
	digest := sha256.Sum256(encoded)
	row := LedgerRow{
		Sequence: event.Sequence, EventID: event.EventID, EventType: event.EventType,
		OperatorID: event.OperatorID, InstallID: event.InstallID, KeyID: event.KeyID,
		EventJSON: string(encoded), EventSHA256: hex.EncodeToString(digest[:]),
		SignatureB64:        base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, append([]byte(LedgerDomain+"\x00"), encoded...))),
		PreviousEventSHA256: event.PreviousEventSHA256, CreatedAt: event.CreatedAt,
	}
	if _, err := VerifyGenesis(row, event.OperatorID, event.StoreIdentity); err != nil {
		return LedgerRow{}, err
	}
	return row, nil
}

// InsertGenesis atomically materializes the signed enrollment event and its
// local encrypted-key binding. The caller owns the surrounding transaction.
func InsertGenesis(ctx context.Context, tx *sql.Tx, event GenesisEvent, privateKey ed25519.PrivateKey) (LedgerRow, error) {
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM authority_ledger LIMIT 1)`).Scan(&exists); err != nil {
		return LedgerRow{}, err
	}
	if exists {
		return LedgerRow{}, errors.New("authority is already enrolled")
	}
	row, err := SignGenesis(event, privateKey)
	if err != nil {
		return LedgerRow{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO authority_ledger(sequence,event_id,event_type,operator_id,install_id,key_id,event_json,event_sha256,signature_b64,previous_event_sha256,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		row.Sequence, row.EventID, row.EventType, row.OperatorID, row.InstallID, row.KeyID,
		row.EventJSON, row.EventSHA256, row.SignatureB64, row.PreviousEventSHA256, row.CreatedAt); err != nil {
		return LedgerRow{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO authority_keys(key_id,operator_id,install_id,store_identity,public_key_b64,public_key_fingerprint,status,ledger_sequence,blob_rel_path,blob_sha256,blob_size,algorithm_suite,enrollment_nonce,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		event.KeyID, event.OperatorID, event.InstallID, event.StoreIdentity,
		event.PublicKeyB64, event.PublicKeyFingerprint, event.Status, event.Sequence,
		event.BlobRelativePath, event.BlobSHA256, event.BlobSize, event.AlgorithmSuite,
		event.EnrollmentNonce, event.CreatedAt); err != nil {
		return LedgerRow{}, err
	}
	return row, nil
}

func VerifyGenesis(row LedgerRow, expectedOperatorID, expectedStoreIdentity string) (GenesisState, error) {
	var event GenesisEvent
	decoder := json.NewDecoder(strings.NewReader(row.EventJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		return GenesisState{}, errors.New("authority ledger genesis is malformed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return GenesisState{}, errors.New("authority ledger genesis is malformed")
	}
	var document map[string]any
	documentDecoder := json.NewDecoder(strings.NewReader(row.EventJSON))
	documentDecoder.UseNumber()
	if err := documentDecoder.Decode(&document); err != nil {
		return GenesisState{}, errors.New("authority ledger genesis is malformed")
	}
	if event.ContractVersion != GenesisEventVersion || event.DomainSeparator != LedgerDomain || event.Sequence != 1 || event.EventType != "enrollment" || event.Status != "active" || event.PreviousEventSHA256 != nil {
		return GenesisState{}, errors.New("authority ledger genesis contract is unsupported")
	}
	if expectedOperatorID == "" || event.OperatorID != expectedOperatorID {
		return GenesisState{}, errors.New("authority ledger operator mismatch")
	}
	if expectedStoreIdentity != "" && event.StoreIdentity != expectedStoreIdentity {
		return GenesisState{}, errors.New("authority ledger store identity mismatch")
	}
	if event.EventID == "" || event.StoreIdentity == "" || row.Sequence != 1 || row.EventID != event.EventID || row.EventType != event.EventType || row.OperatorID != event.OperatorID || row.InstallID != event.InstallID || row.KeyID != event.KeyID || row.PreviousEventSHA256 != nil || row.CreatedAt != event.CreatedAt {
		return GenesisState{}, errors.New("authority ledger row and signed event disagree")
	}
	if err := validateCertificate(KeyCertificate{KeyID: event.KeyID, PublicKeyB64: event.PublicKeyB64, PublicKeyFingerprint: event.PublicKeyFingerprint, InstallID: event.InstallID}); err != nil {
		return GenesisState{}, err
	}
	if event.RecoveryBinding != nil {
		if err := validateCertificate(*event.RecoveryBinding); err != nil {
			return GenesisState{}, errors.New("authority genesis recovery binding is invalid")
		}
		if event.RecoveryBinding.KeyID == event.KeyID {
			return GenesisState{}, errors.New("authority genesis key identities collide")
		}
	}
	if event.AlgorithmSuite != AlgorithmSuite || !lowercaseSHA256.MatchString(event.BlobSHA256) || event.BlobSize <= 0 || !safeRelativeBlobPath(event.BlobRelativePath) || event.EnrollmentNonce == "" {
		return GenesisState{}, errors.New("authority genesis key binding is invalid")
	}
	if _, err := utcTimestamp(event.CreatedAt); err != nil {
		return GenesisState{}, err
	}
	encoded, err := canonicalContract(document)
	if err != nil {
		return GenesisState{}, err
	}
	digest := sha256.Sum256(encoded)
	digestText := hex.EncodeToString(digest[:])
	if row.EventSHA256 != digestText {
		return GenesisState{}, errors.New("authority ledger event digest mismatch")
	}
	publicKey, err := PublicKeyFromBase64(event.PublicKeyB64)
	if err != nil {
		return GenesisState{}, err
	}
	signature, err := canonicalBase64(row.SignatureB64)
	message := append([]byte(LedgerDomain+"\x00"), encoded...)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, message, signature) {
		return GenesisState{}, errors.New("authority ledger signature is invalid")
	}
	state := GenesisState{
		OperatorID: event.OperatorID, StoreIdentity: event.StoreIdentity,
		HeadSHA256: digestText, CreatedAt: event.CreatedAt,
		AlgorithmSuite: event.AlgorithmSuite, BlobRelativePath: event.BlobRelativePath,
		BlobSHA256: event.BlobSHA256, BlobSize: event.BlobSize,
		Installation: KeyCertificate{KeyID: event.KeyID, PublicKeyB64: event.PublicKeyB64, PublicKeyFingerprint: event.PublicKeyFingerprint, InstallID: event.InstallID},
	}
	if event.RecoveryBinding != nil {
		state.Recovery, state.HasRecovery = *event.RecoveryBinding, true
	}
	return state, nil
}

func validateCertificate(value KeyCertificate) error {
	publicKey, err := PublicKeyFromBase64(value.PublicKeyB64)
	if err != nil || value.KeyID == "" || value.InstallID == "" {
		return errors.New("authority ledger public key is invalid")
	}
	digest := sha256.Sum256(publicKey)
	if value.PublicKeyFingerprint != "sha256:"+hex.EncodeToString(digest[:]) {
		return errors.New("authority ledger public key fingerprint mismatch")
	}
	return nil
}

func canonicalLedgerEvent(raw string) (map[string]any, []byte, string, error) {
	var document map[string]any
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, nil, "", err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, nil, "", errors.New("authority ledger event contains trailing JSON")
	}
	encoded, err := canonicalContract(document)
	if err != nil {
		return nil, nil, "", err
	}
	digest := sha256.Sum256(encoded)
	return document, encoded, hex.EncodeToString(digest[:]), nil
}

func safeRelativeBlobPath(value string) bool {
	portable := strings.ReplaceAll(value, `\`, "/")
	if portable == "" || strings.HasPrefix(portable, "/") || (len(portable) >= 2 && portable[1] == ':') {
		return false
	}
	for _, part := range strings.Split(portable, "/") {
		if part == ".." {
			return false
		}
	}
	clean := path.Clean(portable)
	return clean != "." && !strings.ContainsRune(clean, '\x00')
}
