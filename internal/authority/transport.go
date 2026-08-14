package authority

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

const TransportVersion = "imprint.authority.transport/1.0.0"

type PortableLedgerRow struct {
	Sequence            int64   `json:"sequence"`
	EventID             string  `json:"event_id"`
	EventType           string  `json:"event_type"`
	OperatorID          string  `json:"operator_id"`
	InstallID           string  `json:"install_id"`
	KeyID               string  `json:"key_id"`
	EventJSON           string  `json:"event_json"`
	EventSHA256         string  `json:"event_sha256"`
	SignatureB64        string  `json:"signature_b64"`
	PreviousEventSHA256 *string `json:"previous_event_sha256"`
	CreatedAt           string  `json:"created_at"`
}

type AuthorityTransport struct {
	TransportVersion             string            `json:"transport_version"`
	OperatorID                   string            `json:"operator_id"`
	StoreIdentity                string            `json:"store_identity"`
	AuthorityLedgerGenesisSHA256 string            `json:"authority_ledger_genesis_sha256"`
	Ledger                       []json.RawMessage `json:"ledger"`
	LedgerSHA256                 string            `json:"ledger_sha256"`
	CheckpointHistory            []json.RawMessage `json:"checkpoint_history"`
	Checkpoint                   json.RawMessage   `json:"checkpoint"`
}

type VerifiedAuthorityTransport struct {
	Transport  AuthorityTransport
	Ledger     []PortableLedgerRow
	Chain      VerifiedChain
	Checkpoint CheckpointResult
}

var transportFields = []string{"transport_version", "operator_id", "store_identity", "authority_ledger_genesis_sha256", "ledger", "ledger_sha256", "checkpoint_history", "checkpoint"}
var portableLedgerRowFields = []string{"sequence", "event_id", "event_type", "operator_id", "install_id", "key_id", "event_json", "event_sha256", "signature_b64", "previous_event_sha256", "created_at"}

// VerifyAuthorityTransport verifies the canonical, newline-terminated public
// transport artifact, its ledger, and its fresh closed checkpoint history.
func VerifyAuthorityTransport(raw []byte, now time.Time) (VerifiedAuthorityTransport, error) {
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return VerifiedAuthorityTransport{}, errors.New("authority transport is not canonical")
	}
	body := raw[:len(raw)-1]
	var transport AuthorityTransport
	if decodeExactObject(body, &transport, transportFields) != nil || transport.TransportVersion != TransportVersion {
		return VerifiedAuthorityTransport{}, errors.New("authority transport has unknown fields or version")
	}
	canonical, err := canonicalContract(transport)
	if err != nil || !bytes.Equal(canonical, body) {
		return VerifiedAuthorityTransport{}, errors.New("authority transport is not canonical")
	}
	portableRows, rows, err := decodePortableLedger(transport.Ledger)
	if err != nil {
		return VerifiedAuthorityTransport{}, err
	}
	ledgerSHA, err := rawLedgerSHA256(transport.Ledger)
	if err != nil || ledgerSHA != transport.LedgerSHA256 {
		return VerifiedAuthorityTransport{}, errors.New("authority transport ledger digest mismatch")
	}
	chain, err := VerifyChain(rows, transport.OperatorID, transport.StoreIdentity)
	if err != nil {
		return VerifiedAuthorityTransport{}, err
	}
	results, err := VerifyCheckpointHistory(chain, transport.CheckpointHistory, nil, now)
	if err != nil {
		return VerifiedAuthorityTransport{}, err
	}
	latest, err := canonicalContract(json.RawMessage(transport.Checkpoint))
	lastHistory, historyErr := canonicalContract(json.RawMessage(transport.CheckpointHistory[len(transport.CheckpointHistory)-1]))
	if err != nil || historyErr != nil || !bytes.Equal(latest, lastHistory) {
		return VerifiedAuthorityTransport{}, errors.New("authority transport latest checkpoint is inconsistent")
	}
	checkpoint, err := VerifyCheckpoint(chain, transport.Checkpoint, now, MaxCheckpointAge, true)
	if err != nil {
		return VerifiedAuthorityTransport{}, err
	}
	if chain.GenesisSHA256 != transport.AuthorityLedgerGenesisSHA256 {
		return VerifiedAuthorityTransport{}, errors.New("authority transport genesis binding mismatch")
	}
	if checkpoint.CheckpointSHA256 != results[len(results)-1].CheckpointSHA256 {
		return VerifiedAuthorityTransport{}, errors.New("authority transport latest checkpoint is inconsistent")
	}
	return VerifiedAuthorityTransport{Transport: transport, Ledger: portableRows, Chain: chain, Checkpoint: checkpoint}, nil
}

func LedgerSHA256(rows []PortableLedgerRow) (string, error) {
	encoded, err := canonicalContract(struct {
		Ledger []PortableLedgerRow `json:"ledger"`
	}{Ledger: rows})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func rawLedgerSHA256(rows []json.RawMessage) (string, error) {
	encoded, err := canonicalContract(struct {
		Ledger []json.RawMessage `json:"ledger"`
	}{Ledger: rows})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func decodePortableLedger(rows []json.RawMessage) ([]PortableLedgerRow, []LedgerRow, error) {
	portable := make([]PortableLedgerRow, len(rows))
	result := make([]LedgerRow, len(rows))
	for index, raw := range rows {
		var row PortableLedgerRow
		if decodeExactObject(raw, &row, portableLedgerRowFields) != nil {
			return nil, nil, errors.New("authority ledger row has unknown or missing fields")
		}
		portable[index] = row
		result[index] = LedgerRow{
			Sequence: row.Sequence, EventID: row.EventID, EventType: row.EventType,
			OperatorID: row.OperatorID, InstallID: row.InstallID, KeyID: row.KeyID,
			EventJSON: row.EventJSON, EventSHA256: row.EventSHA256,
			SignatureB64: row.SignatureB64, PreviousEventSHA256: row.PreviousEventSHA256,
			CreatedAt: row.CreatedAt,
		}
	}
	return portable, result, nil
}

func portableRow(row LedgerRow) PortableLedgerRow {
	return PortableLedgerRow{
		Sequence: row.Sequence, EventID: row.EventID, EventType: row.EventType,
		OperatorID: row.OperatorID, InstallID: row.InstallID, KeyID: row.KeyID,
		EventJSON: row.EventJSON, EventSHA256: row.EventSHA256,
		SignatureB64: row.SignatureB64, PreviousEventSHA256: row.PreviousEventSHA256,
		CreatedAt: row.CreatedAt,
	}
}
