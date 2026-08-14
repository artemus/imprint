package authority

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/artemus/imprint/internal/privateio"
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

type AuthorityTransportArtifact struct {
	Bytes     []byte
	Transport AuthorityTransport
	SHA256    string
}

type PublishedAuthorityTransport struct {
	Path, TransportSHA256 string
	Checkpoint            Checkpoint
}

var transportFields = []string{"transport_version", "operator_id", "store_identity", "authority_ledger_genesis_sha256", "ledger", "ledger_sha256", "checkpoint_history", "checkpoint"}
var portableLedgerRowFields = []string{"sequence", "event_id", "event_type", "operator_id", "install_id", "key_id", "event_json", "event_sha256", "signature_b64", "previous_event_sha256", "created_at"}

// BuildAuthorityTransport constructs and self-verifies the public chain and
// closed checkpoint history before publication.
func BuildAuthorityTransport(rows []LedgerRow, history []Checkpoint, checkpoint Checkpoint, now time.Time) (AuthorityTransportArtifact, error) {
	if len(rows) == 0 || len(history) == 0 {
		return AuthorityTransportArtifact{}, errors.New("authority transport ledger or checkpoint history is empty")
	}
	chain, err := VerifyChain(rows, rows[0].OperatorID, "")
	if err != nil {
		return AuthorityTransportArtifact{}, err
	}
	portable := make([]PortableLedgerRow, len(rows))
	ledgerRaw := make([]json.RawMessage, len(rows))
	for index, row := range rows {
		portable[index] = portableRow(row)
		encoded, encodeErr := canonicalContract(portable[index])
		if encodeErr != nil {
			return AuthorityTransportArtifact{}, encodeErr
		}
		ledgerRaw[index] = encoded
	}
	ledgerSHA, err := LedgerSHA256(portable)
	if err != nil {
		return AuthorityTransportArtifact{}, err
	}
	historyRaw := make([]json.RawMessage, len(history))
	for index, item := range history {
		encoded, encodeErr := canonicalContract(item)
		if encodeErr != nil {
			return AuthorityTransportArtifact{}, encodeErr
		}
		historyRaw[index] = encoded
	}
	checkpointRaw, err := canonicalContract(checkpoint)
	if err != nil {
		return AuthorityTransportArtifact{}, err
	}
	transport := AuthorityTransport{
		TransportVersion: TransportVersion, OperatorID: chain.OperatorID,
		StoreIdentity: chain.StoreIdentity, AuthorityLedgerGenesisSHA256: chain.GenesisSHA256,
		Ledger: ledgerRaw, LedgerSHA256: ledgerSHA,
		CheckpointHistory: historyRaw, Checkpoint: checkpointRaw,
	}
	encoded, err := canonicalContract(transport)
	if err != nil {
		return AuthorityTransportArtifact{}, err
	}
	encoded = append(encoded, '\n')
	if _, err := VerifyAuthorityTransport(encoded, now); err != nil {
		return AuthorityTransportArtifact{}, err
	}
	digest := sha256.Sum256(encoded)
	return AuthorityTransportArtifact{Bytes: encoded, Transport: transport, SHA256: hex.EncodeToString(digest[:])}, nil
}

func PublishAuthorityTransport(destination string, artifact AuthorityTransportArtifact, now time.Time) (PublishedAuthorityTransport, error) {
	absolute, err := filepath.Abs(destination)
	if err != nil || len(artifact.Bytes) == 0 || !lowercaseSHA256.MatchString(artifact.SHA256) {
		return PublishedAuthorityTransport{}, errors.New("authority transport publication is invalid")
	}
	digest := sha256.Sum256(artifact.Bytes)
	if hex.EncodeToString(digest[:]) != artifact.SHA256 {
		return PublishedAuthorityTransport{}, errors.New("authority transport publication digest mismatch")
	}
	verified, err := VerifyAuthorityTransport(artifact.Bytes, now)
	if err != nil {
		return PublishedAuthorityTransport{}, err
	}
	if err := privateio.PublishNew(absolute, artifact.Bytes); err != nil {
		return PublishedAuthorityTransport{}, err
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return PublishedAuthorityTransport{}, errors.New("published authority transport is not a regular file")
	}
	raw, err := os.ReadFile(absolute)
	if err != nil || !bytes.Equal(raw, artifact.Bytes) {
		return PublishedAuthorityTransport{}, errors.New("published authority transport failed verification")
	}
	checkpoint, err := DecodeCanonicalCheckpoint(verified.Transport.Checkpoint)
	if err != nil {
		return PublishedAuthorityTransport{}, err
	}
	return PublishedAuthorityTransport{Path: absolute, TransportSHA256: artifact.SHA256, Checkpoint: checkpoint}, nil
}

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
