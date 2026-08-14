package authority

import (
	"crypto/ed25519"
	"crypto/sha256"
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
	Installation, Recovery                KeyCertificate
	HasRecovery                           bool
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
	state := GenesisState{OperatorID: event.OperatorID, StoreIdentity: event.StoreIdentity, HeadSHA256: digestText, Installation: KeyCertificate{KeyID: event.KeyID, PublicKeyB64: event.PublicKeyB64, PublicKeyFingerprint: event.PublicKeyFingerprint, InstallID: event.InstallID}}
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
