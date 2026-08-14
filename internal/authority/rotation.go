package authority

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
)

const LifecycleEventVersion = "imprint.authority.ledger-event/1.1.0"

type ChainKey struct {
	KeyCertificate
	Kind, Status, AlgorithmSuite, BlobRelativePath, BlobSHA256 string
	BlobSize                                                   int64
	CertificateSequence                                        int64
	CertificateEventSHA256                                     string
	EffectiveAt                                                string
	CompromisedAt, ReplacementKeyID                            *string
}

type ChainState struct {
	OperatorID, StoreIdentity, HeadSHA256 string
	HeadSequence                          int64
	Keys                                  map[string]ChainKey
}

type lifecycleEvent struct {
	ContractVersion     string          `json:"contract_version"`
	DomainSeparator     string          `json:"domain_separator"`
	Sequence            int64           `json:"sequence"`
	EventID             string          `json:"event_id"`
	EventType           string          `json:"event_type"`
	OperatorID          string          `json:"operator_id"`
	InstallID           string          `json:"install_id"`
	KeyID               string          `json:"key_id"`
	SignedByKeyID       string          `json:"signed_by_key_id"`
	Details             json.RawMessage `json:"details"`
	CreatedAt           string          `json:"created_at"`
	PreviousEventSHA256 *string         `json:"previous_event_sha256"`
}

type rotationDetails struct {
	KeyID                string `json:"key_id"`
	PublicKeyB64         string `json:"public_key_b64"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	InstallID            string `json:"install_id"`
	BlobRelativePath     string `json:"blob_rel_path"`
	BlobSHA256           string `json:"blob_sha256"`
	BlobSize             int64  `json:"blob_size"`
	AlgorithmSuite       string `json:"algorithm_suite"`
	OldKeyID             string `json:"old_key_id"`
}

var rotationDetailFields = []string{"key_id", "public_key_b64", "public_key_fingerprint", "install_id", "blob_rel_path", "blob_sha256", "blob_size", "algorithm_suite", "old_key_id"}

func BeginChain(row LedgerRow, expectedOperatorID, expectedStoreIdentity string) (ChainState, error) {
	genesis, err := VerifyGenesis(row, expectedOperatorID, expectedStoreIdentity)
	if err != nil {
		return ChainState{}, err
	}
	state := ChainState{OperatorID: genesis.OperatorID, StoreIdentity: genesis.StoreIdentity, HeadSHA256: genesis.HeadSHA256, HeadSequence: 1, Keys: map[string]ChainKey{}}
	state.Keys[genesis.Installation.KeyID] = ChainKey{KeyCertificate: genesis.Installation, Kind: "installation", Status: "active", AlgorithmSuite: genesis.AlgorithmSuite, BlobRelativePath: genesis.BlobRelativePath, BlobSHA256: genesis.BlobSHA256, BlobSize: genesis.BlobSize, CertificateSequence: 1, CertificateEventSHA256: genesis.HeadSHA256, EffectiveAt: genesis.CreatedAt}
	if genesis.HasRecovery {
		state.Keys[genesis.Recovery.KeyID] = ChainKey{KeyCertificate: genesis.Recovery, Kind: "recovery", Status: "active", CertificateSequence: 1, CertificateEventSHA256: genesis.HeadSHA256, EffectiveAt: genesis.CreatedAt}
	}
	return state, nil
}

func VerifyRotation(prior ChainState, row LedgerRow) (ChainState, error) {
	event, digest, signer, err := verifyLifecycle(prior, row, "key_rotated")
	if err != nil {
		return ChainState{}, err
	}
	if signer.Kind != "installation" {
		return ChainState{}, errors.New("authority rotation signer is unknown or inactive")
	}
	var details rotationDetails
	if decodeExactObject(event.Details, &details, rotationDetailFields) != nil || details.OldKeyID != event.SignedByKeyID || event.KeyID != details.KeyID || event.InstallID != details.InstallID || details.InstallID != signer.InstallID {
		return ChainState{}, errors.New("authority rotation subject is invalid")
	}
	certificate := KeyCertificate{KeyID: details.KeyID, PublicKeyB64: details.PublicKeyB64, PublicKeyFingerprint: details.PublicKeyFingerprint, InstallID: details.InstallID}
	if err := validateCertificate(certificate); err != nil {
		return ChainState{}, err
	}
	if _, exists := prior.Keys[certificate.KeyID]; exists {
		return ChainState{}, errors.New("authority rotation key already exists")
	}
	if details.AlgorithmSuite != AlgorithmSuite || !lowercaseSHA256.MatchString(details.BlobSHA256) || details.BlobSize <= 0 || !safeRelativeBlobPath(details.BlobRelativePath) {
		return ChainState{}, errors.New("authority rotation blob binding is invalid")
	}
	next := ChainState{OperatorID: prior.OperatorID, StoreIdentity: prior.StoreIdentity, HeadSHA256: digest, HeadSequence: event.Sequence, Keys: cloneKeys(prior.Keys)}
	retired := next.Keys[signer.KeyID]
	retired.Status = "retired"
	retired.EffectiveAt = event.CreatedAt
	next.Keys[signer.KeyID] = retired
	next.Keys[certificate.KeyID] = ChainKey{KeyCertificate: certificate, Kind: "installation", Status: "active", AlgorithmSuite: details.AlgorithmSuite, BlobRelativePath: details.BlobRelativePath, BlobSHA256: details.BlobSHA256, BlobSize: details.BlobSize, CertificateSequence: event.Sequence, CertificateEventSHA256: digest, EffectiveAt: event.CreatedAt}
	return next, nil
}

func verifyLifecycle(prior ChainState, row LedgerRow, eventType string) (lifecycleEvent, string, ChainKey, error) {
	var event lifecycleEvent
	if decodeClosed([]byte(row.EventJSON), &event) != nil {
		return event, "", ChainKey{}, errors.New("authority lifecycle event is malformed")
	}
	if event.ContractVersion != LifecycleEventVersion || event.DomainSeparator != LedgerDomain || event.EventType != eventType || event.Sequence != prior.HeadSequence+1 || event.PreviousEventSHA256 == nil || *event.PreviousEventSHA256 != prior.HeadSHA256 || event.OperatorID != prior.OperatorID {
		return event, "", ChainKey{}, errors.New("authority lifecycle event does not continue the verified chain")
	}
	if row.Sequence != event.Sequence || row.EventID != event.EventID || row.EventType != event.EventType || row.OperatorID != event.OperatorID || row.InstallID != event.InstallID || row.KeyID != event.KeyID || row.PreviousEventSHA256 == nil || *row.PreviousEventSHA256 != *event.PreviousEventSHA256 || row.CreatedAt != event.CreatedAt {
		return event, "", ChainKey{}, errors.New("authority ledger row and signed event disagree")
	}
	signer, known := prior.Keys[event.SignedByKeyID]
	if !known || signer.Status != "active" {
		return event, "", ChainKey{}, errors.New("authority lifecycle signer is unknown or inactive")
	}
	if _, err := utcTimestamp(event.CreatedAt); err != nil {
		return event, "", ChainKey{}, err
	}
	document, encoded, digest, err := canonicalLedgerEvent(row.EventJSON)
	if err != nil || document["event_type"] != eventType || row.EventSHA256 != digest {
		return event, "", ChainKey{}, errors.New("authority ledger event digest mismatch")
	}
	publicKey, err := PublicKeyFromBase64(signer.PublicKeyB64)
	signature, signatureErr := canonicalBase64(row.SignatureB64)
	if err != nil || signatureErr != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, append([]byte(LedgerDomain+"\x00"), encoded...), signature) {
		return event, "", ChainKey{}, errors.New("authority ledger signature is invalid")
	}
	return event, digest, signer, nil
}

func cloneKeys(values map[string]ChainKey) map[string]ChainKey {
	result := make(map[string]ChainKey, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func decodeClosed(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func decodeExactObject(raw []byte, target any, fields []string) error {
	if err := decodeClosed(raw, target); err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || len(object) != len(fields) {
		return errors.New("JSON object has unknown or missing fields")
	}
	for _, field := range fields {
		if _, exists := object[field]; !exists {
			return errors.New("JSON object has unknown or missing fields")
		}
	}
	return nil
}
