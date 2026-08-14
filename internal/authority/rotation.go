package authority

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const LifecycleEventVersion = "imprint.authority.ledger-event/1.1.0"

type ChainKey struct {
	KeyCertificate
	Kind, Status, AlgorithmSuite, BlobRelativePath, BlobSHA256 string
	BlobSize                                                   int64
	CertificateSequence                                        int64
	CertificateEventSHA256                                     string
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

func BeginChain(row LedgerRow, expectedOperatorID, expectedStoreIdentity string) (ChainState, error) {
	genesis, err := VerifyGenesis(row, expectedOperatorID, expectedStoreIdentity)
	if err != nil {
		return ChainState{}, err
	}
	state := ChainState{OperatorID: genesis.OperatorID, StoreIdentity: genesis.StoreIdentity, HeadSHA256: genesis.HeadSHA256, HeadSequence: 1, Keys: map[string]ChainKey{}}
	state.Keys[genesis.Installation.KeyID] = ChainKey{KeyCertificate: genesis.Installation, Kind: "installation", Status: "active", CertificateSequence: 1, CertificateEventSHA256: genesis.HeadSHA256}
	if genesis.HasRecovery {
		state.Keys[genesis.Recovery.KeyID] = ChainKey{KeyCertificate: genesis.Recovery, Kind: "recovery", Status: "active", CertificateSequence: 1, CertificateEventSHA256: genesis.HeadSHA256}
	}
	return state, nil
}

func VerifyRotation(prior ChainState, row LedgerRow) (ChainState, error) {
	var event lifecycleEvent
	decoder := json.NewDecoder(strings.NewReader(row.EventJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		return ChainState{}, errors.New("authority lifecycle event is malformed")
	}
	if event.ContractVersion != LifecycleEventVersion || event.DomainSeparator != LedgerDomain || event.EventType != "key_rotated" || event.Sequence != prior.HeadSequence+1 || event.PreviousEventSHA256 == nil || *event.PreviousEventSHA256 != prior.HeadSHA256 || event.OperatorID != prior.OperatorID {
		return ChainState{}, errors.New("authority rotation does not continue the verified chain")
	}
	if row.Sequence != event.Sequence || row.EventID != event.EventID || row.EventType != event.EventType || row.OperatorID != event.OperatorID || row.InstallID != event.InstallID || row.KeyID != event.KeyID || row.PreviousEventSHA256 == nil || *row.PreviousEventSHA256 != *event.PreviousEventSHA256 || row.CreatedAt != event.CreatedAt {
		return ChainState{}, errors.New("authority ledger row and signed event disagree")
	}
	old, known := prior.Keys[event.SignedByKeyID]
	if !known || old.Status != "active" || old.Kind != "installation" {
		return ChainState{}, errors.New("authority rotation signer is unknown or inactive")
	}
	var details rotationDetails
	if decodeClosed(event.Details, &details) != nil || details.OldKeyID != event.SignedByKeyID || event.KeyID != details.KeyID || event.InstallID != details.InstallID || details.InstallID != old.InstallID {
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
	if _, err := utcTimestamp(event.CreatedAt); err != nil {
		return ChainState{}, err
	}
	document, encoded, digest, err := canonicalLedgerEvent(row.EventJSON)
	if err != nil || document["event_type"] != "key_rotated" || row.EventSHA256 != digest {
		return ChainState{}, errors.New("authority ledger event digest mismatch")
	}
	publicKey, err := PublicKeyFromBase64(old.PublicKeyB64)
	signature, signatureErr := canonicalBase64(row.SignatureB64)
	if err != nil || signatureErr != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, append([]byte(LedgerDomain+"\x00"), encoded...), signature) {
		return ChainState{}, errors.New("authority ledger signature is invalid")
	}
	next := ChainState{OperatorID: prior.OperatorID, StoreIdentity: prior.StoreIdentity, HeadSHA256: digest, HeadSequence: event.Sequence, Keys: cloneKeys(prior.Keys)}
	retired := next.Keys[old.KeyID]
	retired.Status = "retired"
	next.Keys[old.KeyID] = retired
	next.Keys[certificate.KeyID] = ChainKey{KeyCertificate: certificate, Kind: "installation", Status: "active", AlgorithmSuite: details.AlgorithmSuite, BlobRelativePath: details.BlobRelativePath, BlobSHA256: details.BlobSHA256, BlobSize: details.BlobSize, CertificateSequence: event.Sequence, CertificateEventSHA256: digest}
	return next, nil
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
