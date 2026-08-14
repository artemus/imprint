package authority

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"
)

const (
	CheckpointVersion = "imprint.authority.checkpoint/1.1.0"
	CheckpointDomain  = "imprint-authority-checkpoint-v1"
	MaxCheckpointAge  = 24 * time.Hour
)

type SignerCertificate struct {
	CertificateVersion       string `json:"certificate_version"`
	KeyID                    string `json:"key_id"`
	InstallID                string `json:"install_id"`
	PublicKeyB64             string `json:"public_key_b64"`
	PublicKeyFingerprint     string `json:"public_key_fingerprint"`
	Kind                     string `json:"kind"`
	Paired                   bool   `json:"paired"`
	AuthorizationSequence    int64  `json:"authorization_sequence"`
	AuthorizationEventSHA256 string `json:"authorization_event_sha256"`
	StatusAtCheckpoint       string `json:"status_at_checkpoint"`
}

type CheckpointUnsigned struct {
	CheckpointVersion     string            `json:"checkpoint_version"`
	DomainSeparator       string            `json:"domain_separator"`
	OperatorID            string            `json:"operator_id"`
	StoreIdentity         string            `json:"store_identity"`
	Sequence              int64             `json:"sequence"`
	EventSHA256           string            `json:"event_sha256"`
	GenesisEventSHA256    string            `json:"genesis_event_sha256"`
	KeyStateSHA256        string            `json:"key_state_sha256"`
	PriorCheckpointSHA256 *string           `json:"prior_checkpoint_sha256"`
	SignerKeyID           string            `json:"signer_key_id"`
	SignerCertificate     SignerCertificate `json:"signer_certificate"`
	IssuedAt              string            `json:"issued_at"`
	ExpiresAt             string            `json:"expires_at"`
}

type Checkpoint struct {
	CheckpointUnsigned
	SignatureB64 string `json:"signature_b64"`
}

type CheckpointResult struct {
	Sequence              int64
	EventSHA256           string
	IssuedAt, ExpiresAt   string
	SignerKeyID           string
	SignerCurrentStatus   string
	KeyStateSHA256        string
	PriorCheckpointSHA256 *string
	SignerCertificate     SignerCertificate
	CheckpointSHA256      string
}

var checkpointFields = []string{"checkpoint_version", "domain_separator", "operator_id", "store_identity", "sequence", "event_sha256", "genesis_event_sha256", "key_state_sha256", "prior_checkpoint_sha256", "signer_key_id", "signer_certificate", "issued_at", "expires_at", "signature_b64"}
var signerCertificateFields = []string{"certificate_version", "key_id", "install_id", "public_key_b64", "public_key_fingerprint", "kind", "paired", "authorization_sequence", "authorization_event_sha256", "status_at_checkpoint"}

// SignCheckpoint creates the Python-compatible checkpoint for the current
// verified head and self-verifies the result before returning it.
func SignCheckpoint(chain VerifiedChain, signerKeyID string, privateKey ed25519.PrivateKey, priorCheckpointSHA256 *string, now time.Time, ttl time.Duration) (Checkpoint, error) {
	if ttl <= 0 || ttl > MaxCheckpointAge {
		return Checkpoint{}, errors.New("authority checkpoint TTL must be within 24 hours")
	}
	signer, exists := chain.Keys[signerKeyID]
	if !exists || signer.Status != "active" {
		return Checkpoint{}, errors.New("authority checkpoint signer is not active")
	}
	snapshot, exists := chain.Snapshots[chain.HeadSequence]
	if !exists || snapshot.EventSHA256 != chain.HeadSHA256 {
		return Checkpoint{}, errors.New("authority chain head snapshot is missing")
	}
	issued := now.UTC()
	checkpoint := Checkpoint{CheckpointUnsigned: CheckpointUnsigned{
		CheckpointVersion: CheckpointVersion, DomainSeparator: CheckpointDomain,
		OperatorID: chain.OperatorID, StoreIdentity: chain.StoreIdentity,
		Sequence: chain.HeadSequence, EventSHA256: chain.HeadSHA256,
		GenesisEventSHA256: chain.GenesisSHA256, KeyStateSHA256: snapshot.KeyStateSHA256,
		PriorCheckpointSHA256: priorCheckpointSHA256, SignerKeyID: signerKeyID,
		SignerCertificate: signerCertificate(signer), IssuedAt: utcText(issued),
		ExpiresAt: utcText(issued.Add(ttl)),
	}}
	encoded, err := canonicalContract(checkpoint.CheckpointUnsigned)
	if err != nil {
		return Checkpoint{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return Checkpoint{}, errors.New("authority private key is invalid")
	}
	checkpoint.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, append([]byte(CheckpointDomain+"\x00"), encoded...)))
	raw, err := canonicalContract(checkpoint)
	if err != nil {
		return Checkpoint{}, err
	}
	if _, err := VerifyCheckpoint(chain, raw, issued, MaxCheckpointAge, true); err != nil {
		return Checkpoint{}, err
	}
	return checkpoint, nil
}

// VerifyCheckpoint verifies a checkpoint against any retained chain sequence.
// Set enforceFreshness false for offline historical verification.
func VerifyCheckpoint(chain VerifiedChain, raw []byte, now time.Time, maxAge time.Duration, enforceFreshness bool) (CheckpointResult, error) {
	checkpoint, err := decodeCheckpoint(raw)
	if err != nil {
		return CheckpointResult{}, err
	}
	if checkpoint.CheckpointVersion != CheckpointVersion || checkpoint.DomainSeparator != CheckpointDomain {
		return CheckpointResult{}, errors.New("authority checkpoint version is unsupported")
	}
	if checkpoint.OperatorID != chain.OperatorID || checkpoint.StoreIdentity != chain.StoreIdentity {
		return CheckpointResult{}, errors.New("authority checkpoint identity mismatch")
	}
	if checkpoint.GenesisEventSHA256 != chain.GenesisSHA256 {
		return CheckpointResult{}, errors.New("authority checkpoint trust genesis mismatch")
	}
	snapshot, exists := chain.Snapshots[checkpoint.Sequence]
	if !exists || snapshot.EventSHA256 != checkpoint.EventSHA256 {
		return CheckpointResult{}, errors.New("authority checkpoint names an absent, rolled-back, or forked head")
	}
	if snapshot.KeyStateSHA256 != checkpoint.KeyStateSHA256 {
		return CheckpointResult{}, errors.New("authority checkpoint key-state digest mismatch")
	}
	if checkpoint.PriorCheckpointSHA256 != nil && !lowercaseSHA256.MatchString(*checkpoint.PriorCheckpointSHA256) {
		return CheckpointResult{}, errors.New("authority checkpoint prior hash is invalid")
	}
	currentSigner, currentExists := chain.Keys[checkpoint.SignerKeyID]
	snapshotSigner, snapshotExists := snapshot.Keys[checkpoint.SignerKeyID]
	if !currentExists || !snapshotExists || snapshotSigner.Status != "active" {
		return CheckpointResult{}, errors.New("authority checkpoint signer is inactive")
	}
	expectedCertificate := signerCertificate(snapshotSigner)
	if checkpoint.SignerCertificate != expectedCertificate {
		return CheckpointResult{}, errors.New("authority checkpoint signer certificate mismatch")
	}
	issued, err := utcTimestamp(checkpoint.IssuedAt)
	if err != nil {
		return CheckpointResult{}, err
	}
	expires, err := utcTimestamp(checkpoint.ExpiresAt)
	if err != nil || !expires.After(issued) || maxAge <= 0 || expires.Sub(issued) > maxAge {
		return CheckpointResult{}, errors.New("authority checkpoint freshness window is invalid")
	}
	if enforceFreshness && (now.Before(issued) || !now.Before(expires)) {
		return CheckpointResult{}, errors.New("authority checkpoint is absent or stale")
	}
	encoded, err := canonicalContract(checkpoint.CheckpointUnsigned)
	signature, signatureErr := canonicalBase64(checkpoint.SignatureB64)
	publicKey, publicKeyErr := PublicKeyFromBase64(currentSigner.PublicKeyB64)
	if err != nil || signatureErr != nil || publicKeyErr != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, append([]byte(CheckpointDomain+"\x00"), encoded...), signature) {
		return CheckpointResult{}, errors.New("authority checkpoint signature is invalid")
	}
	canonical, err := canonicalContract(checkpoint)
	if err != nil {
		return CheckpointResult{}, err
	}
	digest := sha256.Sum256(canonical)
	return CheckpointResult{
		Sequence: checkpoint.Sequence, EventSHA256: checkpoint.EventSHA256,
		IssuedAt: checkpoint.IssuedAt, ExpiresAt: checkpoint.ExpiresAt,
		SignerKeyID: checkpoint.SignerKeyID, SignerCurrentStatus: currentSigner.Status,
		KeyStateSHA256:        checkpoint.KeyStateSHA256,
		PriorCheckpointSHA256: checkpoint.PriorCheckpointSHA256,
		SignerCertificate:     checkpoint.SignerCertificate,
		CheckpointSHA256:      hex.EncodeToString(digest[:]),
	}, nil
}

func decodeCheckpoint(raw []byte) (Checkpoint, error) {
	var checkpoint Checkpoint
	if decodeExactObject(raw, &checkpoint, checkpointFields) != nil {
		return Checkpoint{}, errors.New("authority checkpoint is malformed")
	}
	certificateRaw, err := rawObjectField(raw, "signer_certificate")
	if err != nil || decodeExactObject(certificateRaw, &checkpoint.SignerCertificate, signerCertificateFields) != nil {
		return Checkpoint{}, errors.New("authority checkpoint signer certificate mismatch")
	}
	return checkpoint, nil
}

func signerCertificate(key ChainKey) SignerCertificate {
	return SignerCertificate{
		CertificateVersion: "imprint.authority.installation-certificate/1.0.0",
		KeyID:              key.KeyID, InstallID: key.InstallID, PublicKeyB64: key.PublicKeyB64,
		PublicKeyFingerprint: key.PublicKeyFingerprint, Kind: key.Kind,
		Paired: key.Paired, AuthorizationSequence: key.CertificateSequence,
		AuthorizationEventSHA256: key.CertificateEventSHA256, StatusAtCheckpoint: "active",
	}
}
