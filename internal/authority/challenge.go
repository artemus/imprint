// Package authority implements human-present approval contracts incrementally.
package authority

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/artemus/imprint/internal/canonical"
)

const (
	ApprovalContractVersion = "imprint.authority.approval/1.1.0"
	ApprovalDomain          = "imprint-authority-approval-v1"
	MaxApprovalTTL          = 120 * time.Second
)

type Challenge struct {
	ContractVersion       string   `json:"contract_version"`
	DomainSeparator       string   `json:"domain_separator"`
	OperatorID            string   `json:"operator_id"`
	InstallID             string   `json:"install_id"`
	KeyID                 string   `json:"key_id"`
	StoreIdentity         string   `json:"store_identity"`
	LedgerSequence        int64    `json:"ledger_sequence"`
	OperationID           string   `json:"operation_id"`
	Purpose               string   `json:"purpose"`
	SubjectIDs            []string `json:"subject_ids"`
	SourceIDs             []string `json:"source_ids"`
	TargetIDs             []string `json:"target_ids"`
	ProposalIDs           []string `json:"proposal_ids"`
	ResultVersionIDs      []string `json:"result_version_ids"`
	PayloadSHA256         string   `json:"payload_sha256"`
	PriorStateSHA256      string   `json:"prior_state_sha256"`
	ExecutionFieldsSHA256 string   `json:"execution_fields_sha256"`
	Scope                 []string `json:"scope"`
	FieldPaths            []string `json:"field_paths"`
	AuthorityTransition   string   `json:"authority_transition"`
	Nonce                 string   `json:"nonce"`
	IssuedAt              string   `json:"issued_at"`
	ExpiresAt             string   `json:"expires_at"`
}

type ApprovalToken struct {
	Challenge    Challenge `json:"challenge"`
	SignatureB64 string    `json:"signature_b64"`
}

type ActiveBinding struct {
	OperatorID, InstallID, KeyID, StoreIdentity, PublicKeyB64 string
}

func BuildChallenge(request ChallengeRequest, binding ActiveBinding, ledgerSequence int64, ttl time.Duration, now time.Time, random io.Reader) (Challenge, error) {
	if err := request.Validate(); err != nil {
		return Challenge{}, err
	}
	if ttl < time.Second || ttl > MaxApprovalTTL || ttl%time.Second != 0 {
		return Challenge{}, errors.New("authority challenge TTL must be 1..120 seconds")
	}
	if ledgerSequence < 1 || binding.OperatorID == "" || binding.InstallID == "" || binding.KeyID == "" || binding.StoreIdentity == "" {
		return Challenge{}, errors.New("authority challenge binding is invalid")
	}
	if random == nil {
		random = rand.Reader
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return Challenge{}, errors.New("authority challenge nonce generation failed")
	}
	request = normalizedRequest(request)
	challenge := Challenge{
		ContractVersion: ApprovalContractVersion, DomainSeparator: ApprovalDomain,
		OperatorID: binding.OperatorID, InstallID: binding.InstallID, KeyID: binding.KeyID,
		StoreIdentity: binding.StoreIdentity, LedgerSequence: ledgerSequence,
		OperationID: request.OperationID, Purpose: request.Purpose,
		SubjectIDs: request.SubjectIDs, SourceIDs: request.SourceIDs, TargetIDs: request.TargetIDs,
		ProposalIDs: request.ProposalIDs, ResultVersionIDs: request.ResultVersionIDs,
		PayloadSHA256: request.PayloadSHA256, PriorStateSHA256: request.PriorStateSHA256,
		ExecutionFieldsSHA256: request.ExecutionFieldsSHA256, Scope: request.Scope,
		FieldPaths: request.FieldPaths, AuthorityTransition: request.AuthorityTransition,
		Nonce: base64.RawURLEncoding.EncodeToString(nonce), IssuedAt: utcText(now),
		ExpiresAt: utcText(now.Add(ttl)),
	}
	return challenge, challenge.Validate()
}

func DecodeApprovalToken(raw []byte) (ApprovalToken, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var token ApprovalToken
	if err := decoder.Decode(&token); err != nil {
		return ApprovalToken{}, errors.New("approval token is malformed")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ApprovalToken{}, errors.New("approval token contains trailing JSON")
	}
	if err := token.Challenge.Validate(); err != nil {
		return ApprovalToken{}, err
	}
	signature, err := canonicalBase64(token.SignatureB64)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != token.SignatureB64 {
		return ApprovalToken{}, errors.New("approval signature is not canonical Ed25519 bytes")
	}
	return token, nil
}

func (c Challenge) Validate() error {
	if c.ContractVersion != ApprovalContractVersion || c.DomainSeparator != ApprovalDomain {
		return errors.New("authority challenge contract is unsupported")
	}
	if c.LedgerSequence < 1 {
		return errors.New("authority ledger sequence is invalid")
	}
	for _, value := range []string{c.OperatorID, c.InstallID, c.KeyID, c.StoreIdentity, c.OperationID, c.Purpose, c.PayloadSHA256, c.PriorStateSHA256, c.ExecutionFieldsSHA256, c.AuthorityTransition, c.Nonce, c.IssuedAt, c.ExpiresAt} {
		if value == "" {
			return errors.New("authority challenge contains an empty required field")
		}
	}
	for _, values := range [][]string{c.SubjectIDs, c.SourceIDs, c.TargetIDs, c.ProposalIDs, c.ResultVersionIDs, c.Scope, c.FieldPaths} {
		if values == nil || !uniqueNonempty(values) {
			return errors.New("authority challenge contains an invalid string list")
		}
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(c.Nonce)
	if err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != c.Nonce {
		return errors.New("authority nonce is invalid")
	}
	issued, err := utcTimestamp(c.IssuedAt)
	if err != nil {
		return err
	}
	expires, err := utcTimestamp(c.ExpiresAt)
	if err != nil || !expires.After(issued) || expires.Sub(issued) > MaxApprovalTTL {
		return errors.New("authority challenge expiry is invalid")
	}
	return nil
}

// CanonicalChallenge matches RFC 8785 for this closed contract. Its keys are
// fixed ASCII and its values are strings, integer, and string arrays only.
func CanonicalChallenge(challenge Challenge) ([]byte, error) {
	if err := challenge.Validate(); err != nil {
		return nil, err
	}
	return canonicalContract(challenge)
}

func canonicalContract(value any) ([]byte, error) {
	encoded, err := canonical.JSON(value)
	if err != nil {
		return nil, errors.New("E_AUTH_CANONICALIZATION")
	}
	encoded = bytes.ReplaceAll(encoded, []byte(`\u2028`), []byte("\u2028"))
	encoded = bytes.ReplaceAll(encoded, []byte(`\u2029`), []byte("\u2029"))
	return encoded, nil
}

func SignatureMessage(challenge Challenge) ([]byte, error) {
	encoded, err := CanonicalChallenge(challenge)
	if err != nil {
		return nil, err
	}
	return append([]byte(ApprovalDomain+"\x00"), encoded...), nil
}

func VerifyApproval(token ApprovalToken, publicKey ed25519.PublicKey, now time.Time) error {
	if err := token.Challenge.Validate(); err != nil {
		return err
	}
	issued, _ := utcTimestamp(token.Challenge.IssuedAt)
	expires, _ := utcTimestamp(token.Challenge.ExpiresAt)
	now = now.UTC()
	if now.Before(issued) || !now.Before(expires) {
		return errors.New("authority token is not currently valid")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(token.SignatureB64)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("authority signature is invalid")
	}
	message, err := SignatureMessage(token.Challenge)
	if err != nil || !ed25519.Verify(publicKey, message, signature) {
		return errors.New("authority signature is invalid")
	}
	return nil
}

func utcTimestamp(value string) (time.Time, error) {
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, errors.New("authority time must be RFC 3339 UTC")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, errors.New("authority time must be RFC 3339 UTC")
	}
	return parsed.UTC(), nil
}

func uniqueNonempty(values []string) bool {
	seen := map[string]bool{}
	for _, value := range values {
		if value == "" || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}
