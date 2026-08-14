package authority

import (
	"errors"
	"strings"
)

type keyStateDetails struct {
	TargetKeyID              string   `json:"target_key_id"`
	EffectiveAt              string   `json:"effective_at"`
	CompromisedAt            *string  `json:"compromised_at"`
	Reason                   string   `json:"reason"`
	ReplacementKeyID         *string  `json:"replacement_key_id"`
	AffectedInstallationIDs  []string `json:"affected_installation_ids"`
	EvidenceSHA256s          []string `json:"evidence_sha256s"`
	RequiredRevocationKeyIDs []string `json:"required_revocation_key_ids"`
}

var keyStateDetailFields = []string{
	"target_key_id", "effective_at", "compromised_at", "reason",
	"replacement_key_id", "affected_installation_ids", "evidence_sha256s",
	"required_revocation_key_ids",
}

// VerifyKeyState verifies one revocation or compromise event against an
// already verified chain state and returns a new state without mutating prior.
func VerifyKeyState(prior ChainState, row LedgerRow) (ChainState, error) {
	if row.EventType != "key_revoked" && row.EventType != "key_compromised" && row.EventType != "recovery_revoked" {
		return ChainState{}, errors.New("authority key-state event type is unsupported")
	}
	event, digest, _, err := verifyLifecycle(prior, row, row.EventType)
	if err != nil {
		return ChainState{}, err
	}
	var details keyStateDetails
	if decodeExactObject(event.Details, &details, keyStateDetailFields) != nil || strings.TrimSpace(details.Reason) == "" {
		return ChainState{}, errors.New("authority key-state event has unknown or missing fields")
	}
	target, known := prior.Keys[details.TargetKeyID]
	if !known || target.Status != "active" || event.KeyID != details.TargetKeyID {
		return ChainState{}, errors.New("authority key-state subject is invalid")
	}
	if event.EventType == "key_compromised" && event.SignedByKeyID == target.KeyID {
		return ChainState{}, errors.New("a compromised key cannot revoke itself")
	}
	if event.EventType == "recovery_revoked" && target.Kind != "recovery" {
		return ChainState{}, errors.New("recovery revocation targets a non-recovery key")
	}
	if len(details.AffectedInstallationIDs) != 1 || details.AffectedInstallationIDs[0] != target.InstallID || len(details.RequiredRevocationKeyIDs) != 1 || details.RequiredRevocationKeyIDs[0] != target.KeyID || details.EvidenceSHA256s == nil {
		return ChainState{}, errors.New("authority compromise scope or evidence is invalid")
	}
	for _, evidence := range details.EvidenceSHA256s {
		if !lowercaseSHA256.MatchString(evidence) {
			return ChainState{}, errors.New("authority compromise scope or evidence is invalid")
		}
	}
	effectiveAt, err := utcTimestamp(details.EffectiveAt)
	if err != nil {
		return ChainState{}, err
	}
	compromisedAt := details.CompromisedAt
	if event.EventType == "key_compromised" && compromisedAt == nil {
		value := details.EffectiveAt
		compromisedAt = &value
	}
	if compromisedAt != nil {
		boundary, parseErr := utcTimestamp(*compromisedAt)
		if parseErr != nil {
			return ChainState{}, parseErr
		}
		if boundary.After(effectiveAt) {
			return ChainState{}, errors.New("authority compromise boundary follows its effective time")
		}
	}
	if details.ReplacementKeyID != nil {
		if _, exists := prior.Keys[*details.ReplacementKeyID]; !exists {
			return ChainState{}, errors.New("authority key-state replacement is unknown")
		}
	}
	next := ChainState{OperatorID: prior.OperatorID, StoreIdentity: prior.StoreIdentity, HeadSHA256: digest, HeadSequence: event.Sequence, Keys: cloneKeys(prior.Keys)}
	updated := next.Keys[target.KeyID]
	if event.EventType == "key_compromised" {
		updated.Status = "compromised"
	} else {
		updated.Status = "revoked"
	}
	updated.EffectiveAt = details.EffectiveAt
	updated.CompromisedAt = compromisedAt
	updated.ReplacementKeyID = details.ReplacementKeyID
	next.Keys[target.KeyID] = updated
	return next, nil
}
