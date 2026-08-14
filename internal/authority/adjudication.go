package authority

import (
	"errors"
	"strings"
)

type adjudicationDetails struct {
	ProofID                string `json:"proof_id"`
	ChosenCheckpointSHA256 string `json:"chosen_checkpoint_sha256"`
	RejectedProofSHA256    string `json:"rejected_proof_sha256"`
	Reason                 string `json:"reason"`
	EffectiveAt            string `json:"effective_at"`
}

var adjudicationDetailFields = []string{"proof_id", "chosen_checkpoint_sha256", "rejected_proof_sha256", "reason", "effective_at"}

// VerifyConflictAdjudicated verifies a recovery-signed fork decision. Whether
// the chosen checkpoint is locally pinned is a store policy checked separately.
func VerifyConflictAdjudicated(prior ChainState, row LedgerRow) (ChainState, error) {
	event, digest, signer, err := verifyLifecycle(prior, row, "authority_conflict_adjudicated")
	if err != nil {
		return ChainState{}, err
	}
	var details adjudicationDetails
	if decodeExactObject(event.Details, &details, adjudicationDetailFields) != nil || strings.TrimSpace(details.Reason) == "" || signer.Kind != "recovery" {
		return ChainState{}, errors.New("authority conflict adjudication is invalid")
	}
	if !lowercaseSHA256.MatchString(details.ChosenCheckpointSHA256) || !lowercaseSHA256.MatchString(details.RejectedProofSHA256) {
		return ChainState{}, errors.New("authority conflict adjudication digest is invalid")
	}
	if _, err := utcTimestamp(details.EffectiveAt); err != nil {
		return ChainState{}, err
	}
	return ChainState{
		OperatorID: prior.OperatorID, StoreIdentity: prior.StoreIdentity,
		HeadSHA256: digest, HeadSequence: event.Sequence, Keys: cloneKeys(prior.Keys),
	}, nil
}
