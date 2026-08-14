package authority

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

type AuthorityTrustAnchor struct {
	OperatorID, StoreIdentity, GenesisEventSHA256 string
	RecoveryKeyID, RecoveryPublicKeyB64           *string
	PinnedSequence                                int64
	PinnedHeadSHA256, KeyStateSHA256              string
	CheckpointSHA256                              *string
	SignerCertificateSHA256                       *string
	WritesBlocked                                 bool
	BlockReason                                   *string
}

type VerifiedTransfer struct {
	OperatorID, StoreIdentity, GenesisEventSHA256 string
	SourceHeadSequence                            int64
	SourceHeadSHA256                              string
	Checkpoint                                    CheckpointResult
	CheckpointSHA256, KeyStateSHA256              string
	SignerCertificateSHA256, PriorAnchorSHA256    string
}

type anchorDigestDocument struct {
	OperatorID              string  `json:"operator_id"`
	StoreIdentity           string  `json:"store_identity"`
	GenesisEventSHA256      string  `json:"genesis_event_sha256"`
	RecoveryKeyID           *string `json:"recovery_key_id"`
	RecoveryPublicKeyB64    *string `json:"recovery_public_key_b64"`
	PinnedSequence          int64   `json:"pinned_sequence"`
	PinnedHeadSHA256        string  `json:"pinned_head_sha256"`
	KeyStateSHA256          string  `json:"key_state_sha256"`
	CheckpointSHA256        *string `json:"checkpoint_sha256"`
	SignerCertificateSHA256 *string `json:"signer_certificate_sha256"`
	WritesBlocked           bool    `json:"writes_blocked"`
	BlockReason             *string `json:"block_reason"`
}

func (anchor AuthorityTrustAnchor) Digest() (string, error) {
	document := anchorDigestDocument{
		OperatorID: anchor.OperatorID, StoreIdentity: anchor.StoreIdentity,
		GenesisEventSHA256: anchor.GenesisEventSHA256,
		RecoveryKeyID:      anchor.RecoveryKeyID, RecoveryPublicKeyB64: anchor.RecoveryPublicKeyB64,
		PinnedSequence: anchor.PinnedSequence, PinnedHeadSHA256: anchor.PinnedHeadSHA256,
		KeyStateSHA256: anchor.KeyStateSHA256, CheckpointSHA256: anchor.CheckpointSHA256,
		SignerCertificateSHA256: anchor.SignerCertificateSHA256,
		WritesBlocked:           anchor.WritesBlocked, BlockReason: anchor.BlockReason,
	}
	encoded, err := canonicalContract(document)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func VerifyPinnedHead(chain VerifiedChain, sequence int64, eventSHA256 string) error {
	snapshot, exists := chain.Snapshots[sequence]
	if sequence < 1 || !exists {
		return errors.New("authority source ledger is older than the pinned head")
	}
	if snapshot.EventSHA256 != eventSHA256 {
		return errors.New("authority ledger fork or equivocation against pinned head")
	}
	return nil
}

// VerifyCheckpointHistory verifies a closed checkpoint chain. If startingSHA
// is non-nil, the supplied history must contain that destination-owned pin and
// only its successors require re-verification.
func VerifyCheckpointHistory(chain VerifiedChain, history []json.RawMessage, startingSHA *string, now time.Time) ([]CheckpointResult, error) {
	if len(history) == 0 {
		return nil, errors.New("authority checkpoint history is empty")
	}
	digests := make([]string, len(history))
	for index, raw := range history {
		_, _, digest, err := canonicalLedgerEvent(string(raw))
		if err != nil {
			return nil, errors.New("authority checkpoint history is malformed")
		}
		digests[index] = digest
	}
	start := -1
	if startingSHA != nil {
		for index, digest := range digests {
			if digest == *startingSHA {
				start = index
				break
			}
		}
		if start < 0 {
			return nil, errors.New("authority transfer omits the destination-pinned checkpoint")
		}
	}
	prior := startingSHA
	results := make([]CheckpointResult, 0, len(history)-start-1)
	for index := start + 1; index < len(history); index++ {
		checkpoint, err := decodeCheckpoint(history[index])
		if err != nil || !equalOptionalString(checkpoint.PriorCheckpointSHA256, prior) {
			return nil, errors.New("authority checkpoint history does not extend local trust")
		}
		result, err := VerifyCheckpoint(chain, history[index], now, MaxCheckpointAge, index == len(history)-1)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
		value := digests[index]
		prior = &value
	}
	if start == len(history)-1 {
		result, err := VerifyCheckpoint(chain, history[start], now, MaxCheckpointAge, true)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func VerifyTransfer(chain VerifiedChain, anchor AuthorityTrustAnchor, history []json.RawMessage, now time.Time) (VerifiedTransfer, error) {
	if anchor.WritesBlocked {
		return VerifiedTransfer{}, errors.New("local authority trust is blocked pending adjudication")
	}
	if chain.OperatorID != anchor.OperatorID || chain.StoreIdentity != anchor.StoreIdentity || chain.GenesisSHA256 != anchor.GenesisEventSHA256 {
		return VerifiedTransfer{}, errors.New("authority transfer belongs to a foreign trust genesis")
	}
	if err := VerifyPinnedHead(chain, anchor.PinnedSequence, anchor.PinnedHeadSHA256); err != nil {
		return VerifiedTransfer{}, err
	}
	results, err := VerifyCheckpointHistory(chain, history, anchor.CheckpointSHA256, now)
	if err != nil {
		return VerifiedTransfer{}, err
	}
	checkpoint := results[len(results)-1]
	if checkpoint.Sequence < anchor.PinnedSequence {
		return VerifiedTransfer{}, errors.New("authority transfer is a rollback")
	}
	if checkpoint.Sequence == anchor.PinnedSequence && checkpoint.EventSHA256 != anchor.PinnedHeadSHA256 {
		return VerifiedTransfer{}, errors.New("authority transfer equivocated at the pinned sequence")
	}
	if checkpoint.Sequence > anchor.PinnedSequence && anchor.CheckpointSHA256 != nil && len(history) == 1 && !equalOptionalString(checkpoint.PriorCheckpointSHA256, anchor.CheckpointSHA256) {
		return VerifiedTransfer{}, errors.New("authority checkpoint does not extend the locally pinned checkpoint")
	}
	certificateSHA, err := canonicalValueSHA256(checkpoint.SignerCertificate)
	if err != nil {
		return VerifiedTransfer{}, err
	}
	priorAnchorSHA, err := anchor.Digest()
	if err != nil {
		return VerifiedTransfer{}, err
	}
	return VerifiedTransfer{
		OperatorID: chain.OperatorID, StoreIdentity: chain.StoreIdentity,
		GenesisEventSHA256: chain.GenesisSHA256, SourceHeadSequence: chain.HeadSequence,
		SourceHeadSHA256: chain.HeadSHA256, Checkpoint: checkpoint,
		CheckpointSHA256: checkpoint.CheckpointSHA256, KeyStateSHA256: checkpoint.KeyStateSHA256,
		SignerCertificateSHA256: certificateSHA, PriorAnchorSHA256: priorAnchorSHA,
	}, nil
}

func ValidateRecoveryAnchor(chain VerifiedChain, keyID, publicKeyB64 *string) error {
	if (keyID == nil) != (publicKeyB64 == nil) {
		return errors.New("recovery trust anchor is incomplete")
	}
	if keyID == nil {
		return nil
	}
	key, exists := chain.Keys[*keyID]
	if !exists || key.Kind != "recovery" || key.Status != "active" || key.PublicKeyB64 != *publicKeyB64 {
		return errors.New("recovery trust anchor is not active in the verified chain")
	}
	return nil
}

func canonicalValueSHA256(value any) (string, error) {
	encoded, err := canonicalContract(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func equalOptionalString(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}
