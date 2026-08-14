package authority

import "errors"

type ChainSnapshot struct {
	EventSHA256, KeyStateSHA256 string
	Keys                        map[string]ChainKey
}

type VerifiedChain struct {
	ChainState
	GenesisSHA256 string
	Snapshots     map[int64]ChainSnapshot
}

// VerifyChain composes the bounded event verifiers and retains the historical
// state needed to validate checkpoints that precede the current ledger head.
func VerifyChain(rows []LedgerRow, expectedOperatorID, expectedStoreIdentity string) (VerifiedChain, error) {
	if len(rows) == 0 {
		return VerifiedChain{}, errors.New("authority ledger is absent")
	}
	state, err := BeginChain(rows[0], expectedOperatorID, expectedStoreIdentity)
	if err != nil {
		return VerifiedChain{}, err
	}
	verified := VerifiedChain{ChainState: state, GenesisSHA256: state.HeadSHA256, Snapshots: map[int64]ChainSnapshot{}}
	if err := verified.recordSnapshot(); err != nil {
		return VerifiedChain{}, err
	}
	for _, row := range rows[1:] {
		switch row.EventType {
		case "recovery_created":
			state, err = VerifyRecoveryCreated(state, row)
		case "installation_paired":
			state, err = VerifyInstallationPaired(state, row)
		case "key_rotated":
			state, err = VerifyRotation(state, row)
		case "key_revoked", "key_compromised", "recovery_revoked":
			state, err = VerifyKeyState(state, row)
		case "installation_rebound":
			state, err = VerifyInstallationRebound(state, row)
		case "authority_conflict_adjudicated":
			state, err = VerifyConflictAdjudicated(state, row)
		default:
			return VerifiedChain{}, errors.New("authority ledger event type is unsupported")
		}
		if err != nil {
			return VerifiedChain{}, err
		}
		verified.ChainState = state
		if err := verified.recordSnapshot(); err != nil {
			return VerifiedChain{}, err
		}
	}
	return verified, nil
}

func (chain *VerifiedChain) recordSnapshot() error {
	digest, err := KeyStateSHA256(chain.Keys)
	if err != nil {
		return err
	}
	chain.Snapshots[chain.HeadSequence] = ChainSnapshot{
		EventSHA256: chain.HeadSHA256, KeyStateSHA256: digest, Keys: cloneKeys(chain.Keys),
	}
	return nil
}
