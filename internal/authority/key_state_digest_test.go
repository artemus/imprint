package authority

import "testing"

func TestKeyStateSHA256MatchesLegacyCanonicalContract(t *testing.T) {
	genesis, row := signedGenesis(t)
	state, err := BeginChain(row, genesis.OperatorID, genesis.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := KeyStateSHA256(state.Keys)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "de78008ee7c1c02bc0a7fa468b35254ac2820a0fdca93db350b0bcd999887ad2"
	if digest != expected {
		t.Fatalf("digest=%s", digest)
	}

	copy := cloneKeys(state.Keys)
	copy[genesis.KeyID] = ChainKey{}
	copy["sorts-first"] = state.Keys[genesis.KeyID]
	changed, err := KeyStateSHA256(copy)
	if err != nil || changed == digest {
		t.Fatalf("changed=%s err=%v", changed, err)
	}
}
