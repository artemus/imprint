package authority

import (
	"encoding/json"
	"testing"
	"time"
)

func TestVerifyAuthorityTransportBindsLedgerCheckpointAndGenesis(t *testing.T) {
	genesis, row := signedGenesis(t)
	chain, err := VerifyChain([]LedgerRow{row}, genesis.OperatorID, genesis.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := signedCheckpoint(t, chain, 1, genesis.KeyID, fixturePrivateKey(0))
	checkpointRaw, _ := canonicalContract(checkpoint)
	portable := []PortableLedgerRow{portableRow(row)}
	ledgerSHA, err := LedgerSHA256(portable)
	if err != nil {
		t.Fatal(err)
	}
	rowRaw, _ := canonicalContract(portable[0])
	transport := AuthorityTransport{
		TransportVersion: TransportVersion, OperatorID: chain.OperatorID,
		StoreIdentity: chain.StoreIdentity, AuthorityLedgerGenesisSHA256: chain.GenesisSHA256,
		Ledger: []json.RawMessage{rowRaw}, LedgerSHA256: ledgerSHA,
		CheckpointHistory: []json.RawMessage{checkpointRaw}, Checkpoint: checkpointRaw,
	}
	raw := canonicalTransport(t, transport)
	now := time.Date(2026, 8, 14, 12, 30, 0, 0, time.UTC)
	verified, err := VerifyAuthorityTransport(raw, now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Chain.HeadSequence != 1 || verified.Checkpoint.Sequence != 1 || len(verified.Ledger) != 1 {
		t.Fatalf("verified=%#v", verified)
	}

	tampered := transport
	tampered.LedgerSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err = VerifyAuthorityTransport(canonicalTransport(t, tampered), now); err == nil {
		t.Fatal("accepted another ledger digest")
	}
	tampered = transport
	tampered.AuthorityLedgerGenesisSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err = VerifyAuthorityTransport(canonicalTransport(t, tampered), now); err == nil {
		t.Fatal("accepted another trust genesis")
	}
	if _, err = VerifyAuthorityTransport(raw[:len(raw)-1], now); err == nil {
		t.Fatal("accepted transport without canonical newline")
	}
}

func TestVerifyAuthorityTransportRejectsUnknownLedgerRowFields(t *testing.T) {
	genesis, row := signedGenesis(t)
	chain, err := VerifyChain([]LedgerRow{row}, genesis.OperatorID, genesis.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := signedCheckpoint(t, chain, 1, genesis.KeyID, fixturePrivateKey(0))
	checkpointRaw, _ := canonicalContract(checkpoint)
	portable := portableRow(row)
	rowValue := map[string]any{}
	encoded, _ := json.Marshal(portable)
	_ = json.Unmarshal(encoded, &rowValue)
	rowValue["unknown"] = true
	rowRaw, _ := canonicalContract(rowValue)
	transport := AuthorityTransport{
		TransportVersion: TransportVersion, OperatorID: chain.OperatorID,
		StoreIdentity: chain.StoreIdentity, AuthorityLedgerGenesisSHA256: chain.GenesisSHA256,
		Ledger: []json.RawMessage{rowRaw}, LedgerSHA256: "irrelevant",
		CheckpointHistory: []json.RawMessage{checkpointRaw}, Checkpoint: checkpointRaw,
	}
	now := time.Date(2026, 8, 14, 12, 30, 0, 0, time.UTC)
	if _, err = VerifyAuthorityTransport(canonicalTransport(t, transport), now); err == nil {
		t.Fatal("accepted unknown recovery ledger row field")
	}
}

func canonicalTransport(t *testing.T, transport AuthorityTransport) []byte {
	t.Helper()
	encoded, err := canonicalContract(transport)
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}
