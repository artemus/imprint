package authority

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestPrepareEnrollmentWithoutRecoveryBindsDecryptableKey(t *testing.T) {
	random := bytes.NewReader(make([]byte, 32+32+32+16+32+12))
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	plan, err := PrepareEnrollmentWithoutRecovery(
		"urn:imprint:operator:fixture", "urn:imprint:store:fixture",
		"fixture-passphrase", now, random,
	)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Event.RecoveryBinding != nil || !strings.HasPrefix(plan.Event.InstallID, "urn:imprint:installation:") || len(plan.Event.InstallID) != len("urn:imprint:installation:")+64 {
		t.Fatalf("event=%#v", plan.Event)
	}
	aad := KeyAAD{
		OperatorID: plan.Event.OperatorID, InstallID: plan.Event.InstallID,
		StoreIdentity: plan.Event.StoreIdentity, KeyID: plan.Event.KeyID,
		PublicKeyB64: plan.Event.PublicKeyB64, PublicKeyFingerprint: plan.Event.PublicKeyFingerprint,
		CreatedAt: plan.Event.CreatedAt, AlgorithmSuite: plan.Event.AlgorithmSuite,
		LedgerSequence: plan.Event.Sequence, EnrollmentNonce: plan.Event.EnrollmentNonce,
	}
	privateKey, err := DecryptPrivateKey(plan.KeyBlob, "fixture-passphrase", aad)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublicBinding(privateKey, plan.Event.PublicKeyB64); err != nil {
		t.Fatal(err)
	}
	if _, err := SignGenesis(plan.Event, plan.PrivateKey); err != nil {
		t.Fatal(err)
	}
	keyBytes := plan.PrivateKey
	plan.Clear()
	if plan.PrivateKey != nil || !bytes.Equal(keyBytes, make([]byte, len(keyBytes))) {
		t.Fatal("prepared private key was not released")
	}
}

func TestPrepareEnrollmentWithoutRecoveryRejectsInvalidBoundaryInputs(t *testing.T) {
	if _, err := PrepareEnrollmentWithoutRecovery("wrong", "urn:imprint:store:fixture", "fixture-passphrase", time.Now(), bytes.NewReader(make([]byte, 200))); err == nil {
		t.Fatal("accepted an invalid operator")
	}
	if _, err := PrepareEnrollmentWithoutRecovery("urn:imprint:operator:fixture", "wrong", "fixture-passphrase", time.Now(), bytes.NewReader(make([]byte, 200))); err == nil {
		t.Fatal("accepted an invalid store identity")
	}
	if _, err := PrepareEnrollmentWithoutRecovery("urn:imprint:operator:fixture", "urn:imprint:store:fixture", "short", time.Now(), bytes.NewReader(make([]byte, 200))); err == nil {
		t.Fatal("accepted a short authority passphrase")
	}
}
