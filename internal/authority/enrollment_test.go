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

func TestPrepareEnrollmentWithRecoveryBindsTwoDistinctEncryptedKeys(t *testing.T) {
	randomBytes := make([]byte, 264)
	for index := range randomBytes {
		randomBytes[index] = byte(index)
	}
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	plan, err := PrepareEnrollmentWithRecovery(
		"urn:imprint:operator:fixture", "urn:imprint:store:fixture",
		"authority-passphrase", "recovery-passphrase", now, bytes.NewReader(randomBytes),
	)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Event.RecoveryBinding == nil || plan.Event.RecoveryBinding.KeyID == plan.Event.KeyID {
		t.Fatalf("event=%#v", plan.Event)
	}
	recoveryManifest := RecoveryManifest{
		OperatorID: plan.Event.OperatorID, StoreIdentity: plan.Event.StoreIdentity,
		CreatedAt: plan.Event.CreatedAt, RecoveryKeyID: plan.Event.RecoveryBinding.KeyID,
		RecoveryPublicKeyB64:         plan.Event.RecoveryBinding.PublicKeyB64,
		RecoveryPublicKeyFingerprint: plan.Event.RecoveryBinding.PublicKeyFingerprint,
		RecoveryInstallID:            plan.Event.RecoveryBinding.InstallID,
	}
	recoveryPrivate, err := DecryptRecoveryKey(plan.EncryptedRecoveryKey, "recovery-passphrase", recoveryManifest)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(recoveryPrivate)
	if err := VerifyPublicBinding(recoveryPrivate, plan.Event.RecoveryBinding.PublicKeyB64); err != nil {
		t.Fatal(err)
	}
	machinePrivate, err := DecryptPrivateKey(plan.KeyBlob, "authority-passphrase", KeyAAD{
		OperatorID: plan.Event.OperatorID, InstallID: plan.Event.InstallID,
		StoreIdentity: plan.Event.StoreIdentity, KeyID: plan.Event.KeyID,
		PublicKeyB64: plan.Event.PublicKeyB64, PublicKeyFingerprint: plan.Event.PublicKeyFingerprint,
		CreatedAt: plan.Event.CreatedAt, AlgorithmSuite: plan.Event.AlgorithmSuite,
		LedgerSequence: plan.Event.Sequence, EnrollmentNonce: plan.Event.EnrollmentNonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(machinePrivate)
	plan.Clear()
}

func TestPrepareEnrollmentWithRecoveryRequiresSeparatePassphrases(t *testing.T) {
	if _, err := PrepareEnrollmentWithRecovery(
		"urn:imprint:operator:fixture", "urn:imprint:store:fixture",
		"same-passphrase", "same-passphrase", time.Now(), bytes.NewReader(make([]byte, 300)),
	); err == nil {
		t.Fatal("accepted one passphrase for both authority and recovery")
	}
}
