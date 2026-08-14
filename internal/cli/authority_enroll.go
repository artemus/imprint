package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/artemus/imprint/internal/authority"
	"github.com/artemus/imprint/internal/canonical"
	"github.com/artemus/imprint/internal/ceremony"
	"github.com/artemus/imprint/internal/config"
	"github.com/artemus/imprint/internal/identity"
	"github.com/artemus/imprint/internal/paths"
	"github.com/artemus/imprint/internal/store"
)

func runAuthorityEnrollmentWithoutRecovery(ctx context.Context, configPath string, processInput io.Reader, stdout, stderr io.Writer, console ceremony.Console, now time.Time, random io.Reader) int {
	return runAuthorityEnrollment(ctx, configPath, "", processInput, stdout, stderr, console, now, random)
}

func runAuthorityEnrollmentWithRecovery(ctx context.Context, configPath, recoveryDestination string, processInput io.Reader, stdout, stderr io.Writer, console ceremony.Console, now time.Time, random io.Reader) int {
	return runAuthorityEnrollment(ctx, configPath, recoveryDestination, processInput, stdout, stderr, console, now, random)
}

// runAuthorityEnrollment keeps the native-terminal and durable-store boundary
// shared while leaving each recovery choice as a small explicit ceremony.
func runAuthorityEnrollment(ctx context.Context, configPath, recoveryDestination string, processInput io.Reader, stdout, stderr io.Writer, console ceremony.Console, now time.Time, random io.Reader) int {
	if err := console.RequireNative(processInput); err != nil {
		return fail(stderr, err.Error())
	}
	value, err := config.Load(configPath)
	if err != nil {
		return fail(stderr, err.Error())
	}
	root, err := paths.OperatorRoot(value)
	if err != nil {
		return fail(stderr, err.Error())
	}
	operatorID, err := identity.LoadOrCreate(root)
	if err != nil {
		return fail(stderr, err.Error())
	}
	database, err := store.Open(filepath.Join(root, "imprint.db"), operatorID, value.NodeID)
	if err != nil {
		return fail(stderr, err.Error())
	}
	defer database.Close()
	storeIdentity, err := database.Identity(ctx)
	if err != nil {
		return fail(stderr, err.Error())
	}
	if recoveryDestination != "" {
		return performRecoveryEnrollment(ctx, root, operatorID, storeIdentity, recoveryDestination, database, stdout, stderr, console, now, random)
	}
	enrollmentIdentity, err := authority.NewEnrollmentIdentity(operatorID, storeIdentity, random)
	if err != nil {
		return fail(stderr, err.Error())
	}
	if err := console.Write(fmt.Sprintf(
		"\nImprint authority enrollment\nOperator: %s\nInstallation: %s\nStore: %s\nLosing the passphrase and every recovery path permanently removes the ability to preserve authority.\n",
		operatorID, enrollmentIdentity.InstallID, storeIdentity,
	)); err != nil {
		return fail(stderr, err.Error())
	}
	confirmation, err := console.ReadLine("Type ENROLL DECLINE-RECOVERY to create this trust domain without an offline recovery key: ")
	if err != nil {
		return fail(stderr, err.Error())
	}
	if confirmation != "ENROLL DECLINE-RECOVERY" {
		return fail(stderr, "authority enrollment was not confirmed")
	}
	passphrase, err := readRepeatedSecret(console, "New authority signing passphrase: ", "Repeat authority signing passphrase: ", "authority passphrases do not match")
	if err != nil {
		return fail(stderr, err.Error())
	}
	plan, err := authority.PrepareEnrollmentForIdentity(enrollmentIdentity, passphrase, now, random)
	passphrase = ""
	if err != nil {
		return fail(stderr, err.Error())
	}
	defer plan.Clear()
	result, err := database.EnrollAuthority(ctx, root, plan.Event, plan.PrivateKey, plan.KeyBlob, now)
	if err != nil {
		return fail(stderr, err.Error())
	}
	response, err := canonical.JSON(map[string]any{
		"status": "enrolled", "operator_id": operatorID,
		"install_id": enrollmentIdentity.InstallID, "store_identity": storeIdentity,
		"key_id": plan.Event.KeyID, "public_key_fingerprint": plan.Event.PublicKeyFingerprint,
		"ledger_sequence": int64(1), "ledger_event_sha256": result.LedgerRow.EventSHA256,
		"recovery": "explicitly_declined",
	})
	if err != nil {
		return fail(stderr, err.Error())
	}
	fmt.Fprintln(stdout, string(response))
	return 0
}

func performRecoveryEnrollment(ctx context.Context, root, operatorID, storeIdentity, destination string, database *store.Store, stdout, stderr io.Writer, console ceremony.Console, now time.Time, random io.Reader) int {
	if err := console.Write("\nRecovery will be bound at authority-ledger sequence 1. The encrypted bundle must be kept offline.\n"); err != nil {
		return fail(stderr, err.Error())
	}
	confirmation, err := console.ReadLine("Type ENROLL WITH-RECOVERY to create this trust domain and its offline recovery bundle: ")
	if err != nil {
		return fail(stderr, err.Error())
	}
	if confirmation != "ENROLL WITH-RECOVERY" {
		return fail(stderr, "authority recovery enrollment was not confirmed")
	}
	authorityPassphrase, err := readRepeatedSecret(console, "New authority signing passphrase: ", "Repeat authority signing passphrase: ", "authority passphrases do not match")
	if err != nil {
		return fail(stderr, err.Error())
	}
	recoveryPassphrase, err := readRepeatedSecret(console, "New separate recovery passphrase: ", "Repeat separate recovery passphrase: ", "recovery passphrases do not match")
	if err != nil {
		authorityPassphrase = ""
		return fail(stderr, err.Error())
	}
	plan, err := authority.PrepareEnrollmentWithRecovery(operatorID, storeIdentity, authorityPassphrase, recoveryPassphrase, now, random)
	authorityPassphrase, recoveryPassphrase = "", ""
	if err != nil {
		return fail(stderr, err.Error())
	}
	defer plan.Clear()
	if err := confirmInitialRecoveryBinding(console, plan.Event); err != nil {
		return fail(stderr, err.Error())
	}
	result, err := database.EnrollAuthorityWithRecovery(ctx, root, plan.Event, plan.PrivateKey, plan.KeyBlob, store.RecoveryEnrollmentPublication{
		Destination: destination, EncryptedRecoveryKey: plan.EncryptedRecoveryKey,
	}, now)
	if err != nil {
		return fail(stderr, err.Error())
	}
	bundle := result.RecoveryBundle
	if bundle == nil {
		return fail(stderr, "recovery bundle publication result is absent")
	}
	response, err := canonical.JSON(map[string]any{
		"status": "enrolled", "operator_id": operatorID,
		"install_id": plan.Event.InstallID, "store_identity": storeIdentity,
		"key_id": plan.Event.KeyID, "public_key_fingerprint": plan.Event.PublicKeyFingerprint,
		"ledger_sequence": int64(1), "ledger_event_sha256": result.LedgerRow.EventSHA256,
		"recovery": "created", "recovery_bundle": map[string]any{
			"path": bundle.Path, "manifest": bundle.Manifest, "bundle_sha256": bundle.BundleSHA256,
		},
	})
	if err != nil {
		return fail(stderr, err.Error())
	}
	fmt.Fprintln(stdout, string(response))
	return 0
}

func readRepeatedSecret(console ceremony.Console, firstPrompt, repeatPrompt, mismatch string) (string, error) {
	secret, err := console.ReadSecret(firstPrompt)
	if err != nil {
		return "", err
	}
	repeated, err := console.ReadSecret(repeatPrompt)
	if err != nil {
		secret = ""
		return "", err
	}
	if secret != repeated {
		secret, repeated = "", ""
		return "", errors.New(mismatch)
	}
	repeated = ""
	return secret, nil
}

func confirmInitialRecoveryBinding(console ceremony.Console, event authority.GenesisEvent) error {
	encoded, err := authority.CanonicalGenesisTransition(event)
	if err != nil {
		return err
	}
	return confirmExactTransition(console, "initial authority and recovery binding", "BIND INITIAL AUTHORITY", encoded)
}

func confirmExactTransition(console ceremony.Console, label, phrase string, encoded []byte) error {
	digest := sha256.Sum256(encoded)
	if err := console.Write("\nExact " + label + " (RFC 8785 canonical JSON):\n" + string(encoded) + "\nTransition SHA-256: " + hex.EncodeToString(digest[:]) + "\n"); err != nil {
		return err
	}
	confirmation, err := console.ReadLine("Type " + phrase + " to sign this exact transition: ")
	if err != nil {
		return err
	}
	if confirmation != phrase {
		return errors.New(label + " was not confirmed")
	}
	return nil
}
