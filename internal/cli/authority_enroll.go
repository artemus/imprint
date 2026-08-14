package cli

import (
	"context"
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

// runAuthorityEnrollmentWithoutRecovery remains unregistered until the
// recovery-output variant is native too; this prevents a partial public CLI.
func runAuthorityEnrollmentWithoutRecovery(ctx context.Context, configPath string, processInput io.Reader, stdout, stderr io.Writer, console ceremony.Console, now time.Time, random io.Reader) int {
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
	passphrase, err := console.ReadSecret("New authority signing passphrase: ")
	if err != nil {
		return fail(stderr, err.Error())
	}
	repeated, err := console.ReadSecret("Repeat authority signing passphrase: ")
	if err != nil {
		return fail(stderr, err.Error())
	}
	if passphrase != repeated {
		return fail(stderr, "authority passphrases do not match")
	}
	plan, err := authority.PrepareEnrollmentForIdentity(enrollmentIdentity, passphrase, now, random)
	passphrase, repeated = "", ""
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
