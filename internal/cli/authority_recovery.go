package cli

import (
	"fmt"
	"io"

	"github.com/artemus/imprint/internal/authority"
	"github.com/artemus/imprint/internal/canonical"
	"github.com/artemus/imprint/internal/ceremony"
)

func runAuthorityRecoveryReconcile(configPath string, processInput io.Reader, stdout, stderr io.Writer, console ceremony.Console) int {
	if err := console.RequireNative(processInput); err != nil {
		return fail(stderr, err.Error())
	}
	runtime, err := loadRuntime(configPath, false)
	if err != nil {
		return fail(stderr, err.Error())
	}
	journal, err := authority.LoadRecoveryPublicationJournal(runtime.Root)
	if err != nil {
		return fail(stderr, err.Error())
	}
	if journal == nil {
		return fail(stderr, "interrupted recovery publication journal is absent")
	}
	encoded, err := authority.CanonicalRecoveryPublicationJournal(*journal)
	if err != nil {
		return fail(stderr, err.Error())
	}
	if err := confirmExactTransition(console, "interrupted recovery abandonment", "ABANDON INTERRUPTED RECOVERY", encoded); err != nil {
		return fail(stderr, err.Error())
	}
	if err := authority.ClearRecoveryPublicationJournal(runtime.Root, *journal); err != nil {
		return fail(stderr, err.Error())
	}
	response, err := canonical.JSON(map[string]string{
		"status": "abandoned", "retained_destination": journal.Destination,
		"warning": "the retained external bundle is not active authority and must not be used",
	})
	if err != nil {
		return fail(stderr, err.Error())
	}
	fmt.Fprintln(stdout, string(response))
	return 0
}
