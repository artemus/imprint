package cli

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/artemus/imprint/internal/authority"
	"github.com/artemus/imprint/internal/canonical"
	"github.com/artemus/imprint/internal/ceremony"
)

func runAuthorityCheckpoint(ctx context.Context, configPath string, ttl time.Duration, processInput io.Reader, stdout, stderr io.Writer, console ceremony.Console, now time.Time) int {
	if err := console.RequireNative(processInput); err != nil {
		return fail(stderr, err.Error())
	}
	runtime, err := loadRuntime(configPath, true)
	if err != nil {
		return fail(stderr, err.Error())
	}
	database, err := runtime.openStore()
	if err != nil {
		return fail(stderr, err.Error())
	}
	defer database.Close()
	passphrase, err := console.ReadSecret("Authority signing passphrase: ")
	if err != nil {
		return fail(stderr, err.Error())
	}
	checkpoint, err := database.CreateAuthorityCheckpoint(ctx, runtime.Root, passphrase, now, ttl)
	passphrase = ""
	if err != nil {
		return fail(stderr, err.Error())
	}
	response, err := canonical.JSON(checkpoint)
	if err != nil {
		return fail(stderr, err.Error())
	}
	fmt.Fprintln(stdout, string(response))
	return 0
}

func checkpointTTL(seconds int) (time.Duration, error) {
	if seconds <= 0 || seconds > int(authority.MaxCheckpointAge/time.Second) {
		return 0, fmt.Errorf("authority checkpoint TTL must be within 24 hours")
	}
	return time.Duration(seconds) * time.Second, nil
}
