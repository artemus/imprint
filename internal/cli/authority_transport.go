package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/artemus/imprint/internal/authority"
	"github.com/artemus/imprint/internal/canonical"
	"github.com/artemus/imprint/internal/ceremony"
)

func runAuthorityTransport(ctx context.Context, configPath, destination string, processInput io.Reader, stdout, stderr io.Writer, console ceremony.Console, now time.Time) int {
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
	checkpoint, err := database.CreateAuthorityCheckpoint(ctx, runtime.Root, passphrase, now, authority.MaxCheckpointAge)
	passphrase = ""
	if err != nil {
		return fail(stderr, err.Error())
	}
	artifact, err := database.BuildAuthorityTransport(ctx, checkpoint, now)
	if err != nil {
		return fail(stderr, err.Error())
	}
	absolute, err := filepath.Abs(destination)
	if err != nil {
		return fail(stderr, err.Error())
	}
	checkpointRaw, _ := authority.CanonicalCheckpoint(checkpoint)
	checkpointDigest := sha256.Sum256(checkpointRaw)
	verified, err := authority.VerifyAuthorityTransport(artifact.Bytes, now)
	if err != nil {
		return fail(stderr, err.Error())
	}
	transition, err := canonical.JSON(map[string]any{
		"operation": "export_authority_transport", "destination": absolute,
		"checkpoint_sha256": hex.EncodeToString(checkpointDigest[:]),
		"ledger_sequence":   verified.Chain.HeadSequence, "ledger_head_sha256": verified.Chain.HeadSHA256,
	})
	if err != nil {
		return fail(stderr, err.Error())
	}
	if err := confirmExactTransition(console, "authority transport publication", "PUBLISH AUTHORITY TRANSPORT", transition); err != nil {
		return fail(stderr, err.Error())
	}
	published, err := authority.PublishAuthorityTransport(destination, artifact, now)
	if err != nil {
		return fail(stderr, err.Error())
	}
	response, err := canonical.JSON(map[string]any{"path": published.Path, "transport_sha256": published.TransportSHA256, "checkpoint": published.Checkpoint})
	if err != nil {
		return fail(stderr, err.Error())
	}
	fmt.Fprintln(stdout, string(response))
	return 0
}
