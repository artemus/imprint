package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/artemus/imprint/internal/canonical"
	"github.com/artemus/imprint/internal/capture"
	"github.com/artemus/imprint/internal/derive"
	"github.com/artemus/imprint/internal/proposal"
)

func runDerive(args []string, configPath string, stdout, stderr io.Writer) int {
	if len(args) < 2 || (args[1] != "--pending" && args[1] != "--submit" && args[1] != "--capture") {
		return fail(stderr, "derive requires --submit PATH, --capture PATH, or --pending")
	}
	if (args[1] == "--pending" && len(args) != 2) || (args[1] != "--pending" && len(args) != 3) {
		return fail(stderr, "derive input option requires a path")
	}
	runtime, err := loadRuntime(configPath, args[1] != "--submit")
	if err != nil {
		return fail(stderr, err.Error())
	}
	if args[1] == "--submit" {
		return submitProposal(runtime.Root, args[2], stdout, stderr)
	}
	if args[1] == "--capture" {
		return deriveCapture(runtime, args[2], stdout, stderr)
	}
	database, err := runtime.openStore()
	if err != nil {
		return fail(stderr, err.Error())
	}
	defer database.Close()
	counts, err := derive.Compile(context.Background(), runtime.Root, database)
	if err != nil {
		return fail(stderr, err.Error())
	}
	status, code := "ok", 0
	if counts.Rejected > 0 {
		status, code = "degraded", 2
	}
	response, _ := canonical.JSON(map[string]any{"status": status, "applied": counts.Applied, "duplicates": counts.Duplicates, "rejected": counts.Rejected, "skipped": counts.Skipped, "failures": counts.Failures})
	fmt.Fprintln(stdout, string(response))
	return code
}

func submitProposal(root, path string, stdout, stderr io.Writer) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fail(stderr, err.Error())
	}
	candidate, err := proposal.Decode(raw)
	if err != nil {
		return fail(stderr, err.Error())
	}
	proposalID, err := derive.Submit(root, candidate)
	if err != nil {
		return fail(stderr, err.Error())
	}
	response, _ := canonical.JSON(map[string]string{"status": "queued", "proposal_id": proposalID})
	fmt.Fprintln(stdout, string(response))
	return 0
}

func deriveCapture(runtime runtimeState, path string, stdout, stderr io.Writer) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fail(stderr, err.Error())
	}
	envelope, err := capture.Decode(raw)
	if err != nil {
		return fail(stderr, err.Error())
	}
	if envelope.OperatorID != runtime.OperatorID || envelope.NodeID != runtime.Config.NodeID {
		return fail(stderr, "capture operator/node does not match configured identity")
	}
	candidate, err := proposal.FromCapture(envelope, "imprint-reference-deriver")
	if err != nil {
		return fail(stderr, err.Error())
	}
	proposalID, err := derive.Submit(runtime.Root, candidate)
	if err != nil {
		return fail(stderr, err.Error())
	}
	response, _ := canonical.JSON(map[string]string{"status": "queued", "proposal_id": proposalID, "producer": "imprint-reference-deriver"})
	fmt.Fprintln(stdout, string(response))
	return 0
}
