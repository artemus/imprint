// Package cli implements Imprint's process boundary.
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/artemus/imprint/internal/buildinfo"
	"github.com/artemus/imprint/internal/canonical"
	"github.com/artemus/imprint/internal/capture"
	"github.com/artemus/imprint/internal/config"
	"github.com/artemus/imprint/internal/identity"
	"github.com/artemus/imprint/internal/paths"
	"github.com/artemus/imprint/internal/spool"
)

const usage = `Usage: imprint [--config PATH] COMMAND

Commands:
  version   print version metadata
  config    validate and print resolved public configuration
  capture   validate and durably queue a raw capture envelope
`

func Run(args []string, stdout, stderr io.Writer) int {
	configPath := ""
	if len(args) >= 2 && args[0] == "--config" {
		configPath, args = args[1], args[2:]
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	switch args[0] {
	case "version":
		if len(args) != 1 {
			return fail(stderr, "version accepts no arguments")
		}
		fmt.Fprintln(stdout, buildinfo.Version)
		return 0
	case "config":
		if len(args) != 1 {
			return fail(stderr, "config accepts no arguments")
		}
		value, err := config.Load(configPath)
		if err != nil {
			return fail(stderr, err.Error())
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return fail(stderr, err.Error())
		}
		fmt.Fprintln(stdout, string(encoded))
		return 0
	case "capture":
		if len(args) != 3 || args[1] != "--event" || strings.TrimSpace(args[2]) == "" {
			return fail(stderr, "capture requires --event PATH")
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
		raw, err := os.ReadFile(args[2])
		if err != nil {
			return fail(stderr, err.Error())
		}
		envelope, err := capture.Decode(raw)
		if err != nil {
			return fail(stderr, err.Error())
		}
		if envelope.OperatorID != operatorID || envelope.NodeID != value.NodeID {
			return fail(stderr, "capture operator/node does not match configured identity")
		}
		path, err := spool.Write(root, envelope)
		if err != nil {
			return fail(stderr, err.Error())
		}
		response, err := canonical.JSON(map[string]string{"status": "queued", "path": path})
		if err != nil {
			return fail(stderr, err.Error())
		}
		fmt.Fprintln(stdout, string(response))
		return 0
	default:
		return fail(stderr, fmt.Sprintf("unknown command %q", strings.TrimSpace(args[0])))
	}
}

func fail(stderr io.Writer, message string) int {
	fmt.Fprintf(stderr, "imprint: %s\n", message)
	return 2
}
