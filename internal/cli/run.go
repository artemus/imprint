// Package cli implements Imprint's process boundary.
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/artemus/imprint/internal/buildinfo"
	"github.com/artemus/imprint/internal/config"
)

const usage = `Usage: imprint [--config PATH] COMMAND

Commands:
  version   print version metadata
  config    validate and print resolved public configuration
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
	default:
		return fail(stderr, fmt.Sprintf("unknown command %q", strings.TrimSpace(args[0])))
	}
}

func fail(stderr io.Writer, message string) int {
	fmt.Fprintf(stderr, "imprint: %s\n", message)
	return 2
}
