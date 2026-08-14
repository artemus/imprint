// Package cli implements Imprint's process boundary.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/artemus/imprint/internal/buildinfo"
	"github.com/artemus/imprint/internal/canonical"
	"github.com/artemus/imprint/internal/capture"
	"github.com/artemus/imprint/internal/compiler"
	"github.com/artemus/imprint/internal/config"
	"github.com/artemus/imprint/internal/identity"
	"github.com/artemus/imprint/internal/paths"
	"github.com/artemus/imprint/internal/spool"
	"github.com/artemus/imprint/internal/store"
)

const usage = `Usage: imprint [--config PATH] COMMAND

Commands:
  version   print version metadata
  config    validate and print resolved public configuration
  capture   validate and durably queue a raw capture envelope
  compile   compile queued captures into canonical SQLite state
  whoami    print the configured opaque local identity
  log       list a bounded UTC-day canonical event index
  health    verify configuration and canonical store integrity
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
	case "compile":
		if len(args) != 2 || args[1] != "--once" {
			return fail(stderr, "compile requires --once")
		}
		value, err := config.Load(configPath)
		if err != nil {
			return fail(stderr, err.Error())
		}
		if !value.Compiler {
			return fail(stderr, "canonical mutation requires explicit compiler authority")
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
		counts, err := compiler.Compile(context.Background(), root, database)
		if err != nil {
			return fail(stderr, err.Error())
		}
		response, err := canonical.JSON(map[string]any{"status": "ok", "captured": counts.Captured, "duplicate": counts.Duplicate, "quarantined": counts.Quarantined})
		if err != nil {
			return fail(stderr, err.Error())
		}
		fmt.Fprintln(stdout, string(response))
		if counts.Quarantined > 0 {
			return 2
		}
		return 0
	case "whoami":
		if len(args) != 1 {
			return fail(stderr, "whoami accepts no arguments")
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
		response, _ := canonical.JSON(map[string]string{"status": "ok", "operator_id": operatorID, "node_id": value.NodeID})
		fmt.Fprintln(stdout, string(response))
		return 0
	case "log":
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
		day := time.Now().UTC().Format("2006-01-02")
		limit := 100
		query := ""
		for index := 1; index < len(args); index += 2 {
			if index+1 >= len(args) {
				return fail(stderr, "log options require values")
			}
			switch args[index] {
			case "--date":
				day = args[index+1]
			case "--query":
				query = args[index+1]
			case "--limit":
				limit, err = strconv.Atoi(args[index+1])
				if err != nil {
					return fail(stderr, "log limit must be an integer")
				}
			default:
				return fail(stderr, "unknown log option "+args[index])
			}
		}
		database, err := store.Open(filepath.Join(root, "imprint.db"), operatorID, value.NodeID)
		if err != nil {
			return fail(stderr, err.Error())
		}
		defer database.Close()
		items, err := database.EventLog(context.Background(), day, query, limit)
		if err != nil {
			return fail(stderr, err.Error())
		}
		response, _ := canonical.JSON(map[string]any{"status": "ok", "date": day, "limit": limit, "count": len(items), "items": items})
		fmt.Fprintln(stdout, string(response))
		return 0
	case "health":
		deep := false
		if len(args) == 2 && args[1] == "--deep" {
			deep = true
		} else if len(args) != 1 {
			return fail(stderr, "health accepts only --deep")
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
		integrity := "not_requested"
		if deep {
			integrity, err = database.Integrity(context.Background())
			if err != nil {
				return fail(stderr, err.Error())
			}
			if integrity != "ok" {
				return fail(stderr, "store integrity check failed: "+integrity)
			}
		}
		response, _ := canonical.JSON(map[string]any{"status": "healthy", "store": "compatible", "integrity": integrity, "compiler": value.Compiler, "hook_timeout_seconds": value.HookTimeoutSeconds})
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
