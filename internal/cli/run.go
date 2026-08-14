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
	"github.com/artemus/imprint/internal/session"
	"github.com/artemus/imprint/internal/spool"
	"github.com/artemus/imprint/internal/store"
	"github.com/artemus/imprint/internal/transcript"
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
  hook      execute a native Claude Code hook action
`

func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
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
	case "hook":
		if len(args) != 2 || args[1] != "stop-capture" {
			return fail(stderr, "native hook currently requires stop-capture")
		}
		var event map[string]any
		decoder := json.NewDecoder(stdin)
		if err := decoder.Decode(&event); err != nil {
			return hookFailure(stdout, stderr, "hook_input_invalid", false, true)
		}
		stopActive, _ := event["stop_hook_active"].(bool)
		if schema, ok := event["hook_schema_version"]; ok && schema != "1.0.0" {
			return hookFailure(stdout, stderr, "unsupported hook_schema_version", stopActive, true)
		}
		if name, ok := event["hook_event_name"]; ok && name != "Stop" {
			return hookFailure(stdout, stderr, "hook_event_name_invalid", stopActive, true)
		}
		value, err := config.Load(configPath)
		if err != nil {
			return hookFailure(stdout, stderr, "hook_runtime_failed", stopActive, true)
		}
		root, err := paths.OperatorRoot(value)
		if err != nil {
			return hookFailure(stdout, stderr, "hook_runtime_failed", stopActive, true)
		}
		operatorID, err := identity.LoadOrCreate(root)
		if err != nil {
			return hookFailure(stdout, stderr, "hook_runtime_failed", stopActive, true)
		}
		nativeSession, ok := stringField(event, "session_id", "sessionId")
		if !ok {
			nativeSession = "unavailable-event:" + time.Now().UTC().Format(time.RFC3339Nano)
		}
		sessionID, err := session.OpaqueURN(root, nativeSession)
		if err != nil {
			return hookFailure(stdout, stderr, "hook_runtime_failed", stopActive, true)
		}
		operatorText, ok := stringField(event, "operator_text", "last_user_message")
		priorAssistant, _ := stringField(event, "prior_assistant_output")
		caseDescription, _ := stringField(event, "case_description")
		contextualEvidence := []capture.EvidenceInput{}
		extensions := map[string]capture.Extension{}
		var degradation map[string]any
		if !ok || strings.TrimSpace(operatorText) == "" {
			if transcriptPath, hasPath := stringField(event, "transcript_path"); hasPath {
				parsed, parseErr := transcript.Parse(transcriptPath)
				if parseErr != nil {
					return hookFailure(stdout, stderr, parseErr.Error(), stopActive, true)
				}
				operatorText = parsed.OperatorText
				priorAssistant = parsed.PriorAssistant
				caseDescription = parsed.CaseDescription
				if priorAssistant != "" {
					contextualEvidence = append(contextualEvidence, capture.EvidenceInput{Kind: "context", Content: priorAssistant, SourceLocator: parsed.SourceLocator})
				}
				if parsed.Degradation != nil {
					payload, _ := json.Marshal(parsed.Degradation)
					extensions["org.imprint.transcript"] = capture.Extension{SchemaVersion: "1.0.0", Payload: payload}
					degradation = parsed.Degradation
				}
				ok = true
			}
		}
		if !ok || strings.TrimSpace(operatorText) == "" {
			response, _ := canonical.JSON(map[string]any{"hook_schema_version": "1.0.0", "status": "skipped", "reason": "feedback_text_unavailable"})
			fmt.Fprintln(stdout, string(response))
			return 0
		}
		priorOperator, _ := stringField(event, "prior_operator_text")
		detection := capture.Detect(operatorText, priorOperator, priorAssistant)
		if !detection.IsFeedback {
			response, _ := canonical.JSON(map[string]any{"hook_schema_version": "1.0.0", "status": "skipped", "reason": "not_explicit_feedback"})
			fmt.Fprintln(stdout, string(response))
			return 0
		}
		if strings.TrimSpace(caseDescription) == "" {
			caseDescription = "Explicit operator feedback witnessed by explicit hook input"
		}
		var reason *string
		if text, ok := stringField(event, "reason"); ok {
			reason = &text
		}
		envelope, err := capture.Build(capture.BuildOptions{OperatorID: operatorID, SessionID: sessionID, NodeID: value.NodeID, CaseDescription: caseDescription, RawOperatorText: operatorText, CallType: detection.CallType, CaptureMechanism: "claude_code_stop_hook", CapturedBy: "imprint-hook", Reason: reason, ContextualEvidence: contextualEvidence, Extensions: extensions})
		if err != nil {
			return hookFailure(stdout, stderr, "hook_action_failed", stopActive, true)
		}
		spoolPath, err := spool.Write(root, envelope)
		if err != nil {
			return hookFailure(stdout, stderr, "spool_write_failed", stopActive, true)
		}
		receipt := map[string]any{"hook_schema_version": "1.0.0", "status": "queued", "event_id": envelope.InputEventID, "spool_file": filepath.Base(spoolPath), "canonical_status": "spool_only"}
		if value.Compiler {
			database, openErr := store.Open(filepath.Join(root, "imprint.db"), operatorID, value.NodeID)
			if openErr != nil {
				receipt["compile_status"] = "degraded"
				receipt["compile_error_type"] = "StoreOpenError"
			} else {
				counts, compileErr := compiler.Compile(context.Background(), root, database)
				_ = database.Close()
				if compileErr != nil {
					receipt["compile_status"] = "degraded"
					receipt["compile_error_type"] = "CompilerError"
				} else {
					receipt["canonical_status"] = "compiled"
					receipt["compile_status"] = "healthy"
					receipt["compile"] = counts
				}
			}
		}
		if degradation != nil {
			receipt["degradation"] = degradation
		}
		response, _ := canonical.JSON(receipt)
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

func hookFailure(stdout, stderr io.Writer, message string, stopActive, captureLost bool) int {
	policy := "fail_open"
	if captureLost {
		policy = "fail_closed"
	}
	response, _ := canonical.JSON(map[string]any{"hook_schema_version": "1.0.0", "status": "degraded", "error": message, "hook_action": "stop-capture", "failure_policy": policy})
	fmt.Fprintln(stdout, string(response))
	fmt.Fprintln(stderr, "Imprint Stop capture failed: "+message)
	if captureLost && !stopActive {
		return 2
	}
	return 0
}
func stringField(value map[string]any, names ...string) (string, bool) {
	for _, name := range names {
		if item, ok := value[name].(string); ok {
			return item, true
		}
	}
	return "", false
}
