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
	"github.com/artemus/imprint/internal/domain"
	"github.com/artemus/imprint/internal/identity"
	"github.com/artemus/imprint/internal/paths"
	"github.com/artemus/imprint/internal/retrieve"
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
  spool     prune only acknowledged inputs owned by this producer
  store     explicitly recover crash-resident SQLite WAL state
  export    render a deterministic Markdown view of canonical state
  derive    validate and compile non-authoritative proposals
  whoami    print the configured opaque local identity
  log       list a bounded UTC-day canonical event index
  health    verify configuration and canonical store integrity
  hook      execute a native Claude Code hook action
  retrieve  build provenance-gated context under an exact byte budget
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
	case "spool":
		if len(args) < 2 || args[1] != "prune" {
			return fail(stderr, "spool requires prune")
		}
		value, err := config.Load(configPath)
		if err != nil {
			return fail(stderr, err.Error())
		}
		retention := value.SpoolRetentionDays
		if len(args) == 4 && args[2] == "--retention-days" {
			retention, err = strconv.Atoi(args[3])
			if err != nil {
				return fail(stderr, "spool retention-days must be an integer")
			}
		} else if len(args) != 2 {
			return fail(stderr, "spool prune accepts only --retention-days DAYS")
		}
		root, err := paths.OperatorRoot(value)
		if err != nil {
			return fail(stderr, err.Error())
		}
		counts, err := compiler.PruneAcknowledged(root, value.NodeID, retention, time.Now())
		if err != nil {
			return fail(stderr, err.Error())
		}
		status := "ok"
		if counts.Invalid > 0 {
			status = "degraded"
		}
		response, _ := canonical.JSON(map[string]any{"status": status, "deleted": counts.Deleted, "retained": counts.Retained, "already_pruned": counts.AlreadyPruned, "acknowledgements_deleted": counts.AcknowledgementsDeleted, "quarantine_deleted": counts.QuarantineDeleted, "invalid": counts.Invalid})
		fmt.Fprintln(stdout, string(response))
		if counts.Invalid > 0 {
			return 2
		}
		return 0
	case "store":
		if len(args) != 2 || args[1] != "recover" {
			return fail(stderr, "store requires recover")
		}
		value, err := config.Load(configPath)
		if err != nil {
			return fail(stderr, err.Error())
		}
		root, err := paths.OperatorRoot(value)
		if err != nil {
			return fail(stderr, err.Error())
		}
		result, err := store.Recover(context.Background(), filepath.Join(root, "imprint.db"))
		if err != nil {
			return fail(stderr, err.Error())
		}
		response, _ := canonical.JSON(result)
		fmt.Fprintln(stdout, string(response))
		return 0
	case "export":
		return runExport(args, configPath, stdout, stderr)
	case "derive":
		return runDerive(args, configPath, stdout, stderr)
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
		if len(args) != 2 || (args[1] != "stop-capture" && args[1] != "session-start" && args[1] != "user-prompt-submit" && args[1] != "health-check") {
			return fail(stderr, "unsupported native hook action")
		}
		action := args[1]
		var event map[string]any
		decoder := json.NewDecoder(stdin)
		if err := decoder.Decode(&event); err != nil {
			if action != "stop-capture" {
				return readHookFailure(stdout, action, "hook_input_invalid")
			}
			return hookFailure(stdout, stderr, "hook_input_invalid", false, true)
		}
		stopActive, _ := event["stop_hook_active"].(bool)
		if schema, ok := event["hook_schema_version"]; ok && schema != "1.0.0" {
			if action != "stop-capture" {
				return readHookFailure(stdout, action, "unsupported_hook_schema_version")
			}
			return hookFailure(stdout, stderr, "unsupported hook_schema_version", stopActive, true)
		}
		expectedName := map[string]string{"stop-capture": "Stop", "session-start": "SessionStart", "user-prompt-submit": "UserPromptSubmit", "health-check": "SessionStart"}[action]
		if name, ok := event["hook_event_name"]; ok && name != expectedName {
			if action != "stop-capture" {
				return readHookFailure(stdout, action, "hook_event_name_invalid")
			}
			return hookFailure(stdout, stderr, "hook_event_name_invalid", stopActive, true)
		}
		value, err := config.Load(configPath)
		if err != nil {
			if action != "stop-capture" {
				return readHookFailure(stdout, action, "hook_runtime_failed")
			}
			return hookFailure(stdout, stderr, "hook_runtime_failed", stopActive, true)
		}
		root, err := paths.OperatorRoot(value)
		if err != nil {
			if action != "stop-capture" {
				return readHookFailure(stdout, action, "hook_runtime_failed")
			}
			return hookFailure(stdout, stderr, "hook_runtime_failed", stopActive, true)
		}
		operatorID, err := identity.LoadOrCreate(root)
		if err != nil {
			if action != "stop-capture" {
				return readHookFailure(stdout, action, "hook_runtime_failed")
			}
			return hookFailure(stdout, stderr, "hook_runtime_failed", stopActive, true)
		}
		nativeSession, ok := stringField(event, "session_id", "sessionId")
		if !ok {
			nativeSession = "unavailable-event:" + time.Now().UTC().Format(time.RFC3339Nano)
		}
		sessionID, err := session.OpaqueURN(root, nativeSession)
		if err != nil {
			if action != "stop-capture" {
				return readHookFailure(stdout, action, "hook_runtime_failed")
			}
			return hookFailure(stdout, stderr, "hook_runtime_failed", stopActive, true)
		}
		if action != "stop-capture" {
			return runReadHook(action, event, value, root, operatorID, sessionID, stdout)
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
	case "retrieve":
		value, err := config.Load(configPath)
		if err != nil {
			return fail(stderr, err.Error())
		}
		sessionValue, prompt, domain, mode := "", "", "", "authoritative"
		refresh, audit := false, false
		requested := []string{}
		for index := 1; index < len(args); index++ {
			switch args[index] {
			case "--refresh":
				refresh = true
			case "--audit":
				audit = true
			case "--session", "--prompt", "--domain", "--authority-mode", "--partition":
				if index+1 >= len(args) {
					return fail(stderr, args[index]+" requires a value")
				}
				option := args[index]
				index++
				switch option {
				case "--session":
					sessionValue = args[index]
				case "--prompt":
					prompt = args[index]
				case "--domain":
					domain = args[index]
				case "--authority-mode":
					mode = args[index]
				case "--partition":
					requested = append(requested, args[index])
				}
			default:
				return fail(stderr, "unknown retrieve option "+args[index])
			}
		}
		if sessionValue == "" {
			return fail(stderr, "retrieve requires --session")
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
		records, snapshotID, err := retrieve.FromStore(context.Background(), database)
		if err != nil {
			return fail(stderr, err.Error())
		}
		scope := ""
		if mode != "authoritative" || len(requested) > 0 {
			scope = "query-" + retrieve.SafeSession(mode + "\x00" + strings.Join(requested, "\x00"))[:16]
		}
		safeSession := retrieve.SafeSession(sessionValue)
		if !refresh {
			cached, delivered, receiptErr := retrieve.Existing(root, safeSession, snapshotID, scope)
			if receiptErr != nil {
				return fail(stderr, receiptErr.Error())
			}
			if delivered {
				response, _ := canonical.JSON(map[string]any{"status": "already_delivered", "snapshot_id": snapshotID, "payload": "", "selected_ids": []string{}})
				fmt.Fprintln(stdout, string(response))
				return 0
			}
			if cached != nil {
				response, _ := canonical.JSON(cached)
				fmt.Fprintln(stdout, string(response))
				return 0
			}
		}
		format := "compact"
		if audit {
			format = "audit"
		}
		result, err := retrieve.Retrieve(records, prompt, domain, requested, retrieve.Config{Budget: value.ContextBudgetBytes, AllowHigher: value.AllowHigherBudget, AuthorityMode: mode, OutputFormat: format})
		if err != nil {
			return fail(stderr, err.Error())
		}
		responseMap := map[string]any{"status": "delivered", "snapshot_id": snapshotID, "payload": string(result.Payload), "selected_ids": result.SelectedIDs, "selected_bytes": result.SelectedBytes, "budget_bytes": result.BudgetBytes, "eligible_count": result.EligibleCount, "omitted_count": result.OmittedCount, "section_bytes": result.SectionBytes, "tokenizer_version": result.TokenizerVersion, "authority_mode": result.AuthorityMode, "requested_partitions": result.RequestedPartitions, "selected_by_partition": result.SelectedByPartition, "receipt_scope": nil}
		if scope != "" {
			responseMap["receipt_scope"] = scope
		}
		if !refresh {
			responseMap, err = retrieve.Prepare(root, safeSession, snapshotID, scope, responseMap)
			if err != nil {
				return fail(stderr, err.Error())
			}
		}
		response, _ := canonical.JSON(responseMap)
		fmt.Fprintln(stdout, string(response))
		if !refresh {
			if flusher, ok := stdout.(interface{ Flush() error }); ok {
				_ = flusher.Flush()
			}
			if _, err = retrieve.Commit(root, safeSession, snapshotID, scope); err != nil {
				return fail(stderr, err.Error())
			}
		}
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
func readHookFailure(stdout io.Writer, action, message string) int {
	eventName := map[string]string{"session-start": "SessionStart", "user-prompt-submit": "UserPromptSubmit", "health-check": "SessionStart"}[action]
	body := map[string]any{"hook_schema_version": "1.0.0", "status": "degraded", "error": message, "hook_action": action, "failure_policy": "fail_open", "hookSpecificOutput": map[string]any{"hookEventName": eventName, "additionalContext": ""}}
	encoded, _ := canonical.JSON(body)
	fmt.Fprintln(stdout, string(encoded))
	return 0
}

func runReadHook(action string, event map[string]any, value config.Config, root, operatorID, sessionID string, stdout io.Writer) int {
	if action == "health-check" {
		database, err := store.Open(filepath.Join(root, "imprint.db"), operatorID, value.NodeID)
		if err != nil {
			return readHookFailure(stdout, action, "hook_runtime_failed")
		}
		defer database.Close()
		integrity, err := database.Integrity(context.Background())
		status := "healthy"
		if err != nil || integrity != "ok" {
			status = "degraded"
		}
		body := map[string]any{"hook_schema_version": "1.0.0", "status": status, "store": "compatible", "integrity": integrity}
		encoded, _ := canonical.JSON(body)
		fmt.Fprintln(stdout, string(encoded))
		if status != "healthy" {
			return 2
		}
		return 0
	}
	if action == "session-start" {
		source, _ := stringField(event, "source")
		refresh := source == "compact" || source == "resume"
		response, snapshot, scope, prepared, err := hookRetrieve(root, operatorID, value, sessionID, "", "", false, refresh)
		if err != nil {
			return readHookFailure(stdout, action, "hook_runtime_failed")
		}
		body := map[string]any{"hook_schema_version": "1.0.0", "status": response["status"], "hookSpecificOutput": map[string]any{"hookEventName": "SessionStart", "additionalContext": stringValue(response["payload"])}}
		encoded, _ := canonical.JSON(body)
		fmt.Fprintln(stdout, string(encoded))
		if prepared {
			_, _ = retrieve.Commit(root, retrieve.SafeSession(sessionID), snapshot, scope)
		}
		return 0
	}
	prompt, _ := stringField(event, "prompt", "user_prompt")
	path, _ := stringField(event, "cwd", "working_directory")
	explicit, _ := stringField(event, "domain_id")
	selection := domain.Select(value.Domains, explicit, path, prompt)
	if selection.ID == "" {
		body := map[string]any{"hook_schema_version": "1.0.0", "status": "skipped", "reason": selection.Diagnostic, "hookSpecificOutput": map[string]any{"hookEventName": "UserPromptSubmit", "additionalContext": ""}}
		encoded, _ := canonical.JSON(body)
		fmt.Fprintln(stdout, string(encoded))
		return 0
	}
	response, snapshot, scope, prepared, err := hookRetrieve(root, operatorID, value, sessionID, prompt, selection.ID, true, false)
	if err != nil {
		return readHookFailure(stdout, action, "hook_runtime_failed")
	}
	body := map[string]any{"hook_schema_version": "1.0.0", "status": response["status"], "domain_id": selection.ID, "selection_method": selection.Method, "hookSpecificOutput": map[string]any{"hookEventName": "UserPromptSubmit", "additionalContext": stringValue(response["payload"])}}
	encoded, _ := canonical.JSON(body)
	fmt.Fprintln(stdout, string(encoded))
	if prepared {
		_, _ = retrieve.Commit(root, retrieve.SafeSession(sessionID), snapshot, scope)
	}
	return 0
}

func hookRetrieve(root, operatorID string, value config.Config, sessionID, prompt, selectedDomain string, domainOnly, refresh bool) (map[string]any, string, string, bool, error) {
	database, err := store.Open(filepath.Join(root, "imprint.db"), operatorID, value.NodeID)
	if err != nil {
		return nil, "", "", false, err
	}
	defer database.Close()
	records, snapshot, err := retrieve.FromStore(context.Background(), database)
	if err != nil {
		return nil, "", "", false, err
	}
	if domainOnly {
		filtered := records[:0]
		for _, record := range records {
			if record.Section == "domain" {
				filtered = append(filtered, record)
			}
		}
		records = filtered
	}
	scope := ""
	if domainOnly {
		scope = selectedDomain
	}
	safeSession := retrieve.SafeSession(sessionID)
	if !refresh {
		cached, delivered, err := retrieve.Existing(root, safeSession, snapshot, scope)
		if err != nil {
			return nil, "", "", false, err
		}
		if delivered {
			return map[string]any{"status": "already_delivered", "snapshot_id": snapshot, "payload": "", "selected_ids": []string{}}, snapshot, scope, false, nil
		}
		if cached != nil {
			return cached, snapshot, scope, true, nil
		}
	}
	result, err := retrieve.Retrieve(records, prompt, selectedDomain, nil, retrieve.Config{Budget: value.ContextBudgetBytes, AllowHigher: value.AllowHigherBudget, AuthorityMode: "authoritative", OutputFormat: "compact"})
	if err != nil {
		return nil, "", "", false, err
	}
	response := map[string]any{"status": "delivered", "snapshot_id": snapshot, "payload": string(result.Payload), "selected_ids": result.SelectedIDs, "selected_bytes": result.SelectedBytes, "budget_bytes": result.BudgetBytes, "eligible_count": result.EligibleCount, "omitted_count": result.OmittedCount, "section_bytes": result.SectionBytes, "tokenizer_version": result.TokenizerVersion, "authority_mode": result.AuthorityMode, "requested_partitions": result.RequestedPartitions, "selected_by_partition": result.SelectedByPartition, "receipt_scope": nil}
	if scope != "" {
		response["receipt_scope"] = scope
	}
	if refresh {
		return response, snapshot, scope, false, nil
	}
	prepared, err := retrieve.Prepare(root, safeSession, snapshot, scope, response)
	return prepared, snapshot, scope, err == nil, err
}
func stringValue(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}
func stringField(value map[string]any, names ...string) (string, bool) {
	for _, name := range names {
		if item, ok := value[name].(string); ok {
			return item, true
		}
	}
	return "", false
}
