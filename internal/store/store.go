// Package store implements the canonical SQLite ledger.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
	_ "modernc.org/sqlite"

	"github.com/artemus/imprint/internal/authority"
	"github.com/artemus/imprint/internal/canonical"
	"github.com/artemus/imprint/internal/capture"
	"github.com/artemus/imprint/internal/privateio"
	"github.com/artemus/imprint/internal/urn"
)

const StoreSchemaVersion = "3.0.0"
const OntologySchemaVersion = "3.1.0"

type Store struct {
	path, operatorID, nodeID string
	db                       *sql.DB
}

type LogItem struct {
	EventID          string `json:"event_id"`
	EventType        string `json:"event_type"`
	SystemTime       string `json:"system_time"`
	ValidTime        string `json:"valid_time"`
	ProvenanceStatus string `json:"provenance_status"`
	NodeTypes        string `json:"node_types"`
}

type NodeRow struct {
	NodeID, NodeType, OperatorID, VersionID, ProvenanceStatus, AuthorityTier, ValidFrom, ValidTo string
	Payload                                                                                      map[string]any
	Evidence                                                                                     []string
}
type EdgeRow struct{ EdgeType, SourceID, TargetID string }
type RetrievalSnapshot struct {
	Identity       string
	Generation     int64
	Nodes          []NodeRow
	Edges          []EdgeRow
	SourceReceipts map[string]bool
}

func (s *Store) RetrievalState(ctx context.Context) (RetrievalSnapshot, error) {
	var result RetrievalSnapshot
	var generation string
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key='store_identity'").Scan(&result.Identity); err != nil {
		return result, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key='content_generation'").Scan(&generation); err != nil {
		return result, err
	}
	parsed, err := strconv.ParseInt(generation, 10, 64)
	if err != nil || parsed < 0 {
		return result, errors.New("content generation metadata is invalid")
	}
	result.Generation = parsed
	knownSemantic := false
	_ = s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='semantic_node_versions')").Scan(&knownSemantic)
	query := `SELECT n.node_id,n.node_type,n.operator_id,nv.version_id,nv.payload_json,nv.provenance_status,nv.authority_tier,nv.evidence_json,nv.valid_from,COALESCE(nv.valid_to,'') FROM nodes n JOIN node_versions nv USING(node_id) WHERE nv.system_to IS NULL`
	if knownSemantic {
		query += ` AND NOT EXISTS(SELECT 1 FROM semantic_node_versions snv WHERE snv.version_id=nv.version_id)`
	}
	query += ` ORDER BY n.node_type,n.node_id`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var item NodeRow
		var payload, evidence string
		if err = rows.Scan(&item.NodeID, &item.NodeType, &item.OperatorID, &item.VersionID, &payload, &item.ProvenanceStatus, &item.AuthorityTier, &evidence, &item.ValidFrom, &item.ValidTo); err != nil {
			return result, err
		}
		if json.Unmarshal([]byte(payload), &item.Payload) != nil || json.Unmarshal([]byte(evidence), &item.Evidence) != nil {
			continue
		}
		result.Nodes = append(result.Nodes, item)
	}
	edgeRows, err := s.db.QueryContext(ctx, `SELECT e.edge_type,e.source_id,e.target_id FROM edges e JOIN edge_versions ev USING(edge_id) WHERE ev.system_to IS NULL AND e.operator_id=? AND e.edge_type IN ('verdict_about_case','supported_by')`, s.operatorID)
	if err != nil {
		return result, err
	}
	defer edgeRows.Close()
	for edgeRows.Next() {
		var item EdgeRow
		if err = edgeRows.Scan(&item.EdgeType, &item.SourceID, &item.TargetID); err != nil {
			return result, err
		}
		result.Edges = append(result.Edges, item)
	}
	result.SourceReceipts = map[string]bool{}
	receiptRows, err := s.db.QueryContext(ctx, `SELECT sr.source_id FROM source_receipts sr JOIN events e USING(event_id) WHERE e.operator_id=?`, s.operatorID)
	if err != nil {
		return result, err
	}
	defer receiptRows.Close()
	for receiptRows.Next() {
		var id string
		if err = receiptRows.Scan(&id); err != nil {
			return result, err
		}
		result.SourceReceipts[id] = true
	}
	return result, nil
}

func (s *Store) EventLog(ctx context.Context, day, query string, limit int) ([]LogItem, error) {
	if limit < 1 || limit > 200 {
		return nil, errors.New("log limit must be 1..200")
	}
	if _, err := time.Parse("2006-01-02", day); err != nil {
		return nil, errors.New("log date must be YYYY-MM-DD")
	}
	pattern := "%" + strings.TrimSpace(query) + "%"
	rows, err := s.db.QueryContext(ctx, `SELECT e.event_id,e.event_type,e.system_time,e.valid_time,e.provenance_status,COALESCE(GROUP_CONCAT(n.node_type,','),'') FROM events e LEFT JOIN nodes n ON n.created_event_id=e.event_id WHERE substr(e.system_time,1,10)=? AND (?='' OR e.event_type LIKE ? OR e.event_id LIKE ?) GROUP BY e.event_id ORDER BY e.system_time DESC,e.event_id DESC LIMIT ?`, day, strings.TrimSpace(query), pattern, pattern, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []LogItem{}
	for rows.Next() {
		var item LogItem
		if err = rows.Scan(&item.EventID, &item.EventType, &item.SystemTime, &item.ValidTime, &item.ProvenanceStatus, &item.NodeTypes); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) Integrity(ctx context.Context) (string, error) {
	var result string
	err := s.db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result)
	return result, err
}

func Open(path, operatorID, nodeID string) (*Store, error) {
	if err := privateio.EnsureDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	existing := true
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		existing = false
	} else if err != nil {
		return nil, err
	}
	if existing {
		if _, err := requireRegularStore(path); err != nil {
			return nil, err
		}
		if err := rejectAmbiguousSQLiteState(path); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=rwc&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	value := &Store{path: path, operatorID: operatorID, nodeID: nodeID, db: db}
	if existing {
		if err = value.requireCompatible(context.Background()); err != nil {
			db.Close()
			return nil, err
		}
	}
	if _, err = db.Exec(captureSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize store: %w", err)
	}
	if err = authority.InitializeApprovalSchema(context.Background(), db); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize authority store: %w", err)
	}
	storeID, _ := urn.New("store")
	for key, item := range map[string]string{"store_schema_version": StoreSchemaVersion, "ontology_schema_version": OntologySchemaVersion, "store_identity": storeID} {
		if _, err = db.Exec("INSERT OR IGNORE INTO meta(key,value) VALUES(?,?)", key, item); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err = value.requireCompatible(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if err = secureSQLite(path); err != nil {
		db.Close()
		return nil, err
	}
	return value, nil
}

// AuthorityTransaction runs an authority-sensitive mutation under SQLite's
// immediate write lock and commits only when the callback succeeds.
func (s *Store) AuthorityTransaction(ctx context.Context, mutate func(*sql.Tx) error) (returned error) {
	if mutate == nil {
		return errors.New("authority mutation callback is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if returned != nil {
			_ = tx.Rollback()
		}
	}()
	if err := mutate(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Close() error {
	err := s.db.Close()
	secureErr := secureSQLite(s.path)
	if err != nil {
		return err
	}
	return secureErr
}

func (s *Store) requireCompatible(ctx context.Context) error {
	return requireCompatibleConnection(ctx, s.db)
}

func (s *Store) ApplyCapture(ctx context.Context, envelope capture.Envelope, sourcePath string) (result string, returned error) {
	if err := envelope.Validate(); err != nil {
		return "", err
	}
	if envelope.OperatorID != s.operatorID {
		return "", errors.New("capture operator does not match the configured canonical operator")
	}
	if envelope.NodeID != s.nodeID {
		return "", errors.New("capture node does not match the configured producer node")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() {
		if returned != nil {
			_ = tx.Rollback()
		}
	}()
	encoded, err := canonical.JSON(envelope)
	if err != nil {
		return "", err
	}
	eventHash := hashBytes(encoded)
	contentHash := feedbackHash(envelope.Verdict.RawOperatorText)
	var prior string
	err = tx.QueryRowContext(ctx, "SELECT payload_sha256 FROM consumed_inputs WHERE input_event_id=?", envelope.InputEventID).Scan(&prior)
	if err == nil {
		_ = tx.Rollback()
		if prior == eventHash {
			return "duplicate", nil
		}
		return "", errors.New("same input_event_id has different bytes")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	var exists int
	err = tx.QueryRowContext(ctx, "SELECT 1 FROM captured_feedback_dedup WHERE operator_id=? AND content_sha256=?", envelope.OperatorID, contentHash).Scan(&exists)
	if err == nil {
		_ = tx.Rollback()
		return "duplicate", nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err = tx.ExecContext(ctx, "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)", envelope.InputEventID, "captured", envelope.OperatorID, now, envelope.CapturedAt, string(encoded), eventHash, nil, "captured"); err != nil {
		return "", err
	}
	if err = s.insertNode(ctx, tx, envelope.Case.ID, "Case", envelope.Case, envelope, now); err != nil {
		return "", err
	}
	if err = s.insertNode(ctx, tx, envelope.Verdict.ID, "Verdict", envelope.Verdict, envelope, now); err != nil {
		return "", err
	}
	if err = s.insertNode(ctx, tx, envelope.Verdict.Call.ID, "Call", envelope.Verdict.Call, envelope, now); err != nil {
		return "", err
	}
	if err = s.insertEdge(ctx, tx, "verdict_about_case", envelope.Verdict.ID, envelope.Case.ID, envelope, now); err != nil {
		return "", err
	}
	if err = s.insertEdge(ctx, tx, "made_call", envelope.Verdict.ID, envelope.Verdict.Call.ID, envelope, now); err != nil {
		return "", err
	}
	for _, evidence := range envelope.Evidence {
		if err = s.insertNode(ctx, tx, evidence.ID, "Evidence", evidence, envelope, now); err != nil {
			return "", err
		}
		if err = s.insertEdge(ctx, tx, "supported_by", envelope.Verdict.ID, evidence.ID, envelope, now); err != nil {
			return "", err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO source_receipts VALUES(?,?,?,?,?)", evidence.ID, evidence.Kind, evidence.SourceLocator, evidence.SHA256, envelope.InputEventID); err != nil {
			return "", err
		}
	}
	for _, alternative := range envelope.Alternatives {
		if err = s.insertNode(ctx, tx, alternative.ID, "Alternative", alternative, envelope, now); err != nil {
			return "", err
		}
	}
	for _, id := range envelope.Verdict.ChosenAlternativeIDs {
		if err = s.insertEdge(ctx, tx, "chose_alternative", envelope.Verdict.ID, id, envelope, now); err != nil {
			return "", err
		}
	}
	for _, id := range envelope.Verdict.RejectedAlternativeIDs {
		if err = s.insertEdge(ctx, tx, "rejected_alternative", envelope.Verdict.ID, id, envelope, now); err != nil {
			return "", err
		}
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO consumed_inputs VALUES(?,?,?,?)", envelope.InputEventID, eventHash, now, sourcePath); err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO captured_feedback_dedup VALUES(?,?,?,?)", envelope.OperatorID, contentHash, envelope.InputEventID, envelope.CapturedAt); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return "captured", secureSQLite(s.path)
}

func (s *Store) insertNode(ctx context.Context, tx *sql.Tx, id, nodeType string, payload any, envelope capture.Envelope, now string) error {
	if _, err := tx.ExecContext(ctx, "INSERT INTO nodes VALUES(?,?,?,?)", id, nodeType, envelope.OperatorID, envelope.InputEventID); err != nil {
		return err
	}
	versionID, err := urn.New("node-version")
	if err != nil {
		return err
	}
	payloadJSON, err := canonical.JSON(payload)
	if err != nil {
		return err
	}
	provenance, err := canonical.JSON(versionProvenance(envelope, ""))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO node_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", versionID, id, string(payloadJSON), hashBytes(payloadJSON), "captured", "observed_candidate", string(provenance), evidenceJSON(envelope), envelope.CapturedAt, nil, now, nil, envelope.InputEventID, nil)
	return err
}

func (s *Store) insertEdge(ctx context.Context, tx *sql.Tx, edgeType, source, target string, envelope capture.Envelope, now string) error {
	edgeID, err := urn.New("edge")
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO edges VALUES(?,?,?,?,?,?)", edgeID, edgeType, source, target, envelope.OperatorID, envelope.InputEventID); err != nil {
		return err
	}
	versionID, err := urn.New("edge-version")
	if err != nil {
		return err
	}
	payload := map[string]string{"why": "witnessed in raw capture", "relation": edgeType}
	payloadJSON, _ := canonical.JSON(payload)
	provenance, _ := canonical.JSON(versionProvenance(envelope, edgeType))
	_, err = tx.ExecContext(ctx, "INSERT INTO edge_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", versionID, edgeID, string(payloadJSON), hashBytes(payloadJSON), "captured", "observed_candidate", string(provenance), evidenceJSON(envelope), envelope.CapturedAt, nil, now, nil, envelope.InputEventID, nil)
	return err
}

func versionProvenance(envelope capture.Envelope, relation string) map[string]any {
	var relationValue any = nil
	if relation != "" {
		relationValue = relation
	}
	return map[string]any{"provenance_schema_version": "1.0.0", "status": "captured", "authority_tier": "observed_candidate", "actor_class": "software", "actor_id": "imprint-recorder", "mechanism": envelope.CaptureMechanism, "software": map[string]string{"name": "imprint-local", "version": "3.1.2"}, "model": nil, "prompt_recipe": nil, "proposal_id": nil, "ratifier": nil, "event_id": envelope.InputEventID, "relation": relationValue}
}
func evidenceJSON(envelope capture.Envelope) string {
	values := make([]string, len(envelope.Evidence))
	for i, item := range envelope.Evidence {
		encoded, _ := json.Marshal(item.ID)
		values[i] = string(encoded)
	}
	return "[" + strings.Join(values, ", ") + "]"
}
func hashBytes(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
func feedbackHash(value string) string {
	normalized := norm.NFKC.String(value)
	normalized = cases.Fold().String(normalized)
	normalized = strings.Join(strings.Fields(normalized), " ")
	return hashBytes([]byte(normalized))
}
func secureSQLite(path string) error {
	for _, item := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		if info, err := os.Lstat(item); err == nil {
			if !info.Mode().IsRegular() {
				return errors.New("SQLite state must be regular files")
			}
			if err = os.Chmod(item, 0o600); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
