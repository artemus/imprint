package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/artemus/imprint/internal/canonical"
	"github.com/artemus/imprint/internal/proposal"
	"github.com/artemus/imprint/internal/urn"
)

func (s *Store) ApplyProposal(ctx context.Context, value proposal.Proposal) (result string, returned error) {
	if err := value.Validate(); err != nil {
		return "", err
	}
	payload, err := canonical.JSON(value)
	if err != nil {
		return "", err
	}
	payloadHash := hashBytes(payload)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() {
		if returned != nil {
			_ = tx.Rollback()
		}
	}()
	var priorHash string
	err = tx.QueryRowContext(ctx, `SELECT nv.payload_sha256 FROM nodes n JOIN node_versions nv USING(node_id) WHERE n.node_id=? AND n.node_type='Proposal' ORDER BY nv.system_from LIMIT 1`, value.ID).Scan(&priorHash)
	if err == nil {
		_ = tx.Rollback()
		if priorHash == payloadHash {
			return "duplicate", nil
		}
		return "", errors.New("same proposal_id has different bytes")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	var operatorID, validTime, eventType, sourcePayload string
	if err = tx.QueryRowContext(ctx, `SELECT operator_id,valid_time,event_type,payload_json FROM events WHERE event_id=?`, value.SourceInputEventID).Scan(&operatorID, &validTime, &eventType, &sourcePayload); err != nil || eventType != "captured" {
		return "", errors.New("proposal source_input_event_id is not a captured canonical event")
	}
	var source map[string]any
	if json.Unmarshal([]byte(sourcePayload), &source) != nil || operatorID != s.operatorID || source["node_id"] != s.nodeID {
		return "", errors.New("proposal source does not match the configured canonical producer")
	}
	for _, reference := range []struct{ id, kind string }{{value.References.CaseID, "Case"}, {value.References.VerdictID, "Verdict"}} {
		var known int
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE node_id=? AND node_type=? AND created_event_id=?)`, reference.id, reference.kind, value.SourceInputEventID).Scan(&known); err != nil || known != 1 {
			return "", errors.New("proposal reference does not belong to its source event")
		}
	}
	evidenceIDs := uniqueStrings(value.References.EvidenceIDs)
	for _, evidenceID := range evidenceIDs {
		var known int
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM nodes n JOIN source_receipts sr ON sr.source_id=n.node_id WHERE n.node_id=? AND n.node_type='Evidence' AND n.created_event_id=? AND sr.event_id=?)`, evidenceID, value.SourceInputEventID, value.SourceInputEventID).Scan(&known); err != nil || known != 1 {
			return "", errors.New("proposal evidence reference does not belong to its source event")
		}
	}
	eventID, _ := urn.New("event")
	versionID, _ := urn.New("node-version")
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err = tx.ExecContext(ctx, `INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)`, eventID, "proposal_submitted", operatorID, now, validTime, string(payload), payloadHash, value.SourceInputEventID, value.Provenance.Status); err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO nodes VALUES(?,?,?,?)`, value.ID, "Proposal", operatorID, eventID); err != nil {
		return "", err
	}
	actorClass := "software"
	if value.Provenance.Model != nil {
		actorClass = "model"
	}
	provenance, _ := canonical.JSON(map[string]any{"provenance_schema_version": "1.0.0", "status": value.Provenance.Status, "authority_tier": value.Provenance.AuthorityTier, "actor_class": actorClass, "actor_id": value.Provenance.Proposer, "mechanism": "validated_proposal_spool", "software": map[string]string{"name": "imprint-local", "version": "3.1.2"}, "model": value.Provenance.Model, "prompt_recipe": value.Provenance.PromptRecipeHash, "proposal_id": value.ID, "ratifier": nil, "event_id": eventID, "relation": nil})
	evidence, _ := json.Marshal(evidenceIDs)
	if _, err = tx.ExecContext(ctx, `INSERT INTO node_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, versionID, value.ID, string(payload), payloadHash, value.Provenance.Status, value.Provenance.AuthorityTier, string(provenance), string(evidence), validTime, nil, now, nil, eventID, nil); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return "applied", secureSQLite(s.path)
}

func (s *Store) CurrentNodeHash(ctx context.Context, nodeID, nodeType string) (string, bool, error) {
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT nv.payload_sha256 FROM nodes n JOIN node_versions nv USING(node_id) WHERE n.node_id=? AND n.node_type=? AND nv.system_to IS NULL`, nodeID, nodeType).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return hash, err == nil, err
}

func uniqueStrings(values []string) []string {
	result, seen := []string{}, map[string]bool{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
