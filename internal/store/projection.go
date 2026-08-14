package store

import (
	"context"
	"encoding/json"
)

type ProjectionNode struct {
	NodeID, NodeType, OperatorID, VersionID, PayloadSHA256 string
	ProvenanceStatus, AuthorityTier, ValidFrom, ValidTo    string
	SystemFrom, SystemTo, EventID                          string
	Payload, Provenance                                    map[string]any
	Evidence                                               []string
}

type ProjectionEdge struct {
	EdgeID, EdgeType, SourceID, TargetID, VersionID, PayloadSHA256 string
	ProvenanceStatus, AuthorityTier, ValidFrom, ValidTo            string
	SystemFrom, SystemTo, EventID                                  string
	Payload, Provenance                                            map[string]any
	Evidence                                                       []string
}

type ProjectionSnapshot struct {
	StoreSchemaVersion, OntologySchemaVersion string
	Nodes                                     []ProjectionNode
	Edges                                     []ProjectionEdge
}

// ProjectionState returns the complete current generic graph. Unlike retrieval
// it applies no authority or semantic eligibility filters.
func (s *Store) ProjectionState(ctx context.Context) (ProjectionSnapshot, error) {
	result := ProjectionSnapshot{StoreSchemaVersion: StoreSchemaVersion, OntologySchemaVersion: OntologySchemaVersion, Nodes: []ProjectionNode{}, Edges: []ProjectionEdge{}}
	rows, err := s.db.QueryContext(ctx, `SELECT n.node_id,n.node_type,n.operator_id,nv.version_id,nv.payload_json,nv.payload_sha256,nv.provenance_status,nv.authority_tier,nv.provenance_json,nv.evidence_json,nv.valid_from,COALESCE(nv.valid_to,''),nv.system_from,COALESCE(nv.system_to,''),nv.event_id FROM nodes n JOIN node_versions nv USING(node_id) WHERE nv.system_to IS NULL ORDER BY n.node_type,n.node_id`)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var item ProjectionNode
		var payload, provenance, evidence string
		if err = rows.Scan(&item.NodeID, &item.NodeType, &item.OperatorID, &item.VersionID, &payload, &item.PayloadSHA256, &item.ProvenanceStatus, &item.AuthorityTier, &provenance, &evidence, &item.ValidFrom, &item.ValidTo, &item.SystemFrom, &item.SystemTo, &item.EventID); err != nil {
			return result, err
		}
		if err = decodeProjectionJSON(payload, provenance, evidence, &item.Payload, &item.Provenance, &item.Evidence); err != nil {
			return result, err
		}
		result.Nodes = append(result.Nodes, item)
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	edges, err := s.db.QueryContext(ctx, `SELECT e.edge_id,e.edge_type,e.source_id,e.target_id,ev.version_id,ev.payload_json,ev.payload_sha256,ev.provenance_status,ev.authority_tier,ev.provenance_json,ev.evidence_json,ev.valid_from,COALESCE(ev.valid_to,''),ev.system_from,COALESCE(ev.system_to,''),ev.event_id FROM edges e JOIN edge_versions ev USING(edge_id) WHERE ev.system_to IS NULL ORDER BY e.edge_type,e.edge_id`)
	if err != nil {
		return result, err
	}
	defer edges.Close()
	for edges.Next() {
		var item ProjectionEdge
		var payload, provenance, evidence string
		if err = edges.Scan(&item.EdgeID, &item.EdgeType, &item.SourceID, &item.TargetID, &item.VersionID, &payload, &item.PayloadSHA256, &item.ProvenanceStatus, &item.AuthorityTier, &provenance, &evidence, &item.ValidFrom, &item.ValidTo, &item.SystemFrom, &item.SystemTo, &item.EventID); err != nil {
			return result, err
		}
		if err = decodeProjectionJSON(payload, provenance, evidence, &item.Payload, &item.Provenance, &item.Evidence); err != nil {
			return result, err
		}
		result.Edges = append(result.Edges, item)
	}
	return result, edges.Err()
}

func decodeProjectionJSON(payload, provenance, evidence string, payloadValue, provenanceValue *map[string]any, evidenceValue *[]string) error {
	if err := json.Unmarshal([]byte(payload), payloadValue); err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(provenance), provenanceValue); err != nil {
		return err
	}
	return json.Unmarshal([]byte(evidence), evidenceValue)
}
