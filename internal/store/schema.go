package store

// captureSchema is the 3.1 generic ledger subset required by raw capture. Every
// definition is byte-compatible with src/imprint/store/schema.py. Later native
// services add their own tables with CREATE IF NOT EXISTS, so existing stores
// and stores first created by Go converge without a conversion step.
const captureSchema = `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=FULL;
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT OR IGNORE INTO meta(key,value) VALUES('content_generation','0');
CREATE TABLE IF NOT EXISTS events (
 event_id TEXT PRIMARY KEY,event_type TEXT NOT NULL,operator_id TEXT NOT NULL,
 system_time TEXT NOT NULL,valid_time TEXT NOT NULL,payload_json TEXT NOT NULL,
 payload_sha256 TEXT NOT NULL,prior_event_id TEXT,provenance_status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes (
 node_id TEXT PRIMARY KEY,node_type TEXT NOT NULL,operator_id TEXT NOT NULL,
 created_event_id TEXT NOT NULL REFERENCES events(event_id)
);
CREATE TABLE IF NOT EXISTS node_versions (
 version_id TEXT PRIMARY KEY,node_id TEXT NOT NULL REFERENCES nodes(node_id),
 payload_json TEXT NOT NULL,payload_sha256 TEXT NOT NULL,provenance_status TEXT NOT NULL,
 authority_tier TEXT NOT NULL,provenance_json TEXT NOT NULL,evidence_json TEXT NOT NULL,
 valid_from TEXT NOT NULL,valid_to TEXT,system_from TEXT NOT NULL,system_to TEXT,
 event_id TEXT NOT NULL REFERENCES events(event_id),prior_version_id TEXT
);
CREATE INDEX IF NOT EXISTS current_node_versions ON node_versions(node_id,valid_from,valid_to) WHERE system_to IS NULL;
CREATE INDEX IF NOT EXISTS node_version_history ON node_versions(node_id,system_from);
CREATE TABLE IF NOT EXISTS edges (
 edge_id TEXT PRIMARY KEY,edge_type TEXT NOT NULL,source_id TEXT NOT NULL REFERENCES nodes(node_id),
 target_id TEXT NOT NULL REFERENCES nodes(node_id),operator_id TEXT NOT NULL,
 created_event_id TEXT NOT NULL REFERENCES events(event_id)
);
CREATE TABLE IF NOT EXISTS edge_versions (
 version_id TEXT PRIMARY KEY,edge_id TEXT NOT NULL REFERENCES edges(edge_id),
 payload_json TEXT NOT NULL,payload_sha256 TEXT NOT NULL,provenance_status TEXT NOT NULL,
 authority_tier TEXT NOT NULL,provenance_json TEXT NOT NULL,evidence_json TEXT NOT NULL,
 valid_from TEXT NOT NULL,valid_to TEXT,system_from TEXT NOT NULL,system_to TEXT,
 event_id TEXT NOT NULL REFERENCES events(event_id),prior_version_id TEXT
);
CREATE INDEX IF NOT EXISTS edges_by_source ON edges(source_id);
CREATE INDEX IF NOT EXISTS edges_by_target ON edges(target_id);
CREATE UNIQUE INDEX IF NOT EXISTS one_current_edge_version ON edge_versions(edge_id) WHERE system_to IS NULL;
CREATE TABLE IF NOT EXISTS source_receipts (
 source_id TEXT PRIMARY KEY,kind TEXT NOT NULL,locator TEXT NOT NULL,
 content_sha256 TEXT NOT NULL,event_id TEXT NOT NULL REFERENCES events(event_id)
);
CREATE TABLE IF NOT EXISTS captured_feedback_dedup (
 operator_id TEXT NOT NULL,content_sha256 TEXT NOT NULL,
 first_event_id TEXT NOT NULL REFERENCES events(event_id),first_captured_at TEXT NOT NULL,
 PRIMARY KEY(operator_id,content_sha256)
);
CREATE TABLE IF NOT EXISTS consumed_inputs (
 input_event_id TEXT PRIMARY KEY,payload_sha256 TEXT NOT NULL,
 consumed_at TEXT NOT NULL,source_path TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS content_generation_nodes_insert AFTER INSERT ON nodes BEGIN UPDATE meta SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT) WHERE key='content_generation'; END;
CREATE TRIGGER IF NOT EXISTS content_generation_node_versions_insert AFTER INSERT ON node_versions BEGIN UPDATE meta SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT) WHERE key='content_generation'; END;
CREATE TRIGGER IF NOT EXISTS content_generation_edges_insert AFTER INSERT ON edges BEGIN UPDATE meta SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT) WHERE key='content_generation'; END;
CREATE TRIGGER IF NOT EXISTS content_generation_edge_versions_insert AFTER INSERT ON edge_versions BEGIN UPDATE meta SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT) WHERE key='content_generation'; END;
CREATE TRIGGER IF NOT EXISTS node_version_authority_lattice_insert BEFORE INSERT ON node_versions
WHEN NOT (
 (NEW.provenance_status='captured' AND NEW.authority_tier IN ('observed_candidate','captured_judgment','ratified_knowledge')) OR
 (NEW.provenance_status='extracted' AND NEW.authority_tier IN ('imported_floor','observed_candidate','ratified_knowledge')) OR
 (NEW.provenance_status='inferred' AND NEW.authority_tier IN ('inferred_candidate','observed_candidate','ratified_knowledge')) OR
 (NEW.provenance_status='ratified' AND NEW.authority_tier='ratified_knowledge')
) BEGIN SELECT RAISE(ABORT,'node version violates authority lattice'); END;
CREATE TRIGGER IF NOT EXISTS edge_version_authority_lattice_insert BEFORE INSERT ON edge_versions
WHEN NOT (
 (NEW.provenance_status='captured' AND NEW.authority_tier IN ('observed_candidate','captured_judgment','ratified_knowledge')) OR
 (NEW.provenance_status='extracted' AND NEW.authority_tier IN ('imported_floor','observed_candidate','ratified_knowledge')) OR
 (NEW.provenance_status='inferred' AND NEW.authority_tier IN ('inferred_candidate','observed_candidate','ratified_knowledge')) OR
 (NEW.provenance_status='ratified' AND NEW.authority_tier='ratified_knowledge')
) BEGIN SELECT RAISE(ABORT,'edge version violates authority lattice'); END;
`
