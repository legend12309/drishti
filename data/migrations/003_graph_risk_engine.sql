-- DRISHTI PostgreSQL Schema Migration 003
-- Phase 4: NetworkX Risk Engine & Explainable Attack Graph
-- Supports graph snapshots, deterministic risk assessments, attack paths, and isolated mitigation simulations

-- 1. Graph Snapshots Table
CREATE TABLE IF NOT EXISTS graph_snapshots (
    id VARCHAR(128) PRIMARY KEY,
    scan_id VARCHAR(128) NOT NULL,
    snapshot_version INTEGER NOT NULL DEFAULT 1,
    schema_version VARCHAR(32) NOT NULL DEFAULT '4.0',
    nodes_count INTEGER NOT NULL DEFAULT 0,
    edges_count INTEGER NOT NULL DEFAULT 0,
    graph_data JSONB NOT NULL,
    statistics JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_graph_snapshots_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_graph_snapshots_scan ON graph_snapshots(scan_id);
CREATE INDEX IF NOT EXISTS idx_graph_snapshots_created ON graph_snapshots(created_at DESC);

-- 2. Attack Paths Table
CREATE TABLE IF NOT EXISTS attack_paths (
    id VARCHAR(128) PRIMARY KEY,
    scan_id VARCHAR(128) NOT NULL,
    snapshot_id VARCHAR(128) NOT NULL,
    source_node VARCHAR(255) NOT NULL,
    target_node VARCHAR(255) NOT NULL,
    path_nodes JSONB NOT NULL,
    path_edges JSONB NOT NULL,
    total_cost DOUBLE PRECISION NOT NULL,
    priority_score DOUBLE PRECISION NOT NULL,
    cves JSONB DEFAULT '[]',
    hypothetical_transitions_count INTEGER DEFAULT 0,
    confidence_level VARCHAR(32) DEFAULT 'medium',
    preconditions JSONB DEFAULT '[]',
    recommendations JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_attack_paths_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    CONSTRAINT fk_attack_paths_snapshot FOREIGN KEY (snapshot_id) REFERENCES graph_snapshots(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_attack_paths_scan ON attack_paths(scan_id);
CREATE INDEX IF NOT EXISTS idx_attack_paths_target ON attack_paths(target_node);
CREATE INDEX IF NOT EXISTS idx_attack_paths_priority ON attack_paths(priority_score DESC);

-- 3. Risk Assessments Table
CREATE TABLE IF NOT EXISTS risk_assessments (
    id VARCHAR(128) PRIMARY KEY,
    scan_id VARCHAR(128) NOT NULL,
    snapshot_id VARCHAR(128),
    overall_risk_score DOUBLE PRECISION NOT NULL,
    criticality_score DOUBLE PRECISION NOT NULL,
    confirmed_vulns_count INTEGER DEFAULT 0,
    potential_vulns_count INTEGER DEFAULT 0,
    compromise_likelihood DOUBLE PRECISION NOT NULL,
    factors JSONB DEFAULT '{}',
    scoring_version VARCHAR(32) DEFAULT '4.0-drishti-risk',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_risk_assessments_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_risk_assessments_scan ON risk_assessments(scan_id);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_created ON risk_assessments(created_at DESC);

-- 4. Mitigation Simulations Table (Isolated Scenarios)
CREATE TABLE IF NOT EXISTS mitigation_simulations (
    id VARCHAR(128) PRIMARY KEY,
    scan_id VARCHAR(128) NOT NULL,
    snapshot_id VARCHAR(128) NOT NULL,
    scenario_name VARCHAR(255) NOT NULL,
    mitigated_cves JSONB DEFAULT '[]',
    disabled_edges JSONB DEFAULT '[]',
    original_risk_score DOUBLE PRECISION NOT NULL,
    simulated_risk_score DOUBLE PRECISION NOT NULL,
    risk_delta DOUBLE PRECISION NOT NULL,
    broken_paths_count INTEGER DEFAULT 0,
    remaining_paths_count INTEGER DEFAULT 0,
    details JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_mitigation_simulations_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mitigation_simulations_scan ON mitigation_simulations(scan_id);
