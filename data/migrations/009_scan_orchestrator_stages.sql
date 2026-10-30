-- DRISHTI PostgreSQL Schema Migration 009
-- Phase 11: Unified Scan Orchestrator & Multi-Stage Workflow Tracking
-- Extends scans with orchestrator metadata and tracks per-scanner stage lifecycle states

ALTER TABLE scans ADD COLUMN IF NOT EXISTS requested_scanners TEXT DEFAULT '["passive"]';
ALTER TABLE scans ADD COLUMN IF NOT EXISTS stage_results TEXT DEFAULT '{}';
ALTER TABLE scans ADD COLUMN IF NOT EXISTS overall_risk_score NUMERIC(3, 1) DEFAULT 0.0;

CREATE TABLE IF NOT EXISTS scan_stages (
    id BIGSERIAL PRIMARY KEY,
    scan_id VARCHAR(128) NOT NULL,
    scanner_name VARCHAR(64) NOT NULL,
    stage_name VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'queued', -- queued, validating, running, completed, partial, failed, cancelled, timed_out, skipped
    progress INTEGER DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_seconds NUMERIC(6, 2) DEFAULT 0.0,
    findings_count INTEGER DEFAULT 0,
    error_message TEXT,
    stage_metadata TEXT,                          -- JSON encoded safe diagnostic metadata
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_stage_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_stages_scan ON scan_stages(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_stages_status ON scan_stages(status);
CREATE INDEX IF NOT EXISTS idx_scan_stages_scanner ON scan_stages(scanner_name);
