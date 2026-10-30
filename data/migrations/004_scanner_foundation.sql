-- DRISHTI PostgreSQL Schema Migration 004
-- Phase 6: Active Network Scanner Foundation & Nmap Port Observations
-- Preserves scan provenance, scanner engine metadata, and open port telemetry

-- 1. Active Port Observations Table
CREATE TABLE IF NOT EXISTS active_port_observations (
    id BIGSERIAL PRIMARY KEY,
    scan_id VARCHAR(128) NOT NULL,
    host VARCHAR(255) NOT NULL,
    ip VARCHAR(64) NOT NULL,
    port INTEGER NOT NULL,
    protocol VARCHAR(16) NOT NULL DEFAULT 'tcp',
    state VARCHAR(32) NOT NULL DEFAULT 'open',
    service_name VARCHAR(128),
    product VARCHAR(128),
    version VARCHAR(64),
    extra_info TEXT,
    cpe23 TEXT,
    scanner_name VARCHAR(64) NOT NULL DEFAULT 'Nmap',
    scanner_version VARCHAR(32),
    observed_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_active_port_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_active_port_obs_scan ON active_port_observations(scan_id);
CREATE INDEX IF NOT EXISTS idx_active_port_obs_host_port ON active_port_observations(host, port);
CREATE INDEX IF NOT EXISTS idx_active_port_obs_product ON active_port_observations(product);
