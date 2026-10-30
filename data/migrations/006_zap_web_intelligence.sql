-- DRISHTI PostgreSQL Schema Migration 006
-- Phase 8: OWASP ZAP Web Security & DAST Intelligence
-- Persists normalized passive web alerts, CWE alignments, evidence, and verification status

CREATE TABLE IF NOT EXISTS zap_alert_observations (
    id BIGSERIAL PRIMARY KEY,
    scan_id VARCHAR(128) NOT NULL,
    plugin_id VARCHAR(64) NOT NULL,
    alert_name TEXT NOT NULL,
    risk VARCHAR(32) NOT NULL DEFAULT 'Informational', -- Informational, Low, Medium, High, Critical
    confidence VARCHAR(32) NOT NULL DEFAULT 'Medium', -- False Positive, Low, Medium, High, User Confirmed
    url TEXT NOT NULL,
    host VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL DEFAULT 80,
    param VARCHAR(255) DEFAULT '',
    attack TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    description TEXT DEFAULT '',
    solution TEXT DEFAULT '',
    reference TEXT DEFAULT '',
    cwe_id INTEGER,
    wasc_id INTEGER,
    source_scanner VARCHAR(64) NOT NULL DEFAULT 'OWASP ZAP',
    verification_status VARCHAR(64) NOT NULL DEFAULT 'unverified_finding', -- unverified_finding, corroborated, suppressed
    observed_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_zap_alert_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_zap_alert_scan ON zap_alert_observations(scan_id);
CREATE INDEX IF NOT EXISTS idx_zap_alert_risk ON zap_alert_observations(risk);
CREATE INDEX IF NOT EXISTS idx_zap_alert_host ON zap_alert_observations(host);
CREATE INDEX IF NOT EXISTS idx_zap_alert_cwe ON zap_alert_observations(cwe_id);
