-- DRISHTI PostgreSQL Schema Migration 001
-- Target: Supabase / PostgreSQL 15+
-- Preserves all primary keys, foreign keys, timestamps, indexes, and constraints.

-- Enable UUID extension if needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Threat Indicators
CREATE TABLE IF NOT EXISTS threat_indicators (
    id BIGSERIAL PRIMARY KEY,
    indicator_type VARCHAR(64) NOT NULL,
    value TEXT NOT NULL UNIQUE,
    confidence DOUBLE PRECISION DEFAULT 0.0,
    first_seen TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_indicators_type ON threat_indicators(indicator_type);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_seen ON threat_indicators(first_seen DESC);

-- 2. Scans Lifecycle Table
CREATE TABLE IF NOT EXISTS scans (
    id VARCHAR(128) PRIMARY KEY,
    target VARCHAR(255) NOT NULL,
    status VARCHAR(64) NOT NULL,
    progress INTEGER DEFAULT 0,
    current_step TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    authorization_id VARCHAR(128),
    scope VARCHAR(64) DEFAULT 'FULL_PASSIVE'
);

CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_auth_id ON scans(authorization_id);

-- 3. Scan Findings Table
CREATE TABLE IF NOT EXISTS scan_findings (
    id BIGSERIAL PRIMARY KEY,
    scan_id VARCHAR(128) NOT NULL,
    host VARCHAR(255) NOT NULL,
    ip VARCHAR(64) NOT NULL,
    tech TEXT NOT NULL,
    status VARCHAR(64) NOT NULL,
    risk VARCHAR(64) NOT NULL,
    score VARCHAR(32) NOT NULL,
    ports TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_scan_findings_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_findings_scan_id ON scan_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_findings_risk ON scan_findings(risk);
CREATE INDEX IF NOT EXISTS idx_scan_findings_host ON scan_findings(host);

-- 4. Consent Domains
CREATE TABLE IF NOT EXISTS consent_domains (
    domain VARCHAR(255) PRIMARY KEY,
    authorized_by VARCHAR(128) DEFAULT 'security-admin',
    scope VARCHAR(64) DEFAULT 'FULL_RECON',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 5. Authorizations Table (Phase 2 Domain Ownership & Scope Verification)
CREATE TABLE IF NOT EXISTS authorizations (
    id VARCHAR(128) PRIMARY KEY,
    target_domain VARCHAR(255) NOT NULL,
    permitted_scope VARCHAR(64) NOT NULL DEFAULT 'FULL_PASSIVE',
    operator_id VARCHAR(128) NOT NULL DEFAULT 'local-operator-dev',
    status VARCHAR(64) NOT NULL DEFAULT 'pending',
    verification_method VARCHAR(64) NOT NULL DEFAULT 'dns_txt',
    verification_token VARCHAR(255) NOT NULL,
    challenge_record_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    verified_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_authorizations_target_domain ON authorizations(target_domain);
CREATE INDEX IF NOT EXISTS idx_authorizations_status ON authorizations(status);
CREATE INDEX IF NOT EXISTS idx_authorizations_expires ON authorizations(expires_at);

-- 6. Audit Events (Tamper-evident log of authorization and scan activities)
CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(128) NOT NULL,
    authorization_id VARCHAR(128),
    scan_id VARCHAR(128),
    operator_id VARCHAR(128) NOT NULL DEFAULT 'local-operator-dev',
    target VARCHAR(255) NOT NULL,
    detail TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_events_scan_id ON audit_events(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_auth_id ON audit_events(authorization_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type);

-- 7. Passive Reconnaissance Observations (Provenance & Evidence Tracking)
CREATE TABLE IF NOT EXISTS passive_observations (
    id BIGSERIAL PRIMARY KEY,
    scan_id VARCHAR(128) NOT NULL,
    authorization_id VARCHAR(128),
    asset_id VARCHAR(255) NOT NULL,
    asset_type VARCHAR(64) NOT NULL,
    query_type VARCHAR(64) NOT NULL,
    observed_value TEXT NOT NULL,
    source VARCHAR(128) NOT NULL,
    status VARCHAR(64) NOT NULL,
    raw_metadata TEXT DEFAULT '{}',
    observed_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_passive_obs_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_passive_observations_scan_id ON passive_observations(scan_id);
CREATE INDEX IF NOT EXISTS idx_passive_observations_auth_id ON passive_observations(authorization_id);
CREATE INDEX IF NOT EXISTS idx_passive_observations_asset ON passive_observations(asset_id);
