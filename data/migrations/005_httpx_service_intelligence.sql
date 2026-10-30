-- DRISHTI PostgreSQL Schema Migration 005
-- Phase 7: ProjectDiscovery httpx Integration & HTTP Service Intelligence
-- Stores HTTP/HTTPS service observations, web titles, servers, and tech stack telemetry

CREATE TABLE IF NOT EXISTS http_service_observations (
    id BIGSERIAL PRIMARY KEY,
    scan_id VARCHAR(128) NOT NULL,
    url TEXT NOT NULL,
    host VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL,
    scheme VARCHAR(16) NOT NULL DEFAULT 'http',
    status_code INTEGER,
    title TEXT,
    webserver VARCHAR(255),
    content_type VARCHAR(128),
    content_length INTEGER,
    technologies JSONB DEFAULT '[]',
    final_url TEXT,
    ip VARCHAR(64),
    cname VARCHAR(255),
    response_time_ms DOUBLE PRECISION,
    scanner_name VARCHAR(64) NOT NULL DEFAULT 'ProjectDiscovery httpx',
    scanner_version VARCHAR(32),
    observed_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_http_service_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_http_service_obs_scan ON http_service_observations(scan_id);
CREATE INDEX IF NOT EXISTS idx_http_service_obs_host_port ON http_service_observations(host, port);
CREATE INDEX IF NOT EXISTS idx_http_service_obs_status ON http_service_observations(status_code);
