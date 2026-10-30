-- DRISHTI PostgreSQL Schema Migration 010
-- PDF Report Generation & Metadata Storage

CREATE TABLE IF NOT EXISTS scan_reports (
    id BIGSERIAL PRIMARY KEY,
    scan_id VARCHAR(128) NOT NULL UNIQUE,
    file_path TEXT NOT NULL,
    file_size BIGINT DEFAULT 0,
    generated_at TIMESTAMPTZ DEFAULT NOW(),
    status VARCHAR(32) DEFAULT 'pending', -- pending, generating, generated, failed
    error_message TEXT,
    report_metadata TEXT, -- JSON encoded metadata
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_report_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_reports_scan ON scan_reports(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_reports_status ON scan_reports(status);