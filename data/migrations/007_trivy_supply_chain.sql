-- DRISHTI PostgreSQL Schema Migration 007
-- Phase 9: Aqua Security Trivy Supply Chain & Artifact Security
-- Stores package vulnerabilities, misconfigurations, and detected secrets

CREATE TABLE IF NOT EXISTS trivy_findings (
    id BIGSERIAL PRIMARY KEY,
    scan_id VARCHAR(128) NOT NULL,
    target_resource TEXT NOT NULL,       -- file path, directory, or container image reference
    finding_class VARCHAR(64) NOT NULL,  -- vulnerability, misconfiguration, secret
    vulnerability_id VARCHAR(128),       -- CVE-2023-xxxx, AVD-xxxx, etc.
    rule_id VARCHAR(128),                -- Defsec/Rego rule or secret rule ID
    title TEXT,
    severity VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN', -- UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL
    package_name VARCHAR(255),
    installed_version VARCHAR(128),
    fixed_version VARCHAR(128),
    primary_url TEXT,
    description TEXT,
    remediation_guidance TEXT,
    evidence TEXT,                       -- Sanitized proof or line snippet
    line_number INTEGER,
    confidence VARCHAR(32) DEFAULT 'HIGH',
    scanner_name VARCHAR(64) NOT NULL DEFAULT 'Aqua Security Trivy',
    scanner_version VARCHAR(32),
    observed_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_trivy_finding_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_trivy_findings_scan ON trivy_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_trivy_findings_severity ON trivy_findings(severity);
CREATE INDEX IF NOT EXISTS idx_trivy_findings_vuln ON trivy_findings(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_trivy_findings_class ON trivy_findings(finding_class);
