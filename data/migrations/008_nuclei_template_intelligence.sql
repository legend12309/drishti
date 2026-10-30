-- DRISHTI PostgreSQL Schema Migration 008
-- Phase 10: ProjectDiscovery Nuclei Template-Based Security Checks
-- Stores normalized template-based finding observations with evidence, classification, and severity

CREATE TABLE IF NOT EXISTS nuclei_findings (
    id BIGSERIAL PRIMARY KEY,
    scan_id VARCHAR(128) NOT NULL,
    template_id VARCHAR(255) NOT NULL,
    template_name TEXT,
    severity VARCHAR(32) NOT NULL DEFAULT 'info', -- info, low, medium, high, critical, unknown
    matched_at TEXT NOT NULL,
    host VARCHAR(255) NOT NULL,
    port INTEGER DEFAULT 80,
    scheme VARCHAR(16) DEFAULT 'http',
    url TEXT,
    matcher_name VARCHAR(128),
    extracted_results TEXT,                      -- JSON array of extracted values
    type VARCHAR(64) DEFAULT 'http',             -- http, dns, ssl, tcp, etc.
    description TEXT,
    remediation TEXT,
    reference TEXT,                              -- JSON array or primary URL
    tags TEXT,                                   -- Comma-separated or JSON array of tags
    cve_id VARCHAR(128),                         -- Extracted CVE if present in classification
    cwe_id VARCHAR(128),                         -- Extracted CWE if present
    cvss_score NUMERIC(3, 1),                    -- Extracted CVSS score
    curl_command TEXT,                           -- Redacted reproduction curl command
    evidence TEXT,                               -- Sanitized match evidence or request/response snippet
    confidence VARCHAR(32) DEFAULT 'TENTATIVE',  -- TENTATIVE, CORROBORATED, CONFIRMED
    scanner_name VARCHAR(64) NOT NULL DEFAULT 'ProjectDiscovery Nuclei',
    scanner_version VARCHAR(32),
    observed_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_nuclei_finding_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_nuclei_findings_scan ON nuclei_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_nuclei_findings_severity ON nuclei_findings(severity);
CREATE INDEX IF NOT EXISTS idx_nuclei_findings_template ON nuclei_findings(template_id);
CREATE INDEX IF NOT EXISTS idx_nuclei_findings_cve ON nuclei_findings(cve_id);
