-- ==============================================================================
-- DRISHTI PostgreSQL Schema Migration 011
-- Target: Supabase / PostgreSQL 15+
-- Purpose: Enable Row Level Security (RLS) on all public tables & resolve PostgREST exposure advisories
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 1. Threat Intelligence & Passive Feeds (Public Read, Backend Write)
-- ------------------------------------------------------------------------------

-- Threat Indicators
ALTER TABLE IF EXISTS public.threat_indicators ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'threat_indicators' AND policyname = 'threat_indicators_read_policy') THEN
        CREATE POLICY threat_indicators_read_policy ON public.threat_indicators
            FOR SELECT TO anon, authenticated USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'threat_indicators' AND policyname = 'threat_indicators_service_write_policy') THEN
        CREATE POLICY threat_indicators_service_write_policy ON public.threat_indicators
            FOR ALL TO service_role USING (true) WITH CHECK (true);
    END IF;
END $$;

-- CVE Vulnerabilities Corpus
ALTER TABLE IF EXISTS public.vulnerabilities ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'vulnerabilities' AND policyname = 'vulnerabilities_read_policy') THEN
        CREATE POLICY vulnerabilities_read_policy ON public.vulnerabilities
            FOR SELECT TO anon, authenticated USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'vulnerabilities' AND policyname = 'vulnerabilities_service_write_policy') THEN
        CREATE POLICY vulnerabilities_service_write_policy ON public.vulnerabilities
            FOR ALL TO service_role USING (true) WITH CHECK (true);
    END IF;
END $$;

-- ------------------------------------------------------------------------------
-- 2. Sensitive Operational & Audit Tables (Authenticated Operators & Service Role Only)
-- ------------------------------------------------------------------------------

-- Scans Lifecycle
ALTER TABLE IF EXISTS public.scans ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'scans' AND policyname = 'scans_operator_access') THEN
        CREATE POLICY scans_operator_access ON public.scans
            FOR ALL TO authenticated, service_role USING (true) WITH CHECK (true);
    END IF;
END $$;

-- Scan Findings
ALTER TABLE IF EXISTS public.scan_findings ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'scan_findings' AND policyname = 'scan_findings_operator_access') THEN
        CREATE POLICY scan_findings_operator_access ON public.scan_findings
            FOR ALL TO authenticated, service_role USING (true) WITH CHECK (true);
    END IF;
END $$;

-- Authorizations & Scope Verification
ALTER TABLE IF EXISTS public.authorizations ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'authorizations' AND policyname = 'authorizations_operator_access') THEN
        CREATE POLICY authorizations_operator_access ON public.authorizations
            FOR ALL TO authenticated, service_role USING (true) WITH CHECK (true);
    END IF;
END $$;

-- Consent Domains
ALTER TABLE IF EXISTS public.consent_domains ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'consent_domains' AND policyname = 'consent_domains_operator_access') THEN
        CREATE POLICY consent_domains_operator_access ON public.consent_domains
            FOR ALL TO authenticated, service_role USING (true) WITH CHECK (true);
    END IF;
END $$;

-- Audit Events Ledger (Write-Ahead Log)
ALTER TABLE IF EXISTS public.audit_events ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'audit_events' AND policyname = 'audit_events_operator_access') THEN
        CREATE POLICY audit_events_operator_access ON public.audit_events
            FOR ALL TO authenticated, service_role USING (true) WITH CHECK (true);
    END IF;
END $$;

-- Passive Observations
ALTER TABLE IF EXISTS public.passive_observations ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'passive_observations' AND policyname = 'passive_observations_operator_access') THEN
        CREATE POLICY passive_observations_operator_access ON public.passive_observations
            FOR ALL TO authenticated, service_role USING (true) WITH CHECK (true);
    END IF;
END $$;

-- ------------------------------------------------------------------------------
-- 3. Attack Graph & Simulation Tables
-- ------------------------------------------------------------------------------

-- Graph Snapshots
ALTER TABLE IF EXISTS public.graph_snapshots ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'graph_snapshots' AND policyname = 'graph_snapshots_operator_access') THEN
        CREATE POLICY graph_snapshots_operator_access ON public.graph_snapshots
            FOR ALL TO authenticated, service_role USING (true) WITH CHECK (true);
    END IF;
END $$;

-- Attack Paths
ALTER TABLE IF EXISTS public.attack_paths ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'attack_paths' AND policyname = 'attack_paths_operator_access') THEN
        CREATE POLICY attack_paths_operator_access ON public.attack_paths
            FOR ALL TO authenticated, service_role USING (true) WITH CHECK (true);
    END IF;
END $$;

-- Risk Assessments
ALTER TABLE IF EXISTS public.risk_assessments ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'risk_assessments' AND policyname = 'risk_assessments_operator_access') THEN
        CREATE POLICY risk_assessments_operator_access ON public.risk_assessments
            FOR ALL TO authenticated, service_role USING (true) WITH CHECK (true);
    END IF;
END $$;

-- Mitigation Simulations
ALTER TABLE IF EXISTS public.mitigation_simulations ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'mitigation_simulations' AND policyname = 'mitigation_simulations_operator_access') THEN
        CREATE POLICY mitigation_simulations_operator_access ON public.mitigation_simulations
            FOR ALL TO authenticated, service_role USING (true) WITH CHECK (true);
    END IF;
END $$;

-- ------------------------------------------------------------------------------
-- 4. Scanner Engine Telemetry & Findings
-- ------------------------------------------------------------------------------

-- Active Port Observations (Nmap)
ALTER TABLE IF EXISTS public.active_port_observations ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'active_port_observations' AND policyname = 'port_obs_operator_access') THEN
        CREATE POLICY port_obs_operator_access ON public.active_port_observations
            FOR ALL TO authenticated, service_role USING (true) WITH CHECK (true);
    END IF;
END $$;

-- HTTP Service Observations (HTTPX)
ALTER TABLE IF EXISTS public.http_service_observations ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'http_service_observations' AND policyname = 'http_obs_operator_access') THEN
        CREATE POLICY http_obs_operator_access ON public.http_service_observations
            FOR ALL TO authenticated, service_role USING (true) WITH CHECK (true);
    END IF;
END $$;

-- ZAP Alert Observations
ALTER TABLE IF EXISTS public.zap_alert_observations ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'zap_alert_observations' AND policyname = 'zap_obs_operator_access') THEN
        CREATE POLICY zap_obs_operator_access ON public.zap_alert_observations
            FOR ALL TO authenticated, service_role USING (true) WITH CHECK (true);
    END IF;
END $$;

-- Trivy Supply Chain Findings
ALTER TABLE IF EXISTS public.trivy_findings ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'trivy_findings' AND policyname = 'trivy_findings_operator_access') THEN
        CREATE POLICY trivy_findings_operator_access ON public.trivy_findings
            FOR ALL TO authenticated, service_role USING (true) WITH CHECK (true);
    END IF;
END $$;

-- Nuclei Template Intelligence Findings
ALTER TABLE IF EXISTS public.nuclei_findings ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'nuclei_findings' AND policyname = 'nuclei_findings_operator_access') THEN
        CREATE POLICY nuclei_findings_operator_access ON public.nuclei_findings
            FOR ALL TO authenticated, service_role USING (true) WITH CHECK (true);
    END IF;
END $$;

-- Vulnerability Findings & Fingerprints
ALTER TABLE IF EXISTS public.vulnerability_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.asset_fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.vulnerability_sync_checkpoints ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'vulnerability_findings' AND policyname = 'vuln_findings_operator_access') THEN
        CREATE POLICY vuln_findings_operator_access ON public.vulnerability_findings
            FOR ALL TO authenticated, service_role USING (true) WITH CHECK (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'asset_fingerprints' AND policyname = 'asset_fingerprints_operator_access') THEN
        CREATE POLICY asset_fingerprints_operator_access ON public.asset_fingerprints
            FOR ALL TO authenticated, service_role USING (true) WITH CHECK (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'vulnerability_sync_checkpoints' AND policyname = 'sync_checkpoints_operator_access') THEN
        CREATE POLICY sync_checkpoints_operator_access ON public.vulnerability_sync_checkpoints
            FOR ALL TO authenticated, service_role USING (true) WITH CHECK (true);
    END IF;
END $$;

-- Scan Stages & PDF Reports
ALTER TABLE IF EXISTS public.scan_stages ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.scan_reports ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'scan_stages' AND policyname = 'scan_stages_operator_access') THEN
        CREATE POLICY scan_stages_operator_access ON public.scan_stages
            FOR ALL TO authenticated, service_role USING (true) WITH CHECK (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'scan_reports' AND policyname = 'scan_reports_operator_access') THEN
        CREATE POLICY scan_reports_operator_access ON public.scan_reports
            FOR ALL TO authenticated, service_role USING (true) WITH CHECK (true);
    END IF;
END $$;
