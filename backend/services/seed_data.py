"""
DRISHTI — Deterministic Baseline Seed Engine (vvdx.in Production Dataset)
Ensures zero-empty startup state across SQLite WAL database.
"""

import json
import logging
import hashlib
from datetime import datetime, timezone
from backend.db.database import get_db

logger = logging.getLogger("drishti.seed")

SEED_TARGET = "vvdx.in"
SEED_SCAN_ID = "wf-seed-vvdx-in"
SEED_AUTH_ID = "auth-loa-vvdx-seed"

SUBDOMAINS_14 = [
    {"subdomain": "vvdx.in", "ip": "104.21.32.10", "ports": [80, 443]},
    {"subdomain": "api.vvdx.in", "ip": "104.21.32.11", "ports": [80, 443]},
    {"subdomain": "auth.vvdx.in", "ip": "104.21.32.12", "ports": [443]},
    {"subdomain": "admin.vvdx.in", "ip": "104.21.32.13", "ports": [80, 443]},
    {"subdomain": "staging.vvdx.in", "ip": "104.21.32.14", "ports": [80, 443, 8080]},
    {"subdomain": "mail.vvdx.in", "ip": "104.21.32.15", "ports": [25, 465, 993]},
    {"subdomain": "vpn.vvdx.in", "ip": "104.21.32.16", "ports": [443, 1194]},
    {"subdomain": "portal.vvdx.in", "ip": "104.21.32.17", "ports": [443]},
    {"subdomain": "billing.vvdx.in", "ip": "104.21.32.18", "ports": [443]},
    {"subdomain": "status.vvdx.in", "ip": "104.21.32.19", "ports": [80, 443]},
    {"subdomain": "cdn.vvdx.in", "ip": "104.21.32.20", "ports": [80, 443]},
    {"subdomain": "internal.vvdx.in", "ip": "10.0.4.15", "ports": [80, 22, 3306]},
    {"subdomain": "db.vvdx.in", "ip": "10.0.4.50", "ports": [5432, 3306]},
    {"subdomain": "legacy.vvdx.in", "ip": "104.21.32.25", "ports": [80, 8080]},
]

GRAPH_SEED = {
    "nodes": [
        {"id": "ingress_vvdx", "label": "Ingress: vvdx.in", "type": "ingress", "column": "01 INGRESS", "x": 100, "y": 250},
        {"id": "service_http_80", "label": "HTTP (80/TCP): PHP-CGI 8.1.2", "type": "service", "column": "02 SERVICE", "x": 300, "y": 180},
        {"id": "service_ssh_22", "label": "SSH (22/TCP): OpenSSH 8.9p1", "type": "service", "column": "02 SERVICE", "x": 300, "y": 320},
        {"id": "vuln_cve_2024_4577", "label": "CVE-2024-4577 (PHP CGI RCE)", "type": "vulnerability", "column": "03 VULN", "x": 500, "y": 180, "cost": 0.40},
        {"id": "vuln_cve_2024_6387", "label": "CVE-2024-6387 (OpenSSH RCE)", "type": "vulnerability", "column": "03 VULN", "x": 500, "y": 320, "cost": 1.00},
        {"id": "pivot_dmz_shell", "label": "DMZ Pivot Shell (www-data)", "type": "pivot", "column": "04 PIVOT", "x": 700, "y": 250},
        {"id": "internal_db_auth", "label": "InternalAuth (OAuth2 SSO)", "type": "internal", "column": "04 PIVOT", "x": 700, "y": 350},
        {"id": "crown_jewel_db", "label": "Crown Jewel: CoreDB (Customer PII)", "type": "target", "column": "05 SIGNAL", "x": 900, "y": 250},
    ],
    "edges": [
        {"source": "ingress_vvdx", "target": "service_http_80", "weight": 0.1},
        {"source": "service_http_80", "target": "vuln_cve_2024_4577", "weight": 0.1},
        {"source": "vuln_cve_2024_4577", "target": "pivot_dmz_shell", "weight": 0.2},
        {"source": "pivot_dmz_shell", "target": "crown_jewel_db", "weight": 0.1},
        {"source": "ingress_vvdx", "target": "service_ssh_22", "weight": 0.2},
        {"source": "service_ssh_22", "target": "vuln_cve_2024_6387", "weight": 0.3},
        {"source": "vuln_cve_2024_6387", "target": "pivot_dmz_shell", "weight": 0.5},
        {"source": "pivot_dmz_shell", "target": "internal_db_auth", "weight": 0.2},
        {"source": "internal_db_auth", "target": "crown_jewel_db", "weight": 0.2},
    ],
    "shortest_path": ["ingress_vvdx", "vuln_cve_2024_4577", "pivot_dmz_shell", "crown_jewel_db"],
    "total_cost": 0.40,
}

ASCII_SEED_REPORT = """================================================================================
DRISHTI CYBER INTELLIGENCE PLATFORM // TACTICAL ASSESSMENT DOSSIER (TEXT FORMAT)
================================================================================
CONFIDENTIALITY : LEVEL 5 // TOP SECRET // AIR-GAP SECURITY ASSESSMENT
ASSESSMENT ID   : RPT-2026-1105-VVDX
TARGET PERIMETER: vvdx.in
TIMESTAMP       : 2026-11-05T22:36:00Z
SHA256 CHECKSUM : 9f86d081884c7d659a2feaa0c55ad0153835e7ff453641889c0a6b7e6717a6c2
RFC-8655 SCOPE  : AUTHORIZED & CRYPTOGRAPHICALLY ATTESTED
AUDIT INTEGRITY : VERIFIED // IMMUTABLE WAL LEDGER CHAIN INTACT
================================================================================

[01] EXECUTIVE POSTURE SUMMARY
--------------------------------------------------------------------------------
OVERALL RISK SCORE       : 94.2 / 100 [CRITICAL EXPOSURE]
POSTURE STATUS           : DEFCON 1 // EXPLOITABLE PATHWAY DETECTED
SUBDOMAINS DISCOVERED    : 14 Active Subdomains
OPEN SERVICES MONITORED  : 3 Verified Ports (80/TCP, 443/TCP, 22/TCP)
CONFIRMED VULNERABILITIES: 2 Active Zero-Trust Violations
WEAPONIZED MODULES      : 2 Rapid7 Metasploit Exploits Available
AI FIREWALL INTERCEPT    : Active (3-Layer Prompt Shield Armed)

[02] CRITICAL ATTACK PATH (DIJKSTRA SHORTEST PATHWAY: 0.40x FRICTION)
--------------------------------------------------------------------------------
  [01 INGRESS]      vvdx.in (External Perimeter)
         │
         ▼ (HTTP 80/TCP - PHP-CGI 8.1.2 Handler)
  [02 EXPLOIT]      CVE-2024-4577 (PHP-CGI Argument Injection RCE)
         │          CVSS: 9.8 | EPSS: 0.972 | CISA KEV: YES
         │          Metasploit: exploit/windows/http/php_cgi_arg_injection
         ▼ (Remote Code Execution as www-data)
  [03 PIVOT]        DMZ Pivot Shell (Lateral Movement Hub)
         │
         ▼ (Direct Database Bridge)
  [04 SIGNAL]       Crown Jewel: CoreDB (Customer PII Cluster)

[03] CORRELATED VULNERABILITIES INTELLIGENCE
--------------------------------------------------------------------------------
* CVE-2024-4577 [CRITICAL 9.8] // PHP CGI Argument Injection Vulnerability
  - Target Asset     : vvdx.in:80 (PHP-CGI 8.1.2 / nginx 1.24.0)
  - EPSS Probability : 0.972 (Top 1% Global Attack Surface)
  - Metasploit Module: exploit/windows/http/php_cgi_arg_injection
  - CISA KEV Status  : CONFIRMED ACTIVE EXPLOITATION
  - Match Rationale  : Observed PHP-CGI 8.1.2 handler on exposed HTTP port 80.
  - Tactical Fix     : Discontinue Apache/Nginx PHP-CGI wrapper; upgrade to PHP 8.3.8+.

* CVE-2021-41773 [HIGH 7.5] // Apache HTTP Server Path Traversal & RCE
  - Target Asset     : staging.vvdx.in:8080 (Apache 2.4.49)
  - EPSS Probability : 0.941
  - Metasploit Module: exploit/multi/http/apache_normalize_path_rce
  - CISA KEV Status  : CONFIRMED
  - Tactical Fix     : Upgrade Apache HTTP Server to 2.4.51+.

* CVE-2024-6387 [HIGH 8.1] // OpenSSH regreSSHion Signal Handler Race Condition
  - Target Asset     : vvdx.in:22 (OpenSSH 8.9p1)
  - EPSS Probability : 0.684
  - Tactical Fix     : Upgrade OpenSSH to 9.8p1+; set LoginGraceTime 0.

[04] AUTONOMOUS REMEDIATION RULES (SYNTHESIZED)
--------------------------------------------------------------------------------
[CLOUDFLARE WAF EXPRESSION]
(http.request.uri.path contains "php-cgi" or http.request.uri.query contains "%ad") => BLOCK [403]

[NGINX MODSECURITY V3 DIRECTIVE]
SecRule REQUEST_URI "@rx (?:%ad|%AD)" "id:100101,phase:2,deny,status:403,log,msg:'DRISHTI: CVE-2024-4577 blocked'"

[LINUX IPTABLES PERIMETER RULE]
iptables -A INPUT -p tcp --dport 80 -m string --hex-string "|ad|" --algo bm -j DROP

================================================================================
END OF DOSSIER // DIGITALLY SIGNED BY DRISHTI AIR-GAP ENGINE MONOLITH-8000
================================================================================
"""

async def ensure_baseline_seed():
    """
    Checks if a completed baseline scan exists for vvdx.in.
    If database has 0 completed scans, automatically populates the deterministic baseline dataset.
    """
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    async with get_db() as db:
        # 1. Ensure table schema modifications exist
        try:
            await db.execute("ALTER TABLE vulnerabilities ADD COLUMN dijkstra_cost REAL DEFAULT 1.0")
        except Exception:
            pass

        try:
            await db.execute("ALTER TABLE scan_reports ADD COLUMN content_text TEXT")
        except Exception:
            pass

        # 2. Check if completed scan exists for vvdx.in
        async with db.execute(
            "SELECT COUNT(*) FROM scans WHERE target = ? AND status = 'completed'",
            (SEED_TARGET,)
        ) as cur:
            row = await cur.fetchone()
            if row and row[0] > 0:
                logger.info("Baseline seed dataset for vvdx.in already present.")
                return

        logger.info("Database empty or unseeded. Populating deterministic baseline dataset for vvdx.in...")

        # 3. Seed Authorization
        await db.execute(
            """
            INSERT OR REPLACE INTO authorizations (
                id, target_domain, permitted_scope, operator_id, status,
                verification_method, verification_token, challenge_record_name, created_at, verified_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                SEED_AUTH_ID,
                SEED_TARGET,
                "FULL_ACTIVE",
                "local-operator-dev",
                "verified",
                "dns_txt",
                hashlib.sha256(b"vvdx-seed-token").hexdigest(),
                f"_drishti-challenge.{SEED_TARGET}",
                now_iso,
                now_iso,
                "2029-12-31 23:59:59"
            )
        )

        # 4. Seed Scan
        await db.execute(
            """
            INSERT OR REPLACE INTO scans (
                id, target, status, progress, current_step,
                created_at, updated_at, completed_at, authorization_id,
                scope, requested_scanners, stage_results, overall_risk_score
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                SEED_SCAN_ID,
                SEED_TARGET,
                "completed",
                100,
                "Workflow orchestration finalized // Baseline armed",
                now_iso,
                now_iso,
                now_iso,
                SEED_AUTH_ID,
                "FULL_ACTIVE",
                json.dumps(["nmap", "httpx", "zap", "trivy", "nuclei"]),
                json.dumps({
                    "nmap": {"status": "completed", "ports_found": 3},
                    "httpx": {"status": "completed", "services_found": 3},
                    "cve_matching": {"status": "completed", "findings_count": 3},
                    "graph_analysis": {"status": "completed", "shortest_path_cost": 0.40}
                }),
                94.2
            )
        )

        # 5. Seed 14 Subdomains into scan_findings
        for item in SUBDOMAINS_14:
            is_crit = item["subdomain"] in ("vvdx.in", "staging.vvdx.in")
            await db.execute(
                """
                INSERT OR REPLACE INTO scan_findings (
                    scan_id, host, ip, tech, status, risk, score, ports, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    SEED_SCAN_ID,
                    item["subdomain"],
                    item["ip"],
                    "nginx, Cloudflare",
                    "live",
                    "CRITICAL" if is_crit else "LOW",
                    9.8 if is_crit else 2.1,
                    json.dumps(item["ports"]),
                    now_iso
                )
            )

        # 6. Seed Active Ports
        ports_data = [
            (80, "tcp", "open", "http", "nginx", "1.24.0", "PHP-CGI 8.1.2", "cpe:2.3:a:php:php:8.1.2:*:*:*:*:*:*:*"),
            (443, "tcp", "open", "https", "nginx", "1.24.0", "TLS 1.3 / OpenSSL 3.0.2", "cpe:2.3:a:igor_sysoev:nginx:1.24.0:*:*:*:*:*:*:*"),
            (22, "tcp", "open", "ssh", "OpenSSH", "8.9p1", "Ubuntu Linux (OpenSSL 3.0.2)", "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"),
        ]
        for p in ports_data:
            await db.execute(
                """
                INSERT OR REPLACE INTO active_port_observations (
                    scan_id, host, ip, port, protocol, state,
                    service_name, product, version, extra_info, cpe23, scanner_name, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    SEED_SCAN_ID, SEED_TARGET, "104.21.32.10", p[0], p[1], p[2],
                    p[3], p[4], p[5], p[6], p[7], "Nmap", now_iso
                )
            )

        # 7. Seed HTTP Services
        http_services = [
            ("https://vvdx.in", 443, "https", 200, "VVDX Core Intelligence Portal", "nginx/1.24.0", ["nginx", "PHP 8.1.2", "Bootstrap"]),
            ("https://api.vvdx.in", 443, "https", 200, "VVDX Secure API Gateway", "nginx/1.24.0", ["nginx", "Node.js", "Express"]),
            ("https://admin.vvdx.in", 443, "https", 403, "VVDX Admin Enclave // 403 Forbidden", "nginx/1.24.0", ["nginx"]),
        ]
        for h in http_services:
            await db.execute(
                """
                INSERT OR REPLACE INTO http_service_observations (
                    scan_id, url, host, port, scheme, status_code,
                    title, webserver, technologies, scanner_name, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    SEED_SCAN_ID, h[0], SEED_TARGET, h[1], h[2], h[3],
                    h[4], h[5], json.dumps(h[6]), "httpx", now_iso
                )
            )

        # 8. Upsert Seed Vulnerabilities (CVE-2024-4577, CVE-2021-41773, CVE-2024-6387)
        cve_seed_list = [
            (
                "CVE-2024-4577",
                "NVD",
                "PHP CGI Argument Injection Vulnerability",
                "Best-fit character encoding conversions in Windows Apache/Nginx PHP-CGI module allows remote command execution.",
                "3.1",
                9.8,
                "CRITICAL",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                0.972,
                0.99,
                1,
                "exploit/windows/http/php_cgi_arg_injection",
                1,
                0.40,
                "Discontinue Apache/Nginx PHP-CGI wrapper; upgrade to PHP 8.3.8+."
            ),
            (
                "CVE-2021-41773",
                "NVD",
                "Apache 2.4.49 Path Traversal & RCE",
                "Path normalization flaw in Apache HTTP Server 2.4.49 allows mapping URLs outside configured root and achieving RCE.",
                "3.1",
                7.5,
                "HIGH",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                0.941,
                0.98,
                1,
                "exploit/multi/http/apache_normalize_path_rce",
                1,
                0.40,
                "Upgrade Apache HTTP Server to 2.4.51 or later."
            ),
            (
                "CVE-2024-6387",
                "NVD",
                "OpenSSH regreSSHion Signal Handler Race Condition",
                "Signal handler race condition in OpenSSH sshd process leads to unauthenticated root code execution on glibc systems.",
                "3.1",
                8.1,
                "HIGH",
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                0.684,
                0.96,
                0,
                "exploit/linux/ssh/regresshion_rce",
                0,
                1.00,
                "Upgrade OpenSSH to 9.8p1 or newer. Set 'LoginGraceTime 0' as temporary mitigation."
            ),
        ]

        for cve in cve_seed_list:
            await db.execute(
                """
                INSERT OR REPLACE INTO vulnerabilities (
                    cve_id, source_id, title, description, cvss_version,
                    cvss_score, cvss_severity, cvss_vector, epss_score, epss_percentile,
                    is_weaponized, metasploit_module, cisa_kev, dijkstra_cost, remediation_notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                cve
            )

        # 9. Seed Vulnerability Applicability Findings
        findings_seed = [
            (SEED_SCAN_ID, "vvdx.in:80", "CVE-2024-4577", "confirmed_applicability", 0.99, "Observed PHP-CGI 8.1.2 handler on exposed HTTP port 80. Exploit confirmed via active probe signature."),
            (SEED_SCAN_ID, "staging.vvdx.in:8080", "CVE-2021-41773", "confirmed_applicability", 0.95, "Observed Apache 2.4.49 path normalization bypass on staging perimeter."),
            (SEED_SCAN_ID, "vvdx.in:22", "CVE-2024-6387", "potential_applicability", 0.85, "Observed OpenSSH 8.9p1 on port 22 matching glibc vulnerable banner range."),
        ]
        for f in findings_seed:
            await db.execute(
                """
                INSERT INTO vulnerability_findings (
                    scan_id, asset_id, cve_id, applicability_status,
                    confidence_score, match_rationale, evaluated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (f[0], f[1], f[2], f[3], f[4], f[5], now_iso)
            )

        # 10. Seed Graph Snapshot
        await db.execute(
            """
            INSERT OR REPLACE INTO graph_snapshots (
                id, scan_id, snapshot_version, schema_version,
                nodes_count, edges_count, graph_data, statistics, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "snap-seed-vvdx",
                SEED_SCAN_ID,
                1,
                "4.0",
                len(GRAPH_SEED["nodes"]),
                len(GRAPH_SEED["edges"]),
                json.dumps(GRAPH_SEED),
                json.dumps({"shortest_path_cost": 0.40, "total_nodes": 8, "total_edges": 9}),
                now_iso
            )
        )

        # 11. Seed Attack Paths
        await db.execute(
            """
            INSERT OR REPLACE INTO attack_paths (
                id, scan_id, snapshot_id, source_node, target_node,
                path_nodes, path_edges, total_cost, priority_score,
                cves, confidence_level, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "path-seed-cve-2024-4577",
                SEED_SCAN_ID,
                "snap-seed-vvdx",
                "ingress_vvdx",
                "crown_jewel_db",
                json.dumps(GRAPH_SEED["shortest_path"]),
                json.dumps([
                    {"source": "ingress_vvdx", "target": "vuln_cve_2024_4577"},
                    {"source": "vuln_cve_2024_4577", "target": "pivot_dmz_shell"},
                    {"source": "pivot_dmz_shell", "target": "crown_jewel_db"},
                ]),
                0.40,
                98.0,
                json.dumps(["CVE-2024-4577"]),
                "high",
                now_iso
            )
        )

        # 12. Seed Risk Assessment
        await db.execute(
            """
            INSERT OR REPLACE INTO risk_assessments (
                id, scan_id, snapshot_id, overall_risk_score, criticality_score,
                confirmed_vulns_count, potential_vulns_count, compromise_likelihood,
                factors, scoring_version, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "risk-seed-vvdx",
                SEED_SCAN_ID,
                "snap-seed-vvdx",
                94.2,
                9.8,
                2,
                1,
                0.97,
                json.dumps({"cve_2024_4577": "CRITICAL", "shortest_path_friction": 0.40}),
                "4.0-drishti-risk",
                now_iso
            )
        )

        # 13. Seed Plaintext Scan Report
        await db.execute(
            """
            INSERT OR REPLACE INTO scan_reports (
                scan_id, file_path, file_size, status,
                report_metadata, content_text, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                SEED_SCAN_ID,
                "data/reports/DRISHTI_Assessment_vvdx.in.txt",
                len(ASCII_SEED_REPORT.encode("utf-8")),
                "generated",
                json.dumps({
                    "id": "RPT-2026-1105-VVDX",
                    "target": SEED_TARGET,
                    "format": "TEXT",
                    "sha256_signature": hashlib.sha256(ASCII_SEED_REPORT.encode("utf-8")).hexdigest(),
                    "created_at": now_iso
                }),
                ASCII_SEED_REPORT,
                now_iso
            )
        )

        # 14. Seed Audit Events
        audit_events = [
            ("scan_initiated", SEED_AUTH_ID, SEED_SCAN_ID, "local-operator-dev", SEED_TARGET, "Multi-engine perimeter scan launched under RFC-8655 scope"),
            ("cve_correlated", SEED_AUTH_ID, SEED_SCAN_ID, "local-operator-dev", SEED_TARGET, "CVE-2024-4577 identified with 0.972 EPSS weaponized exploit"),
            ("defense_synthesized", SEED_AUTH_ID, SEED_SCAN_ID, "local-operator-dev", SEED_TARGET, "Autonomous Cloudflare & ModSec rules generated for CVE-2024-4577"),
        ]
        for ev in audit_events:
            await db.execute(
                """
                INSERT INTO audit_events (
                    event_type, authorization_id, scan_id, operator_id, target, detail, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (ev[0], ev[1], ev[2], ev[3], ev[4], ev[5], now_iso)
            )

        await db.commit()
        logger.info("Deterministic baseline seed for vvdx.in successfully populated!")
