"""
DRISHTI — Phase 6 Active Scanner Persistence Service
Persists normalized HostObservation and PortObservation data into Supabase PostgreSQL,
correlates observed network services with Asset Fingerprints (Phase 3),
and triggers vulnerability applicability evaluations without synthetic assumptions.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional

from backend.db.database import db_queue, get_db
from backend.services.cve_matcher import evaluate_cve_applicability
from backend.services.fingerprint import normalize_tech_banner
from backend.services.nvd_models import AssetFingerprint
from backend.services.scanner_foundation import (
    HostObservation,
    HttpServiceObservation,
    PortObservation,
    ScannerResult,
)
from backend.services.vulnerability_service import list_vulnerabilities

logger = logging.getLogger("drishti.scanner_persistence")


async def persist_active_port_observations(result: ScannerResult) -> int:
    """
    Persists all host and port observations into active_port_observations table.
    Returns the total count of port records created.
    """
    total_ports = 0
    for host_obs in result.hosts:
        for port_obs in host_obs.ports:
            await db_queue.execute_write(
                """
                INSERT INTO active_port_observations (
                    scan_id, host, ip, port, protocol, state,
                    service_name, product, version, extra_info, cpe23,
                    scanner_name, scanner_version, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (
                    result.scan_id,
                    host_obs.host,
                    host_obs.ip,
                    port_obs.port,
                    port_obs.protocol,
                    port_obs.state,
                    port_obs.service_name,
                    port_obs.product,
                    port_obs.version,
                    port_obs.extra_info,
                    port_obs.cpe23,
                    result.scanner_name,
                    result.scanner_version,
                )
            )
            total_ports += 1

    return total_ports


async def correlate_nmap_observations_to_fingerprints(result: ScannerResult) -> int:
    """
    Transforms observed network services into normalized AssetFingerprint records
    and stores them for downstream CPE vulnerability correlation.
    """
    created_fingerprints = 0
    all_vulns = await list_vulnerabilities(limit=100)

    for host_obs in result.hosts:
        for port_obs in host_obs.ports:
            if not port_obs.product and not port_obs.service_name:
                continue

            tech_tokens = []
            if port_obs.product:
                tech_tokens.append(f"{port_obs.product} {port_obs.version or ''}".strip())
            elif port_obs.service_name:
                tech_tokens.append(port_obs.service_name)
            tech_str = ", ".join(tech_tokens)

            fps = normalize_tech_banner(
                host=host_obs.host,
                ip=host_obs.ip,
                port=port_obs.port,
                tech_str=tech_str,
                scan_id=result.scan_id,
                source=f"nmap-{port_obs.service_name or 'service'}",
            )

            for fp in fps:
                # If Nmap provided CPE explicitly, attach it
                if port_obs.cpe23 and not fp.cpe23:
                    fp.cpe23 = port_obs.cpe23

                # Persist fingerprint
                fp_id = await db_queue.execute_write(
                    """
                    INSERT INTO asset_fingerprints (
                        scan_id, asset_id, host, port, vendor, product, version,
                        version_scheme, cpe23, fingerprint_source, is_inferred, confidence, observed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """,
                    (
                        result.scan_id,
                        fp.asset_id,
                        fp.host,
                        fp.port,
                        fp.vendor,
                        fp.product,
                        fp.version,
                        fp.version_scheme,
                        fp.cpe23,
                        fp.fingerprint_source,
                        fp.is_inferred,
                        fp.confidence,
                    )
                )
                created_fingerprints += 1

                # Check applicability against known CVE corpus
                for vuln in all_vulns:
                    res = evaluate_cve_applicability(vuln, fp)
                    status_val = res.applicability_status.value if hasattr(res.applicability_status, 'value') else str(res.applicability_status)
                    if status_val in ("confirmed_applicability", "potential_applicability"):
                        await db_queue.execute_write(
                            """
                            INSERT INTO vulnerability_findings (
                                scan_id, asset_id, cve_id, fingerprint_id,
                                applicability_status, confidence_score, match_rationale, evaluated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                            """,
                            (
                                result.scan_id,
                                fp.asset_id,
                                vuln.cve_id,
                                fp_id,
                                status_val,
                                res.confidence_score,
                                res.match_rationale,
                            )
                        )

    # Persist discovered host & open ports to scan_findings
    for host_obs in result.hosts:
        open_ports = [p.port for p in host_obs.ports if p.state == "open"]
        if open_ports:
            services = [f"{p.service_name or 'port'} ({p.port})" for p in host_obs.ports if p.state == "open"]
            await db_queue.execute_write(
                """
                INSERT INTO scan_findings (
                    scan_id, host, ip, tech, status, risk, score, ports, created_at
                ) VALUES (?, ?, ?, ?, 'Active', 'LOW', '3.0', ?, CURRENT_TIMESTAMP)
                """,
                (
                    result.scan_id,
                    host_obs.host or result.target,
                    host_obs.ip,
                    f"Open Services: {', '.join(services[:5])}",
                    json.dumps(open_ports),
                )
            )

    return created_fingerprints


async def get_active_port_observations(scan_id: str) -> List[Dict[str, Any]]:
    """Retrieves all persisted active port observations for a given scan."""
    async with get_db() as db:
        async with db.execute(
            """
            SELECT id, scan_id, host, ip, port, protocol, state,
                   service_name, product, version, extra_info, cpe23,
                   scanner_name, scanner_version, observed_at
            FROM active_port_observations
            WHERE scan_id = ?
            ORDER BY port ASC
            """,
            (scan_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Phase 7: ProjectDiscovery httpx HTTP Service Persistence & Asset Correlation
# ---------------------------------------------------------------------------

async def persist_http_service_observations(result: ScannerResult) -> int:
    """
    Persists normalized HttpServiceObservation items into the http_service_observations table.
    Returns the total count of HTTP service records created.
    """
    total_saved = 0
    for obs in result.http_services:
        await db_queue.execute_write(
            """
            INSERT INTO http_service_observations (
                scan_id, url, host, port, scheme, status_code,
                title, webserver, content_type, content_length,
                technologies, final_url, ip, cname, response_time_ms,
                scanner_name, scanner_version, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                result.scan_id,
                obs.url,
                obs.host,
                obs.port,
                obs.scheme,
                obs.status_code,
                obs.title,
                obs.webserver,
                obs.content_type,
                obs.content_length,
                json.dumps(obs.technologies),
                obs.final_url,
                obs.ip,
                obs.cname,
                obs.response_time_ms,
                result.scanner_name,
                result.scanner_version,
            )
        )
        total_saved += 1

    return total_saved


async def correlate_httpx_observations_to_fingerprints(result: ScannerResult) -> int:
    """
    Correlates webserver headers and detected technologies from httpx observations
    with AssetFingerprints, performing evidence-grounded CVE applicability matching.
    """
    created_fps = 0
    all_vulns = await list_vulnerabilities(limit=100)

    for obs in result.http_services:
        tech_elements = list(obs.technologies)
        if obs.webserver:
            tech_elements.append(obs.webserver)

        if not tech_elements:
            continue

        tech_str = ", ".join(tech_elements)
        fps = normalize_tech_banner(
            host=obs.host,
            ip=obs.ip or "0.0.0.0",
            port=obs.port,
            tech_str=tech_str,
            scan_id=result.scan_id,
            source="httpx-tech",
        )

        for fp in fps:
            fp_id = await db_queue.execute_write(
                """
                INSERT INTO asset_fingerprints (
                    scan_id, asset_id, host, port, vendor, product, version,
                    version_scheme, cpe23, fingerprint_source, is_inferred, confidence, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (
                    result.scan_id,
                    fp.asset_id,
                    fp.host,
                    fp.port,
                    fp.vendor,
                    fp.product,
                    fp.version,
                    fp.version_scheme,
                    fp.cpe23,
                    fp.fingerprint_source,
                    fp.is_inferred,
                    fp.confidence,
                )
            )
            created_fps += 1

            for vuln in all_vulns:
                res = evaluate_cve_applicability(vuln, fp)
                status_val = (
                    res.applicability_status.value
                    if hasattr(res.applicability_status, "value")
                    else str(res.applicability_status)
                )
                if status_val in ("confirmed_applicability", "potential_applicability"):
                    await db_queue.execute_write(
                        """
                        INSERT INTO vulnerability_findings (
                            scan_id, asset_id, cve_id, fingerprint_id,
                            applicability_status, confidence_score, match_rationale, evaluated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        """,
                        (
                            result.scan_id,
                            fp.asset_id,
                            vuln.cve_id,
                            fp_id,
                            status_val,
                            res.confidence_score,
                            res.match_rationale,
                        )
                    )

    # Persist discovered HTTP/HTTPS services to scan_findings
    fallback_ip = result.hosts[0].ip if (result.hosts and result.hosts[0].ip) else "127.0.0.1"
    for obs in result.http_services:
        tech_summary = ", ".join(obs.technologies) if obs.technologies else (obs.webserver or "HTTP Web Service")
        if obs.title:
            clean_title = obs.title.replace("&amp;", "&").replace("—", "-").strip()[:45]
            tech_summary = f"{tech_summary} - {clean_title}"
        await db_queue.execute_write(
            """
            INSERT INTO scan_findings (
                scan_id, host, ip, tech, status, risk, score, ports, created_at
            ) VALUES (?, ?, ?, ?, ?, 'LOW', '3.5', ?, CURRENT_TIMESTAMP)
            """,
            (
                result.scan_id,
                obs.host or result.target,
                obs.ip or fallback_ip,
                tech_summary,
                f"{obs.status_code} OK" if obs.status_code else "Active",
                json.dumps([obs.port]),
            )
        )

    return created_fps


async def get_http_service_observations(scan_id: str) -> List[Dict[str, Any]]:
    """Retrieves all persisted HTTP service observations for a given scan."""
    async with get_db() as db:
        async with db.execute(
            """
            SELECT id, scan_id, url, host, port, scheme, status_code,
                   title, webserver, content_type, content_length,
                   technologies, final_url, ip, cname, response_time_ms,
                   scanner_name, scanner_version, observed_at
            FROM http_service_observations
            WHERE scan_id = ?
            ORDER BY port ASC
            """,
            (scan_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            out = []
            for r in rows:
                d = dict(r)
                if isinstance(d.get("technologies"), str):
                    try:
                        d["technologies"] = json.loads(d["technologies"])
                    except Exception:
                        d["technologies"] = []
                out.append(d)
            return out


# ---------------------------------------------------------------------------
# Phase 8: OWASP ZAP Alert Persistence & Vulnerability Findings Correlation
# ---------------------------------------------------------------------------

async def persist_zap_alert_observations(result: ScannerResult) -> int:
    """
    Persists normalized ZapAlertObservation items into zap_alert_observations table.
    Returns the total count of ZAP alert records stored.
    """
    total_saved = 0
    for alert in result.zap_alerts:
        await db_queue.execute_write(
            """
            INSERT INTO zap_alert_observations (
                scan_id, plugin_id, alert_name, risk, confidence,
                url, host, port, param, attack, evidence, description,
                solution, reference, cwe_id, wasc_id, source_scanner,
                verification_status, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                result.scan_id,
                alert.plugin_id,
                alert.alert_name,
                alert.risk,
                alert.confidence,
                alert.url,
                alert.host,
                alert.port,
                alert.param or "",
                alert.attack or "",
                alert.evidence or "",
                alert.description or "",
                alert.solution or "",
                alert.reference or "",
                alert.cwe_id,
                alert.wasc_id,
                alert.source_scanner or "OWASP ZAP",
                alert.verification_status or "unverified_finding",
            )
        )
        total_saved += 1

    return total_saved


async def correlate_zap_alerts_to_scan_findings(result: ScannerResult) -> int:
    """
    Correlates high/medium risk ZAP web alerts with the primary scan_findings table
    so they surface seamlessly in DRISHTI's unified findings dashboard.
    """
    findings_created = 0
    risk_score_map = {
        "Critical": "9.5",
        "High": "7.5",
        "Medium": "5.0",
        "Low": "2.5",
        "Informational": "1.0",
    }

    for alert in result.zap_alerts:
        # Map into scan_findings table format
        score = risk_score_map.get(alert.risk, "3.0")
        tech_note = f"OWASP ZAP Plugin {alert.plugin_id} - {alert.alert_name}"
        if alert.cwe_id:
            tech_note += f" (CWE-{alert.cwe_id})"

        await db_queue.execute_write(
            """
            INSERT INTO scan_findings (
                scan_id, host, ip, tech, status, risk, score, ports, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                result.scan_id,
                alert.host,
                "0.0.0.0",
                tech_note,
                f"Web Alert ({alert.confidence} Confidence)",
                alert.risk.upper(),
                score,
                json.dumps([alert.port]),
            )
        )
        findings_created += 1

    return findings_created


async def get_zap_alert_observations(scan_id: str) -> List[Dict[str, Any]]:
    """Retrieves all persisted OWASP ZAP web alert observations for a given scan."""
    async with get_db() as db:
        async with db.execute(
            """
            SELECT id, scan_id, plugin_id, alert_name, risk, confidence,
                   url, host, port, param, attack, evidence, description,
                   solution, reference, cwe_id, wasc_id, source_scanner,
                   verification_status, observed_at
            FROM zap_alert_observations
            WHERE scan_id = ?
            ORDER BY id ASC
            """,
            (scan_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Phase 9: Aqua Security Trivy Supply Chain & Artifact Persistence
# ---------------------------------------------------------------------------

async def persist_trivy_finding_observations(result: ScannerResult) -> int:
    """
    Persists normalized TrivyFindingObservation items into trivy_findings table.
    Returns the total count of Trivy findings stored.
    """
    total_saved = 0
    for finding in result.trivy_findings:
        await db_queue.execute_write(
            """
            INSERT INTO trivy_findings (
                scan_id, target_resource, finding_class, vulnerability_id,
                rule_id, title, severity, package_name, installed_version,
                fixed_version, primary_url, description, remediation_guidance,
                evidence, line_number, confidence, scanner_name, scanner_version,
                observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                result.scan_id,
                finding.target_resource,
                finding.finding_class,
                finding.vulnerability_id,
                finding.rule_id,
                finding.title,
                finding.severity,
                finding.package_name,
                finding.installed_version,
                finding.fixed_version,
                finding.primary_url,
                finding.description,
                finding.remediation_guidance,
                finding.evidence,
                finding.line_number,
                finding.confidence,
                finding.scanner_name,
                finding.scanner_version,
            )
        )
        total_saved += 1

    return total_saved


async def correlate_trivy_findings_to_scan_findings(result: ScannerResult) -> int:
    """
    Correlates Trivy findings into the unified scan_findings table for risk engine analysis.
    """
    findings_created = 0
    risk_score_map = {
        "CRITICAL": "9.8",
        "HIGH": "7.8",
        "MEDIUM": "5.2",
        "LOW": "2.4",
        "UNKNOWN": "1.0",
    }

    for finding in result.trivy_findings:
        score = risk_score_map.get(finding.severity.upper(), "3.0")
        label = f"Trivy {finding.finding_class.capitalize()}"
        if finding.vulnerability_id:
            label += f" ({finding.vulnerability_id})"
        elif finding.rule_id:
            label += f" ({finding.rule_id})"

        detail = finding.package_name or finding.target_resource

        await db_queue.execute_write(
            """
            INSERT INTO scan_findings (
                scan_id, host, ip, tech, status, risk, score, ports, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                result.scan_id,
                finding.target_resource[:250],
                "127.0.0.1",
                f"{label}: {finding.title or ''}"[:250],
                f"{finding.finding_class} detected",
                finding.severity.upper(),
                score,
                json.dumps([]),
            )
        )
        findings_created += 1

    return findings_created


async def get_trivy_finding_observations(scan_id: str) -> List[Dict[str, Any]]:
    """Retrieves all persisted Trivy supply-chain findings for a given scan."""
    async with get_db() as db:
        async with db.execute(
            """
            SELECT id, scan_id, target_resource, finding_class, vulnerability_id,
                   rule_id, title, severity, package_name, installed_version,
                   fixed_version, primary_url, description, remediation_guidance,
                   evidence, line_number, confidence, scanner_name, scanner_version,
                   observed_at
            FROM trivy_findings
            WHERE scan_id = ?
            ORDER BY id ASC
            """,
            (scan_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Phase 10: ProjectDiscovery Nuclei Template-Based Security Checks Persistence
# ---------------------------------------------------------------------------

async def persist_nuclei_finding_observations(result: ScannerResult) -> int:
    """
    Persists normalized NucleiFindingObservation records into nuclei_findings table.
    Returns total count of Nuclei findings saved.
    """
    total_saved = 0
    for finding in result.nuclei_findings:
        await db_queue.execute_write(
            """
            INSERT INTO nuclei_findings (
                scan_id, template_id, template_name, severity, matched_at,
                host, port, scheme, url, matcher_name, extracted_results,
                type, description, remediation, reference, tags, cve_id,
                cwe_id, cvss_score, curl_command, evidence, confidence,
                scanner_name, scanner_version, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                result.scan_id,
                finding.template_id,
                finding.template_name,
                finding.severity.lower(),
                finding.matched_at,
                finding.host,
                finding.port,
                finding.scheme,
                finding.url,
                finding.matcher_name,
                json.dumps(finding.extracted_results),
                finding.type,
                finding.description,
                finding.remediation,
                json.dumps(finding.reference),
                json.dumps(finding.tags),
                finding.cve_id,
                finding.cwe_id,
                finding.cvss_score,
                finding.curl_command,
                finding.evidence,
                finding.confidence,
                finding.scanner_name,
                finding.scanner_version,
            )
        )
        total_saved += 1

    return total_saved


async def correlate_nuclei_findings_to_scan_findings(result: ScannerResult) -> int:
    """
    Correlates Nuclei findings into the unified scan_findings table for risk engine analysis.
    Preserves exact host, CVE associations, severity weights, and evidence tags.
    """
    findings_created = 0
    severity_score_map = {
        "critical": "9.5",
        "high": "7.5",
        "medium": "5.0",
        "low": "2.5",
        "info": "1.0",
        "unknown": "2.0",
    }

    for finding in result.nuclei_findings:
        sev_lower = finding.severity.lower()
        score = severity_score_map.get(sev_lower, "2.0")
        label = f"Nuclei: {finding.template_name or finding.template_id}"
        if finding.cve_id:
            label += f" ({finding.cve_id})"

        detail = f"{finding.type.upper()} on {finding.matched_at}"

        await db_queue.execute_write(
            """
            INSERT INTO scan_findings (
                scan_id, host, ip, tech, status, risk, score, ports, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                result.scan_id,
                finding.host[:250],
                "127.0.0.1",
                f"{label} - {detail}"[:250],
                f"Nuclei Template Match ({sev_lower.upper()})",
                sev_lower.upper(),
                score,
                json.dumps([finding.port] if finding.port else []),
            )
        )
        findings_created += 1

        # Actively confirmed vulnerability on target wire: promote to CONFIRMED in vulnerability_findings
        cve_id_val = None
        if finding.cve_id and finding.cve_id.upper().startswith("CVE-"):
            cve_id_val = finding.cve_id.upper().strip()
        elif finding.template_id and finding.template_id.upper().startswith("CVE-"):
            cve_id_val = finding.template_id.upper().strip()

        if cve_id_val:
            # Ensure vulnerability metadata exists in corpus
            await db_queue.execute_write(
                """
                INSERT OR IGNORE INTO vulnerabilities (
                    cve_id, source_id, title, description, cvss_score, cvss_severity, cached_at
                ) VALUES (?, 'NUCLEI_ACTIVE', ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (
                    cve_id_val,
                    finding.template_name or finding.template_id,
                    f"Confirmed via active ProjectDiscovery Nuclei scan at {finding.matched_at}",
                    float(score),
                    sev_lower.upper(),
                )
            )

            # Check if this CVE was previously recorded as potential/correlated and update to confirmed
            updated_count = await db_queue.execute_write(
                """
                UPDATE vulnerability_findings
                SET applicability_status = 'confirmed_applicability',
                    confidence_score = 0.99,
                    match_rationale = ?
                WHERE scan_id = ? AND UPPER(cve_id) = ?
                """,
                (
                    f"CONFIRMED (ACTIVE SCAN VERIFIED): ProjectDiscovery Nuclei executed active template {finding.template_id} and verified vulnerability on target wire at {finding.matched_at}.",
                    result.scan_id,
                    cve_id_val,
                )
            )

            # If not previously present, insert directly as confirmed
            if not updated_count:
                await db_queue.execute_write(
                    """
                    INSERT INTO vulnerability_findings (
                        scan_id, asset_id, cve_id, fingerprint_id,
                        applicability_status, confidence_score, match_rationale, evaluated_at
                    ) VALUES (?, ?, ?, NULL, 'confirmed_applicability', 0.99, ?, CURRENT_TIMESTAMP)
                    """,
                    (
                        result.scan_id,
                        finding.host[:250],
                        cve_id_val,
                        f"CONFIRMED (ACTIVE SCAN VERIFIED): ProjectDiscovery Nuclei executed active template {finding.template_id} and verified vulnerability on target wire at {finding.matched_at}.",
                    )
                )

    return findings_created


async def get_nuclei_finding_observations(scan_id: str) -> List[Dict[str, Any]]:
    """Retrieves all persisted Nuclei template-based findings for a given scan."""
    async with get_db() as db:
        async with db.execute(
            """
            SELECT id, scan_id, template_id, template_name, severity, matched_at,
                   host, port, scheme, url, matcher_name, extracted_results,
                   type, description, remediation, reference, tags, cve_id,
                   cwe_id, cvss_score, curl_command, evidence, confidence,
                   scanner_name, scanner_version, observed_at
            FROM nuclei_findings
            WHERE scan_id = ?
            ORDER BY id ASC
            """,
            (scan_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]
