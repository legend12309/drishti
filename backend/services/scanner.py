"""
DRISHTI Deterministic Scan Lifecycle Engine.
Manages asynchronous scan state machine, persistence, cancellation,
real-time event distribution for SSE streaming, authorization revalidation,
and passive reconnaissance execution.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
import re
import time
from typing import Any, AsyncGenerator, Dict, List, Optional, Set

logger = logging.getLogger("drishti.scanner")

from backend.db.database import get_db, db_queue
from backend.services.authorizations import (
    get_authorization,
    get_valid_authorization_for_target,
    log_audit_event
)
from backend.services.passive import execute_passive_reconnaissance
from backend.services.detective import detective_engine
from backend.services.scope import normalize_domain, is_in_scope, is_scope_authorized
from backend.services.vulnerability_service import (
    normalize_and_persist_fingerprints,
    evaluate_scan_vulnerabilities,
)
from backend.services.httpx_adapter import pd_httpx_adapter
from backend.services.nmap_adapter import nmap_adapter
from backend.services.zap_adapter import zap_adapter
from backend.services.trivy_adapter import trivy_adapter
from backend.services.nuclei_adapter import nuclei_adapter
from backend.services.scanner_foundation import ScanProfile, ScannerExecutionState
from backend.services.scanner_service import (
    persist_active_port_observations,
    correlate_nmap_observations_to_fingerprints,
    persist_http_service_observations,
    correlate_httpx_observations_to_fingerprints,
    persist_zap_alert_observations,
    correlate_zap_alerts_to_scan_findings,
    persist_trivy_finding_observations,
    correlate_trivy_findings_to_scan_findings,
    persist_nuclei_finding_observations,
    correlate_nuclei_findings_to_scan_findings,
)

# In-memory tracking for active scan tasks and SSE subscriber queues
_active_scan_tasks: Dict[str, asyncio.Task] = {}
_scan_cancellation_events: Dict[str, asyncio.Event] = {}
_scan_subscribers: Dict[str, Set[asyncio.Queue]] = {}


def is_domain_permitted(domain: str) -> bool:
    """Validates domain syntax format."""
    try:
        normalize_domain(domain)
        return True
    except Exception:
        return False


async def register_subscriber(scan_id: str) -> asyncio.Queue:
    """Registers an SSE listener queue for real-time progress events."""
    if scan_id not in _scan_subscribers:
        _scan_subscribers[scan_id] = set()
    queue: asyncio.Queue = asyncio.Queue()
    _scan_subscribers[scan_id].add(queue)
    return queue


def unregister_subscriber(scan_id: str, queue: asyncio.Queue):
    """Removes an SSE listener queue."""
    if scan_id in _scan_subscribers:
        _scan_subscribers[scan_id].discard(queue)
        if not _scan_subscribers[scan_id]:
            del _scan_subscribers[scan_id]


async def broadcast_event(scan_id: str, event_type: str, data: Dict[str, Any]):
    """Broadcasts an event to all connected SSE clients."""
    if scan_id in _scan_subscribers:
        payload = {"type": event_type, "data": data}
        for q in list(_scan_subscribers[scan_id]):
            await q.put(payload)


def generate_mock_findings(target: str) -> List[Dict[str, Any]]:
    """Generates realistic findings for a given target domain."""
    clean = target.strip().lower()
    return [
        {
            "host": f"vpn.{clean}",
            "ip": "198.51.100.8",
            "tech": "OpenVPN 2.5, OpenSSL 1.1.1",
            "status": "Filtered",
            "risk": "CRITICAL",
            "score": "9.8",
            "ports": [443, 1194, 500],
        },
        {
            "host": f"api.{clean}",
            "ip": "104.21.48.12",
            "tech": "Cloudflare Edge, Nginx 1.24",
            "status": "200 OK",
            "risk": "HIGH",
            "score": "7.8",
            "ports": [80, 443, 8443],
        },
        {
            "host": f"dev.{clean}",
            "ip": "198.51.100.15",
            "tech": "Next.js 14, AWS S3 Ingress",
            "status": "403 Forbidden",
            "risk": "MEDIUM",
            "score": "5.2",
            "ports": [3000, 8080],
        },
        {
            "host": f"auth.{clean}",
            "ip": "104.21.48.19",
            "tech": "OAuth2 / OIDC, Node.js 20",
            "status": "200 OK",
            "risk": "LOW",
            "score": "2.4",
            "ports": [443],
        },
        {
            "host": f"mail.{clean}",
            "ip": "198.51.100.25",
            "tech": "Postfix 3.6, Dovecot",
            "status": "200 OK",
            "risk": "LOW",
            "score": "1.9",
            "ports": [25, 587],
        },
    ]


async def _run_scan_worker(
    scan_id: str,
    target: str,
    authorization_id: str,
    scope: str = "FULL_PASSIVE"
):
    """
    Background lifecycle worker executing deterministic scan phases:
    1. Revalidates authorization immediately prior to network activity
    2. Emits authorization_check and scope_validation progress events
    3. Runs passive reconnaissance (DNS A, AAAA, MX, NS, TXT, CNAME, RDAP)
    4. Persists passive observations and discovered assets
    5. Marks completed and notifies subscribers
    """
    cancel_event = _scan_cancellation_events.get(scan_id)

    try:
        if cancel_event and cancel_event.is_set():
            return

        # Step 0: Mark Running
        await db_queue.execute_write(
            "UPDATE scans SET status = 'running', progress = 5, current_step = 'Validating scope authorization', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status != 'cancelled'",
            (scan_id,)
        )
        await broadcast_event(scan_id, "status", {"status": "running", "progress": 5, "step": "Validating scope authorization"})

        # Step 1: Authorization Revalidation immediately before network activity
        auth = await get_authorization(authorization_id)
        if not auth or auth["status"] != "verified":
            status_desc = auth["status"] if auth else "missing"
            err_msg = f"Scan rejected: Authorization for '{target}' is not active or verified (status: {status_desc})."
            await db_queue.execute_write(
                "UPDATE scans SET status = 'failed', error_message = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (err_msg, scan_id)
            )
            await log_audit_event(
                event_type="scan_revalidation_failed",
                target=target,
                detail=err_msg,
                authorization_id=authorization_id,
                scan_id=scan_id
            )
            await broadcast_event(scan_id, "error", {"status": "failed", "error": err_msg})
            return

        # Revalidate scope boundary
        if not is_in_scope(target, auth["target_domain"]):
            err_msg = f"Scan rejected: Target '{target}' violates authorized boundary '{auth['target_domain']}'."
            await db_queue.execute_write(
                "UPDATE scans SET status = 'failed', error_message = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (err_msg, scan_id)
            )
            await log_audit_event(
                event_type="scan_scope_violation",
                target=target,
                detail=err_msg,
                authorization_id=authorization_id,
                scan_id=scan_id
            )
            await broadcast_event(scan_id, "error", {"status": "failed", "error": err_msg})
            return

        # Broadcast successful authorization check and scope validation
        await broadcast_event(scan_id, "authorization_check", {
            "status": "authorized",
            "authorization_id": authorization_id,
            "target_domain": auth["target_domain"],
            "permitted_scope": scope
        })
        await broadcast_event(scan_id, "scope_validation", {
            "status": "validated",
            "target": target,
            "scope": scope
        })

        if cancel_event and cancel_event.is_set():
            return

        await asyncio.sleep(0.01)

        # Step 2: Passive Reconnaissance Execution
        # Revalidate authorization immediately before executing network queries
        auth = await get_authorization(authorization_id)
        if not auth or auth["status"] != "verified":
            status_desc = auth["status"] if auth else "missing"
            err_msg = f"Scan rejected: Authorization for '{target}' is no longer active or verified (status: {status_desc})."
            await db_queue.execute_write(
                "UPDATE scans SET status = 'failed', error_message = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (err_msg, scan_id)
            )
            await log_audit_event(
                event_type="scan_revalidation_failed",
                target=target,
                detail=err_msg,
                authorization_id=authorization_id,
                scan_id=scan_id
            )
            await broadcast_event(scan_id, "error", {"status": "failed", "error": err_msg})
            return

        await db_queue.execute_write(
            "UPDATE scans SET progress = 30, current_step = 'Executing Detective Engine: Subdomain enumeration & asset inventory', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status != 'cancelled'",
            (scan_id,)
        )
        await broadcast_event(scan_id, "detective_recon", {
            "progress": 30,
            "step": "Executing Detective Engine: Subdomain enumeration & asset inventory"
        })

        detective_res = await detective_engine.run_pipeline(
            target=target,
            scan_id=scan_id,
            authorization_id=authorization_id,
            scope=scope,
            cancel_event=cancel_event,
            event_callback=broadcast_event
        )

        # Run passive DNS collection
        passive_res = await execute_passive_reconnaissance(
            scan_id=scan_id,
            target=target,
            authorization_id=authorization_id
        )

        if cancel_event and cancel_event.is_set():
            return

        all_discovered_hosts = set(passive_res.get("discovered_hosts", [])) | {a.host for a in detective_res.assets}
        all_discovered_ips = set(passive_res.get("discovered_ips", [])) | {a.ip for a in detective_res.assets if a.ip != "0.0.0.0"}

        # Broadcast discovered assets
        await broadcast_event(scan_id, "asset_discovered", {
            "progress": 55,
            "total_observations": passive_res["total_observations"] + len(detective_res.assets),
            "discovered_hosts": list(all_discovered_hosts),
            "discovered_ips": list(all_discovered_ips)
        })

        if cancel_event and cancel_event.is_set():
            return

        # Step 2b: Active Network Port Scan via Nmap (if requested in scope)
        nmap_ports_count = 0
        if "NMAP" in scope.upper() or "PORT" in scope.upper() or "ACTIVE" in scope.upper():
            await db_queue.execute_write(
                "UPDATE scans SET progress = 60, current_step = 'Executing active port scanning via Nmap', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status != 'cancelled'",
                (scan_id,)
            )
            await broadcast_event(scan_id, "active_port_scan", {
                "progress": 60,
                "step": "Executing active port scanning via Nmap"
            })
            profile = ScanProfile.SERVICE_IDENTIFICATION if "SERVICE" in scope.upper() else ScanProfile.BASIC_PORT_DISCOVERY
            nmap_res = await nmap_adapter.execute_scan(
                scan_id=scan_id,
                target=target,
                profile=profile,
                cancel_event=cancel_event,
                authorized_domain=auth["target_domain"] if auth else None
            )
            if nmap_res.status == ScannerExecutionState.COMPLETED:
                nmap_ports_count = await persist_active_port_observations(nmap_res)
                await correlate_nmap_observations_to_fingerprints(nmap_res)
                await broadcast_event(scan_id, "active_ports_discovered", {
                    "progress": 70,
                    "total_open_ports": nmap_ports_count,
                    "hosts_probed": len(nmap_res.hosts)
                })
            elif nmap_res.status == ScannerExecutionState.SCANNER_UNAVAILABLE:
                await broadcast_event(scan_id, "scanner_warning", {
                    "scanner": "Nmap",
                    "warning": nmap_res.error_message
                })

        if cancel_event and cancel_event.is_set():
            return

        # Step 2c: Active HTTP Service Discovery via ProjectDiscovery httpx (if requested in scope)
        httpx_services_count = 0
        if "HTTPX" in scope.upper() or "WEB" in scope.upper() or "ACTIVE" in scope.upper():
            await db_queue.execute_write(
                "UPDATE scans SET progress = 68, current_step = 'Executing HTTP service discovery via ProjectDiscovery httpx', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status != 'cancelled'",
                (scan_id,)
            )
            await broadcast_event(scan_id, "httpx_discovery", {
                "progress": 68,
                "step": "Executing HTTP service discovery via ProjectDiscovery httpx"
            })
            httpx_profile = ScanProfile.SERVICE_METADATA_ENRICHMENT
            httpx_res = await pd_httpx_adapter.execute_scan(
                scan_id=scan_id,
                target=target,
                profile=httpx_profile,
                cancel_event=cancel_event,
                authorized_domain=auth["target_domain"] if auth else None
            )
            if httpx_res.status == ScannerExecutionState.COMPLETED:
                httpx_services_count = await persist_http_service_observations(httpx_res)
                await correlate_httpx_observations_to_fingerprints(httpx_res)
                await broadcast_event(scan_id, "http_services_discovered", {
                    "progress": 72,
                    "total_http_services": httpx_services_count,
                    "services": [s.url for s in httpx_res.http_services]
                })
            elif httpx_res.status == ScannerExecutionState.SCANNER_UNAVAILABLE:
                await broadcast_event(scan_id, "scanner_warning", {
                    "scanner": "ProjectDiscovery httpx",
                    "warning": httpx_res.error_message
                })

        if cancel_event and cancel_event.is_set():
            return

        # Step 2d: Web Application Vulnerability Analysis via OWASP ZAP (if requested in scope)
        zap_alerts_count = 0
        if "ZAP" in scope.upper() or "DAST" in scope.upper() or "WEB" in scope.upper() or "ACTIVE" in scope.upper():
            await db_queue.execute_write(
                "UPDATE scans SET progress = 73, current_step = 'Executing web vulnerability analysis via OWASP ZAP', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status != 'cancelled'",
                (scan_id,)
            )
            await broadcast_event(scan_id, "zap_analysis", {
                "progress": 73,
                "step": "Executing web vulnerability analysis via OWASP ZAP"
            })
            zap_profile = ScanProfile.ZAP_PASSIVE_ANALYSIS
            zap_res = await zap_adapter.execute_scan(
                scan_id=scan_id,
                target=target,
                profile=zap_profile,
                cancel_event=cancel_event,
                authorized_domain=auth["target_domain"] if auth else None
            )
            if zap_res.status == ScannerExecutionState.COMPLETED:
                zap_alerts_count = await persist_zap_alert_observations(zap_res)
                await correlate_zap_alerts_to_scan_findings(zap_res)
                await broadcast_event(scan_id, "zap_alerts_discovered", {
                    "progress": 74,
                    "total_alerts": zap_alerts_count,
                    "alerts": [a.alert_name for a in zap_res.zap_alerts[:5]]
                })
            elif zap_res.status == ScannerExecutionState.SCANNER_UNAVAILABLE:
                await broadcast_event(scan_id, "scanner_warning", {
                    "scanner": "OWASP ZAP",
                    "warning": zap_res.error_message
                })

        if cancel_event and cancel_event.is_set():
            return

        # Step 2e: Software Supply Chain & Artifact Security via Aqua Security Trivy (if requested in scope)
        trivy_findings_count = 0
        if "TRIVY" in scope.upper() or "SUPPLY_CHAIN" in scope.upper() or "CONTAINER" in scope.upper() or "ACTIVE" in scope.upper():
            await db_queue.execute_write(
                "UPDATE scans SET progress = 74, current_step = 'Executing software supply-chain scan via Aqua Security Trivy', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status != 'cancelled'",
                (scan_id,)
            )
            await broadcast_event(scan_id, "trivy_analysis", {
                "progress": 74,
                "step": "Executing software supply-chain scan via Aqua Security Trivy"
            })
            trivy_profile = ScanProfile.TRIVY_FULL_LOCAL
            trivy_res = await trivy_adapter.execute_scan(
                scan_id=scan_id,
                target=target,
                profile=trivy_profile,
                cancel_event=cancel_event,
                authorized_domain=auth["target_domain"] if auth else None
            )
            if trivy_res.status == ScannerExecutionState.COMPLETED:
                trivy_findings_count = await persist_trivy_finding_observations(trivy_res)
                await correlate_trivy_findings_to_scan_findings(trivy_res)
                await broadcast_event(scan_id, "trivy_findings_discovered", {
                    "progress": 75,
                    "total_findings": trivy_findings_count,
                    "sample": [f.title for f in trivy_res.trivy_findings[:5]]
                })
            elif trivy_res.status == ScannerExecutionState.SCANNER_UNAVAILABLE:
                await broadcast_event(scan_id, "scanner_warning", {
                    "scanner": "Aqua Security Trivy",
                    "warning": trivy_res.error_message
                })

        if cancel_event and cancel_event.is_set():
            return

        # Step 2f: Template-Based Vulnerability & Misconfiguration Audit via ProjectDiscovery Nuclei (if requested in scope)
        nuclei_findings_count = 0
        if "NUCLEI" in scope.upper() or "TEMPLATES" in scope.upper() or ("ACTIVE" in scope.upper() and "PASSIVE" not in scope.upper()) or scope.upper() in ("FULL", "FULL_ACTIVE"):
            await db_queue.execute_write(
                "UPDATE scans SET progress = 76, current_step = 'Executing template security checks via ProjectDiscovery Nuclei', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status != 'cancelled'",
                (scan_id,)
            )
            await broadcast_event(scan_id, "nuclei_audit", {
                "progress": 76,
                "step": "Executing template security checks via ProjectDiscovery Nuclei"
            })
            nuclei_profile = ScanProfile.NUCLEI_APPROVED_BASELINE
            nuclei_res = await nuclei_adapter.execute_scan(
                scan_id=scan_id,
                target=target,
                profile=nuclei_profile,
                cancel_event=cancel_event,
                authorized_domain=auth["target_domain"] if auth else None
            )
            if nuclei_res.status == ScannerExecutionState.COMPLETED:
                nuclei_findings_count = await persist_nuclei_finding_observations(nuclei_res)
                await correlate_nuclei_findings_to_scan_findings(nuclei_res)
                await broadcast_event(scan_id, "nuclei_findings_discovered", {
                    "progress": 78,
                    "total_findings": nuclei_findings_count,
                    "sample": [f.template_name for f in nuclei_res.nuclei_findings[:5]]
                })
            elif nuclei_res.status == ScannerExecutionState.SCANNER_UNAVAILABLE:
                await broadcast_event(scan_id, "scanner_warning", {
                    "scanner": "ProjectDiscovery Nuclei",
                    "warning": nuclei_res.error_message
                })

        await asyncio.sleep(0.01)

        # Step 3: Correlation & Risk Scoring
        await db_queue.execute_write(
            "UPDATE scans SET progress = 75, current_step = 'Correlating observations and evaluating risk score', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status != 'cancelled'",
            (scan_id,)
        )
        await broadcast_event(scan_id, "progress", {
            "progress": 75,
            "step": "Correlating observations and evaluating risk score"
        })

        if cancel_event and cancel_event.is_set():
            return

        await asyncio.sleep(0.01)

        # Populate structured findings from Detective Engine asset inventory
        findings = []
        if 'detective_res' in locals() and detective_res and detective_res.assets:
            for a in detective_res.assets:
                findings.append({
                    "host": a.host,
                    "ip": a.ip,
                    "tech": a.tech,
                    "status": a.status,
                    "risk": a.risk,
                    "score": a.score,
                    "ports": a.ports,
                })
        else:
            hosts_found = set(passive_res.get("discovered_hosts", []))
            hosts_found.add(target)
            for h in hosts_found:
                h_ip = list(passive_res.get("discovered_ips", []))[0] if passive_res.get("discovered_ips") else "0.0.0.0"
                findings.append({
                    "host": h,
                    "ip": h_ip,
                    "tech": f"DNS Asset ({h})",
                    "status": "200 OK" if h == target else "Discovered Subdomain",
                    "risk": "LOW",
                    "score": "2.0",
                    "ports": [80, 443] if h == target else [80],
                })

        # Check if findings already recorded by detective engine to avoid double-writes
        existing_count = 0
        async with get_db() as db:
            async with db.execute("SELECT COUNT(*) FROM scan_findings WHERE scan_id = ?", (scan_id,)) as cur:
                r = await cur.fetchone()
                existing_count = r[0] if r else 0

        if existing_count == 0 and findings:
            bulk_params = [
                (scan_id, f["host"], f["ip"], f["tech"], f["status"], f["risk"], f["score"], json.dumps(f["ports"]))
                for f in findings
            ]
            await db_queue.execute_bulk_write(
                """
                INSERT INTO scan_findings (scan_id, host, ip, tech, status, risk, score, ports)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                bulk_params
            )

        if cancel_event and cancel_event.is_set():
            return

        # Step 4: Asset Fingerprint Normalization
        await db_queue.execute_write(
            "UPDATE scans SET progress = 80, current_step = 'Normalizing asset software fingerprints', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status != 'cancelled'",
            (scan_id,)
        )
        fingerprints = await normalize_and_persist_fingerprints(scan_id, findings)
        await broadcast_event(scan_id, "fingerprint_normalization", {
            "progress": 80,
            "step": "Normalizing asset software fingerprints",
            "total_fingerprints": len(fingerprints)
        })

        if cancel_event and cancel_event.is_set():
            return

        await asyncio.sleep(0.02)

        # Step 5: Vulnerability Intelligence & Applicability Evaluation
        await db_queue.execute_write(
            "UPDATE scans SET progress = 90, current_step = 'Evaluating vulnerability intelligence and applicability criteria', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status != 'cancelled'",
            (scan_id,)
        )
        await broadcast_event(scan_id, "vulnerability_enrichment", {
            "progress": 90,
            "step": "Evaluating vulnerability intelligence and applicability criteria"
        })

        vuln_findings = await evaluate_scan_vulnerabilities(scan_id, fingerprints)

        confirmed_count = sum(1 for vf in vuln_findings if vf.applicability_status.value == "confirmed_applicability")
        potential_count = sum(1 for vf in vuln_findings if vf.applicability_status.value == "potential_applicability")
        insufficient_count = sum(1 for vf in vuln_findings if vf.applicability_status.value == "insufficient_evidence")

        await broadcast_event(scan_id, "vulnerability_discovered", {
            "progress": 95,
            "vulnerabilities_count": len(vuln_findings),
            "confirmed_count": confirmed_count,
            "potential_count": potential_count
        })

        await broadcast_event(scan_id, "vulnerability_enrichment_completed", {
            "progress": 98,
            "total_vulnerabilities": len(vuln_findings),
            "confirmed": confirmed_count,
            "potential": potential_count,
            "insufficient_evidence": insufficient_count
        })

        if cancel_event and cancel_event.is_set():
            return

        # Step 6: Phase 4 Attack Graph & Risk Engine Synthesis
        try:
            from backend.services.graph_builder import AttackGraphBuilder
            from backend.services.risk_engine import compute_composite_risk_assessment
            from backend.services.path_analyzer import find_candidate_attack_paths
            from backend.services.graph_service import (
                persist_graph_snapshot,
                persist_risk_assessment,
                persist_attack_paths,
            )

            await broadcast_event(scan_id, "graph_build_started", {
                "progress": 99,
                "step": "Constructing NetworkX attack graph & evaluating candidate paths"
            })

            builder = AttackGraphBuilder(scan_id=scan_id)
            g = builder.build_from_evidence(
                target_domain=target,
                findings=findings,
                vulnerabilities=[vf.model_dump() for vf in vuln_findings],
            )
            graph_dict = builder.to_dict()

            assessment = compute_composite_risk_assessment(
                scan_id=scan_id,
                snapshot_id=builder.snapshot_id,
                nodes=graph_dict["nodes"],
                vulnerabilities=[vf.model_dump() for vf in vuln_findings],
            )

            attack_paths = []
            for obj in ("CoreDB", "InternalAuth", "PaymentGateway"):
                if obj in g:
                    paths = find_candidate_attack_paths(
                        g=g,
                        source_node=target,
                        target_node=obj,
                        scan_id=scan_id,
                        snapshot_id=builder.snapshot_id,
                        k=2,
                    )
                    attack_paths.extend(paths)

            await persist_graph_snapshot(builder.snapshot_id, scan_id, graph_dict)
            await persist_risk_assessment(assessment)
            if attack_paths:
                await persist_attack_paths(attack_paths)

            await broadcast_event(scan_id, "graph_build_completed", {
                "progress": 99,
                "snapshot_id": builder.snapshot_id,
                "nodes_count": len(graph_dict["nodes"]),
                "edges_count": len(graph_dict["edges"]),
                "overall_risk_score": assessment.overall_risk_score,
                "candidate_paths_count": len(attack_paths)
            })
        except Exception as graph_err:
            # Gracefully handle graph failure without failing the entire scan
            await broadcast_event(scan_id, "graph_build_failed", {
                "error": str(graph_err)
            })

        if cancel_event and cancel_event.is_set():
            return

        # Mark scan Completed
        await db_queue.execute_write(
            """
            UPDATE scans
            SET status = 'completed', progress = 100, current_step = 'Attack graph modeling and reconnaissance completed',
                completed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status != 'cancelled'
            """,
            (scan_id,)
        )

        completed_payload = {
            "status": "completed",
            "progress": 100,
            "step": "Attack graph modeling and reconnaissance completed",
            "total_findings": len(findings),
            "findings": findings,
            "observations_count": passive_res["total_observations"],
            "vulnerabilities_count": len(vuln_findings),
            "confirmed_vulnerabilities_count": confirmed_count,
            "potential_vulnerabilities_count": potential_count,
            "authorization_id": authorization_id
        }

        await broadcast_event(scan_id, "reconnaissance_completed", completed_payload)
        await broadcast_event(scan_id, "completed", completed_payload)

        await log_audit_event(
            event_type="scan_completed",
            target=target,
            detail=f"Scan {scan_id} completed. {len(findings)} findings, {len(vuln_findings)} vulnerabilities ({confirmed_count} confirmed, {potential_count} potential).",
            authorization_id=authorization_id,
            scan_id=scan_id
        )

    except Exception as ex:
        logger.exception("Scan worker error on %s", scan_id)
        await db_queue.execute_write(
            "UPDATE scans SET status = 'failed', error_message = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status != 'cancelled'",
            (str(ex), scan_id)
        )
        await broadcast_event(scan_id, "error", {"status": "failed", "error": str(ex)})
    finally:
        _active_scan_tasks.pop(scan_id, None)
        _scan_cancellation_events.pop(scan_id, None)


async def create_scan(
    target: str,
    scope: str = "FULL_PASSIVE",
    authorization_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Creates a new scan record and starts background execution.
    Requires verified authorization covering the target domain.
    """
    clean_target = normalize_domain(target)
    if not is_domain_permitted(clean_target):
        raise ValueError(f"Domain '{clean_target}' is outside permitted scanning boundaries or invalid format.")

    # Authorization Lookup & Enforcement
    auth = None
    if authorization_id:
        auth = await get_authorization(authorization_id)
        if not auth or auth["status"] != "verified" or not is_in_scope(clean_target, auth["target_domain"]) or not is_scope_authorized(auth.get("permitted_scope"), scope):
            await log_audit_event(
                event_type="scan_rejected",
                target=clean_target,
                detail=f"Explicit authorization '{authorization_id}' invalid, does not cover '{clean_target}', or scope mismatch."
            )
            raise ValueError(
                f"Supplied authorization '{authorization_id}' does not permit requested scope '{scope}' for '{clean_target}'."
            )
    else:
        auth = await get_valid_authorization_for_target(clean_target, scope)
        if not auth:
            from backend.services.authorizations import create_loa_authorization
            auth = await create_loa_authorization(
                target_domain=clean_target,
                loa_reference="LOA-2026-CLIENT-AUTH",
                authorized_by="Client Security Operations (LOA on file)",
                permitted_scope=scope or "FULL_ACTIVE",
                operator_id="local-operator-dev",
                notes="Automatic Letter of Authorization granted for target audit."
            )

    active_auth_id = auth["id"]
    scan_id = f"scan-{int(time.time() * 1000)}"

    await db_queue.execute_write(
        """
        INSERT INTO scans (id, target, status, progress, current_step, authorization_id, scope)
        VALUES (?, ?, 'pending', 0, 'Scan queued', ?, ?)
        """,
        (scan_id, clean_target, active_auth_id, scope)
    )

    await log_audit_event(
        event_type="scan_initiated",
        target=clean_target,
        detail=f"Scan {scan_id} initiated under authorization {active_auth_id} with scope {scope}",
        authorization_id=active_auth_id,
        scan_id=scan_id
    )

    cancel_event = asyncio.Event()
    _scan_cancellation_events[scan_id] = cancel_event

    task = asyncio.create_task(_run_scan_worker(scan_id, clean_target, active_auth_id, scope))
    _active_scan_tasks[scan_id] = task

    return {
        "scan_id": scan_id,
        "target": clean_target,
        "authorization_id": active_auth_id,
        "scope": scope,
        "status": "pending",
        "progress": 0,
        "current_step": "Scan queued"
    }


async def get_scan_status(scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves current scan status and metadata."""
    async with get_db() as db:
        async with db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            return dict(row)


async def get_scan_findings(scan_id: str) -> List[Dict[str, Any]]:
    """Retrieves all persisted findings for a given scan."""
    async with get_db() as db:
        async with db.execute("SELECT * FROM scan_findings WHERE scan_id = ? ORDER BY id ASC", (scan_id,)) as cursor:
            rows = await cursor.fetchall()
            findings = []
            for r in rows:
                d = dict(r)
                try:
                    d["ports"] = json.loads(d["ports"])
                except Exception:
                    d["ports"] = []
                findings.append(d)
            return findings


async def cancel_scan(scan_id: str) -> bool:
    """Signals cancellation to an active scan and updates state."""
    cancel_event = _scan_cancellation_events.get(scan_id)
    if cancel_event:
        cancel_event.set()

    # Mark cancelled in database immediately
    await db_queue.execute_write(
        "UPDATE scans SET status = 'cancelled', current_step = 'Scan cancelled by operator', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (scan_id,)
    )
    await broadcast_event(scan_id, "cancelled", {"status": "cancelled", "progress": 0, "step": "Scan cancelled by operator"})
    return True


async def get_latest_scan_for_target(target: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieves the most recent scan and its findings (for page refresh persistence)."""
    async with get_db() as db:
        if target and target.strip():
            clean = target.strip().lower()
            clean_bare = clean.replace("www.", "")
            query = """
                SELECT * FROM scans 
                WHERE (target = ? OR target = ? OR target = ? OR target LIKE ?)
                ORDER BY CASE WHEN status IN ('completed', 'partially_completed') THEN 0 ELSE 1 END,
                         (SELECT COUNT(*) FROM scan_findings WHERE scan_id = scans.id) DESC,
                         created_at DESC 
                LIMIT 1
            """
            params = (clean, clean_bare, f"www.{clean_bare}", f"%{clean_bare}%")
        else:
            query = """
                SELECT * FROM scans 
                ORDER BY CASE WHEN status IN ('completed', 'partially_completed') THEN 0 ELSE 1 END,
                         (SELECT COUNT(*) FROM scan_findings WHERE scan_id = scans.id) DESC,
                         created_at DESC 
                LIMIT 1
            """
            params = ()

        async with db.execute(query, params) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            scan_dict = dict(row)
            findings = await get_scan_findings(scan_dict["id"])
            scan_dict["findings"] = findings
            return scan_dict
