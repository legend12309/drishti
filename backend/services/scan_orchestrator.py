"""
DRISHTI — Phase 11 Unified Scan Orchestrator Engine
Coordinates multi-stage scanning workflows across all registered scanner adapters:
1. Target & authorization pre-flight validation.
2. Dependency-aware execution scheduling (Discovery -> Web -> In-Depth Vulnerabilities).
3. Concurrency bounding and per-scanner resource controls.
4. Stage lifecycle tracking (Queued -> Running -> Completed/Failed/Skipped/Blocked).
5. Safe cancellation propagation and child subprocess cleanup.
6. Unified result aggregation, deduplication, and risk engine synthesis.
7. Real-time SSE event distribution.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.db.database import get_db, db_queue
from backend.services.authorizations import (
    get_authorization,
    get_valid_authorization_for_target,
    log_audit_event,
)
from backend.services.scope import normalize_domain, is_in_scope, is_sandbox_target, is_scope_authorized
from backend.services.scanner_foundation import (
    ScanProfile,
    ScannerExecutionState,
    ScannerResult,
)
from backend.services.scanner_registry import scanner_registry, TargetType
from backend.services.orchestrator_models import (
    CreateUnifiedScanPlanRequest,
    WorkflowExecutionState,
    StageExecutionState,
    ScannerStageSummary,
    UnifiedWorkflowStatusResponse,
)
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
from backend.services.vulnerability_service import evaluate_scan_vulnerabilities

logger = logging.getLogger("drishti.orchestrator")

# Global Concurrency Limit: max 3 concurrent active workflows across the platform
GLOBAL_WORKFLOW_SEMAPHORE = asyncio.Semaphore(3)

# Active workflow tracking
_active_workflows: Dict[str, asyncio.Task] = {}
_workflow_cancellations: Dict[str, asyncio.Event] = {}
_workflow_subscribers: Dict[str, Set[asyncio.Queue]] = {}


async def register_workflow_subscriber(workflow_id: str) -> asyncio.Queue:
    if workflow_id not in _workflow_subscribers:
        _workflow_subscribers[workflow_id] = set()
    q: asyncio.Queue = asyncio.Queue()
    _workflow_subscribers[workflow_id].add(q)
    return q


def unregister_workflow_subscriber(workflow_id: str, q: asyncio.Queue):
    if workflow_id in _workflow_subscribers:
        _workflow_subscribers[workflow_id].discard(q)
        if not _workflow_subscribers[workflow_id]:
            del _workflow_subscribers[workflow_id]


async def broadcast_workflow_event(workflow_id: str, event_type: str, data: Dict[str, Any]):
    if workflow_id in _workflow_subscribers:
        payload = {"type": event_type, "data": data, "timestamp": datetime.now(timezone.utc).isoformat()}
        for q in list(_workflow_subscribers[workflow_id]):
            await q.put(payload)


class UnifiedScanOrchestrator:
    """Coordinates multi-engine security assessments with dependency awareness and lifecycle controls."""

    def __init__(self):
        self.registry = scanner_registry

    def validate_plan(
        self, plan: CreateUnifiedScanPlanRequest, authorized_domain: Optional[str] = None
    ) -> Tuple[bool, List[str]]:
        """
        Validates target format, requested scanner modules, and stage configs.
        Returns (is_valid, validation_errors).
        """
        errors = []
        if not plan.target or not plan.target.strip():
            return False, ["Target cannot be empty."]

        try:
            clean_target = normalize_domain(plan.target)
        except Exception as e:
            return False, [f"Invalid target domain: {str(e)}"]

        if authorized_domain and not is_in_scope(clean_target, authorized_domain):
            errors.append(f"Target '{clean_target}' is outside authorized domain boundary '{authorized_domain}'.")

        # Validate scanner names
        valid_scanners, scanner_errs = self.registry.validate_plan_scanners(plan.scanners)
        if not valid_scanners:
            errors.extend(scanner_errs)

        return len(errors) == 0, errors

    async def create_workflow(
        self,
        plan: CreateUnifiedScanPlanRequest,
        operator_id: str = "local-operator-dev"
    ) -> Dict[str, Any]:
        """
        Validates authorizations, registers initial scan records and stage slots,
        and launches the asynchronous orchestration task.
        """
        clean_target = normalize_domain(plan.target)

        # Authorization Enforcement
        auth = None
        if plan.authorization_id:
            auth = await get_authorization(plan.authorization_id)
            if not auth or auth["status"] != "verified" or not is_in_scope(clean_target, auth["target_domain"]) or not is_scope_authorized(auth.get("permitted_scope"), plan.scope):
                raise ValueError(
                    f"Supplied authorization '{plan.authorization_id}' (scope: {auth.get('permitted_scope') if auth else 'none'}) does not permit requested scope '{plan.scope}' for '{clean_target}'."
                )
        else:
            auth = await get_valid_authorization_for_target(clean_target, scope=plan.scope)
            if not auth:
                raise ValueError(
                    f"Target '{clean_target}' is not authorized for '{plan.scope}'. Please complete DNS TXT verification challenge first."
                )

        # Validate Plan against Authorization
        is_valid, errors = self.validate_plan(plan, auth["target_domain"])
        if not is_valid:
            raise ValueError(f"Plan validation rejected: {'; '.join(errors)}")

        workflow_id = f"wf-{int(time.time())}-{clean_target.replace('.', '-')[:16]}"
        cancel_event = asyncio.Event()
        _workflow_cancellations[workflow_id] = cancel_event

        # Normalized requested scanners
        requested_scanners = [s.strip().lower() for s in plan.scanners]

        # Tier 2 Frictionless OSINT: If scope is PASSIVE_OSINT, restrict scanners to non-intrusive modules only
        if plan.scope == "PASSIVE_OSINT":
            # Exclude active port/exploit scanners (nmap, zap) if accidentally included
            requested_scanners = [s for s in requested_scanners if s not in ("nmap", "zap")]
            if not requested_scanners:
                requested_scanners = ["httpx", "trivy"]

        # Initialize parent scan row in PostgreSQL / SQLite
        await db_queue.execute_write(
            """
            INSERT INTO scans (
                id, target, status, progress, current_step, authorization_id, scope,
                requested_scanners, created_at, updated_at
            ) VALUES (?, ?, 'queued', 0, 'Initializing workflow stages', ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (
                workflow_id,
                clean_target,
                auth["id"],
                plan.scope or "FULL_ACTIVE",
                json.dumps(requested_scanners),
            )
        )

        # Initialize per-scanner stage records
        for sid in requested_scanners:
            adapter = self.registry.get_adapter(sid)
            sname = adapter.scanner_name if adapter else sid.upper()
            await db_queue.execute_write(
                """
                INSERT INTO scan_stages (
                    scan_id, scanner_name, stage_name, status, progress, created_at
                ) VALUES (?, ?, ?, 'queued', 0, CURRENT_TIMESTAMP)
                """,
                (workflow_id, sname, sid)
            )

        # Launch background orchestrator worker
        task = asyncio.create_task(
            self._execute_workflow_pipeline(
                workflow_id=workflow_id,
                target=clean_target,
                plan=plan,
                auth=auth,
                cancel_event=cancel_event,
            )
        )
        _active_workflows[workflow_id] = task

        await log_audit_event(
            event_type="workflow_created",
            target=clean_target,
            detail=f"Unified workflow {workflow_id} created with modules: {', '.join(requested_scanners)}",
            authorization_id=auth["id"],
            scan_id=workflow_id
        )

        return {
            "status": "success",
            "workflow_id": workflow_id,
            "target": clean_target,
            "requested_scanners": requested_scanners,
            "overall_status": WorkflowExecutionState.QUEUED.value,
        }

    async def cancel_workflow(self, workflow_id: str) -> bool:
        """Cancels a running multi-stage workflow and aborts active subprocesses."""
        cancel_evt = _workflow_cancellations.get(workflow_id)
        if cancel_evt:
            cancel_evt.set()

        task = _active_workflows.get(workflow_id)
        if task and not task.done():
            task.cancel()

        await db_queue.execute_write(
            """
            UPDATE scans
            SET status = 'cancelled', current_step = 'Workflow cancelled by operator', updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status NOT IN ('completed', 'failed')
            """,
            (workflow_id,)
        )

        await db_queue.execute_write(
            """
            UPDATE scan_stages
            SET status = 'cancelled', error_message = 'Cancelled by operator', completed_at = CURRENT_TIMESTAMP
            WHERE scan_id = ? AND status IN ('queued', 'running', 'validating')
            """,
            (workflow_id,)
        )

        await broadcast_workflow_event(workflow_id, "workflow_cancelled", {"workflow_id": workflow_id})
        return True

    async def _execute_workflow_pipeline(
        self,
        workflow_id: str,
        target: str,
        plan: CreateUnifiedScanPlanRequest,
        auth: Dict[str, Any],
        cancel_event: asyncio.Event,
    ):
        """Asynchronous execution pipeline with bounded concurrency, stage tracking, and error handling.
        
        Strict sequential execution:
        1. DNS TXT Authorization validation
        2. Domain-to-IP resolution and scope validation
        3. Nmap (-Pn -A -T2)
        4. OWASP ZAP
        5. Nuclei
        6. SQL Security Assessment (if configured)
        7. Trivy (if eligible target exists)
        """
        start_time = time.time()
        stage_results: Dict[str, Any] = {}
        stage_status_map: Dict[str, StageExecutionState] = {}
        total_findings = 0
        resolved_ips: List[str] = []

        async with GLOBAL_WORKFLOW_SEMAPHORE:
            try:
                # Mark Workflow Running
                await db_queue.execute_write(
                    "UPDATE scans SET status = 'running', progress = 5, current_step = 'Validating authorization and resolving target', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (workflow_id,)
                )
                await broadcast_workflow_event(workflow_id, "workflow_started", {"workflow_id": workflow_id, "progress": 5})

                # Step 1: Domain-to-IP Resolution and Scope Validation
                await db_queue.execute_write(
                    "UPDATE scans SET progress = 10, current_step = 'Resolving domain to authorized IP addresses', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (workflow_id,)
                )
                await broadcast_workflow_event(workflow_id, "stage_started", {
                    "scanner": "resolution",
                    "step": "Resolving domain to authorized IP addresses"
                })
                
                resolved_ips = await self._resolve_and_validate_target(target, auth["target_domain"], cancel_event)
                if not resolved_ips:
                    stage_status_map["resolution"] = StageExecutionState.FAILED
                    await self._record_stage_completion(
                        workflow_id=workflow_id,
                        scanner_id="resolution",
                        scanner_name="Domain Resolution",
                        status=StageExecutionState.FAILED,
                        duration=0.0,
                        findings=0,
                        err="No valid authorized IP addresses found for target",
                    )
                    await db_queue.execute_write(
                        "UPDATE scans SET status = 'failed', error_message = 'No valid authorized IP addresses found for target', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                        (workflow_id,)
                    )
                    return
                
                stage_status_map["resolution"] = StageExecutionState.COMPLETED
                await broadcast_workflow_event(workflow_id, "stage_completed", {
                    "scanner": "resolution",
                    "step": "Domain resolution completed",
                    "resolved_ips": resolved_ips
                })

                # Strict Sequential Pipeline: Nmap -> HTTPX -> ZAP -> Nuclei -> SQL -> Trivy
                # Each stage runs only after the previous reaches a terminal state
                # HTTPX must run before ZAP and Nuclei (dependency declared in registry)
                execution_sequence = [
                    ("nmap", ScanProfile.BASIC_PORT_DISCOVERY, "Nmap Port & Service Discovery"),
                    ("httpx", ScanProfile.SERVICE_METADATA_ENRICHMENT, "HTTPX Service Discovery"),
                    ("zap", ScanProfile.ZAP_BASELINE_AUDIT, "OWASP ZAP Web Application Scan"),
                    ("nuclei", ScanProfile.NUCLEI_APPROVED_BASELINE, "Nuclei Template-Based Vulnerability Scan"),
                    ("sql", ScanProfile.CUSTOM_APPROVED, "SQL Security Assessment"),
                    ("trivy", ScanProfile.TRIVY_FULL_LOCAL, "Trivy Supply Chain & Artifact Scan"),
                ]
                
                # Filter to only requested scanners that are available
                requested = [s.lower() for s in plan.scanners]
                active_modules = []
                for sid, profile, display_name in execution_sequence:
                    if sid in requested or (sid == "sql" and plan.scope == "FULL_ACTIVE"):
                        adapter = self.registry.get_adapter(sid)
                        if adapter:
                            cap = self.registry.get_capability(sid)
                            if cap and cap.is_available:
                                active_modules.append((sid, profile, display_name))
                            else:
                                # Mark as SKIPPED if not available
                                stage_status_map[sid] = StageExecutionState.SKIPPED
                                await self._record_stage_completion(
                                    workflow_id=workflow_id,
                                    scanner_id=sid,
                                    scanner_name=sid.upper(),
                                    status=StageExecutionState.SKIPPED,
                                    duration=0.0,
                                    findings=0,
                                    err=f"Scanner {sid} not available",
                                )
                                await broadcast_workflow_event(workflow_id, "stage_skipped", {
                                    "scanner": sid,
                                    "reason": cap.error_message if cap else "Scanner unavailable"
                                })
                        else:
                            stage_status_map[sid] = StageExecutionState.SKIPPED
                            await self._record_stage_completion(
                                workflow_id=workflow_id,
                                scanner_id=sid,
                                scanner_name=sid.upper(),
                                status=StageExecutionState.SKIPPED,
                                duration=0.0,
                                findings=0,
                                err=f"Adapter {sid} not found",
                            )

                total_stages = len(active_modules)
                progress_per_stage = 75 // max(total_stages, 1) if total_stages > 0 else 0
                current_overall_progress = 15

                for idx, (sid, profile, display_name) in enumerate(active_modules):
                    if cancel_event.is_set():
                        break

                    adapter = self.registry.get_adapter(sid)
                    sname = adapter.scanner_name if adapter else sid.upper()

                    # Check Dependency Constraint - ensure previous stage completed
                    if idx > 0:
                        prev_sid = active_modules[idx - 1][0]
                        if stage_status_map.get(prev_sid) == StageExecutionState.FAILED:
                            stage_status_map[sid] = StageExecutionState.BLOCKED
                            await self._record_stage_completion(
                                workflow_id=workflow_id,
                                scanner_id=sid,
                                scanner_name=sname,
                                status=StageExecutionState.BLOCKED,
                                duration=0.0,
                                findings=0,
                                err=f"Previous stage '{prev_sid}' failed; blocking this stage.",
                            )
                            await broadcast_workflow_event(workflow_id, "stage_blocked", {
                                "scanner": sid,
                                "prerequisite": prev_sid
                            })
                            continue

                    # Special handling for Trivy - check target eligibility before running
                    if sid == "trivy":
                        target_eligible = await self._check_trivy_eligibility(target, resolved_ips, plan)
                        if not target_eligible[0]:
                            stage_status_map[sid] = StageExecutionState.NOT_APPLICABLE
                            await self._record_stage_completion(
                                workflow_id=workflow_id,
                                scanner_id=sid,
                                scanner_name=sname,
                                status=StageExecutionState.NOT_APPLICABLE,
                                duration=0.0,
                                findings=0,
                                err=target_eligible[1],
                            )
                            await broadcast_workflow_event(workflow_id, "stage_skipped", {
                                "scanner": sid,
                                "reason": target_eligible[1]
                            })
                            continue

                    # Execute Stage
                    stage_start = time.time()
                    await self._record_stage_started(workflow_id, sid, sname)
                    await broadcast_workflow_event(workflow_id, "stage_started", {"scanner": sid, "scanner_name": sname, "step": display_name})

                    try:
                        res: ScannerResult = await self._run_single_stage(
                            scanner_id=sid,
                            adapter=adapter,
                            workflow_id=workflow_id,
                            target=target,
                            plan=plan,
                            auth_domain=auth["target_domain"],
                            cancel_event=cancel_event,
                            resolved_ips=resolved_ips,  # Pass resolved IPs for Nmap
                        )
                        stage_duration = round(time.time() - stage_start, 2)

                        if res.status == ScannerExecutionState.COMPLETED:
                            findings_count = await self._persist_and_correlate_results(sid, res)
                            total_findings += findings_count
                            stage_status_map[sid] = StageExecutionState.COMPLETED
                            await self._record_stage_completion(
                                workflow_id=workflow_id,
                                scanner_id=sid,
                                scanner_name=sname,
                                status=StageExecutionState.COMPLETED,
                                duration=stage_duration,
                                findings=findings_count,
                            )
                            await broadcast_workflow_event(workflow_id, "stage_completed", {
                                "scanner": sid,
                                "findings_count": findings_count,
                                "duration_seconds": stage_duration
                            })
                        elif res.status == ScannerExecutionState.CANCELLED:
                            stage_status_map[sid] = StageExecutionState.CANCELLED
                            await self._record_stage_completion(
                                workflow_id=workflow_id,
                                scanner_id=sid,
                                scanner_name=sname,
                                status=StageExecutionState.CANCELLED,
                                duration=stage_duration,
                                findings=0,
                                err="Operator cancelled execution",
                            )
                            break
                        elif res.status == ScannerExecutionState.SKIPPED:
                            stage_status_map[sid] = StageExecutionState.SKIPPED
                            await self._record_stage_completion(
                                workflow_id=workflow_id,
                                scanner_id=sid,
                                scanner_name=sname,
                                status=StageExecutionState.SKIPPED,
                                duration=stage_duration,
                                findings=0,
                                err=res.error_message,
                            )
                            await broadcast_workflow_event(workflow_id, "stage_skipped", {
                                "scanner": sid,
                                "reason": res.error_message
                            })
                        elif res.status == ScannerExecutionState.NOT_APPLICABLE:
                            stage_status_map[sid] = StageExecutionState.NOT_APPLICABLE
                            await self._record_stage_completion(
                                workflow_id=workflow_id,
                                scanner_id=sid,
                                scanner_name=sname,
                                status=StageExecutionState.NOT_APPLICABLE,
                                duration=stage_duration,
                                findings=0,
                                err=res.error_message,
                            )
                            await broadcast_workflow_event(workflow_id, "stage_skipped", {
                                "scanner": sid,
                                "reason": res.error_message
                            })
                        else:
                            stage_status_map[sid] = StageExecutionState.FAILED
                            await self._record_stage_completion(
                                workflow_id=workflow_id,
                                scanner_id=sid,
                                scanner_name=sname,
                                status=StageExecutionState.FAILED,
                                duration=stage_duration,
                                findings=0,
                                err=res.error_message,
                            )
                            await broadcast_workflow_event(workflow_id, "stage_failed", {
                                "scanner": sid,
                                "error": res.error_message
                            })
                            if not plan.allow_partial_completion:
                                break

                    except Exception as stage_ex:
                        stage_duration = round(time.time() - stage_start, 2)
                        stage_status_map[sid] = StageExecutionState.FAILED
                        await self._record_stage_completion(
                            workflow_id=workflow_id,
                            scanner_id=sid,
                            scanner_name=sname,
                            status=StageExecutionState.FAILED,
                            duration=stage_duration,
                            findings=0,
                            err=str(stage_ex),
                        )
                        if not plan.allow_partial_completion:
                            break

                    current_overall_progress = min(current_overall_progress + progress_per_stage, 90)
                    await db_queue.execute_write(
                        "UPDATE scans SET progress = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                        (current_overall_progress, workflow_id)
                    )

                if cancel_event.is_set():
                    await db_queue.execute_write(
                        "UPDATE scans SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                        (workflow_id,)
                    )
                    return

                # Terminal State Evaluation
                completed_count = sum(1 for st in stage_status_map.values() if st == StageExecutionState.COMPLETED)
                failed_count = sum(1 for st in stage_status_map.values() if st == StageExecutionState.FAILED)
                # Only count skipped/not_applicable for stages that were actually requested (in active_modules)
                active_module_ids = {sid for sid, _, _ in active_modules}
                skipped_count = sum(
                    1 for sid, st in stage_status_map.items()
                    if st in (StageExecutionState.SKIPPED, StageExecutionState.NOT_APPLICABLE) and sid in active_module_ids
                )

                if completed_count == len(active_modules) and len(active_modules) > 0:
                    final_state = WorkflowExecutionState.COMPLETED
                elif completed_count > 0 and (failed_count > 0 or skipped_count > 0):
                    final_state = WorkflowExecutionState.PARTIALLY_COMPLETED
                elif failed_count > 0 and completed_count == 0:
                    final_state = WorkflowExecutionState.FAILED
                else:
                    final_state = WorkflowExecutionState.COMPLETED

                # Correlate findings, normalize fingerprints, evaluate vulnerabilities, and build attack graph
                try:
                    from backend.services.scanner import get_scan_findings
                    from backend.services.vulnerability_service import (
                        normalize_and_persist_fingerprints,
                        evaluate_scan_vulnerabilities,
                    )
                    from backend.services.graph_builder import AttackGraphBuilder
                    from backend.services.risk_engine import compute_composite_risk_assessment
                    from backend.services.path_analyzer import find_candidate_attack_paths
                    from backend.services.graph_service import (
                        persist_graph_snapshot,
                        persist_risk_assessment,
                        persist_attack_paths,
                    )

                    all_findings = await get_scan_findings(workflow_id)
                    if all_findings:
                        fingerprints = await normalize_and_persist_fingerprints(workflow_id, all_findings)
                        vuln_findings = await evaluate_scan_vulnerabilities(workflow_id, fingerprints)
                        
                        builder = AttackGraphBuilder(scan_id=workflow_id)
                        g = builder.build_from_evidence(
                            target_domain=target,
                            findings=all_findings,
                            vulnerabilities=[vf.model_dump() for vf in vuln_findings],
                        )
                        graph_dict = builder.to_dict()
                        assessment = compute_composite_risk_assessment(
                            scan_id=workflow_id,
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
                                    scan_id=workflow_id,
                                    snapshot_id=builder.snapshot_id,
                                    k=2,
                                )
                                attack_paths.extend(paths)

                        await persist_graph_snapshot(builder.snapshot_id, workflow_id, graph_dict)
                        await persist_risk_assessment(assessment)
                        if attack_paths:
                            await persist_attack_paths(attack_paths)
                except Exception as enrich_ex:
                    logger.warning(f"Workflow enrichment note on {workflow_id}: {enrich_ex}")

                total_duration = round(time.time() - start_time, 2)

                await db_queue.execute_write(
                    """
                    UPDATE scans
                    SET status = ?, progress = 100, current_step = 'Workflow orchestration finalized',
                        completed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ? AND status != 'cancelled'
                    """,
                    (final_state.value, workflow_id)
                )

                await broadcast_workflow_event(workflow_id, "workflow_completed", {
                    "workflow_id": workflow_id,
                    "status": final_state.value,
                    "total_findings": total_findings,
                    "duration_seconds": total_duration,
                })

                await log_audit_event(
                    event_type="workflow_completed",
                    target=target,
                    detail=f"Unified workflow {workflow_id} finished ({final_state.value}). {completed_count} completed, {failed_count} failed, {total_findings} findings.",
                    authorization_id=auth["id"],
                    scan_id=workflow_id
                )

            except Exception as e:
                logger.exception("Workflow pipeline error on %s", workflow_id)
                await db_queue.execute_write(
                    "UPDATE scans SET status = 'failed', error_message = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (str(e), workflow_id)
                )
                await broadcast_workflow_event(workflow_id, "workflow_failed", {"error": str(e)})
            finally:
                _active_workflows.pop(workflow_id, None)
                _workflow_cancellations.pop(workflow_id, None)

    async def _run_single_stage(
        self,
        scanner_id: str,
        adapter: Any,
        workflow_id: str,
        target: str,
        plan: CreateUnifiedScanPlanRequest,
        auth_domain: str,
        cancel_event: asyncio.Event,
        resolved_ips: Optional[List[str]] = None,
    ) -> ScannerResult:
        """Invokes a specific adapter with safe parameters."""
        stage_cfg = plan.stage_configs.get(scanner_id) if plan.stage_configs else None
        
        # Use scanner capability default timeout if not explicitly configured
        cap = self.registry.get_capability(scanner_id)
        default_timeout = cap.timeout_default_seconds if cap and cap.timeout_default_seconds else 120
        timeout = stage_cfg.timeout_seconds if stage_cfg and stage_cfg.timeout_seconds else default_timeout

        if scanner_id == "nmap":
            return await adapter.execute_scan(
                scan_id=workflow_id,
                target=target,
                profile=ScanProfile.BASIC_PORT_DISCOVERY,
                timeout_seconds=timeout,
                cancel_event=cancel_event,
                authorized_domain=auth_domain,
                resolved_ips=resolved_ips,
            )
        elif scanner_id == "httpx":
            return await adapter.execute_scan(
                scan_id=workflow_id,
                target=target,
                profile=ScanProfile.SERVICE_METADATA_ENRICHMENT,
                timeout_seconds=timeout,
                cancel_event=cancel_event,
                authorized_domain=auth_domain,
            )
        elif scanner_id == "zap":
            return await adapter.execute_scan(
                scan_id=workflow_id,
                target=target,
                profile=ScanProfile.ZAP_BASELINE_AUDIT,
                timeout_seconds=timeout,
                cancel_event=cancel_event,
                authorized_domain=auth_domain,
            )
        elif scanner_id == "trivy":
            return await adapter.execute_scan(
                scan_id=workflow_id,
                target=target,
                profile=ScanProfile.TRIVY_FULL_LOCAL,
                timeout_seconds=timeout,
                cancel_event=cancel_event,
                authorized_domain=auth_domain,
            )
        elif scanner_id == "nuclei":
            custom_tags = stage_cfg.custom_tags if stage_cfg else None
            custom_sev = stage_cfg.custom_severity if stage_cfg else None
            return await adapter.execute_scan(
                scan_id=workflow_id,
                target=target,
                profile=ScanProfile.NUCLEI_APPROVED_BASELINE,
                timeout_seconds=timeout,
                cancel_event=cancel_event,
                authorized_domain=auth_domain,
                custom_tags=custom_tags,
                custom_severity=custom_sev,
            )
        elif scanner_id == "sql":
            # SQL Security Assessment - placeholder for future implementation
            return ScannerResult(
                scan_id=workflow_id,
                target=target,
                scanner_name=adapter.scanner_name if adapter else "SQL Assessment",
                scanner_version="0.x",
                profile=ScanProfile.CUSTOM_APPROVED,
                status=ScannerExecutionState.NOT_APPLICABLE,
                error_message="SQL security assessment not configured. Requires explicit authorized web application endpoint or database target configuration.",
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
            )
        else:
            raise ValueError(f"Unsupported scanner engine ID: {scanner_id}")

    async def _resolve_and_validate_target(self, target: str, authorized_domain: str, cancel_event: asyncio.Event) -> List[str]:
        """Resolve domain to IP addresses and validate against authorized scope."""
        from backend.services.scope import normalize_domain, is_in_scope, validate_destination_ip
        import socket
        
        if cancel_event.is_set():
            return []
        
        try:
            norm_target = normalize_domain(target)
        except ValueError as val_err:
            logger.error(f"Invalid target format: {val_err}")
            return []
        
        # Check scope
        if not is_in_scope(norm_target, authorized_domain):
            logger.error(f"Target '{norm_target}' is outside authorized scope '{authorized_domain}'")
            return []
        
        # Resolve A and AAAA records non-blockingly with timeout
        resolved_ips = []
        for record_type in [socket.AF_INET, socket.AF_INET6]:
            try:
                infos = await asyncio.wait_for(
                    asyncio.to_thread(socket.getaddrinfo, norm_target, None, record_type),
                    timeout=4.0
                )
                for info in infos:
                    ip = info[4][0]
                    # Validate against SSRF protection only
                    # Domain scope validation applies to domain names, not IP addresses
                    is_valid, ip_err = validate_destination_ip(ip)
                    if is_valid:
                        if ip not in resolved_ips:
                            resolved_ips.append(ip)
                    else:
                        logger.warning(f"Resolved IP {ip} failed SSRF validation: {ip_err}")
            except (socket.gaierror, asyncio.TimeoutError, Exception) as e:
                logger.warning(f"DNS resolution failed or timed out for {norm_target}: {e}")
        
        return resolved_ips

    async def _check_trivy_eligibility(self, target: str, resolved_ips: List[str], plan: CreateUnifiedScanPlanRequest) -> Tuple[bool, str]:
        """Check if Trivy has a compatible target (filesystem, image, or repository)."""
        from backend.services.trivy_adapter import trivy_adapter
        from backend.services.scanner_foundation import ScanProfile
        
        # For website-only targets, Trivy is not applicable
        # Check if there's an explicit filesystem or image target configured in the plan
        trivy_config = plan.stage_configs.get("trivy") if plan.stage_configs else None
        
        if trivy_config and trivy_config.target:
            # Explicit Trivy target provided
            target_resource = trivy_config.target
            profile = trivy_config.profile if hasattr(trivy_config, 'profile') else ScanProfile.TRIVY_FULL_LOCAL
            
            # Validate the target resource
            is_valid, safe_target, val_err = trivy_adapter.validate_target_resource(target_resource, profile)
            if is_valid:
                return True, ""
            else:
                return False, f"Trivy target validation failed: {val_err}"
        
        # No explicit Trivy target - check if target is filesystem path or image
        is_fs_target = target.startswith("/") or target.startswith("./") or target.startswith("C:\\") or target.startswith("C:/")
        
        is_image_target = False
        if not target.startswith("http") and not target.startswith("https"):
            if ":" in target and not target.endswith((".com", ".net", ".org", ".io", ".dev", ".app", ".co")):
                parts = target.split(":", 1)
                if len(parts) == 2 and parts[1].strip():
                    is_image_target = True
        
        if is_fs_target or is_image_target:
            return True, ""

        # Web domain targets are audited by Trivy for client-side / frontend software supply chain dependencies
        return True, ""

    async def _persist_and_correlate_results(self, scanner_id: str, res: ScannerResult) -> int:
        """Persists stage findings to database and correlates into unified finding index."""
        if scanner_id == "nmap":
            await persist_active_port_observations(res)
            return await correlate_nmap_observations_to_fingerprints(res)
        elif scanner_id == "httpx":
            await persist_http_service_observations(res)
            return await correlate_httpx_observations_to_fingerprints(res)
        elif scanner_id == "zap":
            await persist_zap_alert_observations(res)
            return await correlate_zap_alerts_to_scan_findings(res)
        elif scanner_id == "trivy":
            await persist_trivy_finding_observations(res)
            return await correlate_trivy_findings_to_scan_findings(res)
        elif scanner_id == "nuclei":
            await persist_nuclei_finding_observations(res)
            return await correlate_nuclei_findings_to_scan_findings(res)
        return 0

    async def _record_stage_started(self, workflow_id: str, sid: str, sname: str):
        await db_queue.execute_write(
            """
            UPDATE scan_stages
            SET status = 'running', started_at = CURRENT_TIMESTAMP, progress = 10
            WHERE scan_id = ? AND stage_name = ?
            """,
            (workflow_id, sid)
        )

    async def _record_stage_completion(
        self,
        workflow_id: str,
        scanner_id: str,
        scanner_name: str,
        status: StageExecutionState,
        duration: float,
        findings: int,
        err: Optional[str] = None
    ):
        await db_queue.execute_write(
            """
            UPDATE scan_stages
            SET status = ?, duration_seconds = ?, findings_count = ?, error_message = ?,
                completed_at = CURRENT_TIMESTAMP, progress = 100
            WHERE scan_id = ? AND stage_name = ?
            """,
            (status.value, duration, findings, err, workflow_id, scanner_id)
        )

    async def get_workflow_status(self, workflow_id: str) -> Optional[UnifiedWorkflowStatusResponse]:
        """Retrieves complete workflow state including all individual stage records."""
        async with get_db() as db:
            async with db.execute("SELECT * FROM scans WHERE id = ?", (workflow_id,)) as cursor:
                scan_row = await cursor.fetchone()
                if not scan_row:
                    return None

                scan = dict(scan_row)
                requested_scanners = json.loads(scan.get("requested_scanners") or "[]")

            async with db.execute(
                "SELECT * FROM scan_stages WHERE scan_id = ? ORDER BY id ASC",
                (workflow_id,)
            ) as s_cursor:
                stage_rows = await s_cursor.fetchall()
                stages = [
                    ScannerStageSummary(
                        stage_name=r["stage_name"],
                        scanner_name=r["scanner_name"],
                        status=StageExecutionState(r["status"]),
                        progress=r["progress"] or 0,
                        duration_seconds=float(r["duration_seconds"] or 0.0),
                        findings_count=r["findings_count"] or 0,
                        started_at=str(r["started_at"]) if r["started_at"] else None,
                        completed_at=str(r["completed_at"]) if r["completed_at"] else None,
                        error_message=r["error_message"],
                    )
                    for r in stage_rows
                ]

            total_findings = sum(s.findings_count for s in stages)

            return UnifiedWorkflowStatusResponse(
                workflow_id=scan["id"],
                target=scan["target"],
                overall_status=WorkflowExecutionState(scan["status"]),
                progress=scan["progress"] or 0,
                current_step=scan["current_step"] or "",
                requested_scanners=requested_scanners,
                stages=stages,
                total_findings=total_findings,
                overall_risk_score=float(scan.get("overall_risk_score") or 0.0),
                started_at=str(scan["created_at"]),
                completed_at=str(scan["completed_at"]) if scan["completed_at"] else None,
                error_summary=scan.get("error_message"),
            )


# Global singleton instance
scan_orchestrator = UnifiedScanOrchestrator()
