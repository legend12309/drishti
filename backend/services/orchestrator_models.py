"""
DRISHTI — Phase 11 Unified Scan Plan & Stage Data Contracts
Pydantic schemas and dataclasses defining the multi-scanner plan,
dependency rules, and per-scanner execution stage status.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class WorkflowExecutionState(str, Enum):
    QUEUED = "queued"
    VALIDATING = "validating"
    RUNNING = "running"
    PARTIALLY_COMPLETED = "partially_completed"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class StageExecutionState(str, Enum):
    QUEUED = "queued"
    VALIDATING = "validating"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    NOT_APPLICABLE = "not_applicable"


class ScannerStageConfig(BaseModel):
    profile: Optional[str] = Field(None, description="Specific ScanProfile override (e.g. NUCLEI_KNOWN_VULNS)")
    timeout_seconds: Optional[int] = Field(120, ge=10, le=600, description="Stage timeout in seconds")
    custom_tags: Optional[List[str]] = Field(None, description="Template tags for Nuclei")
    custom_severity: Optional[List[str]] = Field(None, description="Severity filters")


class CreateUnifiedScanPlanRequest(BaseModel):
    target: str = Field(..., description="Target domain, URL, or asset identifier (e.g. company.com)")
    scanners: List[str] = Field(
        default=["nmap", "httpx", "zap", "trivy", "nuclei"],
        description="Ordered list of scanner modules to orchestrate (nmap, httpx, zap, trivy, nuclei)"
    )
    scope: Optional[str] = Field("FULL_ACTIVE", description="Permitted scope boundary (e.g. FULL_ACTIVE, FULL_PASSIVE)")
    authorization_id: Optional[str] = Field(None, description="Verified domain authorization ID")
    stage_configs: Optional[Dict[str, ScannerStageConfig]] = Field(
        default_factory=dict,
        description="Per-scanner execution configurations"
    )
    allow_partial_completion: bool = Field(
        True,
        description="If True, independent stages continue even if a peer scanner fails or is unavailable"
    )
    global_timeout_seconds: int = Field(
        300, ge=30, le=1800,
        description="Overall workflow timeout in seconds"
    )


class ScannerStageSummary(BaseModel):
    stage_name: str
    scanner_name: str
    status: StageExecutionState
    progress: int = 0
    duration_seconds: float = 0.0
    findings_count: int = 0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    raw_output: Optional[str] = None


class UnifiedWorkflowStatusResponse(BaseModel):
    workflow_id: str
    target: str
    overall_status: WorkflowExecutionState
    progress: int
    current_step: str
    requested_scanners: List[str]
    stages: List[ScannerStageSummary]
    total_findings: int
    overall_risk_score: float
    started_at: str
    completed_at: Optional[str] = None
    duration_seconds: float = 0.0
    error_summary: Optional[str] = None
