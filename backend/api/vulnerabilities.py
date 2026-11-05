"""
DRISHTI — Vulnerability Intelligence REST API Router
Provides endpoints for retrieving CVE intelligence, scan vulnerability findings,
asset vulnerabilities, and synchronization checkpoints.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel
from backend.services.scanner import get_latest_scan_for_target
from backend.services.vulnerability_service import (
    get_asset_vulnerabilities,
    get_scan_vulnerabilities,
    get_vulnerability,
    list_vulnerabilities,
    seed_vulnerability_corpus,
)

router = APIRouter(prefix="/api", tags=["Vulnerabilities"])


class SyncResponse(BaseModel):
    status: str
    message: str
    total_synced: int


@router.get("/vulnerabilities/{cve_id}")
async def get_cve_detail(cve_id: str):
    """Retrieves full details for a specific CVE from DB cache or NVD API."""
    vuln = await get_vulnerability(cve_id)
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability '{cve_id}' not found in local cache or NVD corpus."
        )
    return {"status": "success", "vulnerability": vuln.model_dump()}


@router.get("/vulnerabilities")
async def list_cves(
    severity: Optional[str] = Query(None, description="Filter by CVSS severity: CRITICAL, HIGH, MEDIUM, LOW, ALL"),
    search: Optional[str] = Query(None, description="Search term for CVE ID, title, or description"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0)
):
    """Lists cached vulnerabilities with optional severity and search filters."""
    records = await list_vulnerabilities(severity=severity, search=search, limit=limit, offset=offset)
    return {
        "status": "success",
        "total": len(records),
        "vulnerabilities": [r.model_dump() for r in records]
    }


@router.get("/scans/{scan_id}/vulnerabilities")
@router.get("/intel/scans/{scan_id}/vulnerabilities")
async def get_scan_vulns(scan_id: str):
    """Retrieves all vulnerability findings and applicability results for a scan."""
    actual_scan_id = scan_id
    if scan_id == "latest":
        latest = await get_latest_scan_for_target(None)
        if latest:
            actual_scan_id = latest["id"]
        else:
            return {
                "status": "success",
                "scan_id": "latest",
                "total_findings": 0,
                "confirmed_count": 0,
                "potential_count": 0,
                "insufficient_evidence_count": 0,
                "confirmed_vulnerabilities": [],
                "correlated_passive_vulnerabilities": [],
                "vulnerabilities": []
            }

    findings = await get_scan_vulnerabilities(actual_scan_id)
    confirmed_vulns = [f for f in findings if f.get("applicability_status") == "confirmed_applicability"]
    correlated_vulns = [f for f in findings if f.get("applicability_status") != "confirmed_applicability"]
    confirmed_count = len(confirmed_vulns)
    potential_count = sum(1 for f in findings if f.get("applicability_status") == "potential_applicability")
    insufficient_count = sum(1 for f in findings if f.get("applicability_status") == "insufficient_evidence")

    return {
        "status": "success",
        "scan_id": actual_scan_id,
        "total_findings": len(findings),
        "confirmed_count": confirmed_count,
        "potential_count": potential_count,
        "insufficient_evidence_count": insufficient_count,
        "confirmed_vulnerabilities": confirmed_vulns,
        "correlated_passive_vulnerabilities": correlated_vulns,
        "vulnerabilities": findings
    }


@router.get("/assets/{asset_id:path}/vulnerabilities")
async def get_asset_vulns(asset_id: str):
    """Retrieves all vulnerability findings evaluated for a specific asset."""
    findings = await get_asset_vulnerabilities(asset_id)
    return {
        "status": "success",
        "asset_id": asset_id,
        "total": len(findings),
        "vulnerabilities": findings
    }


@router.post("/vulnerabilities/sync", response_model=SyncResponse)
async def trigger_vulnerability_sync():
    """
    Triggers bounded synchronization of high-fidelity vulnerability intelligence.
    Seeds and refreshes local CVE corpus from NVD fixtures and verified data sources.
    """
    try:
        await seed_vulnerability_corpus()
        all_vulns = await list_vulnerabilities(limit=100)
        return SyncResponse(
            status="success",
            message="Vulnerability intelligence corpus synchronized successfully.",
            total_synced=len(all_vulns)
        )
    except Exception as ex:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Synchronization failed: {str(ex)}"
        )
