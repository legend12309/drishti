"""
DRISHTI — Pure Tactical Plaintext Report Router
Eliminates all PDF binary dependencies; returns clean, readable ASCII Tactical Dossiers.
"""

from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, Query, Response, status
from pydantic import BaseModel, Field

from backend.db.database import get_db
from backend.services.report_engine import synthesize_text_report

router = APIRouter(prefix="/api", tags=["Tactical Reports (Plaintext)"])


class GenerateReportRequest(BaseModel):
    target: Optional[str] = Field("vvdx.in", description="Target perimeter domain, e.g. vvdx.in")
    scan_id: Optional[str] = Field(None, description="Scan reference ID")
    format: Optional[str] = Field("TEXT", description="Requested output format (TEXT)")
    include_ai: Optional[bool] = Field(True, description="Include AI synthesis")


@router.post("/reports/generate")
@router.post("/scans/orchestrator/workflows/{workflow_id}/report")
async def generate_report_endpoint(
    req: Optional[GenerateReportRequest] = None,
    workflow_id: Optional[str] = None
) -> Dict[str, Any]:
    """Generates a certified tactical plaintext ASCII assessment dossier with passive and active findings."""
    target = req.target if req and req.target else None
    scan_id = workflow_id or (req.scan_id if req else None)

    try:
        report = await synthesize_text_report(target=target, scan_id=scan_id)
        return {
            "status": "success",
            "id": report["id"],
            "target": report["target"],
            "scan_id": report.get("scan_id"),
            "format": report["format"],
            "created_at": report["created_at"],
            "sha256_signature": report["sha256_signature"],
            "size_bytes": report["size_bytes"],
            "content_text": report["content_text"],
            "summary": report.get("summary", {}),
            "confirmed_vulnerabilities": report.get("confirmed_vulnerabilities", []),
            "correlated_vulnerabilities": report.get("correlated_vulnerabilities", []),
            "passive_recon_findings": report.get("passive_recon_findings", []),
            "active_recon_findings": report.get("active_recon_findings", {}),
        }
    except Exception as ex:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate tactical text report: {str(ex)}"
        )


@router.get("/reports/latest")
async def get_latest_report_endpoint(
    target: Optional[str] = Query(None, description="Target perimeter domain, e.g. iiit-bh.ac.in")
) -> Dict[str, Any]:
    """Retrieves the most recent tactical assessment report with raw content_text, passive/active findings, and confirmed bugs."""
    report = await synthesize_text_report(target=target, scan_id="latest")
    return report


@router.get("/reports")
async def list_reports_endpoint() -> Dict[str, Any]:
    """Lists all available reports in tactical plaintext format."""
    import json
    reports = []
    async with get_db() as db:
        try:
            async with db.execute(
                "SELECT scan_id, file_path, file_size, status, created_at, content_text, report_metadata FROM scan_reports ORDER BY created_at DESC"
            ) as cur:
                rows = await cur.fetchall()
                for r in rows:
                    meta = {}
                    if r[6]:
                        try:
                            meta = json.loads(r[6]) if isinstance(r[6], str) else r[6]
                        except Exception:
                            pass
                    
                    target_name = meta.get("target") or (r[1].split("_")[-1].replace(".txt", "") if r[1] and "_" in r[1] else "Host")
                    reports.append({
                        "id": meta.get("id") or f"RPT-{r[0]}",
                        "scan_id": r[0],
                        "target": target_name,
                        "file_path": r[1],
                        "file_size": r[2],
                        "status": r[3],
                        "format": "TEXT",
                        "created_at": r[4],
                        "has_content": bool(r[5]),
                        "sha256_signature": meta.get("sha256_signature", ""),
                        "content_text": r[5] or "",
                    })
        except Exception:
            pass

    if not reports:
        # Generate baseline
        seed_report = await synthesize_text_report(target="iiit-bh.ac.in", scan_id="latest")
        reports = [{
            "id": seed_report["id"],
            "scan_id": seed_report.get("scan_id", "latest"),
            "target": seed_report["target"],
            "file_path": f"data/reports/DRISHTI_Assessment_{seed_report['target']}.txt",
            "file_size": seed_report["size_bytes"],
            "status": "generated",
            "format": "TEXT",
            "created_at": seed_report["created_at"],
            "has_content": True,
            "sha256_signature": seed_report["sha256_signature"],
            "content_text": seed_report["content_text"],
        }]

    return {"status": "success", "total": len(reports), "reports": reports}


@router.get("/reports/{report_id}/download")
@router.get("/reports/latest/download")
@router.get("/scans/reports/latest/download")
@router.get("/scans/orchestrator/workflows/{workflow_id}/report/download")
@router.get("/scans/{workflow_id}/report/download")
async def download_report_text(
    report_id: Optional[str] = None,
    workflow_id: Optional[str] = None,
    target: Optional[str] = Query(None)
):
    """
    Delivers pure ASCII Tactical Assessment Report as a downloadable .txt file.
    No binary PDF wrapping.
    """
    scan_ref = workflow_id or report_id or "latest"
    report = await synthesize_text_report(target=target, scan_id=scan_ref)
    content_text = report["content_text"]
    filename = f"DRISHTI_Assessment_{report['target']}.txt"

    return Response(
        content=content_text,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache",
        }
    )
