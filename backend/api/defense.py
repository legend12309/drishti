"""
DRISHTI — Phase 13 Autonomous Defense & Remediation REST API Router
Endpoints:
  - POST /api/defense/generate  -> Synthesize WAF, ModSec, iptables, & Patch diffs
  - POST /api/defense/verify    -> Execute diagnostic micro-probe to verify rule enforcement
  - GET  /api/defense/templates -> List available high-fidelity deterministic CVE mitigation templates
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.services.remediation_engine import (
    DETERMINISTIC_RULES,
    DefenseRulesResponse,
    VerifyRemediationRequest,
    VerifyRemediationResponse,
    execute_verification_probe,
    generate_defense_rules,
)

router = APIRouter(prefix="/api/defense", tags=["Autonomous Defense & Remediation"])


class GenerateDefenseRequest(BaseModel):
    cve_id: str = Field(..., description="CVE identifier, e.g. CVE-2024-4577")
    target: str = Field(..., description="Target hostname or IP address, e.g. vvdx.in")
    port: Optional[int] = Field(None, description="Target port number, e.g. 80, 443, 22")
    service_banner: Optional[str] = Field(None, description="Detected service banner")
    path_id: Optional[str] = Field(None, description="Optional attack path identifier")


@router.post("/generate", response_model=DefenseRulesResponse)
async def generate_defense(req: GenerateDefenseRequest) -> DefenseRulesResponse:
    """
    Synthesizes multi-tier defense rules (Cloudflare WAF, ModSecurity Nginx,
    Linux iptables, and code-level patch diffs) for a given vulnerability and target.
    """
    if not req.cve_id.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="cve_id cannot be blank.",
        )
    if not req.target.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target cannot be blank.",
        )

    try:
        return await generate_defense_rules(
            cve_id=req.cve_id,
            target=req.target,
            port=req.port,
            service_banner=req.service_banner,
            path_id=req.path_id,
        )
    except Exception as ex:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate defense rules: {str(ex)}",
        )


@router.post("/verify", response_model=VerifyRemediationResponse)
async def verify_defense(req: VerifyRemediationRequest) -> VerifyRemediationResponse:
    """
    Executes a non-intrusive verification probe to test whether a defensive
    firewall/WAF rule is actively blocking suspicious traffic to the target endpoint.
    """
    if not req.target_url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target_url cannot be blank.",
        )

    try:
        return await execute_verification_probe(req)
    except Exception as ex:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Verification probe execution failed: {str(ex)}",
        )


@router.get("/templates")
async def list_defense_templates() -> Dict[str, Any]:
    """
    Lists high-fidelity deterministic mitigation templates pre-compiled into DRISHTI.
    """
    return {
        "count": len(DETERMINISTIC_RULES),
        "templates": [
            {
                "cve_id": cve_id,
                "summary": data.get("summary", ""),
                "has_cloudflare": bool(data.get("cloudflare")),
                "has_modsecurity": bool(data.get("modsecurity")),
                "has_iptables": bool(data.get("iptables")),
                "has_patch": bool(data.get("patch")),
                "has_probe": bool(data.get("probe")),
            }
            for cve_id, data in DETERMINISTIC_RULES.items()
        ],
    }
