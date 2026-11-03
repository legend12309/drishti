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
    target: Optional[str] = Field(None, description="Target hostname or IP address, e.g. vvdx.in")
    target_domain: Optional[str] = Field(None, description="Target domain alias")
    port: Optional[int] = Field(None, description="Target port number, e.g. 80, 443, 22")
    service_banner: Optional[str] = Field(None, description="Detected service banner")
    path_id: Optional[str] = Field(None, description="Optional attack path identifier")


@router.post("/generate", response_model=DefenseRulesResponse)
@router.post("/generate-rule", response_model=DefenseRulesResponse)
async def generate_defense(req: GenerateDefenseRequest) -> DefenseRulesResponse:
    """
    Synthesizes multi-tier defense rules (Cloudflare WAF, ModSecurity Nginx,
    Linux iptables, and code-level patch diffs) for a given vulnerability and target.
    """
    target_val = (req.target or req.target_domain or "").strip()
    if not req.cve_id.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="cve_id cannot be blank.",
        )
    if not target_val:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target cannot be blank.",
        )

    try:
        return await generate_defense_rules(
            cve_id=req.cve_id,
            target=target_val,
            port=req.port,
            service_banner=req.service_banner,
            path_id=req.path_id,
        )
    except Exception as ex:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate defense rules: {str(ex)}",
        )


class FlexibleVerifyRequest(BaseModel):
    target_url: Optional[str] = Field(None, description="Target URL to probe")
    url: Optional[str] = Field(None, description="URL alias")
    method: str = "GET"
    test_header_key: Optional[str] = "X-DRISHTI-VERIFY"
    test_header_val: Optional[str] = "probe-diagnostic"
    expected_status: int = 403
    timeout_seconds: float = 3.0


@router.post("/verify", response_model=VerifyRemediationResponse)
async def verify_defense(req: FlexibleVerifyRequest) -> VerifyRemediationResponse:
    """
    Executes a non-intrusive verification probe to test whether a defensive
    firewall/WAF rule is actively blocking suspicious traffic to the target endpoint.
    """
    actual_url = (req.target_url or req.url or "").strip()
    if not actual_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target_url cannot be blank.",
        )

    try:
        strict_req = VerifyRemediationRequest(
            target_url=actual_url,
            method=req.method,
            test_header_key=req.test_header_key,
            test_header_val=req.test_header_val,
            expected_status=req.expected_status,
            timeout_seconds=req.timeout_seconds,
        )
        return await execute_verification_probe(strict_req)
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
