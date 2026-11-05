"""
DRISHTI — Metasploit Weaponization & Exploit Management API Endpoints (Grade 10/10)
Provides module inspection, threat actor campaigns, MITRE ATT&CK attribution,
custom payload matrix selection, resource script generation, and exploit simulation.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.services.metasploit_service import (
    get_all_metasploit_modules,
    get_module_by_cve,
    get_threat_campaigns_summary,
    generate_msf_resource_script,
    simulate_exploit_assessment,
)

router = APIRouter(prefix="/api/metasploit", tags=["Metasploit Engine"])


class GenerateMsfScriptRequest(BaseModel):
    cve_id: str = Field(..., description="CVE ID, e.g. CVE-2024-4577")
    target_host: str = Field(..., description="Target host IP or domain")
    target_port: Optional[int] = Field(None, description="Target port number")
    lhost: Optional[str] = Field("127.0.0.1", description="Listener host IP")
    lport: Optional[int] = Field(4444, description="Listener port number")
    ssl: Optional[bool] = Field(None, description="Force SSL on connection")
    target_uri: Optional[str] = Field(None, description="Target URI path")
    payload_override: Optional[str] = Field(None, description="Custom payload from supported matrix")
    safe_check_only: Optional[bool] = Field(True, description="Output safe non-destructive check command")
    encoder: Optional[str] = Field(None, description="Payload encoder (e.g. x64/zutto_dekiru)")


class SimulateExploitRequest(BaseModel):
    cve_id: str = Field(..., description="CVE ID to evaluate")
    target_host: str = Field(..., description="Target host IP or domain")
    observed_version: Optional[str] = Field(None, description="Observed version banner")
    target_port: Optional[int] = Field(None, description="Target port number")


@router.get("/modules")
async def list_metasploit_modules():
    """Returns all 32 indexed Metasploit exploit and auxiliary modules with weaponization data."""
    modules = get_all_metasploit_modules()
    return {"status": "success", "total": len(modules), "modules": modules}


@router.get("/campaigns")
async def get_threat_campaigns():
    """Returns an aggregated index of all threat actors, ransomware groups, and MITRE tactics."""
    summary = get_threat_campaigns_summary()
    return {"status": "success", **summary}


@router.get("/modules/{cve_id}")
async def get_metasploit_module(cve_id: str):
    """Retrieves comprehensive Metasploit module information mapped to a specific CVE."""
    module = get_module_by_cve(cve_id)
    if not module:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No curated Metasploit module found for CVE '{cve_id}'."
        )
    return {
        "status": "success",
        "module": {
            "cve_id": module.cve_id,
            "module_path": module.module_path,
            "title": module.title,
            "platform": module.platform,
            "category": module.category,
            "rank": module.rank,
            "cisa_kev": module.cisa_kev,
            "default_port": module.default_port,
            "payload_default": module.payload_default,
            "description": module.description,
            "target_uri": module.target_uri,
            "ssl": module.ssl,
            "mitre_attack": module.mitre_attack,
            "mitre_tactic": module.mitre_tactic,
            "threat_actors": module.threat_actors,
            "supported_payloads": module.supported_payloads,
            "safe_check_available": module.safe_check_available,
            "cwe_id": module.cwe_id,
        }
    }


@router.post("/generate")
async def generate_script(payload: GenerateMsfScriptRequest):
    """
    Synthesizes an executable Metasploit Resource Script (.rc) and runnable msfconsole CLI commands.
    """
    try:
        result = generate_msf_resource_script(
            cve_id=payload.cve_id,
            target_host=payload.target_host,
            target_port=payload.target_port,
            lhost=payload.lhost or "127.0.0.1",
            lport=payload.lport or 4444,
            ssl_override=payload.ssl,
            target_uri=payload.target_uri,
            payload_override=payload.payload_override,
            safe_check_only=payload.safe_check_only if payload.safe_check_only is not None else True,
            encoder=payload.encoder,
        )
        return {"status": "success", **result}
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))


@router.post("/simulate")
async def simulate_exploit(payload: SimulateExploitRequest):
    """
    Simulates a non-destructive Metasploit exploit verification assessment against an asset.
    """
    try:
        assessment = simulate_exploit_assessment(
            cve_id=payload.cve_id,
            target_host=payload.target_host,
            observed_version=payload.observed_version,
            target_port=payload.target_port,
        )
        return {"status": "success", **assessment}
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
