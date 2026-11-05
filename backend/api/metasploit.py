"""
DRISHTI — Metasploit Weaponization & Exploit Management API Endpoints
Provides module inspection, resource script generation, and exploit simulation.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.services.metasploit_service import (
    get_all_metasploit_modules,
    get_module_by_cve,
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


class SimulateExploitRequest(BaseModel):
    cve_id: str = Field(..., description="CVE ID to evaluate")
    target_host: str = Field(..., description="Target host IP or domain")
    observed_version: Optional[str] = Field(None, description="Observed version banner")
    target_port: Optional[int] = Field(None, description="Target port number")


@router.get("/modules")
async def list_metasploit_modules():
    """Returns all indexed Metasploit exploit and auxiliary modules with weaponization data."""
    modules = get_all_metasploit_modules()
    return {"status": "success", "total": len(modules), "modules": modules}


@router.get("/modules/{cve_id}")
async def get_metasploit_module(cve_id: str):
    """Retrieves Metasploit module information mapped to a specific CVE."""
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
        }
    }


@router.post("/generate")
async def generate_script(payload: GenerateMsfScriptRequest):
    """
    Synthesizes an executable Metasploit Resource Script (.rc) and runnable msfconsole CLI command.
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
        return assessment
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
