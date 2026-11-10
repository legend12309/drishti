"""
DRISHTI — Phase 5 LLM Router & Cyber Intelligence REST API Router
Endpoints:
  - POST /api/llm/generate
  - POST /api/llm/explain-path
  - POST /api/llm/explain-vulnerability
  - POST /api/llm/executive-brief
  - GET  /api/llm/providers
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from backend.middleware.guard import sanitize_llm_input
from backend.services.intelligence_explainer import (
    explain_candidate_attack_path,
    explain_vulnerability,
    generate_executive_brief,
)
from backend.services.llm_models import (
    ExecutiveBriefRequest,
    ExecutiveBriefResponse,
    ExplainAttackPathRequest,
    ExplainVulnerabilityRequest,
    LLMProvider,
    LLMRequest,
    LLMResponse,
)
from backend.services.llm_router import llm_router
from backend.services.scanner import get_latest_scan_for_target

router = APIRouter(prefix="/api/llm", tags=["AI Router & Cyber Intelligence"])


@router.get("/providers")
async def list_available_providers():
    """Lists supported AI providers and their configuration availability status."""
    providers_info = []
    for p in llm_router.default_priority:
        is_avail = llm_router.is_provider_available(p)
        adapter = llm_router.adapters[p]
        providers_info.append({
            "provider": p.value,
            "name": p.name,
            "model": adapter.model_name,
            "available": is_avail,
            "is_offline_fallback": (p == LLMProvider.OFFLINE_SYNTHETIC),
        })

    return {
        "status": "success",
        "total_providers": len(providers_info),
        "active_provider_count": sum(1 for p in providers_info if p["available"]),
        "providers": providers_info,
    }


@router.post("/generate", response_model=LLMResponse)
async def generate_text(payload: LLMRequest, provider: Optional[LLMProvider] = None):
    """Generates text via intelligent fallback across configured providers."""
    payload.prompt = sanitize_llm_input(payload.prompt)
    if payload.system_instruction:
        payload.system_instruction = sanitize_llm_input(payload.system_instruction)
    return await llm_router.generate_with_fallback(payload, provider_override=provider)


@router.post("/explain-path")
async def explain_attack_path_endpoint(payload: ExplainAttackPathRequest):
    """Generates an evidence-grounded explanation for a candidate attack path."""
    actual_scan_id = payload.scan_id
    if actual_scan_id == "latest":
        latest = await get_latest_scan_for_target(None)
        if not latest:
            raise HTTPException(status_code=404, detail="No scan available to explain path.")
        actual_scan_id = latest["id"]

    return await explain_candidate_attack_path(
        scan_id=actual_scan_id,
        path_id=payload.path_id,
        target_node=payload.target_node or "CoreDB",
        provider_override=payload.provider_override,
    )


@router.post("/explain-vulnerability")
async def explain_vulnerability_endpoint(payload: ExplainVulnerabilityRequest):
    """Generates actionable vulnerability analysis and step-by-step remediation."""
    if payload.match_rationale:
        payload.match_rationale = sanitize_llm_input(payload.match_rationale)
    return await explain_vulnerability(
        cve_id=payload.cve_id,
        asset_id=payload.asset_id,
        match_rationale=payload.match_rationale,
        provider_override=payload.provider_override,
    )


@router.post("/executive-brief", response_model=ExecutiveBriefResponse)
async def executive_brief_endpoint(payload: ExecutiveBriefRequest):
    """Generates an executive-level threat intelligence summary from scan evidence."""
    actual_scan_id = payload.scan_id
    if actual_scan_id == "latest":
        latest = await get_latest_scan_for_target(payload.target_domain)
        if not latest:
            raise HTTPException(status_code=404, detail="No scan available to generate executive briefing.")
        actual_scan_id = latest["id"]

    return await generate_executive_brief(
        scan_id=actual_scan_id,
        target_domain=payload.target_domain,
        provider_override=payload.provider_override,
    )


class SetApiKeyRequest(BaseModel):
    provider: str
    api_key: str


@router.post("/set-key")
async def set_provider_api_key(payload: SetApiKeyRequest):
    """Dynamically updates an AI provider's API key for live cloud reasoning."""
    import os
    p_lower = payload.provider.lower().strip()
    key = payload.api_key.strip()
    if p_lower == "gemini":
        os.environ["GEMINI_API_KEY"] = key
    elif p_lower == "groq":
        os.environ["GROQ_API_KEY"] = key
    elif p_lower == "nvidia":
        os.environ["NVIDIA_API_KEY"] = key
    elif p_lower in ("huggingface", "hf"):
        os.environ["HUGGINGFACE_API_KEY"] = key
        os.environ["HF_TOKEN"] = key
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {payload.provider}")

    is_live = bool(key and "test" not in key.lower())
    return {
        "status": "success",
        "provider": p_lower,
        "is_live": is_live,
        "message": f"{p_lower.upper()} API key successfully updated." if is_live else f"{p_lower.upper()} reset to offline mode."
    }
