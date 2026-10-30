"""
DRISHTI — Phase 5 LLM Models, Provider Interfaces & Prompt Schemas
Defines supported providers, routing policies, generation requests,
and explainable cyber intelligence outputs.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class LLMProvider(str, Enum):
    GROQ = "groq"
    NVIDIA = "nvidia"
    GEMINI = "gemini"
    HUGGINGFACE = "huggingface"
    OFFLINE_SYNTHETIC = "offline_synthetic"


class RoutingPolicy(str, Enum):
    PRIORITY_ORDER = "priority_order"   # Tries providers in explicit priority sequence
    ROUND_ROBIN = "round_robin"         # Rotates across active providers
    COST_LATENCY = "cost_latency"       # Prefers Groq / Cerebras for fast latency


class LLMMessage(BaseModel):
    role: str   # "system", "user", "assistant"
    content: str


class LLMRequest(BaseModel):
    prompt: str
    system_instruction: Optional[str] = None
    max_tokens: int = Field(1024, ge=64, le=4096)
    temperature: float = Field(0.2, ge=0.0, le=1.0)
    task_type: str = "threat_explanation"  # threat_explanation, mitigation_guidance, attack_path_narrative


class LLMResponse(BaseModel):
    text: str
    provider_used: LLMProvider
    model_name: str
    fallback_attempts: int = 0
    fallback_history: List[str] = Field(default_factory=list)
    latency_ms: float = 0.0
    tokens_used: Optional[int] = None
    is_fallback: bool = False
    evidence_grounding_score: float = 1.0


class ExplainAttackPathRequest(BaseModel):
    scan_id: str
    path_id: Optional[str] = None
    target_node: Optional[str] = "CoreDB"
    provider_override: Optional[LLMProvider] = None


class ExplainVulnerabilityRequest(BaseModel):
    cve_id: str
    asset_id: Optional[str] = None
    match_rationale: Optional[str] = None
    cvss_score: Optional[float] = None
    provider_override: Optional[LLMProvider] = None


class ExecutiveBriefRequest(BaseModel):
    scan_id: str
    target_domain: Optional[str] = None
    provider_override: Optional[LLMProvider] = None


class ExecutiveBriefResponse(BaseModel):
    scan_id: str
    target_domain: str
    executive_summary: str
    critical_attack_vectors: List[str]
    immediate_actions: List[str]
    residual_risk_verdict: str
    provider_metadata: Dict[str, Any]
