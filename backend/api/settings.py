"""
DRISHTI Settings API & Dynamic Provider Configuration.
Configured for:
1. Google (Gemini)
2. NVIDIA (NIM / AI Foundation)
3. Hugging Face (Hub & Inference API)
4. Groq (LPU Inference)

Handles local commodity fallback mode when no external API keys are provided,
and dynamically reconfigures providers when keys are submitted via the UI.
"""

import os
from pathlib import Path
from typing import Dict, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/settings", tags=["Configuration"])

ENV_PATH = Path(__file__).resolve().parent.parent.parent / ".env"

# Active In-Memory Configuration State
RUNTIME_CONFIG = {
    "groq_api_key": os.getenv("GROQ_API_KEY", ""),
    "nvidia_api_key": os.getenv("NVIDIA_API_KEY", ""),
    "huggingface_api_key": os.getenv("HUGGINGFACE_API_KEY", os.getenv("HF_TOKEN", "")),
    "gemini_api_key": os.getenv("GEMINI_API_KEY", ""),
    "jwt_secret": os.getenv("JWT_SECRET", "drishti-local-dev-secret-key"),
    "force_local_mode": os.getenv("FORCE_LOCAL_MODE", "false").lower() == "true",
}


def reload_env_config():
    """Syncs RUNTIME_CONFIG from .env file if it exists."""
    if ENV_PATH.exists():
        with open(ENV_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip()
                    if k == "GROQ_API_KEY":
                        RUNTIME_CONFIG["groq_api_key"] = v
                    elif k == "NVIDIA_API_KEY":
                        RUNTIME_CONFIG["nvidia_api_key"] = v
                    elif k in ("HUGGINGFACE_API_KEY", "HF_TOKEN") and v:
                        RUNTIME_CONFIG["huggingface_api_key"] = v
                        os.environ["HF_TOKEN"] = v
                    elif k == "GEMINI_API_KEY":
                        RUNTIME_CONFIG["gemini_api_key"] = v
                    elif k == "JWT_SECRET":
                        RUNTIME_CONFIG["jwt_secret"] = v
                    elif k == "FORCE_LOCAL_MODE":
                        RUNTIME_CONFIG["force_local_mode"] = v.lower() == "true"


reload_env_config()


def mask_key(key: str) -> str:
    """Masks secret key while revealing first 4 and last 3 characters."""
    if not key or key.strip() == "":
        return ""
    if len(key) <= 8:
        return "••••••••"
    return f"{key[:4]}••••••••{key[-3:]}"


def determine_engine_mode() -> Dict[str, str]:
    """Returns active analytical tier based on provided API keys."""
    reload_env_config()
    if RUNTIME_CONFIG["force_local_mode"]:
        return {
            "mode": "LOCAL_COMMODITY",
            "provider": "Local CPU (all-MiniLM-L6-v2 + Regex Heuristics)",
            "description": "Zero external cloud dependencies. Running 100% on local commodity hardware."
        }
    
    active_providers = []
    if RUNTIME_CONFIG["groq_api_key"]:
        active_providers.append("Groq (LPU)")
    if RUNTIME_CONFIG["nvidia_api_key"]:
        active_providers.append("NVIDIA (NIM)")
    if RUNTIME_CONFIG["huggingface_api_key"]:
        active_providers.append("Hugging Face (Inference)")
    if RUNTIME_CONFIG["gemini_api_key"]:
        active_providers.append("Google (Gemini)")

    if not active_providers:
        return {
            "mode": "LOCAL_COMMODITY",
            "provider": "Local CPU (all-MiniLM-L6-v2 + Regex Heuristics)",
            "description": "No external API keys configured. Running in high-speed local offline mode."
        }
    
    return {
        "mode": "CLOUD_ACCELERATED",
        "provider": " + ".join(active_providers),
        "description": f"Cloud accelerated reasoning enabled via {', '.join(active_providers)}."
    }


class SettingsUpdateRequest(BaseModel):
    groq_api_key: Optional[str] = None
    nvidia_api_key: Optional[str] = None
    huggingface_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None
    jwt_secret: Optional[str] = None
    force_local_mode: Optional[bool] = None


@router.get("")
async def get_settings():
    """Returns current active settings with masked keys and active engine mode."""
    mode_info = determine_engine_mode()
    return {
        "status": "success",
        "engine_mode": mode_info,
        "keys": {
            "google": {
                "configured": bool(RUNTIME_CONFIG["gemini_api_key"]),
                "masked": mask_key(RUNTIME_CONFIG["gemini_api_key"]),
            },
            "nvidia": {
                "configured": bool(RUNTIME_CONFIG["nvidia_api_key"]),
                "masked": mask_key(RUNTIME_CONFIG["nvidia_api_key"]),
            },
            "huggingface": {
                "configured": bool(RUNTIME_CONFIG["huggingface_api_key"]),
                "masked": mask_key(RUNTIME_CONFIG["huggingface_api_key"]),
            },
            "groq": {
                "configured": bool(RUNTIME_CONFIG["groq_api_key"]),
                "masked": mask_key(RUNTIME_CONFIG["groq_api_key"]),
            },
            # Aliases for backward compatibility
            "gemini": {
                "configured": bool(RUNTIME_CONFIG["gemini_api_key"]),
                "masked": mask_key(RUNTIME_CONFIG["gemini_api_key"]),
            },
        },
        "jwt_configured": bool(RUNTIME_CONFIG["jwt_secret"]),
        "force_local_mode": RUNTIME_CONFIG["force_local_mode"],
    }


@router.post("")
async def update_settings(payload: SettingsUpdateRequest):
    """
    Updates runtime settings and persists non-empty secrets to .env.
    If keys are omitted or empty, local offline commodity mode remains active.
    """
    # Update runtime memory
    if payload.groq_api_key is not None and not payload.groq_api_key.startswith("••"):
        RUNTIME_CONFIG["groq_api_key"] = payload.groq_api_key.strip()
    if payload.nvidia_api_key is not None and not payload.nvidia_api_key.startswith("••"):
        RUNTIME_CONFIG["nvidia_api_key"] = payload.nvidia_api_key.strip()
    if payload.huggingface_api_key is not None and not payload.huggingface_api_key.startswith("••"):
        RUNTIME_CONFIG["huggingface_api_key"] = payload.huggingface_api_key.strip()
        # Also set HF_TOKEN environment variable for sentence-transformers & huggingface hub
        os.environ["HF_TOKEN"] = RUNTIME_CONFIG["huggingface_api_key"]
    if payload.gemini_api_key is not None and not payload.gemini_api_key.startswith("••"):
        RUNTIME_CONFIG["gemini_api_key"] = payload.gemini_api_key.strip()
    if payload.jwt_secret is not None:
        RUNTIME_CONFIG["jwt_secret"] = payload.jwt_secret.strip()
    if payload.force_local_mode is not None:
        RUNTIME_CONFIG["force_local_mode"] = payload.force_local_mode

    # Persist updated values into .env
    env_lines = []
    if ENV_PATH.exists():
        with open(ENV_PATH, "r", encoding="utf-8") as f:
            env_lines = f.readlines()

    updated_keys = {
        "GROQ_API_KEY": RUNTIME_CONFIG["groq_api_key"],
        "NVIDIA_API_KEY": RUNTIME_CONFIG["nvidia_api_key"],
        "HUGGINGFACE_API_KEY": RUNTIME_CONFIG["huggingface_api_key"],
        "HF_TOKEN": RUNTIME_CONFIG["huggingface_api_key"],
        "GEMINI_API_KEY": RUNTIME_CONFIG["gemini_api_key"],
        "JWT_SECRET": RUNTIME_CONFIG["jwt_secret"],
        "FORCE_LOCAL_MODE": str(RUNTIME_CONFIG["force_local_mode"]).lower(),
    }

    new_file_lines = []
    seen = set()
    for line in env_lines:
        if "=" in line and not line.strip().startswith("#"):
            k = line.split("=", 1)[0].strip()
            if k in updated_keys:
                new_file_lines.append(f"{k}={updated_keys[k]}\n")
                seen.add(k)
                continue
        new_file_lines.append(line)

    for k, v in updated_keys.items():
        if k not in seen and v:
            new_file_lines.append(f"{k}={v}\n")

    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.writelines(new_file_lines)

    return {
        "status": "success",
        "message": "Configuration updated and persisted.",
        "engine_mode": determine_engine_mode()
    }
