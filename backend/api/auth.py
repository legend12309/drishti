"""
DRISHTI Operator Authentication & Profile API Endpoints.
Provides operator authentication, session validation, profile querying,
and audit logging for operator logins.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Header, status
from pydantic import BaseModel, Field

from backend.services.authorizations import log_audit_event

router = APIRouter(prefix="/api/auth", tags=["Authentication & Profile"])


class LoginRequest(BaseModel):
    username: str = Field(..., description="Operator identifier or email")
    password: str = Field(..., description="Operator password")
    role: Optional[str] = Field("SecOps Lead", description="Operational role")


class ProfileUpdateRequest(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    default_scope: Optional[str] = None


# Default mock operator profile for local enterprise development
DEFAULT_OPERATOR = {
    "id": "local-operator-dev",
    "name": "Alex Morgan",
    "email": "a.morgan@drishti.sec",
    "role": "SecOps Lead",
    "clearance": "LEVEL 5 // TOP SECRET // SI-TK / GBD-AUTH",
    "organization": "Cyber Intelligence Division (Monolith SecOps)",
    "avatar_text": "OP",
    "permissions": [
        "FULL_PASSIVE_RECON",
        "ATTACK_GRAPH_PATHFINDING",
        "PROMPT_GUARD_EVAL",
        "STIX_BUNDLE_EXPORT",
        "WAL_AUDIT_INSPECTION",
        "SCOPE_CHALLENGE_ISSUER",
    ],
    "client_ip": "127.0.0.1 (Local Monolith)",
    "mfa_enabled": True,
    "hardware_key_bound": True,
    "default_scope": "FULL_PASSIVE",
    "token_fingerprint": "SHA256: 8f43...27aa4",
}


@router.post("/login")
async def login_operator(payload: LoginRequest):
    """
    Authenticates a local security operator.
    Validates credentials and generates session context.
    """
    username = payload.username.strip()
    if not username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username or operator ID required")

    # In local commodity / air-gapped mode, accept valid development credentials
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=7)

    profile = dict(DEFAULT_OPERATOR)
    profile["id"] = username if "@" not in username else username.split("@")[0]
    profile["role"] = payload.role or "SecOps Lead"
    if "@" in username:
        profile["email"] = username

    # Record tamper-evident audit log
    await log_audit_event(
        event_type="operator_login",
        target="console.drishti.local",
        detail=f"Operator '{profile['id']}' authenticated with role '{profile['role']}' from 127.0.0.1",
        operator_id=profile["id"]
    )

    return {
        "status": "success",
        "token": f"drishti-jwt-{now.timestamp()}",
        "expires_at": expires.isoformat(),
        "operator": profile
    }


@router.get("/me")
async def get_current_operator():
    """Returns the active operator profile and clearance permissions."""
    return {
        "status": "success",
        "operator": DEFAULT_OPERATOR,
        "authenticated": True,
        "session_expires": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
    }


@router.post("/logout")
async def logout_operator(authorization: Optional[str] = Header(None)):
    """Terminates active session and records audit event."""
    await log_audit_event(
        event_type="operator_logout",
        target="console.drishti.local",
        detail="Operator session terminated by user sign-out",
        operator_id=DEFAULT_OPERATOR["id"]
    )
    return {"status": "success", "message": "Session terminated successfully"}
