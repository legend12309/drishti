"""
DRISHTI Authorization & Scope Management API Endpoints.
Provides challenge generation, DNS verification, revocation,
scope querying, and tamper-evident audit log inspection.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.db.database import get_db
from backend.services.authorizations import (
    create_challenge,
    create_loa_authorization,
    get_authorization,
    verify_challenge,
    revoke_authorization,
    list_authorizations,
    get_valid_authorization_for_target,
)
from backend.services.scope import PERMITTED_SCOPES, normalize_domain

router = APIRouter(prefix="/api/authorizations", tags=["Authorizations"])


class CreateLoaRequest(BaseModel):
    target_domain: str = Field(..., description="Target apex domain or IP, e.g. vvdx.in")
    loa_reference: str = Field("LOA-2026-ENGAGEMENT-AUTH", description="Letter of Authorization reference / contract number")
    authorized_by: str = Field("Client Security Operations", description="Authorizing organization official")
    permitted_scope: str = Field("FULL_ACTIVE", description="Permitted scope: FULL_ACTIVE or FULL_PASSIVE")
    operator_id: str = Field("local-operator-dev", description="Operator identity identifier")
    notes: Optional[str] = Field("Signed Letter of Authorization (LOA) executed.", description="Engagement notes")


class CreateChallengeRequest(BaseModel):
    target_domain: str = Field(..., description="Target apex domain, e.g. company.com")
    permitted_scope: str = Field("FULL_PASSIVE", description="Permitted scope: FULL_PASSIVE, PASSIVE_DNS, or PASSIVE_METADATA")
    operator_id: str = Field("local-operator-dev", description="Operator identity identifier")


class VerifyChallengeRequest(BaseModel):
    authorization_id: str = Field(..., description="ID of the challenge authorization to verify")


class RevokeAuthorizationRequest(BaseModel):
    reason: str = Field("Revoked by operator", description="Reason for revoking authorization")
    operator_id: str = Field("local-operator-dev", description="Operator requesting revocation")


@router.post("/loa", status_code=status.HTTP_201_CREATED)
async def grant_letter_of_authorization(payload: CreateLoaRequest):
    """
    Records and verifies an enterprise Letter of Authorization (LOA) for a target domain.
    Instantly grants verified active scanning permissions without requiring DNS TXT records.
    """
    try:
        auth = await create_loa_authorization(
            target_domain=payload.target_domain,
            loa_reference=payload.loa_reference,
            authorized_by=payload.authorized_by,
            permitted_scope=payload.permitted_scope,
            operator_id=payload.operator_id,
            notes=payload.notes
        )
        return {"status": "success", "authorization": auth}
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))


@router.post("/challenges", status_code=status.HTTP_201_CREATED)
async def create_domain_challenge(payload: CreateChallengeRequest):
    """
    Creates a new DNS TXT ownership challenge for a target domain.
    Returns the required DNS record name (_drishti-challenge.<domain>) and verification token.
    """
    try:
        challenge = await create_challenge(
            target_domain=payload.target_domain,
            permitted_scope=payload.permitted_scope,
            operator_id=payload.operator_id
        )
        return {"status": "success", "challenge": challenge}
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))


@router.get("/challenges/{challenge_id}")
async def get_challenge_status(challenge_id: str):
    """Retrieves status and details of a pending or active challenge."""
    auth = await get_authorization(challenge_id)
    if not auth:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Challenge '{challenge_id}' not found.")
    return {"status": "success", "challenge": auth}


@router.post("/verify")
async def verify_domain_ownership(payload: VerifyChallengeRequest):
    """
    Executes DNS TXT verification for a challenge token.
    If DNS record matches, authorization status becomes 'verified' with 30-day validity.
    """
    try:
        result = await verify_challenge(payload.authorization_id)
        if not result["success"]:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=result["message"]
            )
        return result
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except HTTPException:
        raise
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))


@router.get("")
async def query_authorizations(domain: Optional[str] = Query(None, description="Filter by domain")):
    """Lists authorizations with optional domain filtering."""
    try:
        items = await list_authorizations(domain)
        return {"status": "success", "total": len(items), "authorizations": items}
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))


@router.get("/check")
async def check_target_scope(
    target: str = Query(..., description="Domain target to check"),
    scope: Optional[str] = Query(None, description="Scan scope (e.g., FULL_PASSIVE, PASSIVE_OSINT)")
):
    """
    Checks if a target domain is covered by an active, verified authorization.
    """
    try:
        auth = await get_valid_authorization_for_target(target, scope)
        if not auth:
            return {
                "authorized": False,
                "target": target,
                "message": f"Target '{target}' is not covered by any active, verified authorization."
            }
        return {
            "authorized": True,
            "target": target,
            "authorization_id": auth["id"],
            "target_domain": auth["target_domain"],
            "permitted_scope": auth["permitted_scope"],
            "expires_at": auth["expires_at"]
        }
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))


@router.get("/scopes")
async def get_permitted_scopes():
    """Returns available scanning scopes supported by DRISHTI."""
    return {"status": "success", "scopes": PERMITTED_SCOPES}


@router.get("/audit")
async def get_audit_log(limit: int = Query(50, ge=1, le=200)):
    """Retrieves immutable audit event logs for compliance verification."""
    async with get_db() as db:
        async with db.execute(
            "SELECT * FROM audit_events ORDER BY created_at DESC LIMIT ?",
            (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
            return {"status": "success", "total": len(rows), "events": [dict(r) for r in rows]}


@router.get("/{auth_id}")
async def get_authorization_detail(auth_id: str):
    """Retrieves an authorization by ID."""
    auth = await get_authorization(auth_id)
    if not auth:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Authorization '{auth_id}' not found.")
    return {"status": "success", "authorization": auth}


@router.post("/{auth_id}/revoke")
async def revoke_domain_authorization(auth_id: str, payload: RevokeAuthorizationRequest):
    """Revokes an authorization, immediately terminating scanning permissions."""
    try:
        revoked = await revoke_authorization(
            auth_id=auth_id,
            reason=payload.reason,
            operator_id=payload.operator_id
        )
        return {"status": "success", "authorization": revoked}
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
