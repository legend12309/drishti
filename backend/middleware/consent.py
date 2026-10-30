"""
DRISHTI Consent & Scope Verification Middleware.
Implements RFC 8655 DNS TXT challenge validation with local DRISHTI_DEV_MODE bypass.
"""

import os
import logging
from typing import Optional, Dict, Any
from fastapi import HTTPException, status
import dns.asyncresolver
import dns.resolver
import dns.exception

logger = logging.getLogger("drishti.consent")


def is_dev_mode_active() -> bool:
    """Returns True if DRISHTI_DEV_MODE is enabled for local evaluation and testing."""
    val = os.getenv("DRISHTI_DEV_MODE", "false").strip().lower()
    return val in ("true", "1", "yes", "on")


async def verify_dns_txt_record(target_domain: str, challenge_token: Optional[str]) -> bool:
    """
    Queries public DNS resolvers for the _drishti-challenge.<domain> TXT record
    and verifies whether it matches the expected challenge token.
    """
    if not target_domain or not challenge_token:
        return False

    clean_domain = target_domain.strip().lower().rstrip(".")
    record_name = f"_drishti-challenge.{clean_domain}"

    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 4.0
        answers = await resolver.resolve(record_name, "TXT")
        for rdata in answers:
            txt = "".join(s.decode("utf-8") if isinstance(s, bytes) else str(s) for s in rdata.strings)
            clean_txt = txt.strip("\"'")
            if clean_txt == challenge_token or challenge_token in clean_txt:
                return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return False
    except Exception as ex:
        logger.warning(f"DNS TXT resolution error for {record_name}: {ex}")
        return False

    return False


async def validate_scan_consent(target_domain: str, token_payload: Optional[Dict[str, Any]] = None) -> bool:
    """
    Validates scan authorization.
    If DRISHTI_DEV_MODE=true, bypasses DNS TXT verification for frictionless local testing and demos.
    Otherwise, strictly verifies RFC 8655 DNS TXT record or raises 403 Forbidden.
    """
    # 1. Check if Local Dev Bypass is active
    if is_dev_mode_active():
        logger.warning(f"[DEV_MODE ACTIVE] Bypassing DNS TXT validation for target: {target_domain}")
        return True

    payload = token_payload or {}
    challenge_token = payload.get("challenge_token") or payload.get("verification_token")

    # 2. Production / Strict Mode Logic (RFC 8655 DNS TXT Verification)
    if not await verify_dns_txt_record(target_domain, challenge_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Consent verification failed: Missing or invalid DNS TXT record for {target_domain}"
        )

    return True
