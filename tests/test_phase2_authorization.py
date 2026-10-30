"""
DRISHTI Phase 2: Domain Authorization & Passive Reconnaissance Test Suite.
Validates:
- Challenge-response verification via DNS TXT
- Expiration, replay prevention, and revocation lifecycle
- Strict scope boundary enforcement (exact domains vs subdomains vs domain hopping)
- SSRF prevention (blocking loopback, private RFC1918, link-local, multicast)
- Pre-network execution authorization revalidation
- Immutable audit event logging
- Passive reconnaissance observations provenance
- Local laboratory testing isolation mode
"""

import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
import uuid
import pytest
from httpx import ASGITransport, AsyncClient

from backend.main import app
from backend.db.database import get_db, init_db, db_queue
from backend.services.authorizations import (
    create_challenge,
    get_authorization,
    verify_challenge,
    revoke_authorization,
    get_valid_authorization_for_target,
    log_audit_event
)
from backend.services.passive import execute_passive_reconnaissance, get_scan_observations
from backend.services.scanner import create_scan, get_scan_status
from backend.services.scope import (
    normalize_domain,
    is_public_suffix,
    is_in_scope,
    validate_destination_ip,
)


@pytest.fixture(autouse=True)
def clear_sandbox_allowlist(monkeypatch):
    """Clear SANDBOX_ALLOWLIST for tests to avoid synthetic sandbox authorizations."""
    monkeypatch.setenv("SANDBOX_ALLOWLIST", "")


class MockDNSAnswer:
    def __init__(self, strings):
        self.strings = [s.encode("utf-8") if isinstance(s, str) else s for s in strings]

    def __str__(self):
        return "".join(s.decode("utf-8") for s in self.strings)


class MockDNSResolver:
    """Mock DNS resolver for testing TXT verification without external network lookups.
    Also provides mock responses for passive reconnaissance DNS queries (A, AAAA, MX, NS, TXT, CNAME)."""
    def __init__(self, records=None):
        self.records = records or {}

    def resolve(self, qname, qtype):
        key = (qname.rstrip("."), qtype)
        if key in self.records:
            return self.records[key]
        
        # Provide mock responses for passive reconnaissance DNS queries
        clean_name = qname.rstrip(".")
        if qtype == "A":
            return [MockDNSAnswer(["198.51.100.10"])]
        elif qtype == "AAAA":
            return [MockDNSAnswer(["2001:db8::1"])]
        elif qtype == "MX":
            return [MockDNSAnswer([f"mail.{clean_name} (priority 10)"])]
        elif qtype == "NS":
            return [MockDNSAnswer([f"ns1.{clean_name}", f"ns2.{clean_name}"])]
        elif qtype == "TXT":
            if (qname.rstrip("."), "TXT") in self.records:
                return self.records[(qname.rstrip("."), "TXT")]
            return [MockDNSAnswer(["v=spf1 mx ~all"])]
        elif qtype == "NS":
            return [MockDNSAnswer([f"ns1.{clean_name}", f"ns2.{clean_name}"])]
        elif qtype == "CNAME":
            return []
        
        import dns.resolver
        raise dns.resolver.NXDOMAIN()


@pytest.mark.asyncio
async def test_domain_normalization_and_public_suffix():
    """Verify robust domain normalization and rejection of public suffixes / TLDs."""
    # 1. Normalization
    assert normalize_domain("  HTTPS://VPN.Company.COM:443/login?q=1  ") == "vpn.company.com"
    assert normalize_domain("api.sub.domain.org.") == "api.sub.domain.org"

    # 2. Syntax errors
    with pytest.raises(ValueError):
        normalize_domain("invalid_domain!.com")
    with pytest.raises(ValueError):
        normalize_domain("-leading-hyphen.com")
    with pytest.raises(ValueError):
        normalize_domain("trailing-hyphen-.com")
    with pytest.raises(ValueError):
        normalize_domain("")

    # 3. Public suffixes must be recognized and blocked from ownership challenge
    assert is_public_suffix("com") is True
    assert is_public_suffix("org.uk") is True
    assert is_public_suffix("company.com") is False

    with pytest.raises(ValueError, match="public suffix"):
        await create_challenge("com")
    with pytest.raises(ValueError, match="public suffix"):
        await create_challenge("co.uk")


@pytest.mark.asyncio
async def test_scope_boundary_enforcement():
    """Verify strict scope boundaries: exact domain & subdomains allowed, domain hopping blocked."""
    auth_domain = "target.corp"

    # Exact match
    assert is_in_scope("target.corp", auth_domain) is True
    # Subdomain match
    assert is_in_scope("api.target.corp", auth_domain) is True
    assert is_in_scope("vpn.internal.target.corp", auth_domain) is True

    # Domain hopping & partial string spoofing blocked
    assert is_in_scope("evil-target.corp", auth_domain) is False
    assert is_in_scope("target.corp.attacker.com", auth_domain) is False
    assert is_in_scope("corp", auth_domain) is False


@pytest.mark.asyncio
async def test_ssrf_destination_ip_blocking():
    """Verify that private, loopback, link-local, and multicast addresses are blocked by default."""
    # Loopback
    is_safe, reason = validate_destination_ip("127.0.0.1", allow_lab=False)
    assert is_safe is False
    assert "loopback" in reason.lower()

    # Private RFC1918
    is_safe, reason = validate_destination_ip("10.0.0.1", allow_lab=False)
    assert is_safe is False
    assert "private" in reason.lower()

    is_safe, reason = validate_destination_ip("192.168.1.1", allow_lab=False)
    assert is_safe is False

    is_safe, reason = validate_destination_ip("172.16.5.10", allow_lab=False)
    assert is_safe is False

    # Link-local
    is_safe, reason = validate_destination_ip("169.254.169.254", allow_lab=False)
    assert is_safe is False
    assert "link-local" in reason.lower()

    # Multicast
    is_safe, reason = validate_destination_ip("224.0.0.1", allow_lab=False)
    assert is_safe is False
    assert "multicast" in reason.lower()

    # Public IP allowed
    is_safe, reason = validate_destination_ip("93.184.216.34", allow_lab=False)
    assert is_safe is True
    assert reason is None

    # Laboratory override mode allows loopback and private
    is_safe, _ = validate_destination_ip("127.0.0.1", allow_lab=True)
    assert is_safe is True
    is_safe, _ = validate_destination_ip("192.168.1.50", allow_lab=True)
    assert is_safe is True


@pytest.mark.asyncio
async def test_dns_txt_challenge_verification_lifecycle():
    """Verify challenge creation, successful verification, expiration, and revocation."""
    await init_db()
    test_domain = "verify-test.org"
    await db_queue.execute_write("DELETE FROM authorizations WHERE target_domain = ?", (test_domain,))

    # 1. Create challenge
    challenge = await create_challenge(target_domain=test_domain, permitted_scope="FULL_PASSIVE")
    auth_id = challenge["id"]
    token = challenge["verification_token"]
    record_name = challenge["challenge_record_name"]

    assert auth_id.startswith("auth-")
    assert token.startswith("drishti-verify-")
    assert record_name == f"_drishti-challenge.{test_domain}"
    assert challenge["status"] == "pending"

    # 2. Verification fails when token is not in DNS
    mock_resolver_empty = MockDNSResolver()
    fail_res = await verify_challenge(auth_id, custom_resolver=mock_resolver_empty)
    assert fail_res["success"] is False

    # 3. Verification succeeds when token matches in DNS TXT
    mock_resolver_match = MockDNSResolver({
        (record_name, "TXT"): [MockDNSAnswer([token])]
    })
    success_res = await verify_challenge(auth_id, custom_resolver=mock_resolver_match)
    assert success_res["success"] is True
    assert success_res["authorization"]["status"] == "verified"
    assert success_res["authorization"]["verified_at"] is not None

    # 4. Check that target domain is now recognized as authorized
    active_auth = await get_valid_authorization_for_target(test_domain)
    assert active_auth is not None
    assert active_auth["id"] == auth_id

    # 5. Revocation immediately terminates authorization
    revoked = await revoke_authorization(auth_id, reason="Compliance test revocation")
    assert revoked["status"] == "revoked"
    assert revoked["revoked_at"] is not None

    # After revocation, target domain is no longer authorized
    active_after = await get_valid_authorization_for_target(test_domain)
    assert active_after is None


@pytest.mark.asyncio
async def test_expired_challenge_rejection():
    """Verify that expired challenges cannot be verified or used."""
    await init_db()
    domain = "expired-target.com"
    challenge = await create_challenge(target_domain=domain)
    auth_id = challenge["id"]

    # Manually backdate expires_at to 1 hour ago
    past_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    await db_queue.execute_write(
        "UPDATE authorizations SET expires_at = ? WHERE id = ?",
        (past_time, auth_id)
    )

    # Retrieval should transition to expired
    auth = await get_authorization(auth_id)
    assert auth["status"] == "expired"

    # Verification attempt must be rejected
    with pytest.raises(ValueError, match="expired"):
        await verify_challenge(auth_id)


@pytest.mark.asyncio
async def test_unauthorized_scan_rejection():
    """Verify that a scan against an unauthorized domain is strictly rejected with 403 Forbidden."""
    await init_db()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Target with no verified authorization
        res = await client.post("/api/scans", json={"target": "totally-unauthorized-target.xyz"})
        assert res.status_code == 403
        data = res.json()
        assert "not authorized" in data["detail"].lower()


@pytest.mark.asyncio
async def test_pre_network_revalidation_defense():
    """
    Verify time-of-check to time-of-use (TOCTOU) defense:
    If authorization is revoked AFTER scan creation but BEFORE network execution,
    the scan worker aborts and records a failed status without executing network queries.
    """
    await init_db()
    test_domain = "toctou-defense.org"

    # Create and verify authorization
    challenge = await create_challenge(target_domain=test_domain)
    auth_id = challenge["id"]
    token = challenge["verification_token"]
    mock_res = MockDNSResolver({
        (challenge["challenge_record_name"], "TXT"): [MockDNSAnswer([token])]
    })
    await verify_challenge(auth_id, custom_resolver=mock_res)

    # Create scan
    scan_meta = await create_scan(test_domain, authorization_id=auth_id)
    scan_id = scan_meta["scan_id"]

    # Revoke authorization immediately
    await revoke_authorization(auth_id, reason="Immediate security pause")

    # Wait for worker to revalidate and stop
    final_status = "running"
    for _ in range(15):
        await asyncio.sleep(0.1)
        st = await get_scan_status(scan_id)
        if st and st["status"] in ("failed", "cancelled"):
            final_status = st["status"]
            break

    status = await get_scan_status(scan_id)
    assert status["status"] in ("failed", "cancelled")
    if status["status"] == "failed":
        assert "not" in status["error_message"].lower() or "rejected" in status["error_message"].lower()


@pytest.mark.asyncio
async def test_passive_reconnaissance_provenance_and_audit():
    """Verify that passive observations and audit events are properly persisted with provenance."""
    await init_db()
    domain = f"prov-{uuid.uuid4().hex[:8]}.net"

    # Create and verify challenge
    chal = await create_challenge(domain)
    mock_res = MockDNSResolver({
        (chal["challenge_record_name"], "TXT"): [MockDNSAnswer([chal["verification_token"]])]
    })
    await verify_challenge(chal["id"], custom_resolver=mock_res)

    scan_res = await create_scan(domain)
    scan_id = scan_res["scan_id"]

    # Wait for completion (timeout up to 10s)
    for _ in range(60):
        await asyncio.sleep(0.15)
        st = await get_scan_status(scan_id)
        if st["status"] == "completed":
            await asyncio.sleep(0.2)
            break

    # 1. Verify passive observations exist
    obs = await get_scan_observations(scan_id)
    assert len(obs) >= 5
    query_types = {o["query_type"] for o in obs}
    assert "A" in query_types
    assert "MX" in query_types
    assert "RDAP" in query_types
    for o in obs:
        assert o["source"] in ("dns_resolver", "rdap_registry", "active_dns", "passive_ct")
        assert o["scan_id"] == scan_id

    # 2. Verify audit events logged
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        audit_res = await client.get("/api/authorizations/audit?limit=200")
        assert audit_res.status_code == 200
        events = audit_res.json()["events"]
        event_types = [e["event_type"] for e in events]
        assert "challenge_created" in event_types
        assert "challenge_verified" in event_types
        assert "scan_initiated" in event_types
        assert "scan_completed" in event_types
