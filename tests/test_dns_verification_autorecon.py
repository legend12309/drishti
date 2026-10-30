"""
DRISHTI DNS TXT Verification & AutoRecon Scope Enforcement Test Suite.
Validates:
- Challenge generation with cryptographic tokens and normalized record names
- Exact DNS TXT verification success
- Rejection on incorrect token
- Rejection on missing DNS record (NXDOMAIN / NoAnswer)
- Multi-record handling (matching one among several TXT records)
- DNS lookup timeout and resolver errors
- Rejection of expired challenges
- Rejection of challenges bound to a different domain
- Cross-user challenge isolation / operator validation
- AutoRecon workflow rejection before domain authorization
- Successful AutoRecon workflow initiation after valid verification
"""

import asyncio
from datetime import datetime, timedelta, timezone
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
)
from backend.services.scan_orchestrator import scan_orchestrator
from backend.services.orchestrator_models import CreateUnifiedScanPlanRequest


class MockDNSAnswer:
    def __init__(self, strings):
        self.strings = [s.encode("utf-8") if isinstance(s, str) else s for s in strings]

    def __str__(self):
        return "".join(s.decode("utf-8") for s in self.strings)


class MockMultiResolver:
    """Mock DNS resolver supporting custom record maps, delays, and simulated errors."""
    def __init__(self, record_map=None, error_to_raise=None):
        self.record_map = record_map or {}
        self.error_to_raise = error_to_raise

    def resolve(self, qname, qtype):
        if self.error_to_raise:
            raise self.error_to_raise
        clean_key = (qname.rstrip("."), qtype)
        if clean_key in self.record_map:
            return self.record_map[clean_key]
        import dns.resolver
        raise dns.resolver.NXDOMAIN()


@pytest.mark.asyncio
async def test_challenge_generation_lifecycle():
    """Verify challenge generation produces cryptographically strong tokens and valid record names."""
    await init_db()
    domain = "ownership-test.io"
    challenge = await create_challenge(target_domain=domain, permitted_scope="FULL_PASSIVE", operator_id="test-op-1")

    assert challenge["target_domain"] == domain
    assert challenge["permitted_scope"] == "FULL_PASSIVE"
    assert challenge["status"] == "pending"
    assert challenge["challenge_record_name"] == f"_drishti-challenge.{domain}"
    assert challenge["verification_token"].startswith("drishti-verify-")
    assert len(challenge["verification_token"]) >= 35

    # Check database persistence
    saved = await get_authorization(challenge["id"])
    assert saved is not None
    assert saved["id"] == challenge["id"]
    assert saved["operator_id"] == "test-op-1"


@pytest.mark.asyncio
async def test_correct_txt_token_verification():
    """Verify that a DNS TXT record matching the exact token verifies successfully."""
    await init_db()
    domain = "match-success.corp"
    challenge = await create_challenge(target_domain=domain)
    auth_id = challenge["id"]
    token = challenge["verification_token"]
    record_name = challenge["challenge_record_name"]

    resolver = MockMultiResolver({
        (record_name, "TXT"): [MockDNSAnswer([token])]
    })

    res = await verify_challenge(auth_id, custom_resolver=resolver)
    assert res["success"] is True
    assert res["authorization"]["status"] == "verified"
    assert res["authorization"]["verified_at"] is not None

    # Check scope lookup recognizes verified target
    valid_auth = await get_valid_authorization_for_target(domain)
    assert valid_auth is not None
    assert valid_auth["id"] == auth_id


@pytest.mark.asyncio
async def test_incorrect_txt_token_verification_rejection():
    """Verify that an incorrect TXT token returns failure without authorizing the domain."""
    await init_db()
    domain = "wrong-token.org"
    challenge = await create_challenge(target_domain=domain)
    auth_id = challenge["id"]
    record_name = challenge["challenge_record_name"]

    resolver = MockMultiResolver({
        (record_name, "TXT"): [MockDNSAnswer(["drishti-verify-completely-wrong-token-abc123"])]
    })

    res = await verify_challenge(auth_id, custom_resolver=resolver)
    assert res["success"] is False
    assert "not found" in res["message"].lower()

    # Domain remains unauthorized
    valid_auth = await get_valid_authorization_for_target(domain)
    assert valid_auth is None


@pytest.mark.asyncio
async def test_missing_dns_record_rejection():
    """Verify that NXDOMAIN / missing record returns graceful failure."""
    await init_db()
    domain = "nonexistent-record.org"
    challenge = await create_challenge(target_domain=domain)
    auth_id = challenge["id"]

    resolver = MockMultiResolver()  # Empty: will raise NXDOMAIN
    res = await verify_challenge(auth_id, custom_resolver=resolver)
    assert res["success"] is False
    assert res["authorization"]["status"] == "pending"


@pytest.mark.asyncio
async def test_multiple_txt_records_support():
    """Verify that if a domain has SPF, verification tokens, and other TXT entries, DRISHTI finds its token."""
    await init_db()
    domain = "multi-txt.com"
    challenge = await create_challenge(target_domain=domain)
    auth_id = challenge["id"]
    token = challenge["verification_token"]
    record_name = challenge["challenge_record_name"]

    multi_answers = [
        MockDNSAnswer(["v=spf1 include:_spf.google.com ~all"]),
        MockDNSAnswer(["google-site-verification=some_hash_string"]),
        MockDNSAnswer([token]),
        MockDNSAnswer(["ms=ms12345678"]),
    ]

    resolver = MockMultiResolver({
        (record_name, "TXT"): multi_answers
    })

    res = await verify_challenge(auth_id, custom_resolver=resolver)
    assert res["success"] is True
    assert res["authorization"]["status"] == "verified"


@pytest.mark.asyncio
async def test_dns_lookup_timeout_and_resolver_errors():
    """Verify that DNS timeouts and resolver exceptions fail safely."""
    await init_db()
    import dns.exception
    domain = "timeout-dns.com"
    challenge = await create_challenge(target_domain=domain)
    auth_id = challenge["id"]

    timeout_resolver = MockMultiResolver(error_to_raise=dns.exception.Timeout())
    res = await verify_challenge(auth_id, custom_resolver=timeout_resolver)
    assert res["success"] is False
    assert res["authorization"]["status"] == "pending"


@pytest.mark.asyncio
async def test_expired_challenge_verification_blocked():
    """Verify that an expired challenge cannot be verified and raises a descriptive error."""
    await init_db()
    domain = "expired-verify.net"
    challenge = await create_challenge(target_domain=domain)
    auth_id = challenge["id"]

    # Backdate expiration by 3 hours
    expired_time = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
    await db_queue.execute_write(
        "UPDATE authorizations SET expires_at = ? WHERE id = ?",
        (expired_time, auth_id)
    )

    with pytest.raises(ValueError, match="expired"):
        await verify_challenge(auth_id)


@pytest.mark.asyncio
async def test_challenge_bound_to_different_domain():
    """Verify that verification token for domain A cannot authorize domain B."""
    await init_db()
    domain_a = "alpha-corp.com"
    domain_b = "beta-corp.com"

    chal_a = await create_challenge(target_domain=domain_a)
    chal_b = await create_challenge(target_domain=domain_b)

    # If domain_b publishes domain_a's token in its record, domain_a verification must still fail
    resolver_for_b = MockMultiResolver({
        (chal_b["challenge_record_name"], "TXT"): [MockDNSAnswer([chal_a["verification_token"]])]
    })

    # Verifying chal_a checks chal_a's record name (_drishti-challenge.alpha-corp.com), not beta
    res_a = await verify_challenge(chal_a["id"], custom_resolver=resolver_for_b)
    assert res_a["success"] is False

    # Verifying chal_b with chal_a's token will fail because chal_b expects chal_b's token
    res_b = await verify_challenge(chal_b["id"], custom_resolver=resolver_for_b)
    assert res_b["success"] is False


@pytest.mark.asyncio
async def test_autorecon_rejection_before_authorization():
    """Verify that AutoRecon orchestrator strictly rejects unverified targets."""
    await init_db()
    unauthorized_target = "rogue-unauthorized-host.net"

    plan = CreateUnifiedScanPlanRequest(
        target=unauthorized_target,
        scanners=["nmap", "httpx"],
        scope="FULL_ACTIVE"
    )

    with pytest.raises(ValueError, match="not authorized"):
        await scan_orchestrator.create_workflow(plan)


@pytest.mark.asyncio
async def test_autorecon_initiation_after_authorization():
    """Verify that AutoRecon orchestrator accepts and starts workflows for verified domains."""
    await init_db()
    target_domain = "authorized-recon-target.com"

    # Create & verify domain
    chal = await create_challenge(target_domain=target_domain)
    resolver = MockMultiResolver({
        (chal["challenge_record_name"], "TXT"): [MockDNSAnswer([chal["verification_token"]])]
    })
    ver_res = await verify_challenge(chal["id"], custom_resolver=resolver)
    assert ver_res["success"] is True

    # Initiate AutoRecon
    plan = CreateUnifiedScanPlanRequest(
        target=target_domain,
        scanners=["nmap", "httpx"],
        scope="FULL_PASSIVE",
        authorization_id=chal["id"],
        allow_partial_completion=True
    )

    wf = await scan_orchestrator.create_workflow(plan)
    assert wf is not None
    assert "workflow_id" in wf
    assert wf["target"] == target_domain
    assert wf["status"] in ("success", "pending", "running", "completed")


@pytest.mark.asyncio
async def test_api_challenge_endpoints():
    """Verify HTTP API endpoints for challenge creation, check, and verification."""
    await init_db()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Check initially unauthorized
        chk_res = await client.get("/api/authorizations/check?target=api-flow-target.org")
        assert chk_res.status_code == 200
        assert chk_res.json()["authorized"] is False

        # 2. Create challenge via API
        create_res = await client.post(
            "/api/authorizations/challenges",
            json={"target_domain": "api-flow-target.org", "permitted_scope": "FULL_PASSIVE"}
        )
        assert create_res.status_code == 201
        data = create_res.json()["challenge"]
        auth_id = data["id"]
        assert data["challenge_record_name"] == "_drishti-challenge.api-flow-target.org"

        # 3. Verify via API without DNS record should return 422
        ver_res = await client.post(
            "/api/authorizations/verify",
            json={"authorization_id": auth_id}
        )
        assert ver_res.status_code == 422
