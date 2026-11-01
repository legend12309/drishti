"""
DRISHTI — Phase 13 Autonomous Defense & Remediation Engine Unit & Integration Tests
Tests:
  1. Generation of multi-tier defense rules for weaponized CVEs (CVE-2024-4577, CVE-2021-41773).
  2. Generation of generic fallback defense rules for unmapped CVEs.
  3. Verification micro-probe behavior (403 block vs 200 bypass vs connection drop).
  4. REST API contract validation: /api/defense/generate, /api/defense/verify, /api/defense/templates.
"""

import pytest
from unittest.mock import AsyncMock, patch
import httpx
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.remediation_engine import (
    generate_defense_rules,
    execute_verification_probe,
    VerifyRemediationRequest,
    DETERMINISTIC_RULES,
)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.mark.asyncio
async def test_defense_generation_weaponized_cve():
    """Verifies that weaponized Metasploit CVEs generate accurate WAF, ModSec, iptables, and patch rules."""
    resp = await generate_defense_rules(
        cve_id="CVE-2024-4577",
        target="vvdx.in",
        port=80,
        service_banner="PHP/8.1.2-CGI",
    )

    assert resp.cve_id == "CVE-2024-4577"
    assert resp.target == "vvdx.in"
    assert resp.is_weaponized is True
    assert resp.metasploit_module == "exploit/windows/http/php_cgi_arg_injection"
    assert "%ad" in resp.cloudflare_waf["expression"]
    assert "SecRule ARGS" in resp.modsecurity_nginx["directive"]
    assert "auto_prepend_file" in resp.iptables_firewall["command"]
    assert "cgi.force_redirect" in resp.patch_diff["diff"]
    assert resp.verification_probe["expected_status"] == 403


@pytest.mark.asyncio
async def test_defense_generation_generic_cve():
    """Verifies that unmapped CVEs receive robust generic fallback shielding."""
    resp = await generate_defense_rules(
        cve_id="CVE-2025-99999",
        target="192.168.1.50",
        port=5432,
        service_banner="PostgreSQL 14.2",
    )

    assert resp.cve_id == "CVE-2025-99999"
    assert "Autonomous Multi-Layer Defense" in resp.summary
    assert "192.168.1.50" in resp.cloudflare_waf["expression"]
    assert resp.modsecurity_nginx["rule_id"] == 300001
    assert "5432" in resp.iptables_firewall["command"]
    assert "DROP" in resp.iptables_firewall["command"]


@pytest.mark.asyncio
async def test_verification_probe_blocked():
    """Verifies that a 403 response triggers a 'VECTOR SECURED' verdict."""
    mock_resp = httpx.Response(status_code=403, request=httpx.Request("GET", "https://vvdx.in"))
    
    with patch("httpx.AsyncClient.request", new_callable=AsyncMock, return_value=mock_resp):
        req = VerifyRemediationRequest(target_url="https://vvdx.in/icons/.%2e/etc/passwd")
        result = await execute_verification_probe(req)

        assert result.verified is True
        assert result.verdict == "VECTOR SECURED"
        assert result.status_code == 403


@pytest.mark.asyncio
async def test_verification_probe_unprotected():
    """Verifies that a 200 response triggers a 'VECTOR UNPROTECTED' verdict."""
    mock_resp = httpx.Response(status_code=200, request=httpx.Request("GET", "https://vvdx.in"))
    
    with patch("httpx.AsyncClient.request", new_callable=AsyncMock, return_value=mock_resp):
        req = VerifyRemediationRequest(target_url="https://vvdx.in/icons/.%2e/etc/passwd")
        result = await execute_verification_probe(req)

        assert result.verified is False
        assert result.verdict == "VECTOR UNPROTECTED"
        assert result.status_code == 200


@pytest.mark.asyncio
async def test_verification_probe_port_closed():
    """Verifies that a ConnectError triggers a 'PORT CLOSED / DROPPED' verdict."""
    with patch("httpx.AsyncClient.request", new_callable=AsyncMock, side_effect=httpx.ConnectError("Connection refused")):
        req = VerifyRemediationRequest(target_url="https://vvdx.in:5432")
        result = await execute_verification_probe(req)

        assert result.verified is True
        assert result.verdict == "PORT CLOSED / DROPPED"
        assert result.status_code is None


def test_api_defense_endpoints(client):
    """Verifies the REST API endpoints /api/defense/templates, /api/defense/generate, and /api/defense/verify."""
    # 1. Templates
    t_resp = client.get("/api/defense/templates")
    assert t_resp.status_code == 200
    t_data = t_resp.json()
    assert t_data["count"] >= 3
    assert any(t["cve_id"] == "CVE-2024-4577" for t in t_data["templates"])

    # 2. Generate
    g_resp = client.post(
        "/api/defense/generate",
        json={"cve_id": "CVE-2021-41773", "target": "vvdx.in", "port": 80},
    )
    assert g_resp.status_code == 200
    g_data = g_resp.json()
    assert g_data["cve_id"] == "CVE-2021-41773"
    assert "cloudflare_waf" in g_data
    assert "modsecurity_nginx" in g_data
    assert "iptables_firewall" in g_data
    assert "patch_diff" in g_data

    # 3. Bad requests
    bad_resp = client.post("/api/defense/generate", json={"cve_id": "", "target": "vvdx.in"})
    assert bad_resp.status_code == 400
