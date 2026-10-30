"""
DRISHTI — Phase 1 Detective Engine Unit & Integration Test Suite
Validates the complete reconnaissance pipeline:
1. Passive Subdomain Enumeration (crt.sh & Wayback Machine CDX API)
2. Active DNS Wordlist Brute-Forcing with SSRF Protection
3. HTTP/HTTPS Liveness & Technology Fingerprinting
4. Content Discovery & Sensitive File Fuzzing (.git, .env, backups)
5. Asset Inventory Normalization and Database Persistence
6. Cooperative Cancellation & Error Resilience
7. API Endpoint Verification (/api/recon/detective)
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from httpx import ASGITransport, AsyncClient

from backend.main import app
from backend.db.database import init_db, get_db
from backend.services.detective import (
    DetectiveEngine,
    detective_engine,
    DiscoveredAsset,
    ExposedFinding,
    SUBDOMAIN_WORDLIST,
    SENSITIVE_PATHS,
)


@pytest.mark.asyncio
async def test_crtsh_subdomain_parsing():
    """Verify that crt.sh JSON output is parsed cleanly, wildcards stripped, and out-of-scope domains rejected."""
    mock_crt_json = [
        {"name_value": "api.target.com\nvpn.target.com"},
        {"name_value": "*.target.com"},
        {"name_value": "mail.target.com"},
        {"name_value": "evil-target.com"},  # Out of scope domain hopping
        {"name_value": "target.com.attacker.org"},  # Out of scope
    ]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_crt_json

    engine = DetectiveEngine()
    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        subs = await engine.fetch_crtsh_subdomains("target.com")

        assert "api.target.com" in subs
        assert "vpn.target.com" in subs
        assert "mail.target.com" in subs
        # Wildcard stripped
        assert "*.target.com" not in subs
        # Out-of-scope rejected
        assert "evil-target.com" not in subs
        assert "target.com.attacker.org" not in subs


@pytest.mark.asyncio
async def test_wayback_cdx_subdomain_and_url_mining():
    """Verify historical URL mining via Wayback Machine CDX API."""
    mock_cdx_json = [
        ["original"],  # Header row
        ["https://admin.target.com/login.php"],
        ["https://dev.target.com/api/v1/users"],
        ["https://target.com/archive/backup.zip"],
        ["https://out-of-scope.org/index.html"],
    ]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_cdx_json

    engine = DetectiveEngine()
    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        subs, urls = await engine.fetch_wayback_endpoints("target.com")

        assert "admin.target.com" in subs
        assert "dev.target.com" in subs
        assert "out-of-scope.org" not in subs
        assert "https://target.com/archive/backup.zip" in urls


@pytest.mark.asyncio
async def test_active_dns_bruteforce_with_ssrf_blocking():
    """Verify active DNS enumeration resolves candidates and strictly drops SSRF prohibited IPs."""
    engine = DetectiveEngine()

    class MockRData:
        def __init__(self, ip):
            self.address = ip

    # Mock resolver resolving:
    # api.target.corp -> 93.184.216.34 (public, permitted)
    # dev.target.corp -> 127.0.0.1 (loopback, blocked by SSRF)
    # internal.target.corp -> 10.0.0.1 (private RFC1918, blocked by SSRF)
    def mock_resolve(qname, qtype):
        if "api." in qname:
            return [MockRData("93.184.216.34")]
        elif "dev." in qname:
            return [MockRData("127.0.0.1")]
        elif "internal." in qname:
            return [MockRData("10.0.0.1")]
        raise Exception("NXDOMAIN")

    mock_res = MagicMock()
    mock_res.resolve.side_effect = mock_resolve

    resolved = await engine.brute_force_subdomains(
        domain="target.corp",
        wordlist=["api", "dev", "internal", "nonexistent"],
        custom_resolver=mock_res
    )

    assert "api.target.corp" in resolved
    assert resolved["api.target.corp"] == "93.184.216.34"
    # SSRF blocked targets must NOT be included in valid live hosts
    assert "dev.target.corp" not in resolved
    assert "internal.target.corp" not in resolved


@pytest.mark.asyncio
async def test_sensitive_path_fuzzing_git_and_env_exposure():
    """
    Verify content discovery / sensitive path fuzzing finds exposed .git and .env
    files with signature verification and evidence capture.
    """
    engine = DetectiveEngine()

    async def mock_get(url):
        resp = MagicMock()
        if "/.git/HEAD" in url:
            resp.status_code = 200
            resp.text = "ref: refs/heads/main\n"
            resp.content = resp.text.encode("utf-8")
        elif "/.env" in url:
            resp.status_code = 200
            resp.text = "DB_HOST=10.0.0.5\nDB_PASSWORD=SuperSecretKey123\nSECRET_KEY=jwt_secret\n"
            resp.content = resp.text.encode("utf-8")
        elif "/backup.sql" in url:
            resp.status_code = 200
            resp.text = "-- MySQL dump\nCREATE TABLE users (id int, password varchar(255));\n"
            resp.content = resp.text.encode("utf-8")
        else:
            resp.status_code = 404
            resp.text = "Not Found"
            resp.content = b""
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        findings = await engine.fuzz_sensitive_paths("https://target.corp", "target.corp")

        exp_types = [f.exposure_type for f in findings]
        assert "git_repo_exposure" in exp_types
        assert "env_secrets_leak" in exp_types
        assert "database_backup_leak" in exp_types

        git_finding = next(f for f in findings if f.exposure_type == "git_repo_exposure")
        assert git_finding.severity == "CRITICAL"
        assert "refs/heads/main" in git_finding.evidence_snippet

        env_finding = next(f for f in findings if f.exposure_type == "env_secrets_leak")
        assert env_finding.severity == "CRITICAL"
        assert "DB_" in env_finding.evidence_snippet


@pytest.mark.asyncio
async def test_detective_pipeline_execution_and_persistence():
    """Verify complete Detective pipeline execution and asset inventory persistence in database."""
    await init_db()
    scan_id = "test-detective-pipe-01"
    target = "company.com"

    result = await detective_engine.run_pipeline(
        target=target,
        scan_id=scan_id,
        authorization_id="auth-demo-company"
    )

    assert result.scan_id == scan_id
    assert result.target == target
    assert result.total_live_hosts >= 3
    assert len(result.assets) >= 3

    # Verify rows in scan_findings table
    async with get_db() as db:
        async with db.execute("SELECT host, tech, risk FROM scan_findings WHERE scan_id = ?", (scan_id,)) as cur:
            rows = await cur.fetchall()
            assert len(rows) >= 3
            hosts = [r[0] for r in rows]
            assert any("vpn" in h for h in hosts)
            assert any("api" in h for h in hosts)


@pytest.mark.asyncio
async def test_detective_pipeline_cancellation():
    """Verify cooperative cancellation in Detective pipeline."""
    cancel_ev = asyncio.Event()
    cancel_ev.set()  # Cancelled before start

    res = await detective_engine.run_pipeline(
        target="example.com",
        scan_id="test-detective-cancelled",
        cancel_event=cancel_ev
    )
    assert res.total_subdomains == 0
    assert len(res.assets) == 0


@pytest.mark.asyncio
async def test_detective_api_endpoint():
    """Verify /api/recon/detective endpoint contract and JSON response format."""
    await init_db()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/recon/detective", json={"domain": "example.com"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["target"] == "example.com"
        assert "total_subdomains" in data
        assert "assets" in data
        assert len(data["assets"]) >= 1
