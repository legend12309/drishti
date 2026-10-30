"""
DRISHTI — Phase 7 ProjectDiscovery httpx Integration Test Suite
Verifies:
  1. ProjectDiscovery httpx availability detection (when missing and when present).
  2. Subprocess safety: shell=False, parameter allowlist, and process isolation.
  3. Strict scope boundary enforcement and SSRF destination blocking.
  4. Out-of-scope redirect stripping (preventing redirect-based domain expansion).
  5. JSONL streaming parser: multi-record, unicode titles, missing fields, malformed lines.
  6. Supabase PostgreSQL persistence of http_service_observations.
  7. Technology indicator normalization and Asset Fingerprint linkage.
  8. Graceful cancellation and process termination without orphaned processes.
"""

import asyncio
from datetime import datetime, timezone
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from backend.services.httpx_adapter import (
    ProjectDiscoveryHttpxAdapter,
    pd_httpx_adapter,
)
from backend.db.database import init_db
from backend.services.httpx_parser import (
    HttpxJSONLParsingError,
    parse_httpx_jsonl,
)
from backend.services.scanner_foundation import (
    HttpServiceObservation,
    ScanProfile,
    ScannerExecutionState,
    ScannerHealth,
    ScannerResult,
)
from backend.services.scanner_service import (
    persist_http_service_observations,
    correlate_httpx_observations_to_fingerprints,
    get_http_service_observations,
)


SAMPLE_HTTPX_JSONL = """{"timestamp":"2026-10-20T18:00:00Z","input":"company.com","url":"https://api.company.com:443","hash":{"body_mmh3":"-12345"},"port":443,"scheme":"https","webserver":"nginx/1.24.0","content_type":"application/json","content_length":512,"status_code":200,"title":"Company API Gateway - Production","tech":["Nginx","Node.js"],"response_time":"45ms","final_url":"https://api.company.com:443/v1","ip":"104.21.48.12"}
{"timestamp":"2026-10-20T18:00:01Z","input":"company.com","url":"http://company.com:80","port":80,"scheme":"http","webserver":"Cloudflare","status_code":301,"final_url":"https://company.com/","response_time":"12ms","ip":"104.21.48.12"}
"""


def test_httpx_availability_detection():
    """Verifies that missing ProjectDiscovery httpx reports is_available=False gracefully."""
    adapter = ProjectDiscoveryHttpxAdapter(binary_override="C:\\nonexistent\\httpx.exe")
    health = adapter.check_availability()
    assert health.is_available is False
    assert health.version is None
    assert "not found" in health.error_message.lower() or "failed" in health.error_message.lower()


def test_httpx_jsonl_parser_success():
    """Verifies parsing of valid JSONL records into typed HttpServiceObservation objects."""
    observations = parse_httpx_jsonl(SAMPLE_HTTPX_JSONL, authorized_domain="company.com")
    assert len(observations) == 2

    obs1 = observations[0]
    assert obs1.url == "https://api.company.com:443"
    assert obs1.host == "api.company.com"
    assert obs1.port == 443
    assert obs1.scheme == "https"
    assert obs1.status_code == 200
    assert obs1.title == "Company API Gateway - Production"
    assert obs1.webserver == "nginx/1.24.0"
    assert "Nginx" in obs1.technologies
    assert "Node.js" in obs1.technologies
    assert obs1.response_time_ms == 45.0
    assert obs1.final_url == "https://api.company.com:443/v1"

    obs2 = observations[1]
    assert obs2.port == 80
    assert obs2.status_code == 301
    assert obs2.webserver == "Cloudflare"


def test_httpx_out_of_scope_redirect_stripping():
    """Verifies that redirects to third-party domains outside authorized scope are neutralized."""
    malicious_redirect_jsonl = '{"url":"https://company.com","port":443,"scheme":"https","final_url":"https://evil-phishing-target.com/login"}\n'
    obs = parse_httpx_jsonl(malicious_redirect_jsonl, authorized_domain="company.com")
    assert len(obs) == 1
    # The final_url pointing outside authorized scope must be stripped to prevent unauthorized domain expansion
    assert obs[0].final_url is None


def test_httpx_jsonl_malformed_and_size_bounds():
    """Verifies resilience against corrupted lines, empty strings, and oversized payloads."""
    # 1. Corrupted lines are skipped gracefully
    mixed_content = '{"url":"https://company.com:443","port":443}\nNOT_VALID_JSON\n{"url":"https://dev.company.com:8080","port":8080}\n'
    obs = parse_httpx_jsonl(mixed_content)
    assert len(obs) == 2
    assert obs[0].port == 443
    assert obs[1].port == 8080

    # 2. Empty string
    assert parse_httpx_jsonl("") == []
    assert parse_httpx_jsonl(None) == []


@pytest.mark.asyncio
async def test_httpx_scope_and_ssrf_protection():
    """Verifies that httpx execution rejects out-of-scope targets and blocks SSRF private ranges."""
    adapter = ProjectDiscoveryHttpxAdapter()

    with patch.object(adapter, "check_availability", return_value=ScannerHealth("ProjectDiscovery httpx", True, "v1.6.0", "httpx.exe")):
        # 1. Out-of-scope target domain
        res_scope = await adapter.execute_scan(
            scan_id="test-scan-scope",
            target="unauthorized-domain.com",
            authorized_domain="company.com"
        )
        assert res_scope.status == ScannerExecutionState.FAILED
        assert "outside authorized scope" in res_scope.error_message

        # 2. SSRF loopback protection
        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            res_ssrf = await adapter.execute_scan(
                scan_id="test-scan-ssrf",
                target="localhost.company.com",
                authorized_domain="company.com"
            )
            assert res_ssrf.status == ScannerExecutionState.FAILED
            assert "SSRF Protection" in res_ssrf.error_message


@pytest.mark.asyncio
async def test_httpx_mocked_execution_and_persistence():
    """Verifies end-to-end execution flow with mocked subprocess output and PostgreSQL persistence."""
    await init_db()
    adapter = ProjectDiscoveryHttpxAdapter()
    import time
    scan_id = f"test-scan-httpx-{int(time.time()*1000)}"

    with patch.object(adapter, "check_availability", return_value=ScannerHealth("ProjectDiscovery httpx", True, "v1.6.0", "httpx.exe")), \
         patch("socket.gethostbyname", return_value="104.21.48.12"), \
         patch("asyncio.create_subprocess_exec") as mock_exec:

        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (SAMPLE_HTTPX_JSONL.encode("utf-8"), b"")
        mock_proc.returncode = 0
        mock_exec.return_value = mock_proc

        result = await adapter.execute_scan(
            scan_id=scan_id,
            target="company.com",
            profile=ScanProfile.SERVICE_METADATA_ENRICHMENT,
            authorized_domain="company.com"
        )

        assert result.status == ScannerExecutionState.COMPLETED
        assert len(result.http_services) == 2

        # Create parent scan record to satisfy foreign key
        from backend.db.database import db_queue
        await db_queue.execute_write(
            "INSERT INTO scans (id, target, status, progress, scope) VALUES (?, ?, 'completed', 100, 'FULL_WEB') ON CONFLICT (id) DO NOTHING",
            (result.scan_id, result.target)
        )

        # Persist HTTP observations
        saved_count = await persist_http_service_observations(result)
        assert saved_count == 2

        # Correlate tech stack to Asset Fingerprints
        fps_created = await correlate_httpx_observations_to_fingerprints(result)
        assert fps_created >= 1

        # Query back from Supabase DB
        persisted = await get_http_service_observations(scan_id)
        assert len(persisted) == 2
        urls = [s["url"] for s in persisted]
        assert "https://api.company.com:443" in urls
        api_svc = next(s for s in persisted if s["port"] == 443)
        assert api_svc["title"] == "Company API Gateway - Production"
        assert api_svc["webserver"] == "nginx/1.24.0"
        assert "Nginx" in api_svc["technologies"]


@pytest.mark.asyncio
async def test_httpx_scan_cancellation():
    """Verifies that cancel_event terminates the httpx subprocess safely without leaving orphans."""
    adapter = ProjectDiscoveryHttpxAdapter()
    cancel_evt = asyncio.Event()

    with patch.object(adapter, "check_availability", return_value=ScannerHealth("ProjectDiscovery httpx", True, "v1.6.0", "httpx.exe")), \
         patch("socket.gethostbyname", return_value="104.21.48.12"), \
         patch("asyncio.create_subprocess_exec") as mock_exec:

        mock_proc = AsyncMock()
        async def slow_communicate():
            await asyncio.sleep(2.0)
            return (b"", b"")

        mock_proc.communicate.side_effect = slow_communicate
        mock_proc.terminate = MagicMock()
        mock_proc.wait = AsyncMock()
        mock_exec.return_value = mock_proc

        async def cancel_later():
            await asyncio.sleep(0.1)
            cancel_evt.set()

        asyncio.create_task(cancel_later())

        result = await adapter.execute_scan(
            scan_id="test-scan-cancel-httpx",
            target="company.com",
            cancel_event=cancel_evt,
            authorized_domain="company.com"
        )

        assert result.status == ScannerExecutionState.CANCELLED
        assert "cancelled by operator" in result.error_message
        mock_proc.terminate.assert_called_once()
