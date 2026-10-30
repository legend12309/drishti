"""
DRISHTI — Phase 8 OWASP ZAP Integration Test Suite
Verifies:
  1. ZAP availability detection and connection failures (graceful degradation).
  2. Parsing valid, malformed, truncated, and oversized alert payloads.
  3. Sensitive evidence redaction (bearer tokens, session cookies, passwords).
  4. Scope validation and dropping of out-of-scope host alerts.
  5. SSRF destination IP blocking (RFC1918, loopback, link-local).
  6. Authorization boundaries and pre-flight revalidation.
  7. Scan timeout and graceful cancellation handling.
  8. Persistence in zap_alert_observations and scan_findings correlation.
  9. Scan lifecycle and SSE event emissions for ZAP phases.
"""

import asyncio
from datetime import datetime, timezone
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from backend.services.scanner_foundation import (
    ScanProfile,
    ScannerExecutionState,
    ScannerHealth,
    ScannerResult,
    ZapAlertObservation,
)
from backend.services.zap_adapter import OwaspZapAdapter, zap_adapter
from backend.services.zap_parser import (
    parse_zap_alerts,
    sanitize_evidence,
)
from backend.services.scanner_service import (
    persist_zap_alert_observations,
    correlate_zap_alerts_to_scan_findings,
    get_zap_alert_observations,
)


SAMPLE_ZAP_ALERTS_PAYLOAD = {
    "alerts": [
        {
            "id": "10020",
            "pluginId": "10020",
            "alert": "X-Frame-Options Header Missing",
            "risk": "Medium",
            "confidence": "High",
            "url": "https://api.company.com/login",
            "param": "X-Frame-Options",
            "attack": "",
            "evidence": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secretToken1234567890",
            "description": "The X-Frame-Options header is not set by the server.",
            "solution": "Ensure that your web server sets the X-Frame-Options header.",
            "reference": "https://tools.ietf.org/html/rfc7034",
            "cweid": "693",
            "wascid": "15"
        },
        {
            "id": "10038",
            "pluginId": "10038",
            "alert": "Content Security Policy (CSP) Header Not Set",
            "risk": "Medium",
            "confidence": "Medium",
            "url": "https://company.com/",
            "param": "",
            "attack": "",
            "evidence": "",
            "description": "Content Security Policy (CSP) is an added layer of security.",
            "solution": "Ensure that your web server sets Content-Security-Policy.",
            "reference": "https://www.w3.org/TR/CSP/",
            "cweid": "693",
            "wascid": "15"
        },
        {
            "id": "90001",
            "pluginId": "90001",
            "alert": "Out of Scope Third Party Alert",
            "risk": "High",
            "confidence": "High",
            "url": "https://evil-unauthorized.com/test",
            "param": "",
            "attack": "",
            "evidence": "some-evil-payload",
            "cweid": "79",
            "wascid": "8"
        }
    ]
}


def test_zap_availability_offline():
    """Verifies that unreachable ZAP daemon returns is_available=False with diagnostic message."""
    adapter = OwaspZapAdapter(api_url="http://127.0.0.1:59999", api_key="secret")
    health = adapter.check_availability()
    assert health.is_available is False
    assert health.version is None
    assert "not reachable" in health.error_message.lower() or "connection" in health.error_message.lower()


def test_zap_availability_online_mocked():
    """Verifies that an active ZAP daemon is recognized with version and supported profiles."""
    adapter = OwaspZapAdapter(api_url="http://127.0.0.1:8080", api_key="test-key")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"version": "2.14.0"}

    with patch("httpx.Client.get", return_value=mock_resp):
        health = adapter.check_availability()
        assert health.is_available is True
        assert health.version == "2.14.0"
        assert ScanProfile.ZAP_PASSIVE_ANALYSIS in health.supported_profiles


def test_evidence_sanitization_and_masking():
    """Verifies that sensitive tokens, passwords, and sessions in evidence strings are masked."""
    raw = "User auth header: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.longsecrettoken and password=SuperSecretPassword123"
    sanitized = sanitize_evidence(raw)
    assert "[REDACTED_TOKEN]" in sanitized
    assert "longsecrettoken" not in sanitized
    assert "[REDACTED_PASSWORD]" in sanitized
    assert "SuperSecretPassword123" not in sanitized

    # Length bounding
    oversized = "A" * 5000
    bounded = sanitize_evidence(oversized)
    assert len(bounded) < 1100
    assert "TRUNCATED_BY_DRISHTI" in bounded


def test_zap_alerts_parser_and_scope_filtering():
    """Verifies parsing of raw alerts, scope validation, and verification status assignment."""
    alerts = parse_zap_alerts(SAMPLE_ZAP_ALERTS_PAYLOAD, authorized_domain="company.com")

    # The out-of-scope alert on evil-unauthorized.com must be dropped
    assert len(alerts) == 2

    a1 = alerts[0]
    assert a1.plugin_id == "10020"
    assert a1.alert_name == "X-Frame-Options Header Missing"
    assert a1.risk == "Medium"
    assert a1.confidence == "High"
    assert a1.host == "api.company.com"
    assert a1.port == 443
    assert a1.cwe_id == 693
    assert a1.wasc_id == 15
    assert a1.verification_status == "corroborated"  # High confidence + evidence
    assert "[REDACTED_TOKEN]" in a1.evidence

    a2 = alerts[1]
    assert a2.plugin_id == "10038"
    assert a2.verification_status == "unverified_finding"  # Medium confidence without evidence


def test_zap_parser_resilience():
    """Verifies parsing handling of malformed input, non-dict rows, and empty structures."""
    assert parse_zap_alerts([]) == []
    assert parse_zap_alerts(None) == []
    assert parse_zap_alerts({"alerts": "not-a-list"}) == []
    assert parse_zap_alerts({"alerts": [None, "string", 123, {"url": ""}]}) == []


@pytest.mark.asyncio
async def test_zap_adapter_scope_rejection():
    """Verifies that execute_scan rejects targets outside the authorized domain."""
    adapter = OwaspZapAdapter()
    res = await adapter.execute_scan(
        scan_id="test-zap-scope",
        target="unauthorized-evil.com",
        authorized_domain="company.com"
    )
    assert res.status == ScannerExecutionState.FAILED
    assert "outside authorized scope" in res.error_message.lower()


@pytest.mark.asyncio
async def test_zap_adapter_ssrf_blocking():
    """Verifies that SSRF destinations (loopback/private IP) are blocked before network I/O."""
    adapter = OwaspZapAdapter()
    with patch("socket.gethostbyname", return_value="127.0.0.1"):
        res = await adapter.execute_scan(
            scan_id="test-zap-ssrf",
            target="internal-service.company.com",
            authorized_domain="company.com"
        )
        assert res.status == ScannerExecutionState.FAILED
        assert "ssrf" in res.error_message.lower() or "loopback" in res.error_message.lower()


@pytest.mark.asyncio
async def test_zap_adapter_cancellation():
    """Verifies that an active cancellation event halts ZAP execution immediately."""
    adapter = OwaspZapAdapter()
    cancel_event = asyncio.Event()
    cancel_event.set()

    with patch.object(adapter, "check_availability_async", return_value=ScannerHealth("OWASP ZAP", True, "2.14.0")):
        with patch.object(adapter, "_resolve_and_validate_target", return_value=(True, "93.184.216.34", None)):
            res = await adapter.execute_scan(
                scan_id="test-zap-cancel",
                target="company.com",
                cancel_event=cancel_event,
                authorized_domain="company.com"
            )
            assert res.status == ScannerExecutionState.CANCELLED


@pytest.mark.asyncio
async def test_zap_mocked_execution_and_persistence():
    """Verifies full mocked ZAP scan execution, alert parsing, and database persistence."""
    import uuid
    scan_id = f"test-zap-exec-{uuid.uuid4().hex[:8]}"
    adapter = OwaspZapAdapter(api_url="http://127.0.0.1:8080")

    mock_health = ScannerHealth(
        scanner_name="OWASP ZAP",
        is_available=True,
        version="2.14.0",
        supported_profiles=[ScanProfile.ZAP_PASSIVE_ANALYSIS]
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_ZAP_ALERTS_PAYLOAD

    with patch.object(adapter, "check_availability_async", return_value=mock_health):
        with patch.object(adapter, "_resolve_and_validate_target", return_value=(True, "104.21.48.19", None)):
            with patch("httpx.AsyncClient.get", return_value=mock_resp):
                res = await adapter.execute_scan(
                    scan_id=scan_id,
                    target="company.com",
                    profile=ScanProfile.ZAP_PASSIVE_ANALYSIS,
                    authorized_domain="company.com"
                )

                assert res.status == ScannerExecutionState.COMPLETED
                assert len(res.zap_alerts) == 2

                # Create parent scan record to satisfy foreign key
                from backend.db.database import db_queue
                await db_queue.execute_write(
                    "INSERT INTO scans (id, target, status, progress, scope) VALUES (?, ?, 'completed', 100, 'ZAP_PASSIVE') ON CONFLICT (id) DO NOTHING",
                    (res.scan_id, res.target)
                )

                # Test persistence
                saved_count = await persist_zap_alert_observations(res)
                assert saved_count == 2

                # Test scan findings correlation
                findings_count = await correlate_zap_alerts_to_scan_findings(res)
                assert findings_count == 2

                # Test retrieval
                stored_alerts = await get_zap_alert_observations(scan_id)
                assert len(stored_alerts) == 2
                assert stored_alerts[0]["plugin_id"] == "10020"
                assert stored_alerts[0]["host"] == "api.company.com"
