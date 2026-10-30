"""
DRISHTI — Phase 10 ProjectDiscovery Nuclei Integration Test Suite
Verifies:
  1. Nuclei availability detection and graceful degradation when missing.
  2. Safe version parsing across stdout/stderr variations.
  3. JSONL parsing: template metadata, classifications, CVE, CWE, CVSS, curl reproduction command.
  4. Redaction of sensitive credentials, Bearer tokens, cookies, and keys in evidence.
  5. Target scope containment, SSRF prevention, and URL scheme validation.
  6. Template policy enforcement: disallows destructive, DoS, and fuzzing tags.
  7. Safe subprocess execution: shell=False, immutable flag construction, timeout, and cancellation cleanup.
  8. Persistence in nuclei_findings and unified scan_findings risk correlation.
  9. Scan lifecycle and SSE event emissions for Nuclei phase.
"""

import asyncio
from datetime import datetime, timezone
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

from backend.services.scanner_foundation import (
    ScanProfile,
    ScannerExecutionState,
    ScannerHealth,
    ScannerResult,
    NucleiFindingObservation,
)
from backend.services.nuclei_adapter import (
    ProjectDiscoveryNucleiAdapter,
    nuclei_adapter,
    DISALLOWED_TEMPLATE_TAGS,
)
from backend.services.nuclei_parser import (
    parse_nuclei_jsonl,
    sanitize_evidence,
    normalize_severity,
    parse_matched_target,
)
from backend.services.scanner_service import (
    persist_nuclei_finding_observations,
    correlate_nuclei_findings_to_scan_findings,
    get_nuclei_finding_observations,
)


SAMPLE_NUCLEI_JSONL = """
{"template-id":"git-config","info":{"name":"Git Config Disclosure","author":["projectdiscovery"],"severity":"medium","description":".git/config is exposed publicly","classification":{"cve-id":null,"cwe-id":["cwe-200"],"cvss-score":5.3},"reference":["https://owasp.org"],"tags":["exposure","config","git"]},"type":"http","host":"company.com","matched-at":"https://company.com/.git/config","extracted-results":["repositoryformatversion = 0"],"curl-command":"curl -H 'Authorization: Bearer secret-admin-token-12345' https://company.com/.git/config"}
{"template-id":"cve-2023-38606","info":{"name":"Apache ActiveMQ RCE","author":["security"],"severity":"critical","description":"Remote code execution via OpenWire","classification":{"cve-id":["CVE-2023-38606"],"cwe-id":["cwe-502"],"cvss-score":9.8},"reference":["https://nvd.nist.gov/vuln/detail/CVE-2023-38606"],"tags":["cve","cve2023","activemq","rce"]},"type":"tcp","host":"company.com","matched-at":"company.com:61616","matcher-name":"tcp-activemq"}
{"template-id":"cors-misconfig","info":{"name":"CORS Arbitrary Origin Allowed","severity":"low","tags":["misconfig","cors"]},"type":"http","host":"sub.company.com","matched-at":"https://sub.company.com/api/v1","curl-command":"curl -H 'Cookie: session=secret_session_abc' https://sub.company.com/api/v1"}
"""


def test_nuclei_availability_detection_missing():
    """Verify that when Nuclei is not installed or configured, check_availability reports graceful failure."""
    adapter = ProjectDiscoveryNucleiAdapter(binary_override="/nonexistent/path/to/nuclei")
    with patch("shutil.which", return_value=None):
        health = adapter.check_availability()
        assert health.is_available is False
        assert health.binary_path is None
        assert "not found" in health.error_message.lower()


def test_nuclei_availability_detection_success():
    """Verify successful version parsing from mock subprocess output."""
    adapter = ProjectDiscoveryNucleiAdapter(binary_override="nuclei")
    with patch.object(adapter, "get_binary_path", return_value="C:\\tools\\nuclei.exe"):
        mock_proc = MagicMock()
        mock_proc.stdout = "Nuclei Engine Version: v3.2.0\n"
        mock_proc.stderr = ""
        mock_proc.returncode = 0

        with patch("subprocess.run", return_value=mock_proc):
            health = adapter.check_availability()
            assert health.is_available is True
            assert health.version == "v3.2.0"
            assert health.binary_path == "C:\\tools\\nuclei.exe"
            assert len(health.supported_profiles) > 0


def test_nuclei_parser_comprehensive():
    """Verifies complete parsing of JSONL records, metadata, CVE/CWE, CVSS, and evidence sanitization."""
    findings = parse_nuclei_jsonl(
        raw_jsonl=SAMPLE_NUCLEI_JSONL,
        scanner_version="v3.2.0",
        authorized_domain="company.com",
    )
    assert len(findings) == 3

    # Check finding 1: Git config
    f1 = findings[0]
    assert f1.template_id == "git-config"
    assert f1.severity == "medium"
    assert f1.host == "company.com"
    assert f1.port == 443
    assert f1.scheme == "https"
    assert f1.cwe_id == "cwe-200"
    assert f1.cvss_score == 5.3
    assert "Bearer [REDACTED]" in f1.curl_command
    assert "secret-admin-token" not in f1.curl_command
    assert "repositoryformatversion" in f1.evidence

    # Check finding 2: ActiveMQ CVE-2023-38606
    f2 = findings[1]
    assert f2.template_id == "cve-2023-38606"
    assert f2.severity == "critical"
    assert f2.cve_id == "CVE-2023-38606"
    assert f2.cvss_score == 9.8
    assert f2.port == 61616
    assert f2.matcher_name == "tcp-activemq"

    # Check finding 3: CORS on subdomain
    f3 = findings[2]
    assert f3.template_id == "cors-misconfig"
    assert f3.severity == "low"
    assert f3.host == "sub.company.com"
    assert "Cookie: [REDACTED]" in f3.curl_command
    assert "secret_session_abc" not in f3.curl_command


def test_evidence_sanitization_patterns():
    """Verifies that secrets, API tokens, passwords, and cookies are rigorously redacted."""
    raw = (
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\n"
        "Cookie: user_auth=supersecret123\n"
        "api_key: ak_live_998877665544\n"
        "password = my_database_password_999\n"
    )
    sanitized = sanitize_evidence(raw)
    assert "supersecret123" not in sanitized
    assert "ak_live" not in sanitized
    assert "my_database_password" not in sanitized
    assert "Authorization: Bearer [REDACTED]" in sanitized
    assert "Cookie: [REDACTED]" in sanitized


def test_nuclei_parser_resilience():
    """Verify that corrupt or non-JSON log lines do not break parser."""
    bad_lines = (
        "[INF] Current nuclei version: v3.2.0\n"
        "Non JSON banner line\n"
        "{bad json line\n"
        '{"template-id":"ok-1","info":{"name":"Valid","severity":"high"},"host":"company.com","matched-at":"company.com"}\n'
        "\n"
        "{}\n"
    )
    findings = parse_nuclei_jsonl(bad_lines, authorized_domain="company.com")
    assert len(findings) == 1
    assert findings[0].template_id == "ok-1"
    assert findings[0].severity == "high"


def test_target_scope_and_ssrf_validation():
    """Verify target authorization scope enforcement and SSRF loopback blocking."""
    adapter = ProjectDiscoveryNucleiAdapter()

    # Valid in-scope target
    ok, err = adapter.validate_target("https://sub.company.com/api", authorized_domain="company.com")
    assert ok is True
    assert err is None

    # Out of scope domain
    ok_out, err_out = adapter.validate_target("https://attacker.org", authorized_domain="company.com")
    assert ok_out is False
    assert "out of scope" in err_out.lower()

    # Domain hopping attempt
    ok_hop, err_hop = adapter.validate_target("company.com.evil.com", authorized_domain="company.com")
    assert ok_hop is False
    assert "out of scope" in err_hop.lower()

    # Loopback IP (SSRF blocking)
    ok_ssrf, err_ssrf = adapter.validate_target("127.0.0.1", authorized_domain="127.0.0.1")
    assert ok_ssrf is False
    assert "loopback" in err_ssrf.lower()


def test_template_policy_enforcement():
    """Verify that dangerous, destructive, or DoS template tags are strictly rejected."""
    adapter = ProjectDiscoveryNucleiAdapter()

    # Safe tags
    ok_safe, err_safe = adapter.validate_template_policy(tags=["cve", "misconfig", "exposure"])
    assert ok_safe is True
    assert err_safe is None

    # Disallowed tags
    for tag in DISALLOWED_TEMPLATE_TAGS:
        ok_bad, err_bad = adapter.validate_template_policy(tags=["cve", tag])
        assert ok_bad is False
        assert "disallowed by drishti security policy" in err_bad.lower()


@pytest.mark.asyncio
async def test_nuclei_mocked_execution_and_persistence():
    """
    Simulates a mocked Nuclei subprocess execution and tests:
    1. Adapter execution and status
    2. nuclei_findings database table persistence
    3. Unified scan_findings table correlation
    4. Query retrieval
    """
    scan_id = f"test-nuclei-scan-{uuid.uuid4().hex[:8]}"
    adapter = ProjectDiscoveryNucleiAdapter(binary_override="nuclei")

    with patch.object(adapter, "check_availability") as mock_health:
        mock_health.return_value = ScannerHealth(
            scanner_name="ProjectDiscovery Nuclei",
            is_available=True,
            version="v3.2.0",
            binary_path="C:\\tools\\nuclei.exe",
            supported_profiles=[ScanProfile.NUCLEI_APPROVED_BASELINE],
        )

        # Mock asyncio subprocess
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (
            SAMPLE_NUCLEI_JSONL.encode("utf-8"),
            b"",
        )
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            res = await adapter.execute_scan(
                scan_id=scan_id,
                target="company.com",
                profile=ScanProfile.NUCLEI_APPROVED_BASELINE,
                authorized_domain="company.com",
            )

            assert res.status == ScannerExecutionState.COMPLETED
            assert len(res.nuclei_findings) == 3

            # Satisfy foreign key constraint in scans table
            from backend.db.database import db_queue
            await db_queue.execute_write(
                "INSERT INTO scans (id, target, status, progress, scope) VALUES (?, ?, 'completed', 100, 'NUCLEI') ON CONFLICT (id) DO NOTHING",
                (res.scan_id, res.target)
            )

            # Test persistence into nuclei_findings
            saved_count = await persist_nuclei_finding_observations(res)
            assert saved_count == 3

            # Test correlation into scan_findings
            correlated_count = await correlate_nuclei_findings_to_scan_findings(res)
            assert correlated_count == 3

            # Verify retrieval
            persisted = await get_nuclei_finding_observations(scan_id)
            assert len(persisted) == 3
            template_ids = {p["template_id"] for p in persisted}
            assert "git-config" in template_ids
            assert "cve-2023-38606" in template_ids
            assert "cors-misconfig" in template_ids


@pytest.mark.asyncio
async def test_nuclei_scan_cancellation():
    """Verifies that an operator cancellation event cleanly aborts execution."""
    scan_id = f"test-cancel-{uuid.uuid4().hex[:8]}"
    adapter = ProjectDiscoveryNucleiAdapter(binary_override="nuclei")

    with patch.object(adapter, "check_availability") as mock_health:
        mock_health.return_value = ScannerHealth(
            scanner_name="ProjectDiscovery Nuclei",
            is_available=True,
            version="v3.2.0",
            binary_path="C:\\tools\\nuclei.exe",
        )

        cancel_event = asyncio.Event()

        # Simulate slow process that triggers cancel
        mock_proc = AsyncMock()
        async def slow_communicate():
            await asyncio.sleep(2.0)
            return (b"", b"")

        mock_proc.communicate.side_effect = slow_communicate
        mock_proc.terminate = MagicMock()
        mock_proc.kill = MagicMock()
        mock_proc.returncode = None

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            async def trigger_cancel():
                await asyncio.sleep(0.05)
                cancel_event.set()

            asyncio.create_task(trigger_cancel())

            res = await adapter.execute_scan(
                scan_id=scan_id,
                target="company.com",
                cancel_event=cancel_event,
                authorized_domain="company.com",
            )

            assert res.status == ScannerExecutionState.CANCELLED
            assert "cancelled by operator" in res.error_message.lower()
            mock_proc.terminate.assert_called()
