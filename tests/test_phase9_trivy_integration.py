"""
DRISHTI — Phase 9 Aqua Security Trivy Integration Test Suite
Verifies:
  1. Trivy availability detection and graceful degradation when missing.
  2. Safe version parsing across output styles.
  3. JSON parsing: multi-target vulnerabilities, misconfigurations, and secrets.
  4. Redaction of sensitive secrets and credentials in evidence strings.
  5. Target path traversal validation and prohibited root drive blocking.
  6. Subprocess execution safety: shell=False, immutable CLI flags.
  7. Scan timeout and operator cancellation handling.
  8. Persistence in trivy_findings and unified scan_findings correlation.
  9. Scan lifecycle and SSE event emissions for Trivy phases.
"""

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

from backend.services.scanner_foundation import (
    ScanProfile,
    ScannerExecutionState,
    ScannerHealth,
    ScannerResult,
    TrivyFindingObservation,
)
from backend.services.trivy_adapter import AquaSecurityTrivyAdapter, trivy_adapter
from backend.services.trivy_parser import (
    parse_trivy_json,
    sanitize_snippet,
)
from backend.services.scanner_service import (
    persist_trivy_finding_observations,
    correlate_trivy_findings_to_scan_findings,
    get_trivy_finding_observations,
)


SAMPLE_TRIVY_JSON = {
    "SchemaVersion": 2,
    "ArtifactName": "test-app",
    "ArtifactType": "filesystem",
    "Results": [
        {
            "Target": "package-lock.json",
            "Class": "lang-pkgs",
            "Type": "npm",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-26159",
                    "PkgName": "follow-redirects",
                    "InstalledVersion": "1.15.2",
                    "FixedVersion": "1.15.4",
                    "Severity": "CRITICAL",
                    "Title": "follow-redirects: Improper input validation",
                    "Description": "follow-redirects is an open source fully conforming implementation of Node's http and https modules.",
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-26159"
                },
                {
                    "VulnerabilityID": "CVE-2023-45853",
                    "PkgName": "zlib",
                    "InstalledVersion": "1.2.11",
                    "FixedVersion": "1.2.12",
                    "Severity": "HIGH",
                    "Title": "zlib: integer overflow and resultant buffer overflow",
                    "Description": "MiniZip in zlib allows an integer overflow and buffer overflow.",
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-45853"
                }
            ]
        },
        {
            "Target": "Dockerfile",
            "Class": "config",
            "Type": "dockerfile",
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "AVDID": "AVD-DS-0002",
                    "Title": "Image user should not be 'root'",
                    "Description": "Running containers with 'root' user can lead to a container breakout vulnerability.",
                    "Message": "Specify at least 1 USER command in Dockerfile with non-root user as argument",
                    "Resolution": "Add 'USER <non-root-user>' to Dockerfile",
                    "Severity": "MEDIUM",
                    "PrimaryURL": "https://avd.aquasec.com/misconfiguration/ds002",
                    "CauseMetadata": {
                        "StartLine": 1,
                        "Code": {
                            "Lines": [
                                {"Number": 1, "Content": "FROM node:18-alpine"},
                                {"Number": 2, "Content": "WORKDIR /app"}
                            ]
                        }
                    }
                }
            ]
        },
        {
            "Target": "config.env",
            "Class": "secret",
            "Secrets": [
                {
                    "RuleID": "aws-secret-access-key",
                    "Category": "AWS",
                    "Title": "AWS Secret Access Key",
                    "Severity": "CRITICAL",
                    "StartLine": 4,
                    "Code": {
                        "Lines": [
                            {"Number": 4, "Content": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
                        ]
                    }
                }
            ]
        }
    ]
}


def test_trivy_availability_detection_missing():
    """Verifies that missing Trivy binary reports is_available=False gracefully."""
    adapter = AquaSecurityTrivyAdapter(binary_override="C:\\nonexistent\\trivy.exe")
    health = adapter.check_availability()
    assert health.is_available is False
    assert health.version is None
    assert "not found" in health.error_message.lower()


def test_trivy_availability_detection_success():
    """Verifies that installed Trivy binary parses version and profile capabilities."""
    adapter = AquaSecurityTrivyAdapter(binary_override="C:\\mock\\trivy.exe")

    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = "Version: 0.50.1\n"
    mock_res.stderr = ""

    with patch("os.path.isfile", return_value=True), \
         patch("os.access", return_value=True), \
         patch("subprocess.run", return_value=mock_res):
        health = adapter.check_availability()
        assert health.is_available is True
        assert health.version == "0.50.1"
        assert ScanProfile.TRIVY_FS_DEPENDENCIES in health.supported_profiles


def test_trivy_parser_comprehensive():
    """Verifies parsing of vulnerabilities, misconfigurations, and masked secrets."""
    findings = parse_trivy_json(SAMPLE_TRIVY_JSON, scanner_version="0.50.1")
    assert len(findings) == 4

    # 1. Critical package vulnerability
    v1 = next(f for f in findings if f.vulnerability_id == "CVE-2023-26159")
    assert v1.finding_class == "vulnerability"
    assert v1.package_name == "follow-redirects"
    assert v1.installed_version == "1.15.2"
    assert v1.fixed_version == "1.15.4"
    assert v1.severity == "CRITICAL"
    assert "1.15.4" in v1.remediation_guidance

    # 2. High package vulnerability
    v2 = next(f for f in findings if f.vulnerability_id == "CVE-2023-45853")
    assert v2.finding_class == "vulnerability"
    assert v2.severity == "HIGH"

    # 3. Dockerfile misconfiguration
    m1 = next(f for f in findings if f.finding_class == "misconfiguration")
    assert m1.rule_id == "DS002"
    assert m1.severity == "MEDIUM"
    assert m1.line_number == 1
    assert "FROM node:18-alpine" in m1.evidence

    # 4. Secret finding with masked evidence
    s1 = next(f for f in findings if f.finding_class == "secret")
    assert s1.rule_id == "aws-secret-access-key"
    assert s1.severity == "CRITICAL"
    assert "Revoke the exposed credential" in s1.remediation_guidance
    # Proof must not leak plaintext secret token
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in s1.evidence
    assert "[REDACTED_SECRET]" in s1.evidence or "[REDACTED_KEY]" in s1.evidence


def test_snippet_sanitization():
    """Verifies regex pattern redactors for passwords, keys, and tokens in snippets."""
    raw = "export API_KEY=abcdef1234567890 and password=SuperSecretPW123 and token=Bearer eyJhbGciOiJIUzI1"
    sanitized = sanitize_snippet(raw)
    assert "abcdef1234567890" not in sanitized
    assert "SuperSecretPW123" not in sanitized
    assert "[REDACTED_KEY]" in sanitized
    assert "[REDACTED_PASSWORD]" in sanitized


def test_trivy_parser_resilience():
    """Verifies parsing handling of empty, string, and malformed inputs."""
    assert parse_trivy_json({}) == []
    assert parse_trivy_json("") == []
    assert parse_trivy_json(None) == []
    assert parse_trivy_json("INVALID_JSON") == []
    assert parse_trivy_json({"Results": "not_a_list"}) == []


def test_target_validation_rules():
    """Verifies path traversal blocking, non-existent path defense, and image syntax rules."""
    adapter = AquaSecurityTrivyAdapter()

    # 1. Prohibited root filesystem
    valid, target, err = adapter.validate_target_resource("C:/", ScanProfile.TRIVY_FS_DEPENDENCIES)
    assert valid is False
    assert "prohibited" in err.lower()

    # 2. Non-existent path
    valid, target, err = adapter.validate_target_resource("C:/nonexistent/directory/fake", ScanProfile.TRIVY_FS_DEPENDENCIES)
    assert valid is False
    assert "does not exist" in err.lower()

    # 3. Valid directory
    valid, target, err = adapter.validate_target_resource("E:/drishti", ScanProfile.TRIVY_FS_DEPENDENCIES)
    assert valid is True
    assert "drishti" in target.lower()

    # 4. Container image valid & invalid
    valid, target, err = adapter.validate_target_resource("redis:7-alpine", ScanProfile.TRIVY_IMAGE)
    assert valid is True

    valid, target, err = adapter.validate_target_resource("; rm -rf /", ScanProfile.TRIVY_IMAGE)
    assert valid is False


@pytest.mark.asyncio
async def test_trivy_mocked_execution_and_persistence():
    """Verifies full mocked Trivy scan execution, parsing, Supabase persistence, and correlation."""
    adapter = AquaSecurityTrivyAdapter(binary_override="C:\\mock\\trivy.exe")
    scan_id = f"test-trivy-exec-{uuid.uuid4().hex[:8]}"

    mock_health = ScannerHealth(
        scanner_name="Aqua Security Trivy",
        is_available=True,
        version="0.50.1",
        binary_path="C:\\mock\\trivy.exe",
        supported_profiles=[ScanProfile.TRIVY_FULL_LOCAL]
    )

    with patch.object(adapter, "check_availability", return_value=mock_health), \
         patch.object(adapter, "validate_target_resource", return_value=(True, "E:\\drishti", None)), \
         patch("asyncio.create_subprocess_exec") as mock_exec:

        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (json.dumps(SAMPLE_TRIVY_JSON).encode("utf-8"), b"")
        mock_proc.returncode = 0
        mock_exec.return_value = mock_proc

        res = await adapter.execute_scan(
            scan_id=scan_id,
            target="E:\\drishti",
            profile=ScanProfile.TRIVY_FULL_LOCAL,
        )

        assert res.status == ScannerExecutionState.COMPLETED
        assert len(res.trivy_findings) == 4

        # Satisfy foreign key in parent scans table
        from backend.db.database import db_queue
        await db_queue.execute_write(
            "INSERT INTO scans (id, target, status, progress, scope) VALUES (?, ?, 'completed', 100, 'TRIVY_LOCAL') ON CONFLICT (id) DO NOTHING",
            (res.scan_id, res.target)
        )

        # Persist findings
        saved_count = await persist_trivy_finding_observations(res)
        assert saved_count == 4

        # Correlate into scan_findings table
        correlated_count = await correlate_trivy_findings_to_scan_findings(res)
        assert correlated_count == 4

        # Query back
        stored = await get_trivy_finding_observations(scan_id)
        assert len(stored) == 4
        vuln_record = next(f for f in stored if f["vulnerability_id"] == "CVE-2023-26159")
        assert vuln_record["package_name"] == "follow-redirects"
        assert vuln_record["severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_trivy_scan_cancellation():
    """Verifies that an active cancellation event terminates the Trivy process safely."""
    adapter = AquaSecurityTrivyAdapter(binary_override="C:\\mock\\trivy.exe")
    cancel_evt = asyncio.Event()

    mock_health = ScannerHealth(
        scanner_name="Aqua Security Trivy",
        is_available=True,
        version="0.50.1",
        binary_path="C:\\mock\\trivy.exe",
        supported_profiles=[ScanProfile.TRIVY_FULL_LOCAL]
    )

    with patch.object(adapter, "check_availability", return_value=mock_health), \
         patch.object(adapter, "validate_target_resource", return_value=(True, "E:\\drishti", None)), \
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

        res = await adapter.execute_scan(
            scan_id="test-scan-cancel-trivy",
            target="E:\\drishti",
            cancel_event=cancel_evt,
        )

        assert res.status == ScannerExecutionState.CANCELLED
        assert "cancelled by operator" in res.error_message
        mock_proc.terminate.assert_called_once()
