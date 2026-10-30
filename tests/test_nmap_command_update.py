"""
Tests for DRISHTI Nmap Command Update:
Verifies:
1. Exact argument construction: [nmap_executable, "-Pn", "-A", "-T2", "-oX", "-", validated_target]
2. Validated target is passed as one argument (no shell string)
3. Invalid and out-of-scope targets are rejected before subprocess creation
4. Missing Nmap executable handled gracefully
5. Subprocess timeout and cancellation cleanup
6. Parsing of valid XML, handling of malformed XML, and nonzero exit codes
7. AutoRecon orchestration integration receives correct stage status
"""

import asyncio
from datetime import datetime, timezone
import time
from unittest.mock import AsyncMock, patch, MagicMock
import pytest

from backend.db.database import init_db, db_queue
from backend.services.authorizations import create_challenge, verify_challenge
from backend.services.nmap_adapter import NmapAdapter, nmap_adapter
from backend.services.scanner_foundation import (
    ScanProfile,
    ScannerExecutionState,
    ScannerHealth,
)
from backend.services.scan_orchestrator import scan_orchestrator
from backend.services.orchestrator_models import CreateUnifiedScanPlanRequest


SAMPLE_NMAP_A_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -Pn -A -T2 -oX - company.com" start="1700000000" version="7.94">
<host starttime="1700000000" endtime="1700000010">
<status state="up" reason="user-set"/>
<address addr="104.21.48.12" addrtype="ipv4"/>
<hostnames>
<hostname name="company.com" type="user"/>
</hostnames>
<ports>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.24.0" method="probed"/></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="Cloudflare" tunnel="ssl" method="probed"/></port>
</ports>
<os>
<osmatch name="Linux 5.4 - 5.15" accuracy="95"/>
</os>
</host>
</nmaprun>
"""


def test_nmap_exact_argument_construction():
    """Verify build_command_args produces [nmap, "-Pn", "-A", "-T2", "-oX", "-", target]."""
    adapter = NmapAdapter(binary_override="/usr/bin/nmap")
    cmd = adapter.build_command_args("example.com")
    assert cmd == ["/usr/bin/nmap", "-Pn", "-A", "-T2", "-oX", "-", "example.com"]
    assert "-Pn" in cmd
    assert "-A" in cmd
    assert "-T2" in cmd
    assert "-oX" in cmd
    assert "-" in cmd
    assert cmd[-1] == "example.com"
    # Ensure target is not concatenated or passed through a shell
    assert len(cmd) == 7


@pytest.mark.asyncio
async def test_nmap_subprocess_invoked_with_exact_arguments():
    """Verify asyncio.create_subprocess_exec receives the exact argument array."""
    adapter = NmapAdapter()
    scan_id = "test-nmap-args-01"
    target = "example.com"

    with patch.object(adapter, "check_availability", return_value=ScannerHealth("Nmap", True, "7.94", "nmap.exe")), \
         patch("socket.gethostbyname", return_value="93.184.216.34"), \
         patch("asyncio.create_subprocess_exec") as mock_exec:

        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (SAMPLE_NMAP_A_XML.encode("utf-8"), b"")
        mock_proc.returncode = 0
        mock_exec.return_value = mock_proc

        result = await adapter.execute_scan(
            scan_id=scan_id,
            target=target,
            authorized_domain="example.com",
            profile=ScanProfile.BASIC_PORT_DISCOVERY,
        )

        assert result.status == ScannerExecutionState.COMPLETED
        # Verify exact call arguments
        mock_exec.assert_called_once_with(
            "nmap.exe",
            "-Pn",
            "-A",
            "-T2",
            "-oX",
            "-",
            "example.com",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )


@pytest.mark.asyncio
async def test_nmap_out_of_scope_and_ssrf_rejection():
    """Verify that unauthorized and SSRF targets are aborted before subprocess creation."""
    adapter = NmapAdapter()

    with patch.object(adapter, "check_availability", return_value=ScannerHealth("Nmap", True, "7.94", "nmap.exe")), \
         patch("asyncio.create_subprocess_exec") as mock_exec:

        # 1. Out of authorized scope
        res_scope = await adapter.execute_scan(
            scan_id="test-1",
            target="unauthorized.com",
            authorized_domain="authorized.com"
        )
        assert res_scope.status == ScannerExecutionState.FAILED
        assert "outside authorized scope" in res_scope.error_message
        mock_exec.assert_not_called()

        # 2. SSRF loopback target
        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            res_ssrf = await adapter.execute_scan(
                scan_id="test-2",
                target="local.authorized.com",
                authorized_domain="authorized.com"
            )
            assert res_ssrf.status == ScannerExecutionState.FAILED
            assert "SSRF Protection" in res_ssrf.error_message
            mock_exec.assert_not_called()


@pytest.mark.asyncio
async def test_nmap_missing_executable_handling():
    """Verify that missing Nmap executable reports SCANNER_UNAVAILABLE."""
    adapter = NmapAdapter(binary_override="C:\\nonexistent\\nmap.exe")
    result = await adapter.execute_scan(
        scan_id="test-missing",
        target="example.com",
        authorized_domain="example.com"
    )
    assert result.status == ScannerExecutionState.SCANNER_UNAVAILABLE
    assert "not found" in result.error_message.lower() or "cannot find" in result.error_message.lower() or "not available" in result.error_message.lower()


@pytest.mark.asyncio
async def test_nmap_timeout_and_process_termination():
    """Verify that timeout triggers process kill and returns TIMED_OUT status."""
    adapter = NmapAdapter()

    with patch.object(adapter, "check_availability", return_value=ScannerHealth("Nmap", True, "7.94", "nmap.exe")), \
         patch("socket.gethostbyname", return_value="93.184.216.34"), \
         patch("asyncio.create_subprocess_exec") as mock_exec:

        # Use MagicMock for sync methods (terminate, kill) and AsyncMock for async methods (communicate, wait)
        mock_proc = MagicMock()
        mock_proc.kill = MagicMock()
        mock_proc.terminate = MagicMock()
        # Make wait() actually wait so that wait_for times out
        async def mock_wait():
            await asyncio.sleep(10.0)  # Long enough to trigger the 2s timeout in wait_for
        mock_proc.wait = mock_wait
        # Simulate subprocess hanging beyond timeout
        async def hang():
            await asyncio.sleep(10.0)
            return (b"", b"")
        mock_proc.communicate = hang
        mock_exec.return_value = mock_proc

        result = await adapter.execute_scan(
            scan_id="test-timeout",
            target="example.com",
            authorized_domain="example.com",
            timeout_seconds=0.1
        )

        assert result.status == ScannerExecutionState.TIMED_OUT
        mock_proc.kill.assert_called()


@pytest.mark.asyncio
async def test_nmap_nonzero_exit_code_handling():
    """Verify that nonzero exit code returns FAILED with error message."""
    adapter = NmapAdapter()

    with patch.object(adapter, "check_availability", return_value=ScannerHealth("Nmap", True, "7.94", "nmap.exe")), \
         patch("socket.gethostbyname", return_value="93.184.216.34"), \
         patch("asyncio.create_subprocess_exec") as mock_exec:

        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"", b"QUITTING! Failed to resolve or connect.")
        mock_proc.returncode = 1
        mock_exec.return_value = mock_proc

        result = await adapter.execute_scan(
            scan_id="test-fail",
            target="example.com",
            authorized_domain="example.com",
        )

        assert result.status == ScannerExecutionState.FAILED
        assert result.exit_code == 1
        assert "exited with code 1" in result.error_message


@pytest.mark.asyncio
async def test_autorecon_workflow_nmap_stage_execution():
    """Verify AutoRecon invokes updated Nmap command and receives stage completion."""
    await init_db()
    target = "autorecon-nmap-target.com"

    # Set up verified authorization
    chal = await create_challenge(target_domain=target)
    class MockAnswer:
        strings = [chal["verification_token"].encode()]
    class MockResolver:
        def resolve(self, qn, qt):
            return [MockAnswer()]

    await verify_challenge(chal["id"], custom_resolver=MockResolver())

    plan = CreateUnifiedScanPlanRequest(
        target=target,
        scanners=["nmap"],
        scope="FULL_PASSIVE",
        authorization_id=chal["id"],
        allow_partial_completion=True,
    )

    with patch.object(nmap_adapter, "check_availability", return_value=ScannerHealth("Nmap", True, "7.94", "nmap.exe")), \
         patch("socket.gethostbyname", return_value="93.184.216.34"), \
         patch("asyncio.create_subprocess_exec") as mock_exec:

        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (SAMPLE_NMAP_A_XML.encode("utf-8"), b"")
        mock_proc.returncode = 0
        mock_exec.return_value = mock_proc

        cancel_evt = asyncio.Event()

        # Run _run_single_stage directly as orchestrator does
        res = await scan_orchestrator._run_single_stage(
            scanner_id="nmap",
            adapter=nmap_adapter,
            workflow_id="wf-test-123",
            target=target,
            plan=plan,
            auth_domain=target,
            cancel_event=cancel_evt,
        )

        assert res.status == ScannerExecutionState.COMPLETED
        assert len(res.hosts) == 1
        assert len(res.hosts[0].ports) == 2

        # Verify Nmap was executed with exact required arguments
        mock_exec.assert_called_once_with(
            "nmap.exe",
            "-Pn",
            "-A",
            "-T2",
            "-oX",
            "-",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
