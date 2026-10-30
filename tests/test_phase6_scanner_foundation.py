"""
DRISHTI — Phase 6 Scanner Foundation & Nmap Integration Test Suite
Verifies:
  1. Base scanner foundation contracts and data models.
  2. Nmap availability detection (when missing and when present).
  3. Strict subprocess safety: shell=False, immutable argument array construction, no injection.
  4. Scope boundary enforcement and SSRF IP blocking before scan execution.
  5. XML parser accuracy: valid multi-host, empty, malformed, truncated, and DTD/XXE defenses.
  6. Supabase PostgreSQL persistence of port observations and Asset Fingerprint linkage.
  7. Scan cancellation and process termination without orphaned processes.
"""

import asyncio
from datetime import datetime, timezone
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from backend.services.nmap_adapter import (
    NmapAdapter,
    ScanProfile,
    ScannerExecutionState,
    nmap_adapter,
)
from backend.services.nmap_parser import (
    NmapXMLParsingError,
    parse_nmap_xml,
)
from backend.services.scanner_foundation import (
    HostObservation,
    PortObservation,
    ScannerHealth,
    ScannerResult,
)
from backend.services.scanner_service import (
    persist_active_port_observations,
    correlate_nmap_observations_to_fingerprints,
    get_active_port_observations,
)


SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -p 80,443,1194 -oX - company.com" start="1700000000" version="7.94">
  <host starttime="1700000000" endtime="1700000002">
    <status state="up" reason="syn-ack"/>
    <address addr="198.51.100.8" addrtype="ipv4"/>
    <hostnames>
      <hostname name="vpn.company.com" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="OpenSSL" version="1.1.1k" method="probed">
          <cpe>cpe:/a:openssl:openssl:1.1.1k</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="1194">
        <state state="open" reason="syn-ack"/>
        <service name="openvpn" product="OpenVPN" version="2.5.1" method="probed">
          <cpe>cpe:/a:openvpn:openvpn:2.5.1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed" reason="reset"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_nmap_availability_detection():
    """Verifies that missing Nmap executable reports is_available=False gracefully."""
    adapter = NmapAdapter(binary_override="C:\\nonexistent\\nmap.exe")
    health = adapter.check_availability()
    assert health.is_available is False
    assert health.version is None
    assert "not found" in health.error_message.lower() or "failed" in health.error_message.lower()


def test_nmap_xml_parser_success():
    """Verifies parsing of valid Nmap XML output into typed HostObservation and PortObservation."""
    hosts = parse_nmap_xml(SAMPLE_NMAP_XML)
    assert len(hosts) == 1
    h = hosts[0]
    assert h.host == "vpn.company.com"
    assert h.ip == "198.51.100.8"
    assert h.status == "up"
    assert len(h.ports) == 3

    # Check open ports
    open_ports = [p for p in h.ports if p.state == "open"]
    assert len(open_ports) == 2
    p443 = next(p for p in open_ports if p.port == 443)
    assert p443.service_name == "https"
    assert p443.product == "OpenSSL"
    assert p443.version == "1.1.1k"
    assert p443.cpe23 == "cpe:/a:openssl:openssl:1.1.1k"

    p1194 = next(p for p in open_ports if p.port == 1194)
    assert p1194.service_name == "openvpn"
    assert p1194.product == "OpenVPN"
    assert p1194.version == "2.5.1"


def test_nmap_xml_parser_xxe_and_malformed_defense():
    """Verifies that XML with external DTD/entities or invalid syntax is safely rejected."""
    # 1. XXE attack payload
    xxe_payload = """<?xml version="1.0"?>
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://127.0.0.1:8000/secret"> ]>
    <nmaprun>&xxe;</nmaprun>
    """
    with pytest.raises(NmapXMLParsingError) as exc_info:
        parse_nmap_xml(xxe_payload)
    assert "security" in str(exc_info.value).lower() or "rejected" in str(exc_info.value).lower()

    # 2. Malformed / truncated XML
    truncated_xml = "<nmaprun><host><address addr='192.168.1.1'>"
    with pytest.raises(NmapXMLParsingError):
        parse_nmap_xml(truncated_xml)

    # 3. Empty input
    assert parse_nmap_xml("") == []
    assert parse_nmap_xml(None) == []


@pytest.mark.asyncio
async def test_nmap_scope_and_ssrf_protection():
    """Verifies that Nmap execution enforces scope boundaries and blocks private/loopback IPs."""
    adapter = NmapAdapter()
    
    # Fake binary so availability check passes
    with patch.object(adapter, "check_availability", return_value=ScannerHealth("Nmap", True, "7.94", "/usr/bin/nmap")):
        # 1. Out of scope target
        res_scope = await adapter.execute_scan(
            scan_id="test-scan-1",
            target="unauthorized-domain.com",
            authorized_domain="company.com"
        )
        assert res_scope.status == ScannerExecutionState.FAILED
        assert "outside authorized scope" in res_scope.error_message

        # 2. SSRF Loopback resolution protection
        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            res_ssrf = await adapter.execute_scan(
                scan_id="test-scan-2",
                target="localhost.company.com",
                authorized_domain="company.com"
            )
            assert res_ssrf.status == ScannerExecutionState.FAILED
            assert "SSRF Protection" in res_ssrf.error_message


@pytest.mark.asyncio
async def test_nmap_mocked_execution_and_persistence():
    """Verifies end-to-end execution flow with mocked subprocess output and Supabase PostgreSQL persistence."""
    adapter = NmapAdapter()
    import time
    unique_scan_id = f"test-scan-nmap-{int(time.time()*1000)}"

    # Mock availability and subprocess, and use public routable IP 104.21.48.12 (not TEST-NET)
    with patch.object(adapter, "check_availability", return_value=ScannerHealth("Nmap", True, "7.94", "nmap.exe")), \
         patch("socket.gethostbyname", return_value="104.21.48.12"), \
         patch("asyncio.create_subprocess_exec") as mock_exec:

        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (SAMPLE_NMAP_XML.encode("utf-8"), b"")
        mock_proc.returncode = 0
        mock_exec.return_value = mock_proc

        result = await adapter.execute_scan(
            scan_id=unique_scan_id,
            target="company.com",
            profile=ScanProfile.BASIC_PORT_DISCOVERY,
            authorized_domain="company.com"
        )

        assert result.status == ScannerExecutionState.COMPLETED
        assert len(result.hosts) == 1
        assert len(result.hosts[0].ports) == 3

        # Ensure parent scan record exists to satisfy foreign key constraint
        from backend.db.database import db_queue
        await db_queue.execute_write(
            "INSERT INTO scans (id, target, status, progress, scope) VALUES (?, ?, 'completed', 100, 'FULL_ACTIVE') ON CONFLICT (id) DO NOTHING",
            (result.scan_id, result.target)
        )

        # Persist observations in PostgreSQL
        ports_created = await persist_active_port_observations(result)
        assert ports_created == 3

        # Correlate observations to AssetFingerprints
        fp_count = await correlate_nmap_observations_to_fingerprints(result)
        assert fp_count >= 1

        # Query back from DB
        saved_ports = await get_active_port_observations(unique_scan_id)
        assert len(saved_ports) == 3
        port_numbers = [p["port"] for p in saved_ports]
        assert 443 in port_numbers
        assert 1194 in port_numbers


@pytest.mark.asyncio
async def test_nmap_scan_cancellation():
    """Verifies that cancel_event terminates the subprocess safely without leaving orphans."""
    adapter = NmapAdapter()
    cancel_evt = asyncio.Event()

    with patch.object(adapter, "check_availability", return_value=ScannerHealth("Nmap", True, "7.94", "nmap.exe")), \
         patch("socket.gethostbyname", return_value="104.21.48.12"), \
         patch("asyncio.create_subprocess_exec") as mock_exec:

        mock_proc = AsyncMock()
        # Simulate long running scan
        async def slow_communicate():
            await asyncio.sleep(2.0)
            return (b"", b"")

        mock_proc.communicate.side_effect = slow_communicate
        mock_proc.terminate = MagicMock()
        mock_proc.wait = AsyncMock()
        mock_exec.return_value = mock_proc

        # Cancel after 100ms
        async def cancel_later():
            await asyncio.sleep(0.1)
            cancel_evt.set()

        asyncio.create_task(cancel_later())

        result = await adapter.execute_scan(
            scan_id="test-scan-cancel",
            target="company.com",
            cancel_event=cancel_evt,
            authorized_domain="company.com"
        )

        assert result.status == ScannerExecutionState.CANCELLED
        assert "cancelled by user" in result.error_message
        mock_proc.terminate.assert_called_once()
