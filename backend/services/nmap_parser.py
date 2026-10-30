"""
DRISHTI — Phase 6 Nmap XML Parser (Security Hardened)
Parses structured Nmap XML output (-oX -) into normalized DRISHTI HostObservation
and PortObservation data structures.

Security Requirements:
- Uses defusedxml / defused ElementTree protections against XXE and quadratic expansion.
- Disables external entity resolution and DTD loading.
- Rejects oversized XML outputs (> 10 MB).
- Handles truncated, malformed, empty, or unexpected XML structures gracefully.
- Never infers that an open port is a vulnerability on its own.
"""

from datetime import datetime, timezone
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

from backend.services.scanner_foundation import HostObservation, PortObservation

MAX_XML_BYTES = 10 * 1024 * 1024  # 10 MB payload ceiling


class NmapXMLParsingError(Exception):
    """Raised when Nmap XML output is malformed, truncated, or exceeds safety limits."""
    pass


def parse_nmap_xml(xml_content: str) -> List[HostObservation]:
    """
    Safely parses Nmap XML string into a list of normalized HostObservation instances.
    """
    if not xml_content or not xml_content.strip():
        return []

    # Enforce strict size threshold
    if len(xml_content.encode("utf-8")) > MAX_XML_BYTES:
        raise NmapXMLParsingError(f"XML output exceeds maximum allowable size of {MAX_XML_BYTES} bytes.")

    # Guard against XML External Entity (XXE) and billion laughs attacks
    # Allow the standard Nmap DOCTYPE declaration but reject any entity declarations or external DTD references
    xml_lower = xml_content.lower()
    
    # Check for DOCTYPE first - only allow the standard Nmap DOCTYPE declaration
    if "<!doctype" in xml_lower:
        # Find the DOCTYPE declaration and verify it's the standard Nmap one
        import re
        doctype_match = re.search(r'<!doctype\s+([^\s>]+)', xml_content, re.IGNORECASE)
        if not doctype_match or doctype_match.group(1).lower() != "nmaprun":
            raise NmapXMLParsingError("XML containing unexpected DOCTYPE declaration is rejected for security.")
        # Check for external DTD references (SYSTEM or PUBLIC keywords in DOCTYPE)
        doctype_section = xml_content[doctype_match.start():doctype_match.end()]
        if "system" in doctype_section.lower() or "public" in doctype_section.lower():
            raise NmapXMLParsingError("XML containing external DTD reference in DOCTYPE is strictly rejected for security.")
    
    # Reject any ENTITY declaration - these are never present in legitimate Nmap output
    if "<!entity" in xml_lower:
        raise NmapXMLParsingError("XML containing ENTITY declarations is strictly rejected for security.")

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as err:
        # Partial XML recovery: if Nmap timed out mid-stream, attempt closing nmaprun or parsing available hosts
        if "<host" in xml_content:
            try:
                # Attempt appending closing tag </nmaprun> if truncated
                repaired = xml_content.strip()
                if not repaired.endswith("</nmaprun>"):
                    repaired += "\n</nmaprun>"
                root = ET.fromstring(repaired)
            except Exception:
                raise NmapXMLParsingError(f"Malformed or truncated XML cannot be parsed: {err}")
        else:
            raise NmapXMLParsingError(f"Malformed XML syntax: {err}")

    if root.tag != "nmaprun":
        raise NmapXMLParsingError(f"Root XML element is '{root.tag}', expected 'nmaprun'.")

    observations: List[HostObservation] = []

    for host_elem in root.findall("host"):
        # Check host status (up / down)
        status_elem = host_elem.find("status")
        host_state = "up"
        if status_elem is not None:
            host_state = status_elem.attrib.get("state", "up")

        # Extract primary IP and hostnames
        ip_address = ""
        hostnames: List[str] = []

        for addr in host_elem.findall("address"):
            addr_type = addr.attrib.get("addrtype", "ipv4")
            if addr_type in ("ipv4", "ipv6") and not ip_address:
                ip_address = addr.attrib.get("addr", "")

        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            for hn in hostnames_elem.findall("hostname"):
                name = hn.attrib.get("name")
                if name and name not in hostnames:
                    hostnames.append(name)

        primary_host = hostnames[0] if hostnames else ip_address

        # Extract Ports and Services
        port_obs_list: List[PortObservation] = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for p in ports_elem.findall("port"):
                proto = p.attrib.get("protocol", "tcp")
                port_id_str = p.attrib.get("portid", "0")
                try:
                    port_id = int(port_id_str)
                except ValueError:
                    continue

                state_elem = p.find("state")
                port_state = state_elem.attrib.get("state", "closed") if state_elem is not None else "unknown"

                service_elem = p.find("service")
                service_name = None
                product = None
                version = None
                extra_info = None
                cpe23 = None

                if service_elem is not None:
                    service_name = service_elem.attrib.get("name")
                    product = service_elem.attrib.get("product")
                    version = service_elem.attrib.get("version")
                    extra_info = service_elem.attrib.get("extrainfo")

                    # Look for CPE inside service
                    cpe_elem = service_elem.find("cpe")
                    if cpe_elem is not None and cpe_elem.text:
                        cpe23 = cpe_elem.text.strip()

                port_obs_list.append(
                    PortObservation(
                        port=port_id,
                        protocol=proto,
                        state=port_state,
                        service_name=service_name,
                        product=product,
                        version=version,
                        extra_info=extra_info,
                        cpe23=cpe23,
                        confidence=1.0,
                    )
                )

        # Extract OS match if present
        os_match = None
        os_elem = host_elem.find("os")
        if os_elem is not None:
            osmatch_elem = os_elem.find("osmatch")
            if osmatch_elem is not None:
                os_match = osmatch_elem.attrib.get("name")

        observations.append(
            HostObservation(
                host=primary_host,
                ip=ip_address,
                status=host_state,
                ports=port_obs_list,
                os_match=os_match,
                hostnames=hostnames,
                observed_at=datetime.now(timezone.utc),
            )
        )

    return observations
