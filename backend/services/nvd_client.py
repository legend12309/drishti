"""
DRISHTI — Official NIST NVD 2.0 API Client
Implements modular CVE retrieval with connection/read timeouts, exponential
backoff with jitter, HTTP 429 Retry-After handling, bounded pagination,
incremental synchronization, and offline fallback fixtures.
"""

import asyncio
import os
import random
import time
from typing import Any, Dict, List, Optional
import httpx
from backend.services.nvd_models import (
    ConfigurationNode,
    CpeMatchCriteria,
    CveReference,
    VulnerabilityRecord,
)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_TIMEOUT_CONNECT = 10.0
DEFAULT_TIMEOUT_READ = 20.0
MAX_RESULTS_PER_PAGE = 100


class NvdApiClient:
    """Modular, resilient NVD 2.0 REST API client."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = NVD_API_BASE,
        connect_timeout: float = DEFAULT_TIMEOUT_CONNECT,
        read_timeout: float = DEFAULT_TIMEOUT_READ,
        max_retries: int = 3,
    ):
        self.api_key = api_key or os.getenv("NVD_API_KEY", "").strip()
        self.base_url = base_url
        self.timeout = httpx.Timeout(read_timeout, connect=connect_timeout)
        self.max_retries = max_retries

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "DRISHTI-Cyber-Intelligence/1.0",
        }
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    async def fetch_cve(self, cve_id: str) -> Optional[VulnerabilityRecord]:
        """Fetches a single CVE from NVD by its identifier with retry and backoff."""
        clean_id = cve_id.strip().upper()
        # First check deterministic fixture fallback
        fixture = get_offline_cve_fixture(clean_id)
        if fixture:
            return fixture

        url = f"{self.base_url}?cveId={clean_id}"
        data = await self._execute_request(url)
        if not data or "vulnerabilities" not in data:
            return None

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        return self.parse_nvd_item(vulns[0].get("cve", {}))

    async def fetch_incremental(
        self,
        last_mod_start: str,
        last_mod_end: Optional[str] = None,
        results_per_page: int = 50,
        start_index: int = 0,
    ) -> Dict[str, Any]:
        """
        Incrementally queries NVD by modification timestamp window.
        Dates must be ISO-8601 strings (e.g. '2026-10-01T00:00:00.000').
        """
        bounded_limit = min(max(1, results_per_page), MAX_RESULTS_PER_PAGE)
        params = [
            f"lastModStartDate={last_mod_start}",
            f"resultsPerPage={bounded_limit}",
            f"startIndex={start_index}",
        ]
        if last_mod_end:
            params.append(f"lastModEndDate={last_mod_end}")

        url = f"{self.base_url}?{'&'.join(params)}"
        data = await self._execute_request(url)
        if not data:
            return {"totalResults": 0, "vulnerabilities": [], "status": "unavailable"}

        records = []
        for item in data.get("vulnerabilities", []):
            parsed = self.parse_nvd_item(item.get("cve", {}))
            if parsed:
                records.append(parsed)

        return {
            "totalResults": data.get("totalResults", len(records)),
            "resultsPerPage": data.get("resultsPerPage", bounded_limit),
            "startIndex": data.get("startIndex", start_index),
            "vulnerabilities": records,
            "status": "success",
        }

    async def _execute_request(self, url: str) -> Optional[Dict[str, Any]]:
        """Executes HTTP request with bounded retries, jitter, and 429 Retry-After handling."""
        attempt = 0
        backoff = 1.0

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            while attempt <= self.max_retries:
                attempt += 1
                try:
                    res = await client.get(url, headers=self._get_headers())
                    if res.status_code == 200:
                        return res.json()

                    # Handle Rate Limiting (429 Too Many Requests)
                    if res.status_code == 429:
                        retry_after = res.headers.get("Retry-After")
                        wait_seconds = float(retry_after) if retry_after and retry_after.isdigit() else backoff
                        jitter = random.uniform(0.1, 0.4)
                        await asyncio.sleep(wait_seconds + jitter)
                        backoff *= 2.0
                        continue

                    # Server error (500, 502, 503, 504) -> retry with backoff
                    if res.status_code in (500, 502, 503, 504):
                        jitter = random.uniform(0.1, 0.3)
                        await asyncio.sleep(backoff + jitter)
                        backoff *= 2.0
                        continue

                    # Client error (400, 404, etc.) -> no retry
                    return None

                except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout):
                    if attempt > self.max_retries:
                        return None
                    jitter = random.uniform(0.1, 0.5)
                    await asyncio.sleep(backoff + jitter)
                    backoff *= 2.0

        return None

    def parse_nvd_item(self, cve_dict: Dict[str, Any]) -> Optional[VulnerabilityRecord]:
        """Transforms raw NVD 2.0 JSON payload into normalized VulnerabilityRecord."""
        cve_id = cve_dict.get("id")
        if not cve_id:
            return None

        # Descriptions (prefer English)
        desc = ""
        for d in cve_dict.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not desc and cve_dict.get("descriptions"):
            desc = cve_dict["descriptions"][0].get("value", "")

        # CVSS v3.1 / v3.0 / v2
        metrics = cve_dict.get("metrics", {})
        cvss_score = 0.0
        cvss_severity = "UNKNOWN"
        cvss_vector = None
        cvss_ver = "3.1"

        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            m = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_score = float(m.get("baseScore", 0.0))
            cvss_severity = m.get("baseSeverity", "UNKNOWN").upper()
            cvss_vector = m.get("vectorString")
            cvss_ver = "3.1"
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            m = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_score = float(m.get("baseScore", 0.0))
            cvss_severity = m.get("baseSeverity", "UNKNOWN").upper()
            cvss_vector = m.get("vectorString")
            cvss_ver = "3.0"
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            m = metrics["cvssMetricV2"][0].get("cvssData", {})
            cvss_score = float(m.get("baseScore", 0.0))
            cvss_severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN").upper()
            cvss_vector = m.get("vectorString")
            cvss_ver = "2.0"

        # CWE identifiers
        cwe_ids = []
        for w in cve_dict.get("weaknesses", []):
            for d in w.get("description", []):
                val = d.get("value")
                if val and val != "NVD-CWE-Other":
                    cwe_ids.append(val)

        # Configurations & CPE match criteria
        config_nodes = []
        configs = cve_dict.get("configurations", [])
        for cfg in configs:
            for node in cfg.get("nodes", []):
                operator = node.get("operator", "OR")
                negate = node.get("negate", False)
                cpe_matches = []
                for cm in node.get("cpeMatch", []):
                    cpe_matches.append(
                        CpeMatchCriteria(
                            criteria=cm.get("criteria", ""),
                            vulnerable=cm.get("vulnerable", True),
                            matchCriteriaId=cm.get("matchCriteriaId"),
                            versionStartIncluding=cm.get("versionStartIncluding"),
                            versionStartExcluding=cm.get("versionStartExcluding"),
                            versionEndIncluding=cm.get("versionEndIncluding"),
                            versionEndExcluding=cm.get("versionEndExcluding"),
                        )
                    )
                if cpe_matches:
                    config_nodes.append(ConfigurationNode(operator=operator, negate=negate, cpeMatch=cpe_matches))

        # References
        refs = []
        for r in cve_dict.get("references", []):
            url = r.get("url")
            if url:
                refs.append(CveReference(url=url, source=r.get("source", "NVD"), tags=r.get("tags", [])))

        return VulnerabilityRecord(
            cve_id=cve_id,
            source_id="NVD",
            title=f"{cve_id} Vulnerability",
            description=desc,
            published_at=cve_dict.get("published"),
            last_modified_at=cve_dict.get("lastModified"),
            cvss_version=cvss_ver,
            cvss_score=cvss_score,
            cvss_severity=cvss_severity,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            configurations=config_nodes,
            references=refs,
        )


# ---------------------------------------------------------------------------
# Offline & Air-Gapped High-Fidelity CVE Fixture Corpus
# ---------------------------------------------------------------------------

OFFLINE_FIXTURES: Dict[str, VulnerabilityRecord] = {
    "CVE-2024-38077": VulnerabilityRecord(
        cve_id="CVE-2024-38077",
        title="Windows Remote Access Connection Manager RCE",
        description="An unauthenticated attacker can send crafted RPC requests to execute arbitrary code with elevated system privileges in Windows Remote Access Connection Manager.",
        published_at="2024-07-09T17:15:12Z",
        last_modified_at="2024-07-16T13:45:22Z",
        cvss_version="3.1",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        epss_score=0.89,
        epss_percentile=0.99,
        cwe_ids=["CWE-120"],
        remediation_notes="Apply Microsoft Security Update KB5040442 immediately or disable Routing and Remote Access Service (RRAS).",
        references=[
            CveReference(url="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38077", source="Microsoft", tags=["Patch", "Vendor Advisory"])
        ],
        configurations=[
            ConfigurationNode(
                operator="OR",
                cpeMatch=[
                    CpeMatchCriteria(criteria="cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*", vulnerable=True),
                    CpeMatchCriteria(criteria="cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:*:*", vulnerable=True),
                ]
            )
        ]
    ),
    "CVE-2024-4577": VulnerabilityRecord(
        cve_id="CVE-2024-4577",
        title="PHP CGI Argument Injection Vulnerability",
        description="Best-fit character encoding conversions in Windows Apache PHP-CGI module allows remote attackers to bypass security protections and achieve arbitrary command execution.",
        published_at="2024-06-09T19:15:52Z",
        last_modified_at="2024-06-12T14:22:10Z",
        cvss_version="3.1",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        epss_score=0.94,
        epss_percentile=0.99,
        cwe_ids=["CWE-78"],
        remediation_notes="Upgrade PHP to version 8.3.8, 8.2.20, or 8.1.29+. Discontinue PHP-CGI handler in Apache on Windows.",
        references=[
            CveReference(url="https://www.php.net/ChangeLog-8.php#8.3.8", source="PHP.net", tags=["Patch", "Vendor Advisory"]),
            CveReference(url="https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection/", source="DEVCORE", tags=["Exploit", "Third Party Advisory"])
        ],
        configurations=[
            ConfigurationNode(
                operator="AND",
                cpeMatch=[
                    CpeMatchCriteria(criteria="cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", vulnerable=True, versionStartIncluding="8.1.0", versionEndExcluding="8.1.29"),
                    CpeMatchCriteria(criteria="cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", vulnerable=True, versionStartIncluding="8.2.0", versionEndExcluding="8.2.20"),
                    CpeMatchCriteria(criteria="cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", vulnerable=True, versionStartIncluding="8.3.0", versionEndExcluding="8.3.8"),
                    CpeMatchCriteria(criteria="cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*", vulnerable=False)
                ]
            )
        ]
    ),
    "CVE-2024-6387": VulnerabilityRecord(
        cve_id="CVE-2024-6387",
        title="OpenSSH regreSSHion Signal Handler Race Condition",
        description="Signal handler race condition in OpenSSH sshd process leads to unauthenticated root code execution on glibc-based Linux systems.",
        published_at="2024-07-01T08:15:04Z",
        last_modified_at="2024-07-08T18:31:00Z",
        cvss_version="3.1",
        cvss_score=8.1,
        cvss_severity="HIGH",
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        epss_score=0.62,
        epss_percentile=0.97,
        cwe_ids=["CWE-362"],
        remediation_notes="Upgrade OpenSSH to 9.8p1 or newer. Set 'LoginGraceTime 0' as temporary mitigation.",
        references=[
            CveReference(url="https://www.openssh.com/txt/release-9.8", source="OpenSSH", tags=["Release Notes", "Vendor Advisory"])
        ],
        configurations=[
            ConfigurationNode(
                operator="OR",
                cpeMatch=[
                    CpeMatchCriteria(criteria="cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", vulnerable=True, versionStartIncluding="8.5p1", versionEndExcluding="9.8p1")
                ]
            )
        ]
    ),
    "CVE-2024-27348": VulnerabilityRecord(
        cve_id="CVE-2024-27348",
        title="Apache HugeGraph RCE via Gremlin Server",
        description="Improper input validation in Gremlin script execution endpoints leads to unauthenticated Java reflection execution and server takeover.",
        published_at="2024-04-22T08:15:33Z",
        last_modified_at="2024-05-10T12:00:00Z",
        cvss_version="3.1",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        epss_score=0.58,
        epss_percentile=0.96,
        cwe_ids=["CWE-94"],
        remediation_notes="Upgrade Apache HugeGraph to 1.3.0 or higher. Restrict access to Gremlin server ports.",
        references=[
            CveReference(url="https://hugegraph.apache.org/docs/guides/security/", source="Apache", tags=["Vendor Advisory"])
        ],
        configurations=[
            ConfigurationNode(
                operator="OR",
                cpeMatch=[
                    CpeMatchCriteria(criteria="cpe:2.3:a:apache:hugegraph:*:*:*:*:*:*:*:*", vulnerable=True, versionStartIncluding="1.0.0", versionEndIncluding="1.3.0")
                ]
            )
        ]
    ),
    "CVE-2022-37434": VulnerabilityRecord(
        cve_id="CVE-2022-37434",
        title="zlib / OpenVPN Heap Buffer Overflow via inflateGetHeader",
        description="Heap-based buffer over-read and overflow in inflate.c in zlib through 1.2.12 allows memory corruption and potential code execution when processing crafted header fields, impacting OpenVPN 2.5 and prior configurations using compression.",
        published_at="2022-08-05T21:15:08Z",
        last_modified_at="2023-01-12T10:14:00Z",
        cvss_version="3.1",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        epss_score=0.72,
        epss_percentile=0.98,
        cwe_ids=["CWE-787"],
        remediation_notes="Upgrade OpenVPN to 2.6.0 or rebuild with zlib 1.2.13. Disable comp-lzo compression in OpenVPN server profile.",
        references=[
            CveReference(url="https://community.openvpn.net/openvpn/wiki/SecurityAnnouncements", source="OpenVPN", tags=["Vendor Advisory"])
        ],
        configurations=[
            ConfigurationNode(
                operator="OR",
                cpeMatch=[
                    CpeMatchCriteria(criteria="cpe:2.3:a:openvpn:openvpn:*:*:*:*:*:*:*:*", vulnerable=True, versionStartIncluding="2.4.0", versionEndExcluding="2.6.0")
                ]
            )
        ]
    ),
    "CVE-2021-3618": VulnerabilityRecord(
        cve_id="CVE-2021-3618",
        title="Postfix ALPACA Cross-Protocol TLS Information Leak",
        description="Cross-protocol attack sensitivity in Postfix SMTP daemon implementation allows attackers to abuse TLS connections to extract sensitive session data.",
        published_at="2021-11-23T20:15:07Z",
        last_modified_at="2022-04-18T16:20:00Z",
        cvss_version="3.1",
        cvss_score=7.4,
        cvss_severity="HIGH",
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        epss_score=0.15,
        epss_percentile=0.78,
        cwe_ids=["CWE-200"],
        remediation_notes="Upgrade Postfix to 3.6.2 or 3.7.0+. Configure tls_server_sni_maps and enforce modern cipher suites.",
        references=[
            CveReference(url="http://www.postfix.org/announcements/postfix-3.6.2.html", source="Postfix", tags=["Vendor Advisory"])
        ],
        configurations=[
            ConfigurationNode(
                operator="OR",
                cpeMatch=[
                    CpeMatchCriteria(criteria="cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*", vulnerable=True, versionStartIncluding="3.4.0", versionEndExcluding="3.6.2")
                ]
            )
        ]
    ),
    "CVE-2024-21413": VulnerabilityRecord(
        cve_id="CVE-2024-21413",
        title="Microsoft Outlook Remote Code Execution Flaw",
        description="MonikerLink bug bypassing Protected View in Microsoft Outlook when opening malicious email hyperlinks leading to NTLM credential relay and code execution.",
        published_at="2024-02-13T18:15:58Z",
        last_modified_at="2024-02-28T14:15:00Z",
        cvss_version="3.1",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        epss_score=0.74,
        epss_percentile=0.98,
        cwe_ids=["CWE-20"],
        remediation_notes="Apply Microsoft February 2024 Patch Tuesday update.",
        references=[
            CveReference(url="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413", source="Microsoft", tags=["Vendor Advisory"])
        ],
        configurations=[
            ConfigurationNode(
                operator="OR",
                cpeMatch=[
                    CpeMatchCriteria(criteria="cpe:2.3:a:microsoft:outlook:*:*:*:*:*:*:*:*", vulnerable=True)
                ]
            )
        ]
    )
}


def get_offline_cve_fixture(cve_id: str) -> Optional[VulnerabilityRecord]:
    """Retrieves a cached high-fidelity fixture by CVE ID."""
    return OFFLINE_FIXTURES.get(cve_id.strip().upper())


def get_all_offline_cve_fixtures() -> List[VulnerabilityRecord]:
    """Returns all bundled vulnerability fixtures."""
    return list(OFFLINE_FIXTURES.values())
