"""
DRISHTI — Phase 6 Scanner Foundation: Base Scanner Interface & Data Contracts
Defines the standard abstraction for all active and passive scanners.
Enforces typed configurations, bounded execution parameters, normalized observations,
and execution status lifecycle.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class ScanType(str, Enum):
    PASSIVE_RECON = "PASSIVE_RECON"
    NMAP = "NMAP"
    HTTPX = "HTTPX"
    ZAP = "ZAP"
    TRIVY = "TRIVY"
    NUCLEI = "NUCLEI"
    CUSTOM = "CUSTOM"


class ScanProfile(str, Enum):
    BASIC_PORT_DISCOVERY = "BASIC_PORT_DISCOVERY"
    SERVICE_IDENTIFICATION = "SERVICE_IDENTIFICATION"
    QUICK_AUDIT = "QUICK_AUDIT"
    FAST_DEMO = "FAST_DEMO"
    DEEP_AUDIT = "DEEP_AUDIT"
    HTTP_SERVICE_DISCOVERY = "HTTP_SERVICE_DISCOVERY"
    SERVICE_METADATA_ENRICHMENT = "SERVICE_METADATA_ENRICHMENT"
    APPROVED_ASSET_ENRICHMENT = "APPROVED_ASSET_ENRICHMENT"
    ZAP_PASSIVE_ANALYSIS = "ZAP_PASSIVE_ANALYSIS"
    ZAP_BASELINE_AUDIT = "ZAP_BASELINE_AUDIT"
    TRIVY_FS_DEPENDENCIES = "TRIVY_FS_DEPENDENCIES"
    TRIVY_FS_CONFIG = "TRIVY_FS_CONFIG"
    TRIVY_IMAGE = "TRIVY_IMAGE"
    TRIVY_FULL_LOCAL = "TRIVY_FULL_LOCAL"
    NUCLEI_MISCONFIG_AUDIT = "NUCLEI_MISCONFIG_AUDIT"
    NUCLEI_EXPOSURES = "NUCLEI_EXPOSURES"
    NUCLEI_KNOWN_VULNS = "NUCLEI_KNOWN_VULNS"
    NUCLEI_APPROVED_BASELINE = "NUCLEI_APPROVED_BASELINE"
    CUSTOM_APPROVED = "CUSTOM_APPROVED"


class ScannerExecutionState(str, Enum):
    NOT_STARTED = "not_started"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    SCANNER_UNAVAILABLE = "scanner_unavailable"
    SKIPPED = "skipped"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class ScannerHealth:
    scanner_name: str
    is_available: bool
    version: Optional[str] = None
    binary_path: Optional[str] = None
    supported_profiles: List[ScanProfile] = field(default_factory=list)
    error_message: Optional[str] = None


@dataclass
class PortObservation:
    port: int
    protocol: str = "tcp"
    state: str = "open"  # open, closed, filtered, unfiltered
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None
    cpe23: Optional[str] = None
    confidence: float = 1.0


@dataclass
class HostObservation:
    host: str
    ip: str
    status: str = "up"  # up, down, unknown
    ports: List[PortObservation] = field(default_factory=list)
    os_match: Optional[str] = None
    hostnames: List[str] = field(default_factory=list)
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class HttpServiceObservation:
    url: str
    host: str
    port: int
    scheme: str  # http, https
    status_code: Optional[int] = None
    title: Optional[str] = None
    webserver: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    technologies: List[str] = field(default_factory=list)
    final_url: Optional[str] = None
    ip: Optional[str] = None
    cname: Optional[str] = None
    response_time_ms: Optional[float] = None
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ZapAlertObservation:
    plugin_id: str
    alert_name: str
    risk: str  # Informational, Low, Medium, High, Critical
    confidence: str  # False Positive, Low, Medium, High, User Confirmed
    url: str
    host: str
    port: int = 80
    param: Optional[str] = ""
    attack: Optional[str] = ""
    evidence: Optional[str] = ""
    description: Optional[str] = ""
    solution: Optional[str] = ""
    reference: Optional[str] = ""
    cwe_id: Optional[int] = None
    wasc_id: Optional[int] = None
    source_scanner: str = "OWASP ZAP"
    verification_status: str = "unverified_finding"  # unverified_finding, corroborated, suppressed
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class TrivyFindingObservation:
    target_resource: str
    finding_class: str  # vulnerability, misconfiguration, secret
    vulnerability_id: Optional[str] = None
    rule_id: Optional[str] = None
    title: Optional[str] = None
    severity: str = "UNKNOWN"  # UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL
    package_name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    primary_url: Optional[str] = None
    description: Optional[str] = None
    remediation_guidance: Optional[str] = None
    evidence: Optional[str] = None
    line_number: Optional[int] = None
    confidence: str = "HIGH"
    scanner_name: str = "Aqua Security Trivy"
    scanner_version: Optional[str] = None
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class NucleiFindingObservation:
    template_id: str
    template_name: str
    severity: str  # info, low, medium, high, critical, unknown
    matched_at: str
    host: str
    port: int = 80
    scheme: str = "http"
    url: Optional[str] = None
    matcher_name: Optional[str] = None
    extracted_results: List[str] = field(default_factory=list)
    type: str = "http"
    description: Optional[str] = None
    remediation: Optional[str] = None
    reference: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    curl_command: Optional[str] = None
    evidence: Optional[str] = None
    confidence: str = "TENTATIVE"  # TENTATIVE, CORROBORATED, CONFIRMED
    scanner_name: str = "ProjectDiscovery Nuclei"
    scanner_version: Optional[str] = None
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ScannerResult:
    scan_id: str
    target: str
    scanner_name: str
    scanner_version: str
    profile: ScanProfile
    status: ScannerExecutionState
    hosts: List[HostObservation] = field(default_factory=list)
    http_services: List[HttpServiceObservation] = field(default_factory=list)
    zap_alerts: List[ZapAlertObservation] = field(default_factory=list)
    trivy_findings: List[TrivyFindingObservation] = field(default_factory=list)
    nuclei_findings: List[NucleiFindingObservation] = field(default_factory=list)
    raw_output: str = ""
    exit_code: int = 0
    duration_seconds: float = 0.0
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None


class BaseScannerAdapter(ABC):
    """
    Abstract Base Class for security scanner integrations.
    Decouples process execution, CLI parameter construction, and output parsing.
    """

    @property
    @abstractmethod
    def scanner_name(self) -> str:
        pass

    @abstractmethod
    def check_availability(self) -> ScannerHealth:
        """Determines if the scanner binary is installed and executable."""
        pass

    @abstractmethod
    async def execute_scan(
        self,
        scan_id: str,
        target: str,
        profile: ScanProfile,
        timeout_seconds: int = 120,
        cancel_event: Optional[Any] = None,
    ) -> ScannerResult:
        """Executes a bounded, authenticated scan against an authorized target."""
        pass
