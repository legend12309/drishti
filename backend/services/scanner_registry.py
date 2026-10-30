"""
DRISHTI — Phase 11 Unified Scanner Registry & Capability Discovery
Provides dynamic registration, health validation, and capability inspection for all scanner adapters.
Encapsulates safe metadata without leaking internal binary paths, tokens, or host credentials.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Type

from backend.services.scanner_foundation import (
    BaseScannerAdapter,
    ScanProfile,
    ScannerHealth,
)
from backend.services.nmap_adapter import nmap_adapter
from backend.services.httpx_adapter import pd_httpx_adapter
from backend.services.zap_adapter import zap_adapter
from backend.services.trivy_adapter import trivy_adapter
from backend.services.nuclei_adapter import nuclei_adapter


class TargetType(str, Enum):
    DOMAIN = "domain"
    FQDN = "fqdn"
    URL = "url"
    IP = "ip"
    FILESYSTEM = "filesystem"
    CONTAINER_IMAGE = "container_image"


@dataclass
class ScannerCapability:
    scanner_id: str
    display_name: str
    is_available: bool
    version: Optional[str]
    supported_target_types: List[TargetType]
    supported_profiles: List[str]
    requires_dependency: Optional[str] = None
    cancellation_supported: bool = True
    concurrency_limit: int = 5
    timeout_default_seconds: int = 300
    error_message: Optional[str] = None


class ScannerRegistry:
    """Central registry of security scanner adapters."""

    def __init__(self):
        self._adapters: Dict[str, BaseScannerAdapter] = {}
        self._target_compatibilities: Dict[str, List[TargetType]] = {}
        self._dependencies: Dict[str, Optional[str]] = {}

        # Register existing 5 core adapters
        self.register(
            scanner_id="nmap",
            adapter=nmap_adapter,
            target_types=[TargetType.DOMAIN, TargetType.FQDN, TargetType.IP],
            dependency=None,
        )
        # Override timeout for Nmap - can take longer with -A flag
        nmap_cap = self.get_capability("nmap")
        if nmap_cap:
            nmap_cap.timeout_default_seconds = 300
        self.register(
            scanner_id="httpx",
            adapter=pd_httpx_adapter,
            target_types=[TargetType.DOMAIN, TargetType.FQDN, TargetType.URL],
            dependency=None,
        )
        self.register(
            scanner_id="zap",
            adapter=zap_adapter,
            target_types=[TargetType.DOMAIN, TargetType.FQDN, TargetType.URL],
            dependency="httpx",  # Best practice: Web service identified before web app crawling
        )
        self.register(
            scanner_id="trivy",
            adapter=trivy_adapter,
            target_types=[TargetType.FILESYSTEM, TargetType.CONTAINER_IMAGE, TargetType.DOMAIN, TargetType.FQDN, TargetType.URL],
            dependency=None,
        )
        self.register(
            scanner_id="nuclei",
            adapter=nuclei_adapter,
            target_types=[TargetType.DOMAIN, TargetType.FQDN, TargetType.URL],
            dependency="httpx",  # Templates target live HTTP/HTTPS endpoints
        )
        # Override timeout for Nuclei
        nuclei_cap = self.get_capability("nuclei")
        if nuclei_cap:
            nuclei_cap.timeout_default_seconds = 300

    def register(
        self,
        scanner_id: str,
        adapter: BaseScannerAdapter,
        target_types: List[TargetType],
        dependency: Optional[str] = None,
    ):
        clean_id = scanner_id.strip().lower()
        self._adapters[clean_id] = adapter
        self._target_compatibilities[clean_id] = target_types
        self._dependencies[clean_id] = dependency

    def get_adapter(self, scanner_id: str) -> Optional[BaseScannerAdapter]:
        return self._adapters.get(scanner_id.strip().lower())

    def get_registered_ids(self) -> List[str]:
        return list(self._adapters.keys())

    def get_capability(self, scanner_id: str) -> Optional[ScannerCapability]:
        clean_id = scanner_id.strip().lower()
        adapter = self._adapters.get(clean_id)
        if not adapter:
            return None

        health: ScannerHealth = adapter.check_availability()
        target_types = self._target_compatibilities.get(clean_id, [TargetType.DOMAIN])
        dep = self._dependencies.get(clean_id)

        timeout_default = 600 if clean_id in ("nmap", "zap") else 300

        return ScannerCapability(
            scanner_id=clean_id,
            display_name=adapter.scanner_name,
            is_available=health.is_available,
            version=health.version,
            supported_target_types=target_types,
            supported_profiles=[p.value if hasattr(p, "value") else str(p) for p in health.supported_profiles],
            requires_dependency=dep,
            cancellation_supported=True,
            concurrency_limit=10 if clean_id in ("httpx", "nuclei") else 5,
            timeout_default_seconds=timeout_default,
            error_message=health.error_message,
        )

    def get_all_capabilities(self) -> Dict[str, ScannerCapability]:
        capabilities = {}
        for sid in self._adapters.keys():
            cap = self.get_capability(sid)
            if cap:
                capabilities[sid] = cap
        return capabilities

    def validate_plan_scanners(self, requested_scanners: List[str]) -> Tuple[bool, List[str]]:
        """
        Validates that all requested scanner IDs exist and are known to the registry.
        Returns (is_valid, error_messages).
        """
        errors = []
        for sid in requested_scanners:
            clean = sid.strip().lower()
            if clean not in self._adapters:
                errors.append(f"Scanner '{sid}' is not a recognized scanner engine in DRISHTI registry.")
        return len(errors) == 0, errors


# Singleton instance
scanner_registry = ScannerRegistry()
