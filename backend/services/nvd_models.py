"""
DRISHTI — Vulnerability Intelligence Data Models
Defines Pydantic models for NVD CVE 2.0 schemas, normalized asset fingerprints,
applicability criteria, and match audit results.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ApplicabilityStatus(str, Enum):
    CONFIRMED = "confirmed_applicability"
    POTENTIAL = "potential_applicability"
    NOT_AFFECTED = "not_affected"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class CpeMatchCriteria(BaseModel):
    criteria: str
    vulnerable: bool = True
    matchCriteriaId: Optional[str] = None
    versionStartIncluding: Optional[str] = None
    versionStartExcluding: Optional[str] = None
    versionEndIncluding: Optional[str] = None
    versionEndExcluding: Optional[str] = None


class ConfigurationNode(BaseModel):
    operator: str = "OR"
    negate: bool = False
    cpeMatch: List[CpeMatchCriteria] = Field(default_factory=list)


class CveReference(BaseModel):
    url: str
    source: str = "NVD"
    tags: List[str] = Field(default_factory=list)


class VulnerabilityRecord(BaseModel):
    cve_id: str
    source_id: str = "NVD"
    title: Optional[str] = None
    description: str = ""
    published_at: Optional[str] = None
    last_modified_at: Optional[str] = None
    cvss_version: str = "3.1"
    cvss_score: float = 0.0
    cvss_severity: str = "UNKNOWN"
    cvss_vector: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    cwe_ids: List[str] = Field(default_factory=list)
    configurations: List[ConfigurationNode] = Field(default_factory=list)
    references: List[CveReference] = Field(default_factory=list)
    remediation_notes: Optional[str] = None
    cached_at: Optional[str] = None
    is_weaponized: bool = False
    metasploit_module: Optional[str] = None
    cisa_kev: bool = False


class AssetFingerprint(BaseModel):
    id: Optional[int] = None
    scan_id: Optional[str] = None
    asset_id: str
    host: str
    port: Optional[int] = None
    vendor: str
    product: str
    version: Optional[str] = None
    version_scheme: str = "semver"
    cpe23: Optional[str] = None
    os_metadata: Optional[str] = None
    service_metadata: Optional[str] = None
    fingerprint_source: str = "banner"
    is_inferred: bool = False
    confidence: float = 1.0
    observed_at: Optional[str] = None


class VulnerabilityFinding(BaseModel):
    id: Optional[int] = None
    scan_id: str
    asset_id: str
    cve_id: str
    fingerprint_id: Optional[int] = None
    applicability_status: ApplicabilityStatus
    confidence_score: float = 1.0
    match_rationale: str
    evaluated_at: Optional[str] = None

    # Enriched fields for UI and API consumers
    cve_title: Optional[str] = None
    cve_description: Optional[str] = None
    cvss_score: float = 0.0
    cvss_severity: str = "UNKNOWN"
    cvss_vector: Optional[str] = None
    epss_score: Optional[float] = None
    remediation_notes: Optional[str] = None
    references: List[Dict[str, Any]] = Field(default_factory=list)
    affected_product: Optional[str] = None
    observed_version: Optional[str] = None
    is_weaponized: bool = False
    metasploit_module: Optional[str] = None
    cisa_kev: bool = False
