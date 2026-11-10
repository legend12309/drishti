"""
DRISHTI — Phase 4 Graph Analytics Models & Provenance Schemas
Defines node types, relationship types, edge metadata, risk assessments,
attack paths, and mitigation simulation models.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class NodeType(str, Enum):
    ROOT_DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    HOST = "host"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    PIVOT = "pivot"
    CRITICAL_TARGET = "target"


class RelationType(str, Enum):
    RESOLVES_TO = "RESOLVES_TO"
    HOSTS = "HOSTS"
    HAS_SERVICE = "HAS_SERVICE"
    HAS_VULNERABILITY = "HAS_VULNERABILITY"
    DEPENDS_ON = "DEPENDS_ON"
    POTENTIAL_TRANSITION = "POTENTIAL_TRANSITION"


class ProvenanceClassification(str, Enum):
    OBSERVED = "observed"      # Directly supported by passive/active evidence
    DERIVED = "derived"        # Deterministically computed from existing evidence
    INFERRED = "inferred"      # Proposed by documented inference rule
    UNKNOWN = "unknown"        # Insufficient evidence


class GraphNode(BaseModel):
    id: str
    label: str
    node_type: NodeType
    provenance: ProvenanceClassification = ProvenanceClassification.OBSERVED
    risk_score: float = Field(0.0, ge=0.0, le=10.0)
    criticality: float = Field(1.0, ge=1.0, le=5.0)
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    cves: List[str] = Field(default_factory=list)
    source_record_id: Optional[str] = None


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: RelationType
    provenance: ProvenanceClassification = ProvenanceClassification.OBSERVED
    weight: float = Field(1.0, ge=0.01)       # Non-negative traversal cost for Dijkstra
    priority_score: float = Field(0.0)       # Risk signal: higher = higher risk
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    is_hypothetical: bool = False
    evidence_id: Optional[str] = None
    rule_id: Optional[str] = None
    assumptions: List[str] = Field(default_factory=list)


class CandidateAttackPath(BaseModel):
    id: str
    scan_id: str
    snapshot_id: str
    source_node: str
    target_node: str
    path_nodes: List[str]
    path_edges: List[Dict[str, Any]]
    total_cost: float
    priority_score: float
    cves: List[str] = Field(default_factory=list)
    hypothetical_transitions_count: int = 0
    confidence_level: str = "medium"
    preconditions: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    scan_id: str
    snapshot_id: str
    overall_risk_score: float = Field(0.0, ge=0.0, le=10.0)
    criticality_score: float = Field(0.0, ge=0.0, le=10.0)
    confirmed_vulns_count: int = 0
    potential_vulns_count: int = 0
    compromise_likelihood: float = Field(0.0, ge=0.0, le=1.0)
    factors: Dict[str, Any] = Field(default_factory=dict)
    scoring_version: str = "4.0-drishti-risk"


class MitigationScenario(BaseModel):
    scenario_name: str
    mitigated_cves: List[str] = Field(default_factory=list)
    disabled_edges: List[List[str]] = Field(default_factory=list)   # [[u, v], ...]
    target_node: Optional[str] = None


class MitigationSimulationResult(BaseModel):
    id: str
    scan_id: str
    snapshot_id: str
    scenario_name: str
    original_risk_score: float
    simulated_risk_score: float
    risk_delta: float
    broken_paths_count: int
    remaining_paths_count: int
    eliminated_cves: List[str]
    original_paths: List[CandidateAttackPath]
    simulated_paths: List[CandidateAttackPath]
    details: Dict[str, Any] = Field(default_factory=dict)
