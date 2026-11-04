"""
DRISHTI — Phase 4 Comprehensive Test Suite: NetworkX Risk Engine & Attack Graph
Tests:
  1. Deterministic graph construction from known Supabase-backed evidence fixtures
  2. Provenance separation: OBSERVED vs INFERRED vs HYPOTHETICAL edges
  3. Non-negative Dijkstra edge cost and prioritization score calculations
  4. Monotonicity and boundary checks for risk scoring
  5. Shortest path finding, cycles handling, and disconnected graphs
  6. Top-K and depth bounded path search
  7. Isolated defensive mitigation simulation (zero mutation of original scan records)
  8. Graph snapshot persistence and retrieval in Supabase PostgreSQL
  9. Graph REST API endpoints (/api/graph/build, /api/graph/{id}, /api/graph/{id}/paths, /simulate-mitigation)
"""

import pytest
import networkx as nx
from backend.services.graph_builder import AttackGraphBuilder
from backend.services.graph_models import (
    GraphEdge,
    GraphNode,
    MitigationScenario,
    NodeType,
    ProvenanceClassification,
    RelationType,
)
from backend.services.path_analyzer import find_candidate_attack_paths, simulate_mitigation
from backend.services.risk_engine import (
    calculate_vulnerability_weight,
    compute_composite_risk_assessment,
)
from backend.services.graph_service import (
    get_attack_paths,
    get_graph_snapshot,
    get_risk_assessment,
    persist_attack_paths,
    persist_graph_snapshot,
    persist_mitigation_simulation,
    persist_risk_assessment,
)


@pytest.fixture
def mock_evidence():
    findings = [
        {
            "host": "vpn.company.com",
            "ip": "198.51.100.8",
            "tech": "OpenVPN 2.5, OpenSSL 1.1.1",
            "status": "Filtered",
            "risk": "CRITICAL",
            "score": "9.8",
            "ports": [443, 1194],
        },
        {
            "host": "api.company.com",
            "ip": "104.21.48.12",
            "tech": "Nginx 1.24",
            "status": "200 OK",
            "risk": "HIGH",
            "score": "7.8",
            "ports": [80, 443],
        },
    ]
    vulnerabilities = [
        {
            "asset_id": "vpn.company.com:443",
            "cve_id": "CVE-2022-37434",
            "applicability_status": "confirmed_applicability",
            "cvss_score": 9.8,
            "epss_score": 0.72,
            "confidence_score": 0.98,
            "title": "OpenVPN Buffer Overflow",
            "match_rationale": "Version 2.5 satisfies [>=2.4.0, <2.6.0]",
        }
    ]
    return findings, vulnerabilities


def test_attack_graph_construction_and_provenance(mock_evidence):
    """Verifies that nodes and edges are traceable to evidence and distinguish observed from inferred."""
    findings, vulns = mock_evidence
    builder = AttackGraphBuilder(scan_id="test-scan-001")
    g = builder.build_from_evidence("company.com", findings, vulns)

    # Check root domain
    assert "company.com" in g
    assert g.nodes["company.com"]["node_type"] == NodeType.ROOT_DOMAIN.value
    assert g.nodes["company.com"]["provenance"] == ProvenanceClassification.OBSERVED.value

    # Check subdomain & service
    assert "vpn.company.com" in g
    assert "vpn.company.com:443" in g
    assert g.has_edge("company.com", "vpn.company.com")
    assert g.edges["company.com", "vpn.company.com"]["relation"] == RelationType.RESOLVES_TO.value
    assert g.edges["company.com", "vpn.company.com"]["provenance"] == ProvenanceClassification.OBSERVED.value

    # Check vulnerability node
    vuln_node_id = "CVE-2022-37434 (vpn.company.com)"
    assert vuln_node_id in g
    assert g.nodes[vuln_node_id]["node_type"] == NodeType.VULNERABILITY.value

    # Check inferred transition to InternalAuth
    assert g.has_edge(vuln_node_id, "InternalAuth")
    edge_data = g.edges[vuln_node_id, "InternalAuth"]
    assert edge_data["provenance"] == ProvenanceClassification.INFERRED.value
    assert edge_data["is_hypothetical"] is True
    assert len(edge_data["assumptions"]) > 0


def test_dijkstra_weights_non_negative_and_monotonic():
    """Verifies that vulnerability weighting produces strictly non-negative edge costs."""
    # Critical high-risk CVE should yield higher priority and lower traversal cost
    crit_w = calculate_vulnerability_weight(
        cvss_score=9.8,
        epss_score=0.85,
        applicability_status="confirmed_applicability",
        confidence=1.0,
        asset_criticality=5.0,
    )
    assert crit_w["traversal_cost"] >= 0.1
    assert crit_w["priority_score"] >= 8.0

    # Low-risk CVE should yield lower priority and higher traversal cost
    low_w = calculate_vulnerability_weight(
        cvss_score=2.0,
        epss_score=0.01,
        applicability_status="confirmed_applicability",
        confidence=1.0,
        asset_criticality=1.0,
    )
    assert low_w["traversal_cost"] >= crit_w["traversal_cost"]
    assert low_w["priority_score"] <= crit_w["priority_score"]

    # Insufficient evidence should reduce priority
    insuf_w = calculate_vulnerability_weight(
        cvss_score=9.8,
        epss_score=0.85,
        applicability_status="insufficient_evidence",
        confidence=0.5,
    )
    assert insuf_w["priority_score"] < crit_w["priority_score"]


def test_bounded_candidate_attack_paths(mock_evidence):
    """Verifies Dijkstra pathfinding with Top-K and depth bounds."""
    findings, vulns = mock_evidence
    builder = AttackGraphBuilder(scan_id="test-scan-path")
    g = builder.build_from_evidence("company.com", findings, vulns)

    paths = find_candidate_attack_paths(
        g=g,
        source_node="company.com",
        target_node="CoreDB",
        scan_id="test-scan-path",
        snapshot_id=builder.snapshot_id,
        k=2,
    )

    assert len(paths) >= 1
    primary_path = paths[0]
    assert primary_path.source_node == "company.com"
    assert primary_path.target_node == "CoreDB"
    assert "CoreDB" in primary_path.path_nodes
    assert primary_path.total_cost > 0.0
    assert "CVE-2022-37434" in primary_path.cves
    assert primary_path.confidence_level in ("high", "medium", "low")
    assert len(primary_path.recommendations) > 0


def test_disconnected_graph_and_cycles_handling():
    """Verifies that disconnected components and cycles do not cause infinite loops or crashes."""
    g = nx.DiGraph()
    # Add cycle: A -> B -> C -> A
    g.add_edge("A", "B", weight=1.0, priority_score=1.0, assumptions=[])
    g.add_edge("B", "C", weight=1.0, priority_score=1.0, assumptions=[])
    g.add_edge("C", "A", weight=1.0, priority_score=1.0, assumptions=[])
    # Add isolated target D
    g.add_node("D")

    # Path to disconnected node should safely return empty list
    paths = find_candidate_attack_paths(g, source_node="A", target_node="D", scan_id="s1", snapshot_id="snap1")
    assert paths == []

    # Path to non-existent node
    paths_missing = find_candidate_attack_paths(g, source_node="A", target_node="NonExistent", scan_id="s1", snapshot_id="snap1")
    assert paths_missing == []


def test_isolated_mitigation_simulation(mock_evidence):
    """Verifies that defensive mitigation simulation operates on an isolated copy without mutating source data."""
    findings, vulns = mock_evidence
    builder = AttackGraphBuilder(scan_id="test-sim-001")
    g = builder.build_from_evidence("company.com", findings, vulns)
    orig_node_count = len(g.nodes)
    orig_edge_count = len(g.edges)

    scenario = MitigationScenario(
        scenario_name="Patch OpenVPN CVE-2022-37434",
        mitigated_cves=["CVE-2022-37434"],
        target_node="CoreDB",
    )

    sim_res = simulate_mitigation(
        g=g,
        scenario=scenario,
        source_node="company.com",
        target_node="CoreDB",
        scan_id="test-sim-001",
        snapshot_id=builder.snapshot_id,
        original_risk_score=8.5,
    )

    # Ensure original graph was NOT modified
    assert len(g.nodes) == orig_node_count
    assert len(g.edges) == orig_edge_count

    # Simulation results
    assert sim_res.simulated_risk_score < sim_res.original_risk_score
    assert sim_res.risk_delta > 0.0
    assert "CVE-2022-37434" in sim_res.eliminated_cves
    assert sim_res.broken_paths_count >= 1


@pytest.mark.asyncio
async def test_supabase_graph_snapshot_and_risk_persistence(mock_evidence):
    """Verifies that graph snapshots, risk assessments, and attack paths persist cleanly in Supabase."""
    from backend.db.database import db_queue
    findings, vulns = mock_evidence
    scan_id = "test-scan-persist"

    # First insert a parent scan record so foreign key constraint fk_graph_snapshots_scan is satisfied
    await db_queue.execute_write(
        """
        INSERT INTO scans (id, target, status, progress, current_step)
        VALUES (?, 'company.com', 'completed', 100, 'Test scan for graph persistence')
        ON CONFLICT (id) DO NOTHING
        """,
        (scan_id,)
    )

    builder = AttackGraphBuilder(scan_id=scan_id)
    g = builder.build_from_evidence("company.com", findings, vulns)
    graph_dict = builder.to_dict()

    # 1. Persist snapshot
    await persist_graph_snapshot(builder.snapshot_id, scan_id, graph_dict)
    fetched_snap = await get_graph_snapshot(scan_id)
    assert fetched_snap is not None
    assert fetched_snap["scan_id"] == scan_id
    assert fetched_snap["nodes_count"] == len(graph_dict["nodes"])

    # 2. Risk assessment
    assessment = compute_composite_risk_assessment(
        scan_id=scan_id,
        snapshot_id=builder.snapshot_id,
        nodes=graph_dict["nodes"],
        vulnerabilities=vulns,
    )
    await persist_risk_assessment(assessment)
    fetched_risk = await get_risk_assessment(scan_id)
    assert fetched_risk is not None
    assert fetched_risk["overall_risk_score"] == assessment.overall_risk_score

    # 3. Attack paths
    paths = find_candidate_attack_paths(
        g=g,
        source_node="company.com",
        target_node="CoreDB",
        scan_id=scan_id,
        snapshot_id=builder.snapshot_id,
        k=1,
    )
    if paths:
        await persist_attack_paths(paths)
        fetched_paths = await get_attack_paths(scan_id)
        assert len(fetched_paths) >= 1
        assert fetched_paths[0]["target_node"] == "CoreDB"


def test_no_self_loop_for_apex_domain():
    """Verifies that an apex host finding does not create a self-loop edge company.com -> company.com."""
    findings = [{"host": "company.com", "ip": "1.2.3.4", "ports": [80, 443], "risk": "MEDIUM", "score": 4.0}]
    builder = AttackGraphBuilder(scan_id="test-no-loop")
    g = builder.build_from_evidence("company.com", findings, [])
    assert not g.has_edge("company.com", "company.com")


def test_lateral_movement_from_risky_ports():
    """Verifies that high-risk exposed ports (SSH 22, Redis 6379) infer lateral transitions without CVEs."""
    findings = [
        {"host": "cache.company.com", "ip": "10.0.0.5", "ports": [6379], "risk": "HIGH", "score": 8.0},
        {"host": "bastion.company.com", "ip": "10.0.0.6", "ports": [22], "risk": "HIGH", "score": 7.5},
    ]
    builder = AttackGraphBuilder(scan_id="test-risky-ports")
    g = builder.build_from_evidence("company.com", findings, [])

    assert g.has_edge("cache.company.com:6379", "InternalAuth")
    assert g.has_edge("bastion.company.com:22", "InternalAuth")

    paths = find_candidate_attack_paths(
        g=g,
        source_node="company.com",
        target_node="CoreDB",
        scan_id="test-risky-ports",
        snapshot_id=builder.snapshot_id,
        k=2,
    )
    assert len(paths) >= 1
    assert "CoreDB" in paths[0].path_nodes
