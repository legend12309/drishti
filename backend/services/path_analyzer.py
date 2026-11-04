"""
DRISHTI — Phase 4 Attack Path Analyzer & Mitigation Simulator
Uses NetworkX Dijkstra algorithm for non-negative shortest weighted paths,
finds top-K candidate paths, and executes isolated defensive counterfactual simulations.
"""

import copy
import heapq
import time
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx

from backend.services.graph_models import (
    CandidateAttackPath,
    MitigationScenario,
    MitigationSimulationResult,
)


def find_candidate_attack_paths(
    g: nx.DiGraph,
    source_node: str,
    target_node: str,
    scan_id: str,
    snapshot_id: str,
    k: int = 3,
    max_depth: int = 50,
) -> List[CandidateAttackPath]:
    """
    Finds top-K candidate attack paths from source to target using weighted traversal cost.
    Uses NetworkX shortest_simple_paths with strictly non-negative edge weights.
    """
    if source_node not in g or target_node not in g:
        return []

    candidate_paths: List[CandidateAttackPath] = []
    
    try:
        # Bounded simple paths generator sorted by weight
        path_generator = nx.shortest_simple_paths(g, source=source_node, target=target_node, weight="weight")
        
        count = 0
        for path in path_generator:
            if len(path) > max_depth:
                continue

            # Calculate total cost, priority, CVEs, and hypothetical edges
            total_cost = 0.0
            priority_sum = 0.0
            path_edges: List[Dict[str, Any]] = []
            cves: Set[str] = set()
            hypothetical_count = 0
            preconditions: List[str] = []
            recommendations: List[str] = []

            for i in range(len(path) - 1):
                u, v = path[i], path[i + 1]
                edge_data = g.get_edge_data(u, v) or {}
                cost = float(edge_data.get("weight", 1.0))
                prio = float(edge_data.get("priority_score", 1.0))
                total_cost += cost
                priority_sum += prio

                is_hyp = bool(edge_data.get("is_hypothetical", False))
                if is_hyp:
                    hypothetical_count += 1
                
                # Gather assumptions
                for ass in edge_data.get("assumptions", []):
                    preconditions.append(ass)

                path_edges.append({
                    "source": u,
                    "target": v,
                    "relation": edge_data.get("relation", "TRANSITION"),
                    "weight": cost,
                    "priority_score": prio,
                    "is_hypothetical": is_hyp,
                })

                # Check if u or v is a vulnerability node
                for node_id in (u, v):
                    ndata = g.nodes.get(node_id, {})
                    for cve in ndata.get("cves", []):
                        cves.add(cve)
                        recommendations.append(f"Remediate {cve} on {node_id} to block attack traversal.")

            if not recommendations:
                recommendations.append("Enforce micro-segmentation and egress access control between assets.")

            # Priority score: Higher is more critical / dangerous
            avg_priority = round(priority_sum / max(1, len(path) - 1), 2)
            
            # Confidence level
            conf_level = "high" if hypothetical_count == 0 else ("medium" if hypothetical_count <= 2 else "low")

            path_obj = CandidateAttackPath(
                id=f"path-{uuid.uuid4().hex[:10]}",
                scan_id=scan_id,
                snapshot_id=snapshot_id,
                source_node=source_node,
                target_node=target_node,
                path_nodes=path,
                path_edges=path_edges,
                total_cost=round(total_cost, 2),
                priority_score=avg_priority,
                cves=sorted(list(cves)),
                hypothetical_transitions_count=hypothetical_count,
                confidence_level=conf_level,
                preconditions=list(set(preconditions)),
                recommendations=list(set(recommendations)),
            )
            candidate_paths.append(path_obj)
            count += 1
            if count >= k:
                break

    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []

    return candidate_paths


def simulate_mitigation(
    g: nx.DiGraph,
    scenario: MitigationScenario,
    source_node: str,
    target_node: str,
    scan_id: str,
    snapshot_id: str,
    original_risk_score: float,
) -> MitigationSimulationResult:
    """
    Simulates defensive controls on an isolated copy of the graph without mutating
    production database records or the original graph instance.
    """
    sim_g = copy.deepcopy(g)
    
    # 1. Eliminate Vulnerabilities (Remove CVE nodes & incident edges)
    eliminated_cves = list(scenario.mitigated_cves)
    nodes_to_remove = []
    
    for nid, ndata in sim_g.nodes(data=True):
        node_cves = ndata.get("cves", [])
        if any(cve in eliminated_cves for cve in node_cves):
            nodes_to_remove.append(nid)

    for nid in nodes_to_remove:
        sim_g.remove_node(nid)

    # 2. Disable specified edges (e.g. network micro-segmentation)
    for u, v in scenario.disabled_edges:
        if sim_g.has_edge(u, v):
            sim_g.remove_edge(u, v)

    # 3. Re-evaluate Attack Paths
    orig_paths = find_candidate_attack_paths(
        g=g,
        source_node=source_node,
        target_node=target_node,
        scan_id=scan_id,
        snapshot_id=snapshot_id,
        k=3,
    )

    sim_paths = find_candidate_attack_paths(
        g=sim_g,
        source_node=source_node,
        target_node=target_node,
        scan_id=scan_id,
        snapshot_id=snapshot_id,
        k=3,
    )

    broken_paths_count = max(0, len(orig_paths) - len(sim_paths))
    
    # 4. Compute Simulated Risk Score
    # Risk delta based on eliminated CVEs and broken attack vectors
    risk_reduction = 0.0
    if nodes_to_remove:
        risk_reduction += min(5.0, len(nodes_to_remove) * 1.8)
    if broken_paths_count > 0:
        risk_reduction += min(3.5, broken_paths_count * 1.5)

    simulated_risk = max(0.5, round(original_risk_score - risk_reduction, 2))
    risk_delta = round(original_risk_score - simulated_risk, 2)

    return MitigationSimulationResult(
        id=f"sim-{uuid.uuid4().hex[:10]}",
        scan_id=scan_id,
        snapshot_id=snapshot_id,
        scenario_name=scenario.scenario_name,
        original_risk_score=original_risk_score,
        simulated_risk_score=simulated_risk,
        risk_delta=risk_delta,
        broken_paths_count=broken_paths_count,
        remaining_paths_count=len(sim_paths),
        eliminated_cves=eliminated_cves,
        original_paths=orig_paths,
        simulated_paths=sim_paths,
        details={
            "nodes_eliminated": nodes_to_remove,
            "disabled_edges": scenario.disabled_edges,
            "simulation_mode": "in-memory-isolated-copy",
        },
    )
