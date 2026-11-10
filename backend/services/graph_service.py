"""
DRISHTI — Phase 4 Graph & Risk Engine Persistence Service
Handles storing and retrieving graph snapshots, attack paths, risk assessments,
and mitigation simulation runs in Supabase PostgreSQL (and SQLite fallback).
"""

import json
from typing import Any, Dict, List, Optional
from backend.db.database import get_db, db_queue
from backend.services.graph_models import (
    CandidateAttackPath,
    MitigationSimulationResult,
    RiskAssessment,
)


async def persist_graph_snapshot(
    snapshot_id: str,
    scan_id: str,
    graph_dict: Dict[str, Any],
) -> None:
    """Stores graph snapshot JSON and metadata into Supabase PostgreSQL."""
    nodes = graph_dict.get("nodes", [])
    edges = graph_dict.get("edges", [])
    stats = graph_dict.get("statistics", {})

    await db_queue.execute_write(
        """
        INSERT INTO graph_snapshots (id, scan_id, snapshot_version, schema_version, nodes_count, edges_count, graph_data, statistics)
        VALUES (?, ?, 1, '4.0', ?, ?, ?, ?)
        ON CONFLICT (id) DO UPDATE SET
            nodes_count = EXCLUDED.nodes_count,
            edges_count = EXCLUDED.edges_count,
            graph_data = EXCLUDED.graph_data,
            statistics = EXCLUDED.statistics
        """,
        (snapshot_id, scan_id, len(nodes), len(edges), json.dumps(graph_dict), json.dumps(stats))
    )


async def get_graph_snapshot(scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves the latest graph snapshot for a scan."""
    async with get_db() as db:
        async with db.execute(
            "SELECT * FROM graph_snapshots WHERE scan_id = ? ORDER BY created_at DESC LIMIT 1",
            (scan_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            res = dict(row)
            if isinstance(res.get("graph_data"), str):
                res["graph_data"] = json.loads(res["graph_data"])
            if isinstance(res.get("statistics"), str):
                res["statistics"] = json.loads(res["statistics"])
            return res


async def persist_risk_assessment(assessment: RiskAssessment) -> None:
    """Persists a deterministic risk assessment in Supabase PostgreSQL."""
    await db_queue.execute_write(
        """
        INSERT INTO risk_assessments (
            id, scan_id, snapshot_id, overall_risk_score, criticality_score,
            confirmed_vulns_count, potential_vulns_count, compromise_likelihood,
            factors, scoring_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (id) DO UPDATE SET
            overall_risk_score = EXCLUDED.overall_risk_score,
            criticality_score = EXCLUDED.criticality_score,
            compromise_likelihood = EXCLUDED.compromise_likelihood,
            factors = EXCLUDED.factors
        """,
        (
            f"risk-{assessment.snapshot_id}",
            assessment.scan_id,
            assessment.snapshot_id,
            assessment.overall_risk_score,
            assessment.criticality_score,
            assessment.confirmed_vulns_count,
            assessment.potential_vulns_count,
            assessment.compromise_likelihood,
            json.dumps(assessment.factors),
            assessment.scoring_version,
        )
    )


async def get_risk_assessment(scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves the most recent risk assessment for a scan."""
    async with get_db() as db:
        async with db.execute(
            "SELECT * FROM risk_assessments WHERE scan_id = ? ORDER BY created_at DESC LIMIT 1",
            (scan_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            res = dict(row)
            if isinstance(res.get("factors"), str):
                res["factors"] = json.loads(res["factors"])
            return res


async def persist_attack_paths(paths: List[CandidateAttackPath]) -> None:
    """Persists candidate attack paths into Supabase PostgreSQL."""
    for p in paths:
        await db_queue.execute_write(
            """
            INSERT INTO attack_paths (
                id, scan_id, snapshot_id, source_node, target_node, path_nodes,
                path_edges, total_cost, priority_score, cves, hypothetical_transitions_count,
                confidence_level, preconditions, recommendations
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (id) DO NOTHING
            """,
            (
                p.id,
                p.scan_id,
                p.snapshot_id,
                p.source_node,
                p.target_node,
                json.dumps(p.path_nodes),
                json.dumps(p.path_edges),
                p.total_cost,
                p.priority_score,
                json.dumps(p.cves),
                p.hypothetical_transitions_count,
                p.confidence_level,
                json.dumps(p.preconditions),
                json.dumps(p.recommendations),
            )
        )


async def get_attack_paths(scan_id: str, target_node: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves persisted candidate attack paths for a scan."""
    query = "SELECT * FROM attack_paths WHERE scan_id = ?"
    params = [scan_id]
    if target_node:
        query += " AND target_node = ?"
        params.append(target_node)
    else:
        # Exclude intermediate lateral pivot paths so callers receive complete Crown Jewel objectives
        query += " AND target_node != 'InternalAuth'"
    query += " ORDER BY priority_score DESC, total_cost ASC"

    async with get_db() as db:
        async with db.execute(query, tuple(params)) as cursor:
            rows = await cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                for field in ("path_nodes", "path_edges", "cves", "preconditions", "recommendations"):
                    if isinstance(item.get(field), str):
                        try:
                            item[field] = json.loads(item[field])
                        except Exception:
                            pass
                results.append(item)
            return results


async def persist_mitigation_simulation(sim: MitigationSimulationResult) -> None:
    """Stores a defensive counterfactual simulation scenario in Supabase PostgreSQL."""
    await db_queue.execute_write(
        """
        INSERT INTO mitigation_simulations (
            id, scan_id, snapshot_id, scenario_name, mitigated_cves, disabled_edges,
            original_risk_score, simulated_risk_score, risk_delta, broken_paths_count,
            remaining_paths_count, details
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (id) DO UPDATE SET
            simulated_risk_score = EXCLUDED.simulated_risk_score,
            risk_delta = EXCLUDED.risk_delta,
            broken_paths_count = EXCLUDED.broken_paths_count
        """,
        (
            sim.id,
            sim.scan_id,
            sim.snapshot_id,
            sim.scenario_name,
            json.dumps(sim.eliminated_cves),
            json.dumps(sim.details.get("disabled_edges", [])),
            sim.original_risk_score,
            sim.simulated_risk_score,
            sim.risk_delta,
            sim.broken_paths_count,
            sim.remaining_paths_count,
            json.dumps(sim.details),
        )
    )
