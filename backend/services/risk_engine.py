"""
DRISHTI — Phase 4 Deterministic Risk Engine
Calculates normalized, explainable node and graph risk scores.
Keeps official CVSS and EPSS metrics distinct from derived composite risk.
"""

from typing import Any, Dict, List, Optional
from backend.services.graph_models import RiskAssessment


def calculate_vulnerability_weight(
    cvss_score: float,
    epss_score: Optional[float] = None,
    applicability_status: str = "confirmed_applicability",
    confidence: float = 1.0,
    asset_criticality: float = 1.0,
) -> Dict[str, Any]:
    """
    Computes deterministic edge cost and risk priority score for a vulnerability transition.
    
    Mathematical Formulation:
      - Raw Impact: base CVSS (0.0 to 10.0)
      - Exploitation Multiplier: (1.0 + epss_score * 0.4) if epss_score else 1.05
      - Applicability Multiplier:
          * confirmed_applicability: 1.0
          * potential_applicability: 0.65
          * insufficient_evidence: 0.35
          * not_affected: 0.0
      - Asset Criticality Factor: 1.0 + (asset_criticality - 1.0) * 0.15  (range 1.0 - 1.6)

      Priority Score (Higher is more dangerous, range 0.0 to 10.0):
        priority = min(10.0, round(cvss_score * (1.0 + (epss or 0.1) * 0.3) * app_mult * (confidence or 0.8), 2))

      Traversal Cost for Dijkstra (Lower cost = path of least resistance / highest risk):
        traversal_cost = max(0.1, round(11.0 - priority, 2))
    """
    cvss = max(0.0, min(10.0, float(cvss_score or 0.0)))
    epss = max(0.0, min(1.0, float(epss_score or 0.0))) if epss_score is not None else 0.05
    conf = max(0.1, min(1.0, float(confidence or 1.0)))
    crit = max(1.0, min(5.0, float(asset_criticality or 1.0)))

    status_weights = {
        "confirmed_applicability": 1.0,
        "potential_applicability": 0.65,
        "insufficient_evidence": 0.35,
        "not_affected": 0.0,
    }
    app_mult = status_weights.get(applicability_status.lower(), 0.35)

    # Priority score: Higher means higher exploit hazard
    priority = min(10.0, round(cvss * (1.0 + epss * 0.35) * app_mult * conf, 2))
    
    # Non-negative Dijkstra traversal cost: strictly > 0.0
    traversal_cost = max(0.1, round(11.0 - priority, 2))

    return {
        "priority_score": priority,
        "traversal_cost": traversal_cost,
        "cvss": cvss,
        "epss": epss,
        "app_mult": app_mult,
        "conf": conf,
        "crit": crit,
    }


def compute_composite_risk_assessment(
    scan_id: str,
    snapshot_id: str,
    nodes: List[Dict[str, Any]],
    vulnerabilities: List[Dict[str, Any]],
) -> RiskAssessment:
    """
    Computes deterministic overall risk assessment for an asset graph snapshot.
    """
    confirmed = [v for v in vulnerabilities if v.get("applicability_status") == "confirmed_applicability"]
    potential = [v for v in vulnerabilities if v.get("applicability_status") == "potential_applicability"]

    # Calculate max and average CVSS
    cvss_scores = [float(v.get("cvss_score") or 0.0) for v in confirmed]
    max_cvss = max(cvss_scores) if cvss_scores else 0.0
    avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0

    # EPSS max
    epss_scores = [float(v.get("epss_score") or 0.0) for v in confirmed if v.get("epss_score") is not None]
    max_epss = max(epss_scores) if epss_scores else 0.0

    # Overall risk score (0.0 to 10.0 scale)
    # 50% max CVSS, 20% average CVSS, 20% EPSS exploit signal, 10% volume factor
    volume_factor = min(1.0, len(confirmed) * 0.2 + len(potential) * 0.05)
    overall_score = min(
        10.0,
        round(
            (max_cvss * 0.50) +
            (avg_cvss * 0.20) +
            (max_epss * 10.0 * 0.20) +
            (volume_factor * 10.0 * 0.10),
            2
        )
    )

    # Likelihood of compromise (0.0 to 1.0)
    likelihood = min(1.0, round(max_epss * 0.6 + (max_cvss / 10.0) * 0.4, 2))

    # Criticality score
    crit_scores = [float(n.get("criticality") or 1.0) for n in nodes]
    avg_crit = sum(crit_scores) / len(crit_scores) if crit_scores else 1.0
    criticality_score = min(10.0, round(avg_crit * 2.0, 2))

    return RiskAssessment(
        scan_id=scan_id,
        snapshot_id=snapshot_id,
        overall_risk_score=overall_score,
        criticality_score=criticality_score,
        confirmed_vulns_count=len(confirmed),
        potential_vulns_count=len(potential),
        compromise_likelihood=likelihood,
        factors={
            "max_cvss": max_cvss,
            "avg_cvss": round(avg_cvss, 2),
            "max_epss": max_epss,
            "volume_factor": round(volume_factor, 2),
            "total_nodes": len(nodes),
            "scoring_rule": "DRISHTI-4.0-WEIGHTED-CVSS-EPSS",
        },
        scoring_version="4.0-drishti-risk",
    )
