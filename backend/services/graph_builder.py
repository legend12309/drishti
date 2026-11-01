"""
DRISHTI — Phase 4 NetworkX Graph Construction Engine
Constructs directed risk graphs from persisted findings, passive observations,
and correlated CVE intelligence. Distinguishes observed from inferred relationships.
"""

import json
import uuid
from typing import Any, Dict, List, Optional, Tuple
import networkx as nx

from backend.services.graph_models import (
    GraphEdge,
    GraphNode,
    NodeType,
    ProvenanceClassification,
    RelationType,
)
from backend.services.risk_engine import calculate_vulnerability_weight


class AttackGraphBuilder:
    def __init__(self, scan_id: str, snapshot_id: Optional[str] = None):
        self.scan_id = scan_id
        self.snapshot_id = snapshot_id or f"snap-{uuid.uuid4().hex[:12]}"
        self.g = nx.DiGraph()
        self.nodes_dict: Dict[str, GraphNode] = {}
        self.edges_list: List[GraphEdge] = []
        self.statistics: Dict[str, Any] = {
            "observed_edges": 0,
            "inferred_edges": 0,
            "hypothetical_edges": 0,
            "total_nodes": 0,
            "total_edges": 0,
        }

    def add_node(self, node: GraphNode):
        if node.id not in self.nodes_dict:
            self.nodes_dict[node.id] = node
            self.g.add_node(
                node.id,
                label=node.label,
                node_type=node.node_type.value,
                provenance=node.provenance.value,
                risk_score=node.risk_score,
                criticality=node.criticality,
                confidence=node.confidence,
                cves=node.cves,
                metadata=node.metadata,
            )

    def add_edge(self, edge: GraphEdge):
        self.edges_list.append(edge)
        self.g.add_edge(
            edge.source,
            edge.target,
            relation=edge.relation.value,
            provenance=edge.provenance.value,
            weight=edge.weight,
            priority_score=edge.priority_score,
            confidence=edge.confidence,
            is_hypothetical=edge.is_hypothetical,
            evidence_id=edge.evidence_id,
            rule_id=edge.rule_id,
            assumptions=edge.assumptions,
        )
        if edge.provenance == ProvenanceClassification.OBSERVED:
            self.statistics["observed_edges"] += 1
        else:
            self.statistics["inferred_edges"] += 1
        if edge.is_hypothetical:
            self.statistics["hypothetical_edges"] += 1

    def build_from_evidence(
        self,
        target_domain: str,
        findings: List[Dict[str, Any]],
        vulnerabilities: List[Dict[str, Any]],
        critical_targets: Optional[List[Dict[str, Any]]] = None,
    ) -> nx.DiGraph:
        """
        Builds the complete asset graph from verified scan records:
          1. Root Domain node (Observed entrypoint)
          2. Subdomain & Host nodes (Observed DNS & Network resolution)
          3. Service nodes (Observed listening ports & normalized software)
          4. Vulnerability exploit nodes (Applicable CVE findings)
          5. Inferred target objectives (CoreDB, InternalAuth, PaymentGateway)
        """
        # 1. Root Domain Node
        root_node = GraphNode(
            id=target_domain,
            label=target_domain,
            node_type=NodeType.ROOT_DOMAIN,
            provenance=ProvenanceClassification.OBSERVED,
            risk_score=1.0,
            criticality=2.0,
            confidence=1.0,
            metadata={"target": target_domain, "role": "apex_entrypoint"},
        )
        self.add_node(root_node)

        # Map to correlate vulnerabilities with assets
        vuln_by_asset: Dict[str, List[Dict[str, Any]]] = {}
        for v in vulnerabilities:
            aid = v.get("asset_id", "")
            # Normalize asset_id (e.g. 'vpn.company.com:443' -> host 'vpn.company.com' or asset)
            vuln_by_asset.setdefault(aid, []).append(v)
            host_part = aid.split(":")[0] if ":" in aid else aid
            if host_part != aid:
                vuln_by_asset.setdefault(host_part, []).append(v)

        # 2. Iterate Findings (Subdomains & Hosts)
        for f in findings:
            host = f.get("host")
            if not host:
                continue
            ip = f.get("ip", "")
            tech = f.get("tech", "")
            risk_str = f.get("risk", "LOW")
            score_val = float(f.get("score", 2.0) or 2.0)

            # Map risk level to criticality
            crit = 4.0 if risk_str == "CRITICAL" else (3.0 if risk_str == "HIGH" else 2.0)

            sub_node = GraphNode(
                id=host,
                label=host,
                node_type=NodeType.SUBDOMAIN,
                provenance=ProvenanceClassification.OBSERVED,
                risk_score=score_val,
                criticality=crit,
                confidence=0.98,
                metadata={"ip": ip, "tech": tech, "risk": risk_str},
            )
            self.add_node(sub_node)

            # Edge: Root -> Subdomain (OBSERVED: DNS resolution / subdomain relationship)
            self.add_edge(
                GraphEdge(
                    source=target_domain,
                    target=host,
                    relation=RelationType.RESOLVES_TO,
                    provenance=ProvenanceClassification.OBSERVED,
                    weight=max(0.5, round(6.0 - (score_val * 0.4), 2)),
                    priority_score=round(score_val * 0.5, 2),
                    confidence=1.0,
                    evidence_id=f"dns-{host}",
                )
            )

            # Parse ports
            ports = f.get("ports", [])
            if isinstance(ports, str):
                try:
                    ports = json.loads(ports)
                except Exception:
                    ports = [int(p) for p in ports.split() if p.isdigit()]
            elif not isinstance(ports, list):
                ports = [80, 443]

            # 3. Service Nodes
            for port in ports:
                service_id = f"{host}:{port}"
                service_label = f"Port {port} ({tech.split(',')[0] if tech else 'TCP'})"
                
                serv_node = GraphNode(
                    id=service_id,
                    label=service_label,
                    node_type=NodeType.SERVICE,
                    provenance=ProvenanceClassification.OBSERVED,
                    risk_score=score_val,
                    criticality=crit,
                    confidence=0.95,
                    metadata={"host": host, "port": port, "tech": tech},
                )
                self.add_node(serv_node)

                # Edge: Subdomain -> Service (OBSERVED)
                self.add_edge(
                    GraphEdge(
                        source=host,
                        target=service_id,
                        relation=RelationType.HAS_SERVICE,
                        provenance=ProvenanceClassification.OBSERVED,
                        weight=max(0.2, round(4.0 - (score_val * 0.3), 2)),
                        priority_score=round(score_val * 0.6, 2),
                        confidence=0.95,
                        evidence_id=f"port-{port}",
                    )
                )

                # 4. Associate Vulnerabilities
                associated_vulns = vuln_by_asset.get(service_id, []) or vuln_by_asset.get(host, [])
                for v in associated_vulns:
                    cve_id = v.get("cve_id")
                    if not cve_id:
                        continue
                    app_status = v.get("applicability_status", "confirmed_applicability")
                    cvss = float(v.get("cvss_score") or 7.5)
                    epss = float(v.get("epss_score")) if v.get("epss_score") is not None else None
                    conf = float(v.get("confidence_score") or 0.95)

                    is_weaponized = bool(v.get("is_weaponized", False))
                    msf_mod = v.get("metasploit_module")
                    is_cisa_kev = bool(v.get("cisa_kev", False))

                    weight_info = calculate_vulnerability_weight(
                        cvss_score=cvss,
                        epss_score=epss,
                        applicability_status=app_status,
                        confidence=conf,
                        asset_criticality=crit,
                        is_weaponized=is_weaponized,
                        metasploit_module=msf_mod,
                    )

                    vuln_node_id = f"{cve_id} ({host})"
                    node_label = f"⚡ {cve_id} [MSF] (CVSS {cvss})" if is_weaponized else f"{cve_id} (CVSS {cvss})"
                    vuln_node = GraphNode(
                        id=vuln_node_id,
                        label=node_label,
                        node_type=NodeType.VULNERABILITY,
                        provenance=ProvenanceClassification.OBSERVED if app_status == "confirmed_applicability" else ProvenanceClassification.INFERRED,
                        risk_score=weight_info["priority_score"],
                        criticality=crit,
                        confidence=conf,
                        cves=[cve_id],
                        metadata={
                            "cve_id": cve_id,
                            "title": v.get("title", ""),
                            "applicability": app_status,
                            "cvss": cvss,
                            "epss": epss,
                            "rationale": v.get("match_rationale", ""),
                            "is_weaponized": is_weaponized,
                            "metasploit_module": msf_mod,
                            "cisa_kev": is_cisa_kev,
                        },
                    )
                    self.add_node(vuln_node)

                    # Edge: Service -> Vulnerability
                    self.add_edge(
                        GraphEdge(
                            source=service_id,
                            target=vuln_node_id,
                            relation=RelationType.HAS_VULNERABILITY,
                            provenance=ProvenanceClassification.OBSERVED if app_status == "confirmed_applicability" else ProvenanceClassification.INFERRED,
                            weight=weight_info["traversal_cost"],
                            priority_score=weight_info["priority_score"],
                            confidence=conf,
                            evidence_id=f"cve-{cve_id}",
                            assumptions=[v.get("match_rationale", "Applicable software signature match")],
                        )
                    )

            # If finding is a direct DAST / Web Alert (OWASP ZAP, Nuclei, Trivy)
            if any(marker in tech for marker in ("OWASP ZAP", "Nuclei", "Trivy", "CWE-", "CVE-")):
                obs_node_id = f"finding-{f.get('id', uuid.uuid4().hex[:6])}"
                obs_label = tech.split("-")[-1].strip()[:35] if "-" in tech else tech[:35]
                obs_node = GraphNode(
                    id=obs_node_id,
                    label=f"Alert: {obs_label}",
                    node_type=NodeType.VULNERABILITY,
                    provenance=ProvenanceClassification.OBSERVED,
                    risk_score=score_val,
                    criticality=crit,
                    confidence=0.90,
                    metadata={"tech": tech, "risk": risk_str, "score": score_val},
                )
                self.add_node(obs_node)
                parent_id = f"{host}:{ports[0]}" if ports else host
                self.add_edge(
                    GraphEdge(
                        source=parent_id if parent_id in self.nodes_dict else host,
                        target=obs_node_id,
                        relation=RelationType.HAS_VULNERABILITY,
                        provenance=ProvenanceClassification.OBSERVED,
                        weight=max(0.5, round(6.0 - (score_val * 0.5), 2)),
                        priority_score=round(score_val * 0.8, 2),
                        confidence=0.90,
                        evidence_id=f"alert-{obs_node_id}",
                    )
                )

        # 5. Inferred Critical Asset Objectives
        targets_to_add = critical_targets or [
            {
                "id": "CoreDB",
                "label": "CoreDB Cluster (Customer Data)",
                "criticality": 5.0,
                "desc": "Primary PostgreSQL cluster housing customer PII & credentials.",
            },
            {
                "id": "InternalAuth",
                "label": "InternalAuth (OAuth2 / SSO)",
                "criticality": 4.5,
                "desc": "Internal token issuer & service account broker.",
            },
            {
                "id": "PaymentGateway",
                "label": "PaymentGateway (PCI Env)",
                "criticality": 5.0,
                "desc": "Isolated cardholder data payment terminal.",
            },
        ]

        for ct in targets_to_add:
            ct_node = GraphNode(
                id=ct["id"],
                label=ct["label"],
                node_type=NodeType.CRITICAL_TARGET,
                provenance=ProvenanceClassification.DERIVED,
                risk_score=9.5,
                criticality=ct["criticality"],
                confidence=0.85,
                metadata={"description": ct["desc"], "is_target_objective": True},
            )
            self.add_node(ct_node)

        # 6. Establish Inferred Lateral Movement Edges (DOCUMENTED INFERENCE RULES)
        # Rule INFER-LATERAL-RCE: Critical RCE vulnerabilities on ingress assets infer potential transition
        # to internal identity/database services subject to network demarcation.
        vuln_nodes = [nid for nid, n in self.nodes_dict.items() if n.node_type == NodeType.VULNERABILITY]
        
        for vn_id in vuln_nodes:
            vn = self.nodes_dict[vn_id]
            cvss = vn.metadata.get("cvss", 0.0)
            
            # If High or Critical severity vulnerability (CVSS >= 7.0)
            if cvss >= 7.0:
                is_weaponized = bool(vn.metadata.get("is_weaponized", False))
                msf_mod = vn.metadata.get("metasploit_module")
                edge_weight = 0.4 if is_weaponized else 1.5
                edge_priority = 9.9 if is_weaponized else 8.5
                edge_rule = "INFER-LATERAL-METASPLOIT-WEAPONIZED-RCE" if is_weaponized else "INFER-LATERAL-RCE-TO-AUTH"
                assumptions_list = [
                    f"Weaponized Metasploit module ({msf_mod or 'Active Exploit'}) yields immediate interactive shell execution." if is_weaponized
                    else "Assumes compromised service holds valid service-account token to internal authentication gateway.",
                    "Assumes lack of egress micro-segmentation from DMZ to auth authority.",
                ]

                # Transition from Exploit Node -> InternalAuth (Inferred)
                self.add_edge(
                    GraphEdge(
                        source=vn_id,
                        target="InternalAuth",
                        relation=RelationType.POTENTIAL_TRANSITION,
                        provenance=ProvenanceClassification.INFERRED,
                        weight=edge_weight,
                        priority_score=edge_priority,
                        confidence=0.85 if is_weaponized else 0.70,
                        is_hypothetical=True,
                        rule_id=edge_rule,
                        assumptions=assumptions_list,
                    )
                )

        # Transition: InternalAuth -> CoreDB (Inferred)
        self.add_edge(
            GraphEdge(
                source="InternalAuth",
                target="CoreDB",
                relation=RelationType.POTENTIAL_TRANSITION,
                provenance=ProvenanceClassification.INFERRED,
                weight=1.0,
                priority_score=9.2,
                confidence=0.75,
                is_hypothetical=True,
                rule_id="INFER-AUTH-TO-DATASTORE",
                assumptions=[
                    "Assumes token forging or administrative impersonation grants database read access.",
                ],
            )
        )

        # Transition: InternalAuth -> PaymentGateway (Inferred)
        self.add_edge(
            GraphEdge(
                source="InternalAuth",
                target="PaymentGateway",
                relation=RelationType.POTENTIAL_TRANSITION,
                provenance=ProvenanceClassification.INFERRED,
                weight=2.0,
                priority_score=8.8,
                confidence=0.60,
                is_hypothetical=True,
                rule_id="INFER-AUTH-TO-PAYMENT",
                assumptions=[
                    "Assumes SSO token can be exchanged for PCI enclave service credentials.",
                ],
            )
        )

        self.statistics["total_nodes"] = len(self.nodes_dict)
        self.statistics["total_edges"] = len(self.edges_list)

        return self.g

    def to_dict(self) -> Dict[str, Any]:
        """Serializes graph to a clean JSON-friendly dict for Supabase persistence and React rendering."""
        return {
            "snapshot_id": self.snapshot_id,
            "scan_id": self.scan_id,
            "nodes": [n.model_dump() for n in self.nodes_dict.values()],
            "edges": [e.model_dump() for e in self.edges_list],
            "statistics": self.statistics,
        }
