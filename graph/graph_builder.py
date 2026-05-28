import networkx as nx
from typing import Dict, List
from propagation.dependency_mapper import (
    buildDependencyGraph,
    getNodeCriticality,
    getEdgeWeight,
    serializeGraph,
    VENDOR_DEPENDENCY_MAP,
    EDGE_WEIGHTS,
)
from propagation.propagation_engine import mapScoreToSeverity
from graph.neo4j_manager import getNeo4jManager


def buildInMemoryGraph() -> nx.DiGraph:
    return buildDependencyGraph()


def buildNeo4jGraph() -> None:
    manager = getNeo4jManager()
    manager.clearDatabase()
    graph = buildDependencyGraph()

    for node in graph.nodes():
        criticality = getNodeCriticality(node)
        manager.createVendorNode(
            vendor=node,
            criticality=criticality,
            properties={"severity": "NONE", "risk_score": 0.0, "infected": False},
        )

    for source, target in graph.edges():
        weight = getEdgeWeight(graph, source, target)
        manager.createDependencyRelationship(source, target, weight)


def syncPropagationResultToNeo4j(
    origin_vendor: str,
    propagated_scores: Dict[str, float],
) -> None:
    manager = getNeo4jManager()

    for vendor, score in propagated_scores.items():
        severity = mapScoreToSeverity(score)
        manager.updateVendorRiskScore(vendor, score, severity)
        if score > 0.1:
            manager.markVendorInfected(vendor, origin_vendor)


def syncMitigationResultToNeo4j(mitigated_vendors: List[str]) -> None:
    manager = getNeo4jManager()
    for vendor in mitigated_vendors:
        manager.markVendorMitigated(vendor)


def buildGraphSnapshot(
    propagated_scores: Dict[str, float],
    graph: nx.DiGraph = None,
) -> Dict:
    if graph is None:
        graph = buildInMemoryGraph()

    nodes = []
    for node in graph.nodes():
        risk_score = propagated_scores.get(node, 0.0)
        criticality = getNodeCriticality(node)
        nodes.append({
            "id": node,
            "risk_score": round(risk_score, 4),
            "criticality": round(criticality, 4),
            "severity": mapScoreToSeverity(risk_score),
            "infected": risk_score > 0.1,
        })

    edges = []
    for source, target in graph.edges():
        weight = getEdgeWeight(graph, source, target)
        source_risk = propagated_scores.get(source, 0.0)
        target_risk = propagated_scores.get(target, 0.0)
        edges.append({
            "source": source,
            "target": target,
            "weight": round(weight, 4),
            "source_risk": round(source_risk, 4),
            "target_risk": round(target_risk, 4),
            "active": source_risk > 0.1 and target_risk > 0.1,
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "infected_nodes": [n["id"] for n in nodes if n["infected"]],
        "infected_count": sum(1 for n in nodes if n["infected"]),
    }


def buildMitigatedGraphSnapshot(
    propagated_scores: Dict[str, float],
    mitigated_vendors: List[str],
    graph: nx.DiGraph = None,
) -> Dict:
    if graph is None:
        graph = buildInMemoryGraph()

    adjusted_scores = {
        vendor: (0.0 if vendor in mitigated_vendors else score)
        for vendor, score in propagated_scores.items()
    }

    snapshot = buildGraphSnapshot(adjusted_scores, graph)
    snapshot["mitigated_vendors"] = mitigated_vendors
    snapshot["mitigated_count"] = len(mitigated_vendors)
    return snapshot


def buildGraphDiff(
    pre_mitigation_snapshot: Dict,
    post_mitigation_snapshot: Dict,
) -> Dict:
    pre_infected = set(pre_mitigation_snapshot.get("infected_nodes", []))
    post_infected = set(post_mitigation_snapshot.get("infected_nodes", []))

    newly_cleared = list(pre_infected - post_infected)
    still_infected = list(pre_infected & post_infected)
    newly_infected = list(post_infected - pre_infected)

    pre_count = pre_mitigation_snapshot.get("infected_count", 0)
    post_count = post_mitigation_snapshot.get("infected_count", 0)
    reduction = round(((pre_count - post_count) / max(pre_count, 1)) * 100, 2)

    return {
        "pre_mitigation_infected_count": pre_count,
        "post_mitigation_infected_count": post_count,
        "newly_cleared": newly_cleared,
        "still_infected": still_infected,
        "newly_infected": newly_infected,
        "risk_reduction_percentage": reduction,
    }


def buildGraphDataForDashboard(
    propagated_scores: Dict[str, float],
    attack_path: List[str],
    mitigated_vendors: List[str],
    graph: nx.DiGraph = None,
) -> Dict:
    if graph is None:
        graph = buildInMemoryGraph()

    nodes = []
    for node in graph.nodes():
        risk_score = propagated_scores.get(node, 0.0)
        criticality = getNodeCriticality(node)
        nodes.append({
            "id": node,
            "risk_score": round(risk_score, 4),
            "criticality": round(criticality, 4),
            "severity": mapScoreToSeverity(risk_score),
            "infected": risk_score > 0.1 and node not in mitigated_vendors,
            "mitigated": node in mitigated_vendors,
            "on_attack_path": node in attack_path,
        })

    edges = []
    for source, target in graph.edges():
        weight = getEdgeWeight(graph, source, target)
        on_path = (
            source in attack_path
            and target in attack_path
            and attack_path.index(target) == attack_path.index(source) + 1
            if source in attack_path and target in attack_path
            else False
        )
        edges.append({
            "source": source,
            "target": target,
            "weight": round(weight, 4),
            "on_attack_path": on_path,
            "active": (
                propagated_scores.get(source, 0.0) > 0.1
                and propagated_scores.get(target, 0.0) > 0.1
                and source not in mitigated_vendors
                and target not in mitigated_vendors
            ),
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "attack_path": attack_path,
        "mitigated_vendors": mitigated_vendors,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "infected_count": sum(1 for n in nodes if n["infected"]),
        "mitigated_count": len(mitigated_vendors),
    }


def exportGraphToSerializable(graph: nx.DiGraph = None) -> Dict:
    if graph is None:
        graph = buildInMemoryGraph()
    return serializeGraph(graph)