import networkx as nx
from typing import Dict, List, Optional
from propagation.dependency_mapper import (
    buildDependencyGraph,
    getEdgeWeight,
    getNodeCriticality,
)
from propagation.propagation_engine import mapScoreToSeverity


def generateAttackPath(
    graph: nx.DiGraph,
    origin: str,
    target: str,
) -> List[str]:
    try:
        path = nx.shortest_path(graph, source=origin, target=target, weight=None)
        return path
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []


def generateAllAttackPaths(
    graph: nx.DiGraph,
    origin: str,
    target: str,
    cutoff: int = 5,
) -> List[List[str]]:
    try:
        paths = list(nx.all_simple_paths(graph, source=origin, target=target, cutoff=cutoff))
        return paths
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []


def generateHighestRiskPath(
    graph: nx.DiGraph,
    origin: str,
    propagated_scores: Dict[str, float],
) -> List[str]:
    if origin not in graph:
        return [origin]

    path = [origin]
    visited = {origin}
    current = origin

    while True:
        neighbors = list(graph.successors(current))
        unvisited = [n for n in neighbors if n not in visited]
        if not unvisited:
            break

        best_neighbor = max(
            unvisited,
            key=lambda n: (
                propagated_scores.get(n, 0.0) * getEdgeWeight(graph, current, n) * getNodeCriticality(n)
            ),
        )

        best_score = (
            propagated_scores.get(best_neighbor, 0.0)
            * getEdgeWeight(graph, current, best_neighbor)
            * getNodeCriticality(best_neighbor)
        )

        if best_score < 0.1:
            break

        path.append(best_neighbor)
        visited.add(best_neighbor)
        current = best_neighbor

    return path


def calculatePathRiskScore(
    graph: nx.DiGraph,
    path: List[str],
    propagated_scores: Dict[str, float],
) -> float:
    if not path:
        return 0.0

    total_score = 0.0
    for i in range(len(path) - 1):
        source = path[i]
        target = path[i + 1]
        edge_weight = getEdgeWeight(graph, source, target)
        node_risk = propagated_scores.get(target, 0.0)
        criticality = getNodeCriticality(target)
        total_score += edge_weight * node_risk * criticality

    return round(total_score / max(len(path) - 1, 1), 4)


def rankAttackPaths(
    graph: nx.DiGraph,
    paths: List[List[str]],
    propagated_scores: Dict[str, float],
) -> List[Dict]:
    ranked = []
    for path in paths:
        score = calculatePathRiskScore(graph, path, propagated_scores)
        ranked.append({
            "path": path,
            "path_length": len(path),
            "path_risk_score": score,
            "severity": mapScoreToSeverity(score),
        })
    ranked.sort(key=lambda x: x["path_risk_score"], reverse=True)
    return ranked


def buildAttackPathNodes(
    graph: nx.DiGraph,
    path: List[str],
    propagated_scores: Dict[str, float],
) -> List[Dict]:
    nodes = []
    for index, vendor in enumerate(path):
        nodes.append({
            "step": index + 1,
            "vendor": vendor,
            "risk_score": round(propagated_scores.get(vendor, 0.0), 4),
            "criticality": round(getNodeCriticality(vendor), 4),
            "severity": mapScoreToSeverity(propagated_scores.get(vendor, 0.0)),
            "edge_weight_to_next": (
                round(getEdgeWeight(graph, vendor, path[index + 1]), 4)
                if index + 1 < len(path)
                else None
            ),
        })
    return nodes


def generateAttackPathReport(
    origin_vendor: str,
    propagated_scores: Dict[str, float],
    graph: nx.DiGraph = None,
) -> Dict:
    if graph is None:
        graph = buildDependencyGraph()

    highest_risk_path = generateHighestRiskPath(graph, origin_vendor, propagated_scores)
    path_nodes = buildAttackPathNodes(graph, highest_risk_path, propagated_scores)
    path_risk_score = calculatePathRiskScore(graph, highest_risk_path, propagated_scores)

    critical_targets = [
        node for node in highest_risk_path
        if propagated_scores.get(node, 0.0) >= 0.65
    ]

    return {
        "origin": origin_vendor,
        "attack_path": highest_risk_path,
        "path_nodes": path_nodes,
        "path_risk_score": path_risk_score,
        "path_length": len(highest_risk_path),
        "critical_targets": critical_targets,
        "severity": mapScoreToSeverity(path_risk_score),
    }


def getLateralMovementVectors(
    graph: nx.DiGraph,
    origin: str,
    propagated_scores: Dict[str, float],
    min_score: float = 0.5,
) -> List[Dict]:
    vectors = []
    for source, target in graph.edges():
        if source not in propagated_scores or target not in propagated_scores:
            continue
        source_score = propagated_scores[source]
        target_score = propagated_scores[target]
        if source_score >= min_score and target_score >= min_score:
            vectors.append({
                "from": source,
                "to": target,
                "edge_weight": round(getEdgeWeight(graph, source, target), 4),
                "source_risk": round(source_score, 4),
                "target_risk": round(target_score, 4),
                "lateral_risk": round(source_score * getEdgeWeight(graph, source, target), 4),
            })
    vectors.sort(key=lambda x: x["lateral_risk"], reverse=True)
    return vectors