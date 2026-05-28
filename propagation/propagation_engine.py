import networkx as nx
import numpy as np
from typing import Dict, List, Tuple
from propagation.dependency_mapper import (
    buildDependencyGraph,
    getDownstreamDependencies,
    getEdgeWeight,
    getNodeCriticality,
)

SEVERITY_THRESHOLDS = {
    "CRITICAL": 0.85,
    "HIGH": 0.65,
    "MEDIUM": 0.40,
    "LOW": 0.0,
}


def mapSeverityToScore(severity: str) -> float:
    mapping = {
        "CRITICAL": 0.95,
        "HIGH": 0.75,
        "MEDIUM": 0.50,
        "LOW": 0.25,
    }
    return mapping.get(severity.upper(), 0.50)


def mapScoreToSeverity(score: float) -> str:
    if score >= SEVERITY_THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    elif score >= SEVERITY_THRESHOLDS["HIGH"]:
        return "HIGH"
    elif score >= SEVERITY_THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    return "LOW"


def calculateNodeInfectionProbability(
    graph: nx.DiGraph,
    source: str,
    target: str,
    source_risk_score: float,
) -> float:
    edge_weight = getEdgeWeight(graph, source, target)
    target_criticality = getNodeCriticality(target)
    infection_probability = source_risk_score * edge_weight * target_criticality
    return round(min(infection_probability, 1.0), 4)


def propagateRiskScores(
    graph: nx.DiGraph,
    origin: str,
    initial_risk_score: float,
    decay_factor: float = 0.75,
) -> Dict[str, float]:
    infected_scores: Dict[str, float] = {origin: initial_risk_score}
    visited = set()
    queue = [(origin, initial_risk_score)]

    while queue:
        current_node, current_score = queue.pop(0)
        if current_node in visited:
            continue
        visited.add(current_node)

        for neighbor in graph.successors(current_node):
            if neighbor in visited:
                continue
            infection_prob = calculateNodeInfectionProbability(
                graph, current_node, neighbor, current_score
            )
            propagated_score = infection_prob * decay_factor
            if neighbor in infected_scores:
                infected_scores[neighbor] = max(
                    infected_scores[neighbor], propagated_score
                )
            else:
                infected_scores[neighbor] = propagated_score
            if propagated_score > 0.1:
                queue.append((neighbor, propagated_score))

    return infected_scores


def runPropagationSimulation(
    origin_vendor: str,
    initial_severity: str,
    graph: nx.DiGraph = None,
) -> Dict:
    if graph is None:
        graph = buildDependencyGraph()

    initial_risk_score = mapSeverityToScore(initial_severity)
    propagated_scores = propagateRiskScores(graph, origin_vendor, initial_risk_score)

    infected_nodes = [
        {
            "vendor": node,
            "risk_score": round(score, 4),
            "severity": mapScoreToSeverity(score),
            "criticality": getNodeCriticality(node),
        }
        for node, score in propagated_scores.items()
        if node != origin_vendor
    ]

    infected_nodes.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "origin": origin_vendor,
        "initial_severity": initial_severity,
        "initial_risk_score": initial_risk_score,
        "total_infected_nodes": len(infected_nodes),
        "infected_nodes": infected_nodes,
        "propagated_scores": propagated_scores,
    }


def getHighRiskNodes(
    propagated_scores: Dict[str, float],
    threshold: float = 0.65,
) -> List[str]:
    return [
        node
        for node, score in propagated_scores.items()
        if score >= threshold
    ]


def calculateAggregateRisk(propagated_scores: Dict[str, float]) -> float:
    if not propagated_scores:
        return 0.0
    scores = list(propagated_scores.values())
    weighted_avg = float(np.average(scores, weights=scores))
    return round(weighted_avg, 4)


def buildPropagationResult(
    origin_vendor: str,
    propagated_scores: Dict[str, float],
    attack_path: List[str],
    severity_before: str,
    mitigations: List[str],
    reduced_blast_radius: int,
    severity_after: str,
    risk_reduction_percentage: float,
    initial_blast_radius: int,
) -> Dict:
    return {
        "attack_origin": origin_vendor,
        "attack_path": attack_path,
        "initial_blast_radius": initial_blast_radius,
        "severity_before": severity_before,
        "mitigations": mitigations,
        "reduced_blast_radius": reduced_blast_radius,
        "severity_after": severity_after,
        "risk_reduction_percentage": risk_reduction_percentage,
    }