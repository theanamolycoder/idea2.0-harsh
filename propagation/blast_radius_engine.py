import networkx as nx
from typing import Dict, List, Tuple
from propagation.dependency_mapper import (
    buildDependencyGraph,
    getDownstreamDependencies,
    getNodeCriticality,
    getEdgeWeight,
)
from propagation.propagation_engine import (
    mapScoreToSeverity,
    mapSeverityToScore,
    propagateRiskScores,
)

BLAST_RADIUS_SEVERITY_MAP = {
    "CRITICAL": 1.0,
    "HIGH": 0.75,
    "MEDIUM": 0.50,
    "LOW": 0.25,
}

CRITICALITY_WEIGHT = 0.4
RISK_SCORE_WEIGHT = 0.6


def calculateBlastRadius(
    origin_vendor: str,
    propagated_scores: Dict[str, float],
    graph: nx.DiGraph = None,
) -> int:
    if graph is None:
        graph = buildDependencyGraph()

    downstream = getDownstreamDependencies(graph, origin_vendor)
    affected = [node for node in downstream if node in propagated_scores and propagated_scores[node] > 0.1]
    return len(affected)


def calculateWeightedBlastRadius(
    origin_vendor: str,
    propagated_scores: Dict[str, float],
    graph: nx.DiGraph = None,
) -> float:
    if graph is None:
        graph = buildDependencyGraph()

    downstream = getDownstreamDependencies(graph, origin_vendor)
    total_weight = 0.0

    for node in downstream:
        if node not in propagated_scores:
            continue
        risk_score = propagated_scores[node]
        criticality = getNodeCriticality(node)
        weighted = (risk_score * RISK_SCORE_WEIGHT) + (criticality * CRITICALITY_WEIGHT)
        total_weight += weighted

    return round(total_weight, 4)


def getAffectedSystemsByTier(
    origin_vendor: str,
    propagated_scores: Dict[str, float],
    graph: nx.DiGraph = None,
) -> Dict[str, List[str]]:
    if graph is None:
        graph = buildDependencyGraph()

    tiers: Dict[str, List[str]] = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
    }

    downstream = getDownstreamDependencies(graph, origin_vendor)

    for node in downstream:
        if node not in propagated_scores:
            continue
        score = propagated_scores[node]
        severity = mapScoreToSeverity(score)
        tiers[severity].append(node)

    return tiers


def calculateBusinessImpactScore(
    origin_vendor: str,
    propagated_scores: Dict[str, float],
    graph: nx.DiGraph = None,
) -> float:
    if graph is None:
        graph = buildDependencyGraph()

    downstream = getDownstreamDependencies(graph, origin_vendor)
    if not downstream:
        return 0.0

    total_impact = 0.0
    for node in downstream:
        if node not in propagated_scores:
            continue
        risk = propagated_scores[node]
        criticality = getNodeCriticality(node)
        total_impact += risk * criticality

    normalized = total_impact / len(downstream)
    return round(min(normalized, 1.0), 4)


def getTopAffectedVendors(
    origin_vendor: str,
    propagated_scores: Dict[str, float],
    graph: nx.DiGraph = None,
    top_n: int = 5,
) -> List[Dict]:
    if graph is None:
        graph = buildDependencyGraph()

    downstream = getDownstreamDependencies(graph, origin_vendor)
    affected = []

    for node in downstream:
        if node not in propagated_scores:
            continue
        score = propagated_scores[node]
        criticality = getNodeCriticality(node)
        combined_score = (score * RISK_SCORE_WEIGHT) + (criticality * CRITICALITY_WEIGHT)
        affected.append({
            "vendor": node,
            "risk_score": round(score, 4),
            "criticality": round(criticality, 4),
            "combined_score": round(combined_score, 4),
            "severity": mapScoreToSeverity(score),
        })

    affected.sort(key=lambda x: x["combined_score"], reverse=True)
    return affected[:top_n]


def buildBlastRadiusReport(
    origin_vendor: str,
    initial_severity: str,
    propagated_scores: Dict[str, float],
    graph: nx.DiGraph = None,
) -> Dict:
    if graph is None:
        graph = buildDependencyGraph()

    blast_radius = calculateBlastRadius(origin_vendor, propagated_scores, graph)
    weighted_blast = calculateWeightedBlastRadius(origin_vendor, propagated_scores, graph)
    affected_tiers = getAffectedSystemsByTier(origin_vendor, propagated_scores, graph)
    business_impact = calculateBusinessImpactScore(origin_vendor, propagated_scores, graph)
    top_vendors = getTopAffectedVendors(origin_vendor, propagated_scores, graph)

    return {
        "origin_vendor": origin_vendor,
        "initial_severity": initial_severity,
        "blast_radius": blast_radius,
        "weighted_blast_radius": weighted_blast,
        "business_impact_score": business_impact,
        "affected_tiers": affected_tiers,
        "top_affected_vendors": top_vendors,
        "total_propagated_nodes": len(propagated_scores),
    }


def compareBlastRadii(
    initial_blast_radius: int,
    reduced_blast_radius: int,
) -> float:
    if initial_blast_radius == 0:
        return 0.0
    reduction = ((initial_blast_radius - reduced_blast_radius) / initial_blast_radius) * 100
    return round(max(reduction, 0.0), 2)