import numpy as np
import networkx as nx
from typing import Dict, List, Tuple
from app.api.propagation.dependency_mapper import (
    buildDependencyGraph,
    getNodeCriticality,
    getEdgeWeight,
    getDownstreamDependencies,
)
from app.api.propagation.propagation_engine import (
    mapScoreToSeverity,
    mapSeverityToScore,
)
from app.api.mitigation.mitigation_engine import (
    calculateMitigationEffectiveness,
    selectMitigationsForSeverity,
    MITIGATION_STRATEGIES,
)

RESILIENCE_SCORE_WEIGHTS = {
    "redundancy": 0.30,
    "recovery_speed": 0.25,
    "isolation_capability": 0.25,
    "dependency_depth": 0.20,
}

RECOVERY_TIME_MAP = {
    "CRITICAL": 72,
    "HIGH": 24,
    "MEDIUM": 8,
    "LOW": 2,
}

REDUNDANCY_MAP = {
    "CloudServe": 0.3,
    "AuthProvider": 0.5,
    "PaymentAPI": 0.6,
    "FraudSystem": 0.5,
    "StorageAPI": 0.7,
    "IdentityService": 0.4,
    "TransactionDB": 0.6,
    "AlertEngine": 0.7,
    "ComplianceService": 0.4,
    "LoggingService": 0.8,
    "BackupService": 0.9,
    "CDNProvider": 0.8,
    "DirectoryService": 0.5,
    "TokenService": 0.5,
    "AuditService": 0.6,
    "ReportingEngine": 0.7,
    "NotificationService": 0.8,
    "RegulatoryAPI": 0.4,
    "MonitoringDashboard": 0.7,
}


def getVendorRedundancyScore(vendor: str) -> float:
    return REDUNDANCY_MAP.get(vendor, 0.5)


def calculateRecoveryTimeHours(severity: str) -> int:
    return RECOVERY_TIME_MAP.get(severity.upper(), 8)


def calculateVendorResilienceScore(
    vendor: str,
    propagated_scores: Dict[str, float],
    graph: nx.DiGraph = None,
) -> float:
    if graph is None:
        graph = buildDependencyGraph()

    redundancy = getVendorRedundancyScore(vendor)
    criticality = getNodeCriticality(vendor)
    risk_score = propagated_scores.get(vendor, 0.0)

    downstream = getDownstreamDependencies(graph, vendor)
    dependency_depth = len(downstream)
    normalized_depth = float(np.clip(1.0 - (dependency_depth / 20.0), 0.0, 1.0))

    successors = list(graph.successors(vendor))
    isolation_capability = float(np.clip(1.0 - (len(successors) / 10.0), 0.0, 1.0))

    severity = mapScoreToSeverity(risk_score)
    recovery_hours = calculateRecoveryTimeHours(severity)
    recovery_speed = float(np.clip(1.0 - (recovery_hours / 72.0), 0.0, 1.0))

    resilience_score = (
        redundancy * RESILIENCE_SCORE_WEIGHTS["redundancy"]
        + recovery_speed * RESILIENCE_SCORE_WEIGHTS["recovery_speed"]
        + isolation_capability * RESILIENCE_SCORE_WEIGHTS["isolation_capability"]
        + normalized_depth * RESILIENCE_SCORE_WEIGHTS["dependency_depth"]
    )

    impact_multiplier = 1.0 - (risk_score * criticality * 0.5)
    final_score = resilience_score * impact_multiplier

    return round(float(np.clip(final_score, 0.0, 1.0)), 4)


def calculateNetworkResilienceScore(
    propagated_scores: Dict[str, float],
    graph: nx.DiGraph = None,
) -> float:
    if graph is None:
        graph = buildDependencyGraph()

    all_nodes = list(graph.nodes())
    if not all_nodes:
        return 0.0

    scores = [
        calculateVendorResilienceScore(node, propagated_scores, graph)
        for node in all_nodes
    ]
    criticalities = [getNodeCriticality(node) for node in all_nodes]

    weighted_score = float(np.average(scores, weights=criticalities))
    return round(weighted_score, 4)


def identifyResilienceGaps(
    propagated_scores: Dict[str, float],
    graph: nx.DiGraph = None,
    threshold: float = 0.4,
) -> List[Dict]:
    if graph is None:
        graph = buildDependencyGraph()

    gaps = []
    for node in graph.nodes():
        resilience = calculateVendorResilienceScore(node, propagated_scores, graph)
        if resilience < threshold:
            risk_score = propagated_scores.get(node, 0.0)
            gaps.append({
                "vendor": node,
                "resilience_score": resilience,
                "risk_score": round(risk_score, 4),
                "criticality": round(getNodeCriticality(node), 4),
                "redundancy": getVendorRedundancyScore(node),
                "severity": mapScoreToSeverity(risk_score),
                "gap_severity": "CRITICAL" if resilience < 0.2 else "HIGH" if resilience < 0.3 else "MEDIUM",
            })

    gaps.sort(key=lambda x: x["resilience_score"])
    return gaps


def simulateResilienceAfterMitigation(
    origin_vendor: str,
    initial_severity: str,
    propagated_scores: Dict[str, float],
    mitigations: List[str],
    graph: nx.DiGraph = None,
) -> Dict:
    if graph is None:
        graph = buildDependencyGraph()

    risk_reduction, _ = calculateMitigationEffectiveness(mitigations)

    mitigated_scores = {
        vendor: round(max(score * (1.0 - risk_reduction), 0.0), 4)
        for vendor, score in propagated_scores.items()
    }

    pre_resilience = calculateNetworkResilienceScore(propagated_scores, graph)
    post_resilience = calculateNetworkResilienceScore(mitigated_scores, graph)
    resilience_improvement = round(post_resilience - pre_resilience, 4)

    pre_gaps = identifyResilienceGaps(propagated_scores, graph)
    post_gaps = identifyResilienceGaps(mitigated_scores, graph)

    return {
        "origin_vendor": origin_vendor,
        "initial_severity": initial_severity,
        "mitigations_applied": mitigations,
        "pre_mitigation_resilience": pre_resilience,
        "post_mitigation_resilience": post_resilience,
        "resilience_improvement": resilience_improvement,
        "pre_mitigation_gap_count": len(pre_gaps),
        "post_mitigation_gap_count": len(post_gaps),
        "gaps_resolved": len(pre_gaps) - len(post_gaps),
        "remaining_gaps": post_gaps,
    }


def calculateMeanTimeToRecover(
    propagated_scores: Dict[str, float],
    graph: nx.DiGraph = None,
) -> Dict:
    if graph is None:
        graph = buildDependencyGraph()

    recovery_times = []
    vendor_recovery = []

    for node in graph.nodes():
        risk_score = propagated_scores.get(node, 0.0)
        severity = mapScoreToSeverity(risk_score)
        recovery_hours = calculateRecoveryTimeHours(severity)
        redundancy = getVendorRedundancyScore(node)
        criticality = getNodeCriticality(node)
        adjusted_recovery = recovery_hours * criticality * (1.0 - redundancy * 0.5)
        recovery_times.append(adjusted_recovery)
        vendor_recovery.append({
            "vendor": node,
            "severity": severity,
            "base_recovery_hours": recovery_hours,
            "adjusted_recovery_hours": round(adjusted_recovery, 2),
            "redundancy": redundancy,
            "criticality": criticality,
        })

    vendor_recovery.sort(key=lambda x: x["adjusted_recovery_hours"], reverse=True)

    return {
        "mean_recovery_hours": round(float(np.mean(recovery_times)), 2),
        "max_recovery_hours": round(float(np.max(recovery_times)), 2),
        "min_recovery_hours": round(float(np.min(recovery_times)), 2),
        "total_recovery_hours": round(float(np.sum(recovery_times)), 2),
        "vendor_recovery_breakdown": vendor_recovery,
    }


def buildResilienceReport(
    origin_vendor: str,
    initial_severity: str,
    propagated_scores: Dict[str, float],
    graph: nx.DiGraph = None,
) -> Dict:
    if graph is None:
        graph = buildDependencyGraph()

    network_resilience = calculateNetworkResilienceScore(propagated_scores, graph)
    origin_resilience = calculateVendorResilienceScore(origin_vendor, propagated_scores, graph)
    resilience_gaps = identifyResilienceGaps(propagated_scores, graph)
    mttr = calculateMeanTimeToRecover(propagated_scores, graph)

    recommended_mitigations = selectMitigationsForSeverity(initial_severity)
    post_mitigation = simulateResilienceAfterMitigation(
        origin_vendor, initial_severity, propagated_scores, recommended_mitigations, graph
    )

    return {
        "origin_vendor": origin_vendor,
        "initial_severity": initial_severity,
        "network_resilience_score": network_resilience,
        "origin_resilience_score": origin_resilience,
        "resilience_gaps": resilience_gaps,
        "gap_count": len(resilience_gaps),
        "mean_time_to_recover": mttr,
        "post_mitigation_resilience": post_mitigation,
        "resilience_rating": (
            "STRONG" if network_resilience >= 0.7
            else "MODERATE" if network_resilience >= 0.4
            else "WEAK"
        ),
    }