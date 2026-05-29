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
    propagateRiskScores,
)
from app.api.propagation.blast_radius_engine import (
    calculateBlastRadius,
    compareBlastRadii,
)

MITIGATION_STRATEGIES = {
    "ISOLATE_VENDOR": {
        "risk_reduction_factor": 0.95,
        "blast_radius_reduction_factor": 0.90,
        "description": "Completely isolate vendor from dependency graph",
    },
    "PATCH_VULNERABILITY": {
        "risk_reduction_factor": 0.70,
        "blast_radius_reduction_factor": 0.60,
        "description": "Apply emergency patch to vulnerable vendor systems",
    },
    "ROTATE_CREDENTIALS": {
        "risk_reduction_factor": 0.60,
        "blast_radius_reduction_factor": 0.50,
        "description": "Force rotate all credentials and API keys",
    },
    "ENABLE_MFA": {
        "risk_reduction_factor": 0.45,
        "blast_radius_reduction_factor": 0.35,
        "description": "Enforce multi-factor authentication across all access points",
    },
    "BLOCK_LATERAL_MOVEMENT": {
        "risk_reduction_factor": 0.55,
        "blast_radius_reduction_factor": 0.65,
        "description": "Block all lateral movement vectors between vendors",
    },
    "FAILOVER_TO_BACKUP": {
        "risk_reduction_factor": 0.80,
        "blast_radius_reduction_factor": 0.75,
        "description": "Switch to backup vendor or redundant system",
    },
    "ENABLE_WAF": {
        "risk_reduction_factor": 0.40,
        "blast_radius_reduction_factor": 0.30,
        "description": "Enable web application firewall rules",
    },
    "REVOKE_API_ACCESS": {
        "risk_reduction_factor": 0.85,
        "blast_radius_reduction_factor": 0.80,
        "description": "Revoke all API access tokens for compromised vendor",
    },
}

SEVERITY_MITIGATION_MAP = {
    "CRITICAL": [
        "ISOLATE_VENDOR",
        "REVOKE_API_ACCESS",
        "ROTATE_CREDENTIALS",
        "FAILOVER_TO_BACKUP",
    ],
    "HIGH": [
        "PATCH_VULNERABILITY",
        "ROTATE_CREDENTIALS",
        "BLOCK_LATERAL_MOVEMENT",
        "REVOKE_API_ACCESS",
    ],
    "MEDIUM": [
        "PATCH_VULNERABILITY",
        "ENABLE_MFA",
        "ENABLE_WAF",
        "ROTATE_CREDENTIALS",
    ],
    "LOW": [
        "ENABLE_MFA",
        "ENABLE_WAF",
        "PATCH_VULNERABILITY",
    ],
}


def selectMitigationsForSeverity(severity: str) -> List[str]:
    return SEVERITY_MITIGATION_MAP.get(severity.upper(), SEVERITY_MITIGATION_MAP["LOW"])


def calculateMitigationEffectiveness(
    mitigations: List[str],
) -> Tuple[float, float]:
    if not mitigations:
        return 0.0, 0.0

    combined_risk_reduction = 1.0
    combined_blast_reduction = 1.0

    for mitigation in mitigations:
        strategy = MITIGATION_STRATEGIES.get(mitigation, {})
        risk_factor = strategy.get("risk_reduction_factor", 0.0)
        blast_factor = strategy.get("blast_radius_reduction_factor", 0.0)
        combined_risk_reduction *= (1.0 - risk_factor)
        combined_blast_reduction *= (1.0 - blast_factor)

    total_risk_reduction = round(1.0 - combined_risk_reduction, 4)
    total_blast_reduction = round(1.0 - combined_blast_reduction, 4)

    return total_risk_reduction, total_blast_reduction


def applyMitigationSimulation(
    origin_vendor: str,
    initial_severity: str,
    propagated_scores: Dict[str, float],
    mitigations: List[str],
    graph: nx.DiGraph = None,
) -> Dict:
    if graph is None:
        graph = buildDependencyGraph()

    initial_blast_radius = calculateBlastRadius(origin_vendor, propagated_scores, graph)
    risk_reduction, blast_reduction = calculateMitigationEffectiveness(mitigations)

    mitigated_scores: Dict[str, float] = {}
    for vendor, score in propagated_scores.items():
        if vendor == origin_vendor:
            mitigated_score = round(score * (1.0 - risk_reduction), 4)
        else:
            criticality = getNodeCriticality(vendor)
            vendor_reduction = risk_reduction * (1.0 - (criticality * 0.3))
            mitigated_score = round(score * (1.0 - vendor_reduction), 4)
        mitigated_scores[vendor] = max(mitigated_score, 0.0)

    reduced_blast_radius = calculateBlastRadius(origin_vendor, mitigated_scores, graph)
    risk_reduction_percentage = compareBlastRadii(initial_blast_radius, reduced_blast_radius)

    initial_risk = mapSeverityToScore(initial_severity)
    mitigated_origin_risk = mitigated_scores.get(origin_vendor, initial_risk)
    severity_after = mapScoreToSeverity(mitigated_origin_risk)

    mitigated_vendors = [
        vendor for vendor, score in mitigated_scores.items()
        if propagated_scores.get(vendor, 0.0) > 0.1 and score <= 0.1
    ]

    return {
        "attack_origin": origin_vendor,
        "attack_path": [],
        "initial_blast_radius": initial_blast_radius,
        "severity_before": initial_severity,
        "mitigations": mitigations,
        "reduced_blast_radius": reduced_blast_radius,
        "severity_after": severity_after,
        "risk_reduction_percentage": risk_reduction_percentage,
        "mitigated_scores": mitigated_scores,
        "mitigated_vendors": mitigated_vendors,
        "risk_reduction_factor": risk_reduction,
        "blast_reduction_factor": blast_reduction,
    }


def getRecommendedMitigations(
    vendor: str,
    severity: str,
    propagated_scores: Dict[str, float],
) -> List[Dict]:
    strategy_keys = selectMitigationsForSeverity(severity)
    recommendations = []

    for key in strategy_keys:
        strategy = MITIGATION_STRATEGIES.get(key, {})
        vendor_risk = propagated_scores.get(vendor, 0.0)
        estimated_new_risk = round(
            vendor_risk * (1.0 - strategy.get("risk_reduction_factor", 0.0)), 4
        )
        recommendations.append({
            "mitigation": key,
            "description": strategy.get("description", ""),
            "risk_reduction_factor": strategy.get("risk_reduction_factor", 0.0),
            "blast_radius_reduction_factor": strategy.get("blast_radius_reduction_factor", 0.0),
            "current_risk": round(vendor_risk, 4),
            "estimated_risk_after": estimated_new_risk,
            "severity_after": mapScoreToSeverity(estimated_new_risk),
        })

    recommendations.sort(key=lambda x: x["risk_reduction_factor"], reverse=True)
    return recommendations


def simulatePartialMitigation(
    origin_vendor: str,
    initial_severity: str,
    propagated_scores: Dict[str, float],
    mitigation_key: str,
    graph: nx.DiGraph = None,
) -> Dict:
    return applyMitigationSimulation(
        origin_vendor=origin_vendor,
        initial_severity=initial_severity,
        propagated_scores=propagated_scores,
        mitigations=[mitigation_key],
        graph=graph,
    )


def rankMitigationsByImpact(
    origin_vendor: str,
    initial_severity: str,
    propagated_scores: Dict[str, float],
    graph: nx.DiGraph = None,
) -> List[Dict]:
    if graph is None:
        graph = buildDependencyGraph()

    ranked = []
    for key in MITIGATION_STRATEGIES:
        result = simulatePartialMitigation(
            origin_vendor=origin_vendor,
            initial_severity=initial_severity,
            propagated_scores=propagated_scores,
            mitigation_key=key,
            graph=graph,
        )
        ranked.append({
            "mitigation": key,
            "description": MITIGATION_STRATEGIES[key]["description"],
            "initial_blast_radius": result["initial_blast_radius"],
            "reduced_blast_radius": result["reduced_blast_radius"],
            "risk_reduction_percentage": result["risk_reduction_percentage"],
            "severity_before": result["severity_before"],
            "severity_after": result["severity_after"],
        })

    ranked.sort(key=lambda x: x["risk_reduction_percentage"], reverse=True)
    return ranked