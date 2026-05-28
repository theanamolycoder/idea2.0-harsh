from typing import Dict, List
import networkx as nx
from propagation.dependency_mapper import (
    buildDependencyGraph,
    getNodeCriticality,
    getDownstreamDependencies,
)
from propagation.propagation_engine import (
    mapScoreToSeverity,
    mapSeverityToScore,
)
from mitigation.mitigation_engine import (
    selectMitigationsForSeverity,
    getRecommendedMitigations,
    rankMitigationsByImpact,
    calculateMitigationEffectiveness,
    MITIGATION_STRATEGIES,
)
from mitigation.resilience_engine import (
    calculateVendorResilienceScore,
    getVendorRedundancyScore,
    calculateRecoveryTimeHours,
    identifyResilienceGaps,
)

PRIORITY_LEVELS = {
    "IMMEDIATE": 1,
    "SHORT_TERM": 2,
    "MEDIUM_TERM": 3,
    "LONG_TERM": 4,
}

SEVERITY_PRIORITY_MAP = {
    "CRITICAL": "IMMEDIATE",
    "HIGH": "IMMEDIATE",
    "MEDIUM": "SHORT_TERM",
    "LOW": "MEDIUM_TERM",
}

ACTION_OWNER_MAP = {
    "ISOLATE_VENDOR": "SECURITY_TEAM",
    "PATCH_VULNERABILITY": "DEVOPS_TEAM",
    "ROTATE_CREDENTIALS": "SECURITY_TEAM",
    "ENABLE_MFA": "IT_ADMIN",
    "BLOCK_LATERAL_MOVEMENT": "NETWORK_TEAM",
    "FAILOVER_TO_BACKUP": "INFRASTRUCTURE_TEAM",
    "ENABLE_WAF": "NETWORK_TEAM",
    "REVOKE_API_ACCESS": "SECURITY_TEAM",
}


def buildMitigationRecommendation(
    mitigation_key: str,
    vendor: str,
    severity: str,
    current_risk: float,
    graph: nx.DiGraph = None,
) -> Dict:
    if graph is None:
        graph = buildDependencyGraph()

    strategy = MITIGATION_STRATEGIES.get(mitigation_key, {})
    risk_reduction = strategy.get("risk_reduction_factor", 0.0)
    blast_reduction = strategy.get("blast_radius_reduction_factor", 0.0)
    estimated_risk_after = round(current_risk * (1.0 - risk_reduction), 4)
    severity_after = mapScoreToSeverity(estimated_risk_after)
    priority = SEVERITY_PRIORITY_MAP.get(severity.upper(), "SHORT_TERM")
    owner = ACTION_OWNER_MAP.get(mitigation_key, "SECURITY_TEAM")
    recovery_hours = calculateRecoveryTimeHours(severity)
    redundancy = getVendorRedundancyScore(vendor)
    criticality = getNodeCriticality(vendor)

    return {
        "mitigation": mitigation_key,
        "description": strategy.get("description", ""),
        "vendor": vendor,
        "priority": priority,
        "priority_level": PRIORITY_LEVELS.get(priority, 4),
        "owner": owner,
        "current_risk": round(current_risk, 4),
        "estimated_risk_after": estimated_risk_after,
        "severity_before": severity,
        "severity_after": severity_after,
        "risk_reduction_factor": risk_reduction,
        "blast_radius_reduction_factor": blast_reduction,
        "vendor_criticality": round(criticality, 4),
        "vendor_redundancy": round(redundancy, 4),
        "estimated_recovery_hours": recovery_hours,
        "business_impact": buildBusinessImpactStatement(vendor, severity, criticality),
    }


def buildBusinessImpactStatement(
    vendor: str,
    severity: str,
    criticality: float,
) -> str:
    impact_level = (
        "catastrophic" if criticality >= 0.9
        else "severe" if criticality >= 0.7
        else "moderate" if criticality >= 0.5
        else "limited"
    )
    return (
        f"{vendor} compromise at {severity} severity poses {impact_level} "
        f"business impact with criticality score {round(criticality, 2)}."
    )


def generateFullRecommendationReport(
    origin_vendor: str,
    initial_severity: str,
    propagated_scores: Dict[str, float],
    graph: nx.DiGraph = None,
) -> Dict:
    if graph is None:
        graph = buildDependencyGraph()

    origin_risk = propagated_scores.get(origin_vendor, mapSeverityToScore(initial_severity))
    ranked_mitigations = rankMitigationsByImpact(
        origin_vendor, initial_severity, propagated_scores, graph
    )

    primary_mitigations = selectMitigationsForSeverity(initial_severity)
    detailed_recommendations = [
        buildMitigationRecommendation(
            mitigation_key=key,
            vendor=origin_vendor,
            severity=initial_severity,
            current_risk=origin_risk,
            graph=graph,
        )
        for key in primary_mitigations
    ]

    detailed_recommendations.sort(key=lambda x: x["priority_level"])

    downstream = getDownstreamDependencies(graph, origin_vendor)
    downstream_recommendations = []
    for vendor in downstream:
        vendor_risk = propagated_scores.get(vendor, 0.0)
        if vendor_risk < 0.4:
            continue
        vendor_severity = mapScoreToSeverity(vendor_risk)
        vendor_mitigations = selectMitigationsForSeverity(vendor_severity)[:2]
        for key in vendor_mitigations:
            rec = buildMitigationRecommendation(
                mitigation_key=key,
                vendor=vendor,
                severity=vendor_severity,
                current_risk=vendor_risk,
                graph=graph,
            )
            downstream_recommendations.append(rec)

    downstream_recommendations.sort(
        key=lambda x: (x["priority_level"], -x["current_risk"])
    )

    resilience_gaps = identifyResilienceGaps(propagated_scores, graph)
    gap_recommendations = buildGapRecommendations(resilience_gaps)

    combined_risk_reduction, combined_blast_reduction = calculateMitigationEffectiveness(
        primary_mitigations
    )

    return {
        "origin_vendor": origin_vendor,
        "initial_severity": initial_severity,
        "origin_risk_score": round(origin_risk, 4),
        "primary_recommendations": detailed_recommendations,
        "downstream_recommendations": downstream_recommendations[:10],
        "gap_recommendations": gap_recommendations,
        "ranked_mitigations_by_impact": ranked_mitigations,
        "combined_risk_reduction": round(combined_risk_reduction, 4),
        "combined_blast_reduction": round(combined_blast_reduction, 4),
        "total_recommendations": (
            len(detailed_recommendations)
            + len(downstream_recommendations[:10])
            + len(gap_recommendations)
        ),
        "immediate_actions": [
            r for r in detailed_recommendations if r["priority"] == "IMMEDIATE"
        ],
        "executive_action_summary": buildExecutiveActionSummary(
            origin_vendor,
            initial_severity,
            detailed_recommendations,
            combined_risk_reduction,
        ),
    }


def buildGapRecommendations(resilience_gaps: List[Dict]) -> List[Dict]:
    recommendations = []
    for gap in resilience_gaps:
        vendor = gap["vendor"]
        gap_severity = gap["gap_severity"]
        mitigations = selectMitigationsForSeverity(gap_severity)[:2]
        for key in mitigations:
            strategy = MITIGATION_STRATEGIES.get(key, {})
            recommendations.append({
                "mitigation": key,
                "description": strategy.get("description", ""),
                "vendor": vendor,
                "gap_severity": gap_severity,
                "resilience_score": gap["resilience_score"],
                "priority": SEVERITY_PRIORITY_MAP.get(gap_severity, "MEDIUM_TERM"),
                "owner": ACTION_OWNER_MAP.get(key, "SECURITY_TEAM"),
                "risk_reduction_factor": strategy.get("risk_reduction_factor", 0.0),
            })
    recommendations.sort(key=lambda x: x["resilience_score"])
    return recommendations


def buildExecutiveActionSummary(
    origin_vendor: str,
    initial_severity: str,
    recommendations: List[Dict],
    combined_risk_reduction: float,
) -> Dict:
    immediate = [r for r in recommendations if r["priority"] == "IMMEDIATE"]
    short_term = [r for r in recommendations if r["priority"] == "SHORT_TERM"]
    owners = list({r["owner"] for r in recommendations})
    risk_reduction_pct = round(combined_risk_reduction * 100, 2)

    return {
        "summary": (
            f"Immediate response required for {origin_vendor} at {initial_severity} severity. "
            f"Applying recommended mitigations will reduce risk by {risk_reduction_pct}%."
        ),
        "immediate_action_count": len(immediate),
        "short_term_action_count": len(short_term),
        "teams_involved": owners,
        "estimated_risk_reduction_percentage": risk_reduction_pct,
        "top_priority_action": immediate[0]["mitigation"] if immediate else None,
        "top_priority_description": immediate[0]["description"] if immediate else None,
    }


def getVendorSpecificRecommendations(
    vendor: str,
    propagated_scores: Dict[str, float],
    graph: nx.DiGraph = None,
) -> List[Dict]:
    if graph is None:
        graph = buildDependencyGraph()

    risk_score = propagated_scores.get(vendor, 0.0)
    severity = mapScoreToSeverity(risk_score)
    mitigations = selectMitigationsForSeverity(severity)

    return [
        buildMitigationRecommendation(
            mitigation_key=key,
            vendor=vendor,
            severity=severity,
            current_risk=risk_score,
            graph=graph,
        )
        for key in mitigations
    ]


def prioritizeRecommendationsByBusinessImpact(
    recommendations: List[Dict],
) -> List[Dict]:
    def computePriorityScore(rec: Dict) -> float:
        priority_weight = 1.0 / rec.get("priority_level", 4)
        risk_weight = rec.get("current_risk", 0.0)
        criticality_weight = rec.get("vendor_criticality", 0.0)
        reduction_weight = rec.get("risk_reduction_factor", 0.0)
        return (priority_weight * 0.3) + (risk_weight * 0.3) + (criticality_weight * 0.2) + (reduction_weight * 0.2)

    scored = [
        {**rec, "business_priority_score": round(computePriorityScore(rec), 4)}
        for rec in recommendations
    ]
    scored.sort(key=lambda x: x["business_priority_score"], reverse=True)
    return scored