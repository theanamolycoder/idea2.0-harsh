import numpy as np
from typing import Dict, List
import networkx as nx
from propagation.dependency_mapper import (
    buildDependencyGraph,
    getNodeCriticality,
    getAllNodes,
)
from propagation.propagation_engine import (
    mapSeverityToScore,
    mapScoreToSeverity,
    runPropagationSimulation,
)
from monte_carlo.simulation_engine import runMonteCarloSimulation
from monte_carlo.probability_engine import calculateJointProbability

SCENARIO_SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

PREDEFINED_SCENARIOS = {
    "supply_chain_compromise": {
        "origin": "CloudServe",
        "severity": "CRITICAL",
        "description": "Primary cloud vendor fully compromised via supply chain attack",
        "attack_type": "SUPPLY_CHAIN",
    },
    "auth_provider_breach": {
        "origin": "AuthProvider",
        "severity": "HIGH",
        "description": "Authentication provider credentials leaked via phishing",
        "attack_type": "CREDENTIAL_THEFT",
    },
    "payment_api_ransomware": {
        "origin": "PaymentAPI",
        "severity": "CRITICAL",
        "description": "Payment API encrypted by ransomware group",
        "attack_type": "RANSOMWARE",
    },
    "fraud_system_lateral": {
        "origin": "FraudSystem",
        "severity": "HIGH",
        "description": "Fraud detection system compromised via lateral movement",
        "attack_type": "LATERAL_MOVEMENT",
    },
    "identity_service_zero_day": {
        "origin": "IdentityService",
        "severity": "CRITICAL",
        "description": "Zero-day exploit targeting identity service",
        "attack_type": "ZERO_DAY",
    },
    "storage_api_data_exfil": {
        "origin": "StorageAPI",
        "severity": "MEDIUM",
        "description": "Storage API targeted for data exfiltration",
        "attack_type": "DATA_EXFILTRATION",
    },
}


def generateScenario(
    scenario_key: str,
    graph: nx.DiGraph = None,
    iterations: int = 1000,
) -> Dict:
    if graph is None:
        graph = buildDependencyGraph()

    if scenario_key not in PREDEFINED_SCENARIOS:
        return buildEmptyScenarioResult(scenario_key)

    scenario = PREDEFINED_SCENARIOS[scenario_key]
    origin = scenario["origin"]
    severity = scenario["severity"]

    propagation_result = runPropagationSimulation(origin, severity, graph)
    monte_carlo_result = runMonteCarloSimulation(origin, severity, graph, iterations)

    return buildScenarioResult(
        scenario_key=scenario_key,
        scenario=scenario,
        propagation_result=propagation_result,
        monte_carlo_result=monte_carlo_result,
    )


def generateAllScenarios(
    graph: nx.DiGraph = None,
    iterations: int = 1000,
) -> List[Dict]:
    if graph is None:
        graph = buildDependencyGraph()

    results = []
    for scenario_key in PREDEFINED_SCENARIOS:
        result = generateScenario(scenario_key, graph, iterations)
        results.append(result)

    results.sort(key=lambda x: x["composite_risk_score"], reverse=True)
    return results


def generateCustomScenario(
    origin_vendor: str,
    severity: str,
    attack_type: str,
    description: str,
    graph: nx.DiGraph = None,
    iterations: int = 1000,
) -> Dict:
    if graph is None:
        graph = buildDependencyGraph()

    scenario = {
        "origin": origin_vendor,
        "severity": severity,
        "description": description,
        "attack_type": attack_type,
    }

    propagation_result = runPropagationSimulation(origin_vendor, severity, graph)
    monte_carlo_result = runMonteCarloSimulation(origin_vendor, severity, graph, iterations)

    return buildScenarioResult(
        scenario_key="custom",
        scenario=scenario,
        propagation_result=propagation_result,
        monte_carlo_result=monte_carlo_result,
    )


def buildScenarioResult(
    scenario_key: str,
    scenario: Dict,
    propagation_result: Dict,
    monte_carlo_result: Dict,
) -> Dict:
    origin = scenario["origin"]
    severity = scenario["severity"]
    initial_risk = mapSeverityToScore(severity)
    criticality = getNodeCriticality(origin)

    infected_nodes = propagation_result.get("infected_nodes", [])
    mean_blast = monte_carlo_result.get("mean_blast_radius", 0)
    p95_blast = monte_carlo_result.get("percentile_95_blast_radius", 0)
    high_confidence = monte_carlo_result.get("high_confidence_infected", [])

    composite_risk = round(
        (initial_risk * 0.4) + (criticality * 0.3) + (min(mean_blast / 20.0, 1.0) * 0.3),
        4,
    )

    return {
        "scenario_key": scenario_key,
        "attack_origin": origin,
        "attack_type": scenario["attack_type"],
        "description": scenario["description"],
        "severity": severity,
        "initial_risk_score": initial_risk,
        "origin_criticality": criticality,
        "composite_risk_score": composite_risk,
        "total_infected_nodes": len(infected_nodes),
        "mean_blast_radius": mean_blast,
        "percentile_95_blast_radius": p95_blast,
        "high_confidence_infected": high_confidence,
        "infected_nodes": infected_nodes,
        "monte_carlo_summary": {
            "iterations": monte_carlo_result.get("iterations"),
            "std_blast_radius": monte_carlo_result.get("std_blast_radius"),
            "max_blast_radius": monte_carlo_result.get("max_blast_radius"),
            "min_blast_radius": monte_carlo_result.get("min_blast_radius"),
        },
    }


def generateWorstCaseScenario(
    graph: nx.DiGraph = None,
    iterations: int = 1000,
) -> Dict:
    if graph is None:
        graph = buildDependencyGraph()

    all_scenarios = generateAllScenarios(graph, iterations)
    if not all_scenarios:
        return {}
    return all_scenarios[0]


def generateBestCaseScenario(
    graph: nx.DiGraph = None,
    iterations: int = 1000,
) -> Dict:
    if graph is None:
        graph = buildDependencyGraph()

    all_scenarios = generateAllScenarios(graph, iterations)
    if not all_scenarios:
        return {}
    return all_scenarios[-1]


def compareScenarios(
    scenario_keys: List[str],
    graph: nx.DiGraph = None,
    iterations: int = 1000,
) -> List[Dict]:
    if graph is None:
        graph = buildDependencyGraph()

    results = []
    for key in scenario_keys:
        result = generateScenario(key, graph, iterations)
        results.append({
            "scenario_key": key,
            "attack_origin": result.get("attack_origin"),
            "severity": result.get("severity"),
            "composite_risk_score": result.get("composite_risk_score"),
            "mean_blast_radius": result.get("mean_blast_radius"),
            "total_infected_nodes": result.get("total_infected_nodes"),
            "high_confidence_infected": result.get("high_confidence_infected"),
        })

    results.sort(key=lambda x: x["composite_risk_score"], reverse=True)
    return results


def buildEmptyScenarioResult(scenario_key: str) -> Dict:
    return {
        "scenario_key": scenario_key,
        "attack_origin": None,
        "attack_type": None,
        "description": "Scenario not found",
        "severity": None,
        "initial_risk_score": 0.0,
        "origin_criticality": 0.0,
        "composite_risk_score": 0.0,
        "total_infected_nodes": 0,
        "mean_blast_radius": 0,
        "percentile_95_blast_radius": 0,
        "high_confidence_infected": [],
        "infected_nodes": [],
        "monte_carlo_summary": {},
    }


def listAvailableScenarios() -> List[Dict]:
    return [
        {
            "scenario_key": key,
            "origin": val["origin"],
            "severity": val["severity"],
            "attack_type": val["attack_type"],
            "description": val["description"],
        }
        for key, val in PREDEFINED_SCENARIOS.items()
    ]