import numpy as np
from typing import Dict, List, Tuple
import networkx as nx
from propagation.dependency_mapper import (
    buildDependencyGraph,
    getDownstreamDependencies,
    getEdgeWeight,
    getNodeCriticality,
)
from propagation.propagation_engine import (
    mapScoreToSeverity,
    mapSeverityToScore,
)

DEFAULT_SIMULATION_ITERATIONS = 1000
DEFAULT_CONFIDENCE_INTERVAL = 0.95
RANDOM_SEED = 42


def runMonteCarloSimulation(
    origin_vendor: str,
    initial_severity: str,
    graph: nx.DiGraph = None,
    iterations: int = DEFAULT_SIMULATION_ITERATIONS,
) -> Dict:
    if graph is None:
        graph = buildDependencyGraph()

    np.random.seed(RANDOM_SEED)
    initial_risk = mapSeverityToScore(initial_severity)
    downstream = getDownstreamDependencies(graph, origin_vendor)

    if not downstream:
        return buildEmptySimulationResult(origin_vendor, initial_severity)

    node_infection_counts: Dict[str, int] = {node: 0 for node in downstream}
    node_risk_accumulator: Dict[str, List[float]] = {node: [] for node in downstream}
    blast_radius_samples: List[int] = []

    for _ in range(iterations):
        infected_this_run = set()
        risk_this_run: Dict[str, float] = {}
        queue = [(origin_vendor, initial_risk)]
        visited = {origin_vendor}

        while queue:
            current, current_risk = queue.pop(0)
            for neighbor in graph.successors(current):
                if neighbor not in downstream:
                    continue
                edge_weight = getEdgeWeight(graph, current, neighbor)
                criticality = getNodeCriticality(neighbor)
                base_prob = current_risk * edge_weight * criticality
                noise = np.random.normal(0, 0.05)
                infection_prob = float(np.clip(base_prob + noise, 0.0, 1.0))
                roll = np.random.uniform(0, 1)
                if roll <= infection_prob:
                    infected_this_run.add(neighbor)
                    propagated_risk = float(np.clip(infection_prob * np.random.uniform(0.8, 1.0), 0.0, 1.0))
                    if neighbor not in risk_this_run or risk_this_run[neighbor] < propagated_risk:
                        risk_this_run[neighbor] = propagated_risk
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append((neighbor, propagated_risk))

        for node in infected_this_run:
            node_infection_counts[node] += 1
            node_risk_accumulator[node].append(risk_this_run.get(node, 0.0))

        blast_radius_samples.append(len(infected_this_run))

    return buildMonteCarloResult(
        origin_vendor=origin_vendor,
        initial_severity=initial_severity,
        downstream=downstream,
        node_infection_counts=node_infection_counts,
        node_risk_accumulator=node_risk_accumulator,
        blast_radius_samples=blast_radius_samples,
        iterations=iterations,
    )


def buildMonteCarloResult(
    origin_vendor: str,
    initial_severity: str,
    downstream: List[str],
    node_infection_counts: Dict[str, int],
    node_risk_accumulator: Dict[str, List[float]],
    blast_radius_samples: List[int],
    iterations: int,
) -> Dict:
    node_results = []
    for node in downstream:
        count = node_infection_counts[node]
        infection_probability = round(count / iterations, 4)
        risk_samples = node_risk_accumulator[node]
        mean_risk = round(float(np.mean(risk_samples)), 4) if risk_samples else 0.0
        std_risk = round(float(np.std(risk_samples)), 4) if risk_samples else 0.0
        node_results.append({
            "vendor": node,
            "infection_probability": infection_probability,
            "mean_risk_score": mean_risk,
            "std_risk_score": std_risk,
            "severity": mapScoreToSeverity(mean_risk),
            "criticality": getNodeCriticality(node),
        })

    node_results.sort(key=lambda x: x["infection_probability"], reverse=True)

    blast_array = np.array(blast_radius_samples)
    mean_blast = round(float(np.mean(blast_array)), 2)
    std_blast = round(float(np.std(blast_array)), 2)
    max_blast = int(np.max(blast_array))
    min_blast = int(np.min(blast_array))
    percentile_95 = round(float(np.percentile(blast_array, 95)), 2)

    return {
        "attack_origin": origin_vendor,
        "initial_severity": initial_severity,
        "iterations": iterations,
        "mean_blast_radius": mean_blast,
        "std_blast_radius": std_blast,
        "max_blast_radius": max_blast,
        "min_blast_radius": min_blast,
        "percentile_95_blast_radius": percentile_95,
        "node_results": node_results,
        "high_confidence_infected": [
            n["vendor"] for n in node_results if n["infection_probability"] >= DEFAULT_CONFIDENCE_INTERVAL
        ],
    }


def buildEmptySimulationResult(
    origin_vendor: str,
    initial_severity: str,
) -> Dict:
    return {
        "attack_origin": origin_vendor,
        "initial_severity": initial_severity,
        "iterations": 0,
        "mean_blast_radius": 0,
        "std_blast_radius": 0,
        "max_blast_radius": 0,
        "min_blast_radius": 0,
        "percentile_95_blast_radius": 0,
        "node_results": [],
        "high_confidence_infected": [],
    }


def extractSimulationSummary(simulation_result: Dict) -> Dict:
    return {
        "attack_origin": simulation_result.get("attack_origin"),
        "initial_severity": simulation_result.get("initial_severity"),
        "mean_blast_radius": simulation_result.get("mean_blast_radius"),
        "percentile_95_blast_radius": simulation_result.get("percentile_95_blast_radius"),
        "high_confidence_infected": simulation_result.get("high_confidence_infected"),
        "total_nodes_analyzed": len(simulation_result.get("node_results", [])),
    }