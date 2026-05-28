import numpy as np
from typing import Dict, List, Tuple
import networkx as nx
from propagation.dependency_mapper import (
    getEdgeWeight,
    getNodeCriticality,
)
from propagation.propagation_engine import mapScoreToSeverity

RANDOM_SEED = 42
DEFAULT_NOISE_STD = 0.05
DEFAULT_SAMPLES = 1000


def calculateInfectionProbability(
    source_risk: float,
    edge_weight: float,
    target_criticality: float,
    noise_std: float = DEFAULT_NOISE_STD,
) -> float:
    np.random.seed(RANDOM_SEED)
    base_prob = source_risk * edge_weight * target_criticality
    noise = np.random.normal(0, noise_std)
    probability = float(np.clip(base_prob + noise, 0.0, 1.0))
    return round(probability, 4)


def calculateConditionalProbability(
    prior_probability: float,
    edge_weight: float,
    target_criticality: float,
) -> float:
    conditional = prior_probability * edge_weight * target_criticality
    return round(float(np.clip(conditional, 0.0, 1.0)), 4)


def sampleInfectionOutcome(
    infection_probability: float,
    samples: int = DEFAULT_SAMPLES,
) -> Dict:
    np.random.seed(RANDOM_SEED)
    rolls = np.random.uniform(0, 1, samples)
    infections = rolls <= infection_probability
    infection_rate = float(np.mean(infections))
    return {
        "infection_probability": infection_probability,
        "samples": samples,
        "infection_rate": round(infection_rate, 4),
        "infection_count": int(np.sum(infections)),
        "non_infection_count": int(np.sum(~infections)),
        "confidence_interval_95": calculateConfidenceInterval(infections, 0.95),
    }


def calculateConfidenceInterval(
    outcomes: np.ndarray,
    confidence: float = 0.95,
) -> Tuple[float, float]:
    mean = float(np.mean(outcomes))
    std = float(np.std(outcomes))
    n = len(outcomes)
    z = 1.96 if confidence == 0.95 else 2.576
    margin = z * (std / np.sqrt(n))
    lower = round(float(np.clip(mean - margin, 0.0, 1.0)), 4)
    upper = round(float(np.clip(mean + margin, 0.0, 1.0)), 4)
    return (lower, upper)


def calculateJointProbability(
    probabilities: List[float],
    mode: str = "independent",
) -> float:
    if not probabilities:
        return 0.0
    arr = np.array(probabilities)
    if mode == "independent":
        joint = float(np.prod(arr))
    elif mode == "union":
        joint = float(1.0 - np.prod(1.0 - arr))
    else:
        joint = float(np.mean(arr))
    return round(float(np.clip(joint, 0.0, 1.0)), 4)


def calculatePropagationProbabilityMatrix(
    graph: nx.DiGraph,
    propagated_scores: Dict[str, float],
) -> Dict[str, Dict[str, float]]:
    matrix: Dict[str, Dict[str, float]] = {}
    for source, target in graph.edges():
        source_risk = propagated_scores.get(source, 0.0)
        edge_weight = getEdgeWeight(graph, source, target)
        target_criticality = getNodeCriticality(target)
        prob = calculateInfectionProbability(source_risk, edge_weight, target_criticality)
        if source not in matrix:
            matrix[source] = {}
        matrix[source][target] = prob
    return matrix


def calculateCumulativePropagationRisk(
    path: List[str],
    graph: nx.DiGraph,
    propagated_scores: Dict[str, float],
) -> float:
    if len(path) < 2:
        return propagated_scores.get(path[0], 0.0) if path else 0.0

    probabilities = []
    for i in range(len(path) - 1):
        source = path[i]
        target = path[i + 1]
        source_risk = propagated_scores.get(source, 0.0)
        edge_weight = getEdgeWeight(graph, source, target)
        target_criticality = getNodeCriticality(target)
        prob = calculateInfectionProbability(source_risk, edge_weight, target_criticality)
        probabilities.append(prob)

    cumulative = calculateJointProbability(probabilities, mode="union")
    return cumulative


def buildNodeProbabilityProfile(
    vendor: str,
    propagated_scores: Dict[str, float],
    graph: nx.DiGraph,
) -> Dict:
    risk_score = propagated_scores.get(vendor, 0.0)
    criticality = getNodeCriticality(vendor)
    incoming_edges = list(graph.predecessors(vendor)) if vendor in graph else []
    outgoing_edges = list(graph.successors(vendor)) if vendor in graph else []

    incoming_probs = []
    for pred in incoming_edges:
        pred_risk = propagated_scores.get(pred, 0.0)
        edge_weight = getEdgeWeight(graph, pred, vendor)
        prob = calculateInfectionProbability(pred_risk, edge_weight, criticality)
        incoming_probs.append({"from": pred, "probability": prob})

    outgoing_probs = []
    for succ in outgoing_edges:
        succ_criticality = getNodeCriticality(succ)
        edge_weight = getEdgeWeight(graph, vendor, succ)
        prob = calculateInfectionProbability(risk_score, edge_weight, succ_criticality)
        outgoing_probs.append({"to": succ, "probability": prob})

    max_incoming = max((p["probability"] for p in incoming_probs), default=0.0)
    max_outgoing = max((p["probability"] for p in outgoing_probs), default=0.0)

    return {
        "vendor": vendor,
        "risk_score": round(risk_score, 4),
        "criticality": round(criticality, 4),
        "severity": mapScoreToSeverity(risk_score),
        "incoming_infection_probabilities": incoming_probs,
        "outgoing_infection_probabilities": outgoing_probs,
        "max_incoming_probability": round(max_incoming, 4),
        "max_outgoing_probability": round(max_outgoing, 4),
        "composite_risk": round((risk_score * 0.6) + (criticality * 0.4), 4),
    }


def rankVendorsByInfectionProbability(
    vendors: List[str],
    propagated_scores: Dict[str, float],
    graph: nx.DiGraph,
) -> List[Dict]:
    profiles = []
    for vendor in vendors:
        profile = buildNodeProbabilityProfile(vendor, propagated_scores, graph)
        profiles.append(profile)
    profiles.sort(key=lambda x: x["composite_risk"], reverse=True)
    return profiles