import networkx as nx
from typing import Dict, List
from collections import deque
from app.api.propagation.dependency_mapper import (
    buildDependencyGraph,
    getEdgeWeight,
    getNodeCriticality,
    serializeGraph,
)
from app.api.propagation.propagation_engine import (
    mapScoreToSeverity,
    mapSeverityToScore,
    calculateNodeInfectionProbability,
)
from app.api.mitigation.mitigation_engine import (
    MITIGATION_STRATEGIES,
    selectMitigationsForSeverity,
    calculateMitigationEffectiveness,
    applyMitigationSimulation,
)
from app.api.propagation.blast_radius_engine import calculateBlastRadius, compareBlastRadii
from app.api.propagation.attack_path_engine import generateAttackPathReport

FRAME_DELAY_MS = 800
MITIGATION_FRAME_DELAY_MS = 1200
AFTER_FRAME_DELAY_MS = 600

NODE_STATUS_CLEAN = "clean"
NODE_STATUS_ORIGIN = "origin"
NODE_STATUS_INFECTED = "infected"
NODE_STATUS_SPREADING = "spreading"
NODE_STATUS_MITIGATED = "mitigated"
NODE_STATUS_BLOCKED = "blocked"

EDGE_STATUS_INACTIVE = "inactive"
EDGE_STATUS_ACTIVE = "active"
EDGE_STATUS_PROPAGATING = "propagating"
EDGE_STATUS_BLOCKED = "blocked"


def buildNodeState(
    vendor: str,
    status: str,
    risk_score: float,
    is_newly_changed: bool = False,
) -> Dict:
    return {
        "id": vendor,
        "status": status,
        "risk_score": round(risk_score, 4),
        "severity": mapScoreToSeverity(risk_score),
        "criticality": round(getNodeCriticality(vendor), 4),
        "is_newly_changed": is_newly_changed,
    }


def buildEdgeState(
    source: str,
    target: str,
    weight: float,
    status: str,
    is_active_propagation: bool = False,
) -> Dict:
    return {
        "id": f"{source}->{target}",
        "source": source,
        "target": target,
        "weight": round(weight, 4),
        "status": status,
        "is_active_propagation": is_active_propagation,
        "animated": is_active_propagation,
    }


def buildPropagationWaves(
    graph: nx.DiGraph,
    origin: str,
    initial_risk: float,
    decay_factor: float = 0.75,
) -> Dict:
    infected_scores: Dict[str, float] = {origin: initial_risk}
    wave_assignment: Dict[str, int] = {origin: 0}
    propagation_edges: Dict[int, List[tuple]] = {}
    visited = set()
    queue = deque([(origin, initial_risk, 0)])

    while queue:
        node, score, wave = queue.popleft()
        if node in visited:
            continue
        visited.add(node)

        for neighbor in graph.successors(node):
            if neighbor in visited:
                continue
            prob = calculateNodeInfectionProbability(graph, node, neighbor, score)
            propagated = prob * decay_factor
            if propagated > 0.05:
                if neighbor not in infected_scores or infected_scores[neighbor] < propagated:
                    infected_scores[neighbor] = propagated
                    wave_assignment[neighbor] = wave + 1
                    edge_wave = wave + 1
                    if edge_wave not in propagation_edges:
                        propagation_edges[edge_wave] = []
                    propagation_edges[edge_wave].append((node, neighbor, propagated))
                    queue.append((neighbor, propagated, wave + 1))

    max_wave = max(wave_assignment.values()) if wave_assignment else 0
    return {
        "infected_scores": infected_scores,
        "wave_assignment": wave_assignment,
        "propagation_edges": propagation_edges,
        "max_wave": max_wave,
    }


def buildBeforeMitigationFrames(
    graph: nx.DiGraph,
    origin: str,
    initial_severity: str,
) -> List[Dict]:
    initial_risk = mapSeverityToScore(initial_severity)
    all_nodes = list(graph.nodes())
    all_edges = list(graph.edges())
    wave_data = buildPropagationWaves(graph, origin, initial_risk)

    infected_scores = wave_data["infected_scores"]
    wave_assignment = wave_data["wave_assignment"]
    propagation_edges = wave_data["propagation_edges"]
    max_wave = wave_data["max_wave"]

    frames: List[Dict] = []

    frame_0_nodes = [
        buildNodeState(
            v,
            NODE_STATUS_ORIGIN if v == origin else NODE_STATUS_CLEAN,
            initial_risk if v == origin else 0.0,
            is_newly_changed=(v == origin),
        )
        for v in all_nodes
    ]
    frame_0_edges = [
        buildEdgeState(s, t, getEdgeWeight(graph, s, t), EDGE_STATUS_INACTIVE)
        for s, t in all_edges
    ]
    frames.append({
        "phase": "before_mitigation",
        "frame_index": 0,
        "wave": 0,
        "label": f"BREACH DETECTED — {origin} compromised",
        "description": f"{origin} has been compromised at {initial_severity} severity. Risk score: {initial_risk}. Attack is initiating.",
        "nodes": frame_0_nodes,
        "edges": frame_0_edges,
        "infected_nodes": [origin],
        "newly_infected": [origin],
        "active_edges": [],
        "blast_radius": 0,
        "risk_reduction_percentage": 0.0,
        "delay_ms": FRAME_DELAY_MS,
    })

    cumulative_infected = {origin}
    cumulative_scores = {origin: initial_risk}

    for wave in range(1, max_wave + 1):
        newly_infected_this_wave = [
            v for v, w in wave_assignment.items() if w == wave
        ]
        active_edges_this_wave = propagation_edges.get(wave, [])

        for v in newly_infected_this_wave:
            cumulative_infected.add(v)
            cumulative_scores[v] = infected_scores[v]

        active_edge_ids = [f"{s}->{t}" for s, t, _ in active_edges_this_wave]

        frame_nodes = []
        for v in all_nodes:
            if v == origin:
                frame_nodes.append(buildNodeState(v, NODE_STATUS_ORIGIN, initial_risk))
            elif v in newly_infected_this_wave:
                frame_nodes.append(buildNodeState(v, NODE_STATUS_INFECTED, cumulative_scores[v], is_newly_changed=True))
            elif v in cumulative_infected:
                frame_nodes.append(buildNodeState(v, NODE_STATUS_INFECTED, cumulative_scores[v]))
            else:
                frame_nodes.append(buildNodeState(v, NODE_STATUS_CLEAN, 0.0))

        frame_edges = []
        for s, t in all_edges:
            edge_id = f"{s}->{t}"
            if edge_id in active_edge_ids:
                frame_edges.append(buildEdgeState(s, t, getEdgeWeight(graph, s, t), EDGE_STATUS_PROPAGATING, is_active_propagation=True))
            elif s in cumulative_infected and t in cumulative_infected:
                frame_edges.append(buildEdgeState(s, t, getEdgeWeight(graph, s, t), EDGE_STATUS_ACTIVE))
            else:
                frame_edges.append(buildEdgeState(s, t, getEdgeWeight(graph, s, t), EDGE_STATUS_INACTIVE))

        high_risk_spread = [v for v in newly_infected_this_wave if cumulative_scores.get(v, 0) >= 0.4]
        blast = len([v for v in cumulative_infected if v != origin])

        wave_labels = {
            1: "WAVE 1 — Direct dependencies breached",
            2: "WAVE 2 — Second-tier vendors infected",
            3: "WAVE 3 — Deep propagation detected",
            4: "WAVE 4 — Full blast radius reached",
        }
        label = wave_labels.get(wave, f"WAVE {wave} — Propagation continues")

        newly_str = ", ".join(newly_infected_this_wave) if newly_infected_this_wave else "none"
        high_risk_str = ", ".join(high_risk_spread) if high_risk_spread else "none"

        frames.append({
            "phase": "before_mitigation",
            "frame_index": wave,
            "wave": wave,
            "label": label,
            "description": (
                f"Attack spreads to: {newly_str}. "
                f"High-risk vendors in this wave: {high_risk_str}. "
                f"Blast radius now: {blast} vendors."
            ),
            "nodes": frame_nodes,
            "edges": frame_edges,
            "infected_nodes": list(cumulative_infected),
            "newly_infected": newly_infected_this_wave,
            "active_edges": active_edge_ids,
            "blast_radius": blast,
            "risk_reduction_percentage": 0.0,
            "delay_ms": FRAME_DELAY_MS,
        })

    return frames


def buildMitigationPhaseFrames(
    graph: nx.DiGraph,
    origin: str,
    initial_severity: str,
    infected_scores: Dict[str, float],
    mitigations: List[str],
) -> List[Dict]:
    all_nodes = list(graph.nodes())
    all_edges = list(graph.edges())
    frames: List[Dict] = []

    cumulative_risk = {v: s for v, s in infected_scores.items()}
    cumulative_mitigated: List[str] = []
    frame_index = 0

    for i, mitigation_key in enumerate(mitigations):
        strategy = MITIGATION_STRATEGIES.get(mitigation_key, {})
        risk_reduction_factor = strategy.get("risk_reduction_factor", 0.0)
        description = strategy.get("description", "")

        mitigation_explanations = {
            "ISOLATE_VENDOR": {
                "title": "ISOLATE VENDOR",
                "action": f"Network isolation applied to {origin}. All inbound and outbound connections severed.",
                "effect": f"Cuts off the attack source entirely. Downstream vendors can no longer receive infected traffic from {origin}.",
                "icon": "shield-off",
            },
            "REVOKE_API_ACCESS": {
                "title": "REVOKE API ACCESS",
                "action": f"All API tokens and access credentials for {origin} invalidated across the dependency chain.",
                "effect": "Infected systems can no longer authenticate to downstream vendors. Lateral movement via APIs is blocked.",
                "icon": "key-off",
            },
            "ROTATE_CREDENTIALS": {
                "title": "ROTATE CREDENTIALS",
                "action": "Emergency credential rotation triggered for all affected systems.",
                "effect": "Stolen credentials become invalid. Active attacker sessions terminated across the vendor graph.",
                "icon": "refresh-cw",
            },
            "FAILOVER_TO_BACKUP": {
                "title": "FAILOVER TO BACKUP",
                "action": f"Traffic rerouted from {origin} to backup vendor systems.",
                "effect": "Clean backup systems take over. Infected vendor is removed from the active dependency path.",
                "icon": "git-branch",
            },
            "PATCH_VULNERABILITY": {
                "title": "PATCH VULNERABILITY",
                "action": "Emergency vulnerability patch deployed across affected vendor systems.",
                "effect": "Exploitation vector closed. Attack cannot continue through the patched vulnerability.",
                "icon": "tool",
            },
            "BLOCK_LATERAL_MOVEMENT": {
                "title": "BLOCK LATERAL MOVEMENT",
                "action": "Lateral movement rules applied across all vendor-to-vendor communication channels.",
                "effect": "Attack cannot jump between vendors. Each vendor is now isolated in its own network segment.",
                "icon": "slash",
            },
            "ENABLE_MFA": {
                "title": "ENABLE MFA",
                "action": "Multi-factor authentication enforced across all vendor access points.",
                "effect": "Credential-based attacks blocked. Attacker cannot reuse stolen passwords without second factor.",
                "icon": "lock",
            },
            "ENABLE_WAF": {
                "title": "ENABLE WAF",
                "action": "Web Application Firewall rules activated across exposed vendor endpoints.",
                "effect": "Malicious traffic filtered at the perimeter. API-based attack vectors blocked.",
                "icon": "filter",
            },
        }

        explanation = mitigation_explanations.get(mitigation_key, {
            "title": mitigation_key,
            "action": description,
            "effect": f"Reduces risk by {round(risk_reduction_factor * 100)}%",
            "icon": "shield",
        })

        vendors_affected = [
            v for v in cumulative_risk
            if cumulative_risk[v] > 0.1 and v not in cumulative_mitigated
        ]
        for v in vendors_affected:
            cumulative_risk[v] = round(cumulative_risk[v] * (1.0 - risk_reduction_factor * 0.5), 4)

        if i == 0:
            cumulative_mitigated.append(origin)

        current_infected = [v for v in cumulative_risk if cumulative_risk.get(v, 0) > 0.1 and v not in cumulative_mitigated]
        blocked_edges = []
        if origin in cumulative_mitigated:
            blocked_edges = [f"{origin}->{t}" for t in graph.successors(origin)]

        frame_nodes = []
        for v in all_nodes:
            if v in cumulative_mitigated:
                frame_nodes.append(buildNodeState(v, NODE_STATUS_MITIGATED, 0.0, is_newly_changed=(v == origin and i == 0)))
            elif v == origin:
                frame_nodes.append(buildNodeState(v, NODE_STATUS_ORIGIN, cumulative_risk.get(v, 0.0)))
            elif v in cumulative_risk and cumulative_risk[v] > 0.1:
                frame_nodes.append(buildNodeState(v, NODE_STATUS_INFECTED, cumulative_risk[v]))
            elif v in cumulative_risk:
                frame_nodes.append(buildNodeState(v, NODE_STATUS_BLOCKED, cumulative_risk[v]))
            else:
                frame_nodes.append(buildNodeState(v, NODE_STATUS_CLEAN, 0.0))

        frame_edges = []
        for s, t in all_edges:
            edge_id = f"{s}->{t}"
            if edge_id in blocked_edges:
                frame_edges.append(buildEdgeState(s, t, getEdgeWeight(graph, s, t), EDGE_STATUS_BLOCKED))
            elif s in cumulative_mitigated or t in cumulative_mitigated:
                frame_edges.append(buildEdgeState(s, t, getEdgeWeight(graph, s, t), EDGE_STATUS_BLOCKED))
            elif cumulative_risk.get(s, 0) > 0.1 and cumulative_risk.get(t, 0) > 0.1:
                frame_edges.append(buildEdgeState(s, t, getEdgeWeight(graph, s, t), EDGE_STATUS_ACTIVE))
            else:
                frame_edges.append(buildEdgeState(s, t, getEdgeWeight(graph, s, t), EDGE_STATUS_INACTIVE))

        current_blast = len(current_infected)
        risk_already_reduced = round((1.0 - (1 - risk_reduction_factor) ** (i + 1)) * 100, 1)

        frames.append({
            "phase": "mitigation",
            "frame_index": frame_index,
            "mitigation_index": i,
            "mitigation_key": mitigation_key,
            "label": f"APPLYING — {explanation['title']}",
            "mitigation_card": {
                "title": explanation["title"],
                "action": explanation["action"],
                "effect": explanation["effect"],
                "icon": explanation["icon"],
                "risk_reduction_factor": risk_reduction_factor,
                "risk_reduction_percent": round(risk_reduction_factor * 100, 1),
            },
            "description": f"Step {i + 1} of {len(mitigations)}: {explanation['action']}",
            "nodes": frame_nodes,
            "edges": frame_edges,
            "infected_nodes": current_infected,
            "mitigated_nodes": list(cumulative_mitigated),
            "newly_mitigated": [origin] if i == 0 else [],
            "blocked_edges": blocked_edges,
            "blast_radius": current_blast,
            "risk_reduction_percentage": risk_already_reduced,
            "delay_ms": MITIGATION_FRAME_DELAY_MS,
        })
        frame_index += 1

    return frames


def buildAfterMitigationFrames(
    graph: nx.DiGraph,
    origin: str,
    initial_severity: str,
    mitigated_scores: Dict[str, float],
    mitigated_vendors: List[str],
    initial_blast_radius: int,
    reduced_blast_radius: int,
    risk_reduction_percentage: float,
) -> List[Dict]:
    all_nodes = list(graph.nodes())
    all_edges = list(graph.edges())
    frames: List[Dict] = []

    frame_nodes = []
    for v in all_nodes:
        if v in mitigated_vendors:
            frame_nodes.append(buildNodeState(v, NODE_STATUS_MITIGATED, 0.0, is_newly_changed=True))
        elif v == origin:
            frame_nodes.append(buildNodeState(v, NODE_STATUS_MITIGATED, mitigated_scores.get(v, 0.0)))
        elif mitigated_scores.get(v, 0.0) > 0.1:
            frame_nodes.append(buildNodeState(v, NODE_STATUS_INFECTED, mitigated_scores[v]))
        else:
            frame_nodes.append(buildNodeState(v, NODE_STATUS_CLEAN, mitigated_scores.get(v, 0.0)))

    frame_edges = []
    for s, t in all_edges:
        if s in mitigated_vendors or t in mitigated_vendors or s == origin:
            frame_edges.append(buildEdgeState(s, t, getEdgeWeight(graph, s, t), EDGE_STATUS_BLOCKED))
        elif mitigated_scores.get(s, 0) > 0.1 and mitigated_scores.get(t, 0) > 0.1:
            frame_edges.append(buildEdgeState(s, t, getEdgeWeight(graph, s, t), EDGE_STATUS_ACTIVE))
        else:
            frame_edges.append(buildEdgeState(s, t, getEdgeWeight(graph, s, t), EDGE_STATUS_INACTIVE))

    remaining_infected = [v for v in mitigated_scores if mitigated_scores.get(v, 0) > 0.1 and v not in mitigated_vendors]

    frames.append({
        "phase": "after_mitigation",
        "frame_index": 0,
        "label": "MITIGATIONS APPLIED — Blast Radius Contained",
        "description": (
            f"All {len(mitigated_vendors)} mitigations applied. "
            f"Blast radius reduced from {initial_blast_radius} to {reduced_blast_radius} vendors. "
            f"Risk reduced by {risk_reduction_percentage}%."
        ),
        "nodes": frame_nodes,
        "edges": frame_edges,
        "infected_nodes": remaining_infected,
        "mitigated_nodes": mitigated_vendors,
        "active_edges": [],
        "blast_radius": reduced_blast_radius,
        "risk_reduction_percentage": risk_reduction_percentage,
        "delay_ms": AFTER_FRAME_DELAY_MS,
    })

    containment_nodes = []
    for v in all_nodes:
        if v in mitigated_vendors or v == origin:
            containment_nodes.append(buildNodeState(v, NODE_STATUS_MITIGATED, 0.0))
        elif mitigated_scores.get(v, 0.0) > 0.05:
            containment_nodes.append(buildNodeState(v, NODE_STATUS_BLOCKED, mitigated_scores.get(v, 0.0)))
        else:
            containment_nodes.append(buildNodeState(v, NODE_STATUS_CLEAN, 0.0))

    containment_edges = [
        buildEdgeState(s, t, getEdgeWeight(graph, s, t), EDGE_STATUS_INACTIVE)
        for s, t in all_edges
    ]

    frames.append({
        "phase": "after_mitigation",
        "frame_index": 1,
        "label": "CONTAINMENT COMPLETE — Network Stabilizing",
        "description": (
            f"Network containment achieved. "
            f"{risk_reduction_percentage}% risk reduction confirmed. "
            f"Severity reduced from {initial_severity} to {mapScoreToSeverity(max(mitigated_scores.values()) if mitigated_scores else 0.0)}. "
            f"Remaining monitoring in progress."
        ),
        "nodes": containment_nodes,
        "edges": containment_edges,
        "infected_nodes": [],
        "mitigated_nodes": mitigated_vendors,
        "active_edges": [],
        "blast_radius": reduced_blast_radius,
        "risk_reduction_percentage": risk_reduction_percentage,
        "delay_ms": AFTER_FRAME_DELAY_MS,
    })

    return frames


def buildAnimatedSimulationPayload(
    origin_vendor: str,
    initial_severity: str,
    graph: nx.DiGraph = None,
) -> Dict:
    if graph is None:
        graph = buildDependencyGraph()

    mitigations = selectMitigationsForSeverity(initial_severity)
    initial_risk = mapSeverityToScore(initial_severity)
    wave_data = buildPropagationWaves(graph, origin_vendor, initial_risk)
    infected_scores = wave_data["infected_scores"]

    mitigation_result = applyMitigationSimulation(
        origin_vendor, initial_severity, infected_scores, mitigations, graph
    )
    mitigated_scores = mitigation_result["mitigated_scores"]
    mitigated_vendors = mitigation_result["mitigated_vendors"]
    initial_blast_radius = mitigation_result["initial_blast_radius"]
    reduced_blast_radius = mitigation_result["reduced_blast_radius"]
    risk_reduction_pct = mitigation_result["risk_reduction_percentage"]
    severity_after = mitigation_result["severity_after"]

    attack_path_report = generateAttackPathReport(origin_vendor, infected_scores, graph)
    attack_path = attack_path_report.get("attack_path", [origin_vendor])

    before_frames = buildBeforeMitigationFrames(graph, origin_vendor, initial_severity)
    mitigation_frames = buildMitigationPhaseFrames(graph, origin_vendor, initial_severity, infected_scores, mitigations)
    after_frames = buildAfterMitigationFrames(
        graph, origin_vendor, initial_severity,
        mitigated_scores, mitigated_vendors,
        initial_blast_radius, reduced_blast_radius, risk_reduction_pct,
    )

    mitigation_phase_summary = {
        "title": "MITIGATIONS BEING APPLIED",
        "description": (
            f"{len(mitigations)} mitigation strategies activated against {initial_severity}-severity attack on {origin_vendor}. "
            f"Each strategy progressively reduces risk and blast radius."
        ),
        "effect_on_spread": (
            f"Combined effect will reduce blast radius from {initial_blast_radius} to {reduced_blast_radius} vendors "
            f"and cut overall risk by {risk_reduction_pct}%."
        ),
        "strategies_applied": [
            {
                "key": m,
                "description": MITIGATION_STRATEGIES[m]["description"],
                "risk_reduction_percent": round(MITIGATION_STRATEGIES[m]["risk_reduction_factor"] * 100, 1),
            }
            for m in mitigations
        ],
    }

    graph_layout = serializeGraph(graph)

    return {
        "attack_origin": origin_vendor,
        "severity_before": initial_severity,
        "severity_after": severity_after,
        "graph_layout": graph_layout,
        "before_mitigation_frames": before_frames,
        "mitigation_frames": mitigation_frames,
        "mitigation_phase": mitigation_phase_summary,
        "show_after_mitigation_prompt": True,
        "after_mitigation_prompt_text": "Do you want to see the after mitigation graph?",
        "after_mitigation_frames": after_frames,
        "final_summary": {
            "attack_path": attack_path,
            "initial_blast_radius": initial_blast_radius,
            "severity_before": initial_severity,
            "mitigations": mitigations,
            "reduced_blast_radius": reduced_blast_radius,
            "severity_after": severity_after,
            "risk_reduction_percentage": risk_reduction_pct,
        },
        "animation_config": {
            "before_frame_delay_ms": FRAME_DELAY_MS,
            "mitigation_frame_delay_ms": MITIGATION_FRAME_DELAY_MS,
            "after_frame_delay_ms": AFTER_FRAME_DELAY_MS,
            "total_before_frames": len(before_frames),
            "total_mitigation_frames": len(mitigation_frames),
            "total_after_frames": len(after_frames),
        },
    }