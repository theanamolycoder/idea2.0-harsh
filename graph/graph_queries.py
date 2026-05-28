from typing import Dict, List, Optional
from graph.neo4j_manager import getNeo4jManager


def queryAllVendors() -> List[Dict]:
    manager = getNeo4jManager()
    query = """
    MATCH (v:Vendor)
    RETURN v.name AS name,
           v.criticality AS criticality,
           v.risk_score AS risk_score,
           v.severity AS severity,
           v.infected AS infected,
           v.mitigated AS mitigated
    ORDER BY v.criticality DESC
    """
    return manager.runQuery(query)


def queryVendorByName(vendor: str) -> Optional[Dict]:
    manager = getNeo4jManager()
    query = """
    MATCH (v:Vendor {name: $name})
    RETURN v.name AS name,
           v.criticality AS criticality,
           v.risk_score AS risk_score,
           v.severity AS severity,
           v.infected AS infected,
           v.mitigated AS mitigated,
           v.attack_origin AS attack_origin,
           v.infected_at AS infected_at,
           v.mitigated_at AS mitigated_at
    """
    results = manager.runQuery(query, {"name": vendor})
    return results[0] if results else None


def queryInfectedVendors() -> List[Dict]:
    manager = getNeo4jManager()
    query = """
    MATCH (v:Vendor {infected: true})
    RETURN v.name AS name,
           v.risk_score AS risk_score,
           v.severity AS severity,
           v.criticality AS criticality,
           v.attack_origin AS attack_origin,
           v.infected_at AS infected_at
    ORDER BY v.risk_score DESC
    """
    return manager.runQuery(query)


def queryMitigatedVendors() -> List[Dict]:
    manager = getNeo4jManager()
    query = """
    MATCH (v:Vendor {mitigated: true})
    RETURN v.name AS name,
           v.criticality AS criticality,
           v.mitigated_at AS mitigated_at
    ORDER BY v.mitigated_at DESC
    """
    return manager.runQuery(query)


def queryHighRiskVendors(risk_threshold: float = 0.65) -> List[Dict]:
    manager = getNeo4jManager()
    query = """
    MATCH (v:Vendor)
    WHERE v.risk_score >= $threshold
    RETURN v.name AS name,
           v.risk_score AS risk_score,
           v.severity AS severity,
           v.criticality AS criticality,
           v.infected AS infected
    ORDER BY v.risk_score DESC
    """
    return manager.runQuery(query, {"threshold": risk_threshold})


def queryVendorDependencies(vendor: str) -> Dict:
    manager = getNeo4jManager()

    downstream_query = """
    MATCH (v:Vendor {name: $name})-[:DEPENDS_ON*1..]->(downstream:Vendor)
    RETURN DISTINCT downstream.name AS name,
                    downstream.risk_score AS risk_score,
                    downstream.severity AS severity,
                    downstream.criticality AS criticality,
                    downstream.infected AS infected
    ORDER BY downstream.criticality DESC
    """

    upstream_query = """
    MATCH (upstream:Vendor)-[:DEPENDS_ON*1..]->(v:Vendor {name: $name})
    RETURN DISTINCT upstream.name AS name,
                    upstream.risk_score AS risk_score,
                    upstream.severity AS severity,
                    upstream.criticality AS criticality,
                    upstream.infected AS infected
    ORDER BY upstream.criticality DESC
    """

    direct_query = """
    MATCH (v:Vendor {name: $name})-[r:DEPENDS_ON]->(direct:Vendor)
    RETURN direct.name AS name,
           r.weight AS weight,
           direct.criticality AS criticality,
           direct.risk_score AS risk_score
    ORDER BY r.weight DESC
    """

    downstream = manager.runQuery(downstream_query, {"name": vendor})
    upstream = manager.runQuery(upstream_query, {"name": vendor})
    direct = manager.runQuery(direct_query, {"name": vendor})

    return {
        "vendor": vendor,
        "downstream_vendors": downstream,
        "upstream_vendors": upstream,
        "direct_dependencies": direct,
        "downstream_count": len(downstream),
        "upstream_count": len(upstream),
        "direct_count": len(direct),
    }


def queryAttackPropagationPath(
    origin: str,
    target: str,
) -> List[Dict]:
    manager = getNeo4jManager()
    query = """
    MATCH path = shortestPath(
        (origin:Vendor {name: $origin})-[:DEPENDS_ON*]->(target:Vendor {name: $target})
    )
    RETURN [node IN nodes(path) | node.name] AS path_nodes,
           [rel IN relationships(path) | rel.weight] AS edge_weights,
           length(path) AS path_length
    """
    return manager.runQuery(query, {"origin": origin, "target": target})


def queryAllPropagationPaths(
    origin: str,
    target: str,
    max_depth: int = 5,
) -> List[Dict]:
    manager = getNeo4jManager()
    query = """
    MATCH path = (origin:Vendor {name: $origin})-[:DEPENDS_ON*1..$depth]->(target:Vendor {name: $target})
    RETURN [node IN nodes(path) | node.name] AS path_nodes,
           [rel IN relationships(path) | rel.weight] AS edge_weights,
           length(path) AS path_length
    ORDER BY path_length ASC
    LIMIT 10
    """
    return manager.runQuery(query, {"origin": origin, "target": target, "depth": max_depth})


def queryGraphStatistics() -> Dict:
    manager = getNeo4jManager()

    stats_query = """
    MATCH (v:Vendor)
    RETURN count(v) AS total_vendors,
           sum(CASE WHEN v.infected = true THEN 1 ELSE 0 END) AS infected_count,
           sum(CASE WHEN v.mitigated = true THEN 1 ELSE 0 END) AS mitigated_count,
           avg(v.risk_score) AS avg_risk_score,
           max(v.risk_score) AS max_risk_score,
           avg(v.criticality) AS avg_criticality
    """

    edge_query = """
    MATCH ()-[r:DEPENDS_ON]->()
    RETURN count(r) AS total_edges,
           avg(r.weight) AS avg_edge_weight,
           max(r.weight) AS max_edge_weight
    """

    severity_query = """
    MATCH (v:Vendor)
    WHERE v.severity IS NOT NULL
    RETURN v.severity AS severity, count(v) AS count
    ORDER BY count DESC
    """

    stats = manager.runQuery(stats_query)
    edge_stats = manager.runQuery(edge_query)
    severity_dist = manager.runQuery(severity_query)

    return {
        "vendor_stats": stats[0] if stats else {},
        "edge_stats": edge_stats[0] if edge_stats else {},
        "severity_distribution": severity_dist,
    }


def querySimulationHistory(limit: int = 10) -> List[Dict]:
    manager = getNeo4jManager()
    query = """
    MATCH (s:SimulationResult)
    RETURN s.simulation_id AS simulation_id,
           s.attack_origin AS attack_origin,
           s.initial_blast_radius AS initial_blast_radius,
           s.severity_before AS severity_before,
           s.reduced_blast_radius AS reduced_blast_radius,
           s.severity_after AS severity_after,
           s.risk_reduction_percentage AS risk_reduction_percentage,
           s.created_at AS created_at
    ORDER BY s.created_at DESC
    LIMIT $limit
    """
    return manager.runQuery(query, {"limit": limit})


def querySimulationById(simulation_id: str) -> Optional[Dict]:
    manager = getNeo4jManager()
    query = """
    MATCH (s:SimulationResult {simulation_id: $simulation_id})
    RETURN s.simulation_id AS simulation_id,
           s.attack_origin AS attack_origin,
           s.attack_path AS attack_path,
           s.initial_blast_radius AS initial_blast_radius,
           s.severity_before AS severity_before,
           s.mitigations AS mitigations,
           s.reduced_blast_radius AS reduced_blast_radius,
           s.severity_after AS severity_after,
           s.risk_reduction_percentage AS risk_reduction_percentage,
           s.created_at AS created_at
    """
    results = manager.runQuery(query, {"simulation_id": simulation_id})
    return results[0] if results else None


def queryCriticalPathVendors() -> List[Dict]:
    manager = getNeo4jManager()
    query = """
    MATCH (v:Vendor)
    WHERE v.criticality >= 0.8
    RETURN v.name AS name,
           v.criticality AS criticality,
           v.risk_score AS risk_score,
           v.severity AS severity,
           v.infected AS infected
    ORDER BY v.criticality DESC
    """
    return manager.runQuery(query)


def queryVendorRiskTrend(vendor: str) -> List[Dict]:
    manager = getNeo4jManager()
    query = """
    MATCH (s:SimulationResult)
    WHERE $vendor IN s.attack_path
    RETURN s.attack_origin AS attack_origin,
           s.severity_before AS severity_before,
           s.risk_reduction_percentage AS risk_reduction_percentage,
           s.created_at AS created_at
    ORDER BY s.created_at DESC
    LIMIT 20
    """
    return manager.runQuery(query, {"vendor": vendor})