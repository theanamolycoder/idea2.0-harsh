import networkx as nx
from typing import Dict, List

VENDOR_DEPENDENCY_MAP = {
    "CloudServe": ["AuthProvider", "StorageAPI", "LoggingService"],
    "AuthProvider": ["PaymentAPI", "IdentityService"],
    "PaymentAPI": ["FraudSystem", "TransactionDB"],
    "FraudSystem": ["AlertEngine", "ComplianceService"],
    "StorageAPI": ["BackupService", "CDNProvider"],
    "IdentityService": ["DirectoryService", "TokenService"],
    "TransactionDB": ["AuditService", "ReportingEngine"],
    "AlertEngine": ["NotificationService"],
    "ComplianceService": ["RegulatoryAPI"],
    "LoggingService": ["MonitoringDashboard"],
}

EDGE_WEIGHTS = {
    ("CloudServe", "AuthProvider"): 0.9,
    ("CloudServe", "StorageAPI"): 0.7,
    ("CloudServe", "LoggingService"): 0.5,
    ("AuthProvider", "PaymentAPI"): 0.85,
    ("AuthProvider", "IdentityService"): 0.8,
    ("PaymentAPI", "FraudSystem"): 0.75,
    ("PaymentAPI", "TransactionDB"): 0.7,
    ("FraudSystem", "AlertEngine"): 0.6,
    ("FraudSystem", "ComplianceService"): 0.65,
    ("StorageAPI", "BackupService"): 0.5,
    ("StorageAPI", "CDNProvider"): 0.55,
    ("IdentityService", "DirectoryService"): 0.7,
    ("IdentityService", "TokenService"): 0.75,
    ("TransactionDB", "AuditService"): 0.6,
    ("TransactionDB", "ReportingEngine"): 0.5,
    ("AlertEngine", "NotificationService"): 0.4,
    ("ComplianceService", "RegulatoryAPI"): 0.5,
    ("LoggingService", "MonitoringDashboard"): 0.45,
}


def buildDependencyGraph() -> nx.DiGraph:
    graph = nx.DiGraph()
    for source, targets in VENDOR_DEPENDENCY_MAP.items():
        for target in targets:
            weight = EDGE_WEIGHTS.get((source, target), 0.5)
            graph.add_edge(source, target, weight=weight)
    return graph


def getDownstreamDependencies(graph: nx.DiGraph, vendor: str) -> List[str]:
    if vendor not in graph:
        return []
    return list(nx.descendants(graph, vendor))


def getUpstreamDependencies(graph: nx.DiGraph, vendor: str) -> List[str]:
    if vendor not in graph:
        return []
    return list(nx.ancestors(graph, vendor))


def getEdgeWeight(graph: nx.DiGraph, source: str, target: str) -> float:
    if graph.has_edge(source, target):
        return graph[source][target].get("weight", 0.5)
    return 0.0


def getAllNodes(graph: nx.DiGraph) -> List[str]:
    return list(graph.nodes())


def getNodeCriticality(vendor: str) -> float:
    criticality_map = {
        "CloudServe": 1.0,
        "AuthProvider": 0.95,
        "PaymentAPI": 0.9,
        "FraudSystem": 0.8,
        "TransactionDB": 0.85,
        "IdentityService": 0.75,
        "StorageAPI": 0.7,
        "AlertEngine": 0.65,
        "ComplianceService": 0.6,
        "LoggingService": 0.5,
        "BackupService": 0.45,
        "CDNProvider": 0.4,
        "DirectoryService": 0.55,
        "TokenService": 0.6,
        "AuditService": 0.5,
        "ReportingEngine": 0.4,
        "NotificationService": 0.35,
        "RegulatoryAPI": 0.5,
        "MonitoringDashboard": 0.4,
    }
    return criticality_map.get(vendor, 0.5)


def serializeGraph(graph: nx.DiGraph) -> Dict:
    return {
        "nodes": [
            {"id": node, "criticality": getNodeCriticality(node)}
            for node in graph.nodes()
        ],
        "edges": [
            {"source": u, "target": v, "weight": graph[u][v].get("weight", 0.5)}
            for u, v in graph.edges()
        ],
    }