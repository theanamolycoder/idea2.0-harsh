import sys
sys.path.insert(0, ".")

from app.api.propagation.dependency_mapper import buildDependencyGraph
from app.api.propagation.propagation_engine import runPropagationSimulation
from app.api.propagation.attack_path_engine import generateAttackPathReport, getLateralMovementVectors

graph = buildDependencyGraph()
result = runPropagationSimulation("CloudServe", "CRITICAL", graph)
scores = result["propagated_scores"]

print("=== ATTACK PATH REPORT ===\n")
report = generateAttackPathReport("CloudServe", scores, graph)

print(f"Origin: {report['origin']}")
print(f"Attack Path: {' --> '.join(report['attack_path'])}")
print(f"Path Length: {report['path_length']} hops")
print(f"Path Risk Score: {report['path_risk_score']}")
print(f"Severity: {report['severity']}")
print(f"\nCritical Targets on Path:")
for t in report["critical_targets"]:
    print(f"  !! {t}")

print(f"\nStep-by-step path breakdown:")
for node in report["path_nodes"]:
    arrow = f" --[{node['edge_weight_to_next']}]--> " if node['edge_weight_to_next'] else ""
    print(f"  Step {node['step']}: {node['vendor']} (risk={node['risk_score']}, severity={node['severity']}){arrow}")

print(f"\n=== LATERAL MOVEMENT VECTORS ===\n")
vectors = getLateralMovementVectors(graph, "CloudServe", scores)
print(f"Found {len(vectors)} lateral movement vectors above 0.5 risk")
for v in vectors[:5]:
    print(f"  {v['from']} --> {v['to']} | lateral risk: {v['lateral_risk']}")