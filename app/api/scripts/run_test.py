import sys
sys.path.insert(0, ".")

from app.api.propagation.dependency_mapper import buildDependencyGraph
from app.api.propagation.propagation_engine import runPropagationSimulation
from app.api.mitigation.mitigation_engine import applyMitigationSimulation, selectMitigationsForSeverity

print("Building dependency graph...")
graph = buildDependencyGraph()
print(f"Graph has {len(graph.nodes())} vendors and {len(graph.edges())} connections")

print("\nRunning attack simulation from CloudServe at CRITICAL severity...")
result = runPropagationSimulation("CloudServe", "CRITICAL", graph)
print(f"Total infected vendors: {result['total_infected_nodes']}")

print("\nTop 5 infected vendors:")
for v in result["infected_nodes"][:5]:
    print(f"  {v['vendor']} — risk: {v['risk_score']} — severity: {v['severity']}")

print("\nApplying mitigations...")
scores = result["propagated_scores"]
mitigations = selectMitigationsForSeverity("CRITICAL")
mit = applyMitigationSimulation("CloudServe", "CRITICAL", scores, mitigations, graph)
print(f"Blast radius BEFORE: {mit['initial_blast_radius']}")
print(f"Blast radius AFTER:  {mit['reduced_blast_radius']}")
print(f"Risk reduction:      {mit['risk_reduction_percentage']}%")
print(f"Severity BEFORE: {mit['severity_before']}")
print(f"Severity AFTER:  {mit['severity_after']}")

print("\nAll done.")