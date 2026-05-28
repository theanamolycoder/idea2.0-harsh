import sys
sys.path.insert(0, ".")

from propagation.dependency_mapper import buildDependencyGraph
from monte_carlo.simulation_engine import runMonteCarloSimulation

graph = buildDependencyGraph()

print("Running Monte Carlo simulation (1000 iterations)...")
print("This simulates 1000 different attack scenarios probabilistically.\n")

result = runMonteCarloSimulation("CloudServe", "CRITICAL", graph, iterations=1000)

print(f"Attack Origin:          {result['attack_origin']}")
print(f"Severity:               {result['initial_severity']}")
print(f"Iterations Run:         {result['iterations']}")
print(f"Mean Blast Radius:      {result['mean_blast_radius']}")
print(f"Worst Case Blast:       {result['max_blast_radius']}")
print(f"Best Case Blast:        {result['min_blast_radius']}")
print(f"95th Percentile Blast:  {result['percentile_95_blast_radius']}")
print(f"\nHigh Confidence Infected (>95% chance):")
for v in result["high_confidence_infected"]:
    print(f"  - {v}")

print(f"\nTop 5 Most Likely Infected Vendors:")
for v in result["node_results"][:5]:
    print(f"  {v['vendor']}: {v['infection_probability']*100:.1f}% chance, avg risk {v['mean_risk_score']}")