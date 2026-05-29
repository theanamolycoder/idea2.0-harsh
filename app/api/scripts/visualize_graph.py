import sys
sys.path.insert(0, ".")

import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

from app.api.propagation.dependency_mapper import buildDependencyGraph, getNodeCriticality
from app.api.propagation.propagation_engine import runPropagationSimulation, mapScoreToSeverity
from app.api.mitigation.mitigation_engine import applyMitigationSimulation, selectMitigationsForSeverity

graph = buildDependencyGraph()
result = runPropagationSimulation("CloudServe", "CRITICAL", graph)
scores = result["propagated_scores"]
mitigations = selectMitigationsForSeverity("CRITICAL")
mit = applyMitigationSimulation("CloudServe", "CRITICAL", scores, mitigations, graph)
mitigated_vendors = mit["mitigated_vendors"]

def get_color(vendor, scores, mitigated):
    if vendor in mitigated:
        return "#00FF88"
    score = scores.get(vendor, 0.0)
    sev = mapScoreToSeverity(score)
    return {"CRITICAL": "#FF2222", "HIGH": "#FF8800", "MEDIUM": "#FFDD00", "LOW": "#4488FF"}.get(sev, "#888888")

fig, axes = plt.subplots(1, 2, figsize=(20, 10))
fig.patch.set_facecolor("#0a0a1a")

pos = nx.spring_layout(graph, seed=42, k=2.5)

for ax, title, use_mitigated in [
    (axes[0], "BEFORE MITIGATION —> Attack Propagation", False),
    (axes[1], "AFTER MITIGATION —> Blast Radius Reduced", True),
]:
    ax.set_facecolor("#ac8100")
    ax.set_title(title, color="white", fontsize=13, fontweight="bold", pad=15)

    colors = [get_color(n, scores, mitigated_vendors if use_mitigated else []) for n in graph.nodes()]
    sizes  = [1800 * getNodeCriticality(n) + 400 for n in graph.nodes()]

    nx.draw_networkx_edges(graph, pos, ax=ax, edge_color="#334455",
                           arrows=True, arrowsize=15, width=1.5,
                           connectionstyle="arc3,rad=0.1")
    nx.draw_networkx_nodes(graph, pos, ax=ax, node_color=colors,
                           node_size=sizes, alpha=0.92)
    nx.draw_networkx_labels(graph, pos, ax=ax, font_color="black",
                            font_size=7, font_weight="bold")

    legend = [
        mpatches.Patch(color="#FF2222", label="CRITICAL"),
        mpatches.Patch(color="#FF8800", label="HIGH"),
        mpatches.Patch(color="#FFDD00", label="MEDIUM"),
        mpatches.Patch(color="#4488FF", label="LOW / Clean"),
        mpatches.Patch(color="#00FF88", label="MITIGATED"),
    ]
    ax.legend(handles=legend, loc="upper left", facecolor="#111122",
              labelcolor="white", fontsize=8)

plt.suptitle("GARUDA Cyber Propagation Simulation", color="white",
             fontsize=16, fontweight="bold", y=1.01)
plt.tight_layout()
plt.savefig("output/garuda_simulation.png", dpi=150, bbox_inches="tight",
            facecolor="#433300")
print("Graph saved to output/garuda_simulation.png")
plt.show()