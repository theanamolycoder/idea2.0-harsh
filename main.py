
import asyncio
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, List, Optional

from propagation.dependency_mapper import (
    buildDependencyGraph,
    serializeGraph,
)
from propagation.propagation_engine import runPropagationSimulation
from propagation.attack_path_engine import generateAttackPathReport
from propagation.blast_radius_engine import buildBlastRadiusReport
from monte_carlo.simulation_engine import runMonteCarloSimulation
from monte_carlo.scenario_generator import (
    generateScenario,
    generateAllScenarios,
    generateCustomScenario,
    listAvailableScenarios,
)
from mitigation.mitigation_engine import (
    applyMitigationSimulation,
    selectMitigationsForSeverity,
    rankMitigationsByImpact,
)
from mitigation.recommendation_handler import generateFullRecommendationReport
from mitigation.resilience_engine import buildResilienceReport
from graph.neo4j_manager import getNeo4jManager
from graph.graph_builder import (
    buildNeo4jGraph,
    buildGraphDataForDashboard,
    buildGraphSnapshot,
    syncPropagationResultToNeo4j,
    syncMitigationResultToNeo4j,
    exportGraphToSerializable,
)
from graph.graph_queries import (
    queryAllVendors,
    queryInfectedVendors,
    queryGraphStatistics,
    querySimulationHistory,
    querySimulationById,
    queryCriticalPathVendors,
)
from kafka_consumers.propagation_consumer import startPropagationConsumerAsync
from api.animated_simulation_routes import router as animated_router



class SimulateAttackRequest(BaseModel):
    attack_origin: str = Field(..., description="Origin vendor name")
    severity: str = Field(..., description="Severity level: LOW, MEDIUM, HIGH, CRITICAL")
    mitigations: Optional[List[str]] = Field(default=None)
    run_monte_carlo: Optional[bool] = Field(default=True)
    monte_carlo_iterations: Optional[int] = Field(default=500)


class CustomScenarioRequest(BaseModel):
    origin_vendor: str
    severity: str
    attack_type: str
    description: str
    iterations: Optional[int] = Field(default=500)


@asynccontextmanager
async def lifespan(app: FastAPI):
    graph = buildDependencyGraph()
    app.state.graph = graph
    try:
        manager = getNeo4jManager()
        manager.connect()
        buildNeo4jGraph()
    except Exception:
        pass
    asyncio.create_task(startPropagationConsumerAsync())
    yield
    try:
        manager = getNeo4jManager()
        manager.disconnect()
    except Exception:
        pass


app = FastAPI(
    title="GARUDA Propagation Engine",
    description="Cyber Risk Propagation and Attack Simulation Engine",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def healthCheck() -> Dict:
    return {
        "status": "healthy",
        "service": "garuda-propagation-engine",
        "version": "1.0.0",
    }


@app.post("/simulate-attack")
async def simulateAttack(request: SimulateAttackRequest) -> Dict:
    graph = app.state.graph

    propagation_result = runPropagationSimulation(
        request.attack_origin, request.severity, graph
    )
    propagated_scores = propagation_result.get("propagated_scores", {})

    attack_path_report = generateAttackPathReport(
        request.attack_origin, propagated_scores, graph
    )
    attack_path = attack_path_report.get("attack_path", [request.attack_origin])

    blast_radius_report = buildBlastRadiusReport(
        request.attack_origin, request.severity, propagated_scores, graph
    )
    initial_blast_radius = blast_radius_report.get("blast_radius", 0)

    monte_carlo_result = None
    if request.run_monte_carlo:
        monte_carlo_result = runMonteCarloSimulation(
            request.attack_origin,
            request.severity,
            graph,
            iterations=request.monte_carlo_iterations,
        )

    mitigations = request.mitigations or selectMitigationsForSeverity(request.severity)
    mitigation_result = applyMitigationSimulation(
        origin_vendor=request.attack_origin,
        initial_severity=request.severity,
        propagated_scores=propagated_scores,
        mitigations=mitigations,
        graph=graph,
    )

    reduced_blast_radius = mitigation_result.get("reduced_blast_radius", 0)
    severity_after = mitigation_result.get("severity_after", request.severity)
    risk_reduction_pct = mitigation_result.get("risk_reduction_percentage", 0.0)
    mitigated_vendors = mitigation_result.get("mitigated_vendors", [])

    recommendation_report = generateFullRecommendationReport(
        request.attack_origin, request.severity, propagated_scores, graph
    )

    resilience_report = buildResilienceReport(
        request.attack_origin, request.severity, propagated_scores, graph
    )

    simulation_id = str(uuid.uuid4())
    simulation_output = {
        "attack_origin": request.attack_origin,
        "attack_path": attack_path,
        "initial_blast_radius": initial_blast_radius,
        "severity_before": request.severity,
        "mitigations": mitigations,
        "reduced_blast_radius": reduced_blast_radius,
        "severity_after": severity_after,
        "risk_reduction_percentage": risk_reduction_pct,
    }

    try:
        manager = getNeo4jManager()
        manager.createSimulationResult(simulation_id, simulation_output)
        syncPropagationResultToNeo4j(request.attack_origin, propagated_scores)
        syncMitigationResultToNeo4j(mitigated_vendors)
    except Exception:
        pass

    graph_data = buildGraphDataForDashboard(
        propagated_scores, attack_path, mitigated_vendors, graph
    )

    return {
        "simulation_id": simulation_id,
        "simulation_output": simulation_output,
        "propagation_result": propagation_result,
        "attack_path_report": attack_path_report,
        "blast_radius_report": blast_radius_report,
        "monte_carlo_result": monte_carlo_result,
        "mitigation_result": mitigation_result,
        "recommendation_report": recommendation_report,
        "resilience_report": resilience_report,
        "graph_data": graph_data,
    }


@app.get("/simulation-results")
async def getSimulationResults(limit: int = 10) -> Dict:
    try:
        results = querySimulationHistory(limit)
    except Exception:
        results = []
    return {
        "simulation_results": results,
        "total": len(results),
    }


@app.get("/simulation-results/{simulation_id}")
async def getSimulationById(simulation_id: str) -> Dict:
    try:
        result = querySimulationById(simulation_id)
    except Exception:
        result = None
    if not result:
        raise HTTPException(status_code=404, detail="Simulation result not found")
    return result


@app.get("/graph-data")
async def getGraphData() -> Dict:
    graph = app.state.graph
    serialized = exportGraphToSerializable(graph)
    try:
        stats = queryGraphStatistics()
    except Exception:
        stats = {}
    return {
        "graph": serialized,
        "statistics": stats,
    }


@app.get("/latest-threats")
async def getLatestThreats() -> Dict:
    try:
        infected = queryInfectedVendors()
        critical = queryCriticalPathVendors()
    except Exception:
        infected = []
        critical = []
    return {
        "infected_vendors": infected,
        "critical_path_vendors": critical,
        "total_infected": len(infected),
    }


@app.get("/vendors")
async def getAllVendors() -> Dict:
    try:
        vendors = queryAllVendors()
    except Exception:
        graph = app.state.graph
        from propagation.dependency_mapper import getAllNodes
        vendors = [{"name": n} for n in getAllNodes(graph)]
    return {
        "vendors": vendors,
        "total": len(vendors),
    }


@app.get("/scenarios")
async def getAvailableScenarios() -> Dict:
    scenarios = listAvailableScenarios()
    return {
        "scenarios": scenarios,
        "total": len(scenarios),
    }


@app.get("/scenarios/{scenario_key}")
async def runScenario(scenario_key: str, iterations: int = 500) -> Dict:
    graph = app.state.graph
    result = generateScenario(scenario_key, graph, iterations)
    if not result.get("attack_origin"):
        raise HTTPException(status_code=404, detail="Scenario not found")
    return result


@app.post("/scenarios/custom")
async def runCustomScenario(request: CustomScenarioRequest) -> Dict:
    graph = app.state.graph
    result = generateCustomScenario(
        origin_vendor=request.origin_vendor,
        severity=request.severity,
        attack_type=request.attack_type,
        description=request.description,
        graph=graph,
        iterations=request.iterations,
    )
    return result


@app.get("/scenarios/all/run")
async def runAllScenarios(iterations: int = 200) -> Dict:
    graph = app.state.graph
    results = generateAllScenarios(graph, iterations)
    return {
        "scenarios": results,
        "total": len(results),
        "worst_case": results[0] if results else None,
        "best_case": results[-1] if results else None,
    }


@app.get("/mitigations/rank")
async def getRankedMitigations(
    vendor: str,
    severity: str,
) -> Dict:
    graph = app.state.graph
    propagation_result = runPropagationSimulation(vendor, severity, graph)
    propagated_scores = propagation_result.get("propagated_scores", {})
    ranked = rankMitigationsByImpact(vendor, severity, propagated_scores, graph)
    return {
        "vendor": vendor,
        "severity": severity,
        "ranked_mitigations": ranked,
    }

app = FastAPI(
    title="GARUDA Propagation Engine",
    description="Cyber Risk Propagation and Attack Simulation Engine",
    version="1.0.0",
    lifespan=lifespan,
)
app.include_router(animated_router)
@app.get("/resilience")
async def getResilienceReport(
    vendor: str,
    severity: str = "HIGH",
) -> Dict:
    graph = app.state.graph
    propagation_result = runPropagationSimulation(vendor, severity, graph)
    propagated_scores = propagation_result.get("propagated_scores", {})
    report = buildResilienceReport(vendor, severity, propagated_scores, graph)
    return report
### SOUMENS MAIN
def main():
    print("Hello from idea!")


if __name__ == "__main__":
    main()

