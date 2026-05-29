import asyncio
import json
import uuid
from typing import Dict
from kafka import KafkaConsumer
from kafka.errors import KafkaError
from app.api.propagation.dependency_mapper import buildDependencyGraph
from app.api.propagation.propagation_engine import runPropagationSimulation
from app.api.propagation.attack_path_engine import generateAttackPathReport
from app.api.propagation.blast_radius_engine import buildBlastRadiusReport
from app.api.monte_carlo.simulation_engine import runMonteCarloSimulation
from app.api.mitigation.mitigation_engine import (
    applyMitigationSimulation,
    selectMitigationsForSeverity,
)
from app.api.mitigation.recommendation_handler import generateFullRecommendationReport
from app.api.mitigation.resilience_engine import buildResilienceReport
from app.api.graph.neo4j_manager import getNeo4jManager
from app.api.graph.graph_builder import (
    syncPropagationResultToNeo4j,
    syncMitigationResultToNeo4j,
    buildGraphDataForDashboard,
)
from app.api.graph.graph_queries import querySimulationHistory

KAFKA_BOOTSTRAP_SERVERS = "localhost:9092"
KAFKA_TOPIC_INTELLIGENCE = "normalized-intelligence-events"
KAFKA_TOPIC_CRITICAL = "critical-threat-events"
KAFKA_TOPIC_SIMULATION_OUTPUT = "simulation-output-events"
KAFKA_CONSUMER_GROUP = "propagation-engine-group"
KAFKA_AUTO_OFFSET_RESET = "latest"
KAFKA_POLL_TIMEOUT_MS = 1000
KAFKA_MAX_POLL_RECORDS = 10


def buildKafkaConsumer(topics: list) -> KafkaConsumer:
    return KafkaConsumer(
        *topics,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        group_id=KAFKA_CONSUMER_GROUP,
        auto_offset_reset=KAFKA_AUTO_OFFSET_RESET,
        enable_auto_commit=True,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        key_deserializer=lambda k: k.decode("utf-8") if k else None,
        max_poll_records=KAFKA_MAX_POLL_RECORDS,
    )


def validateIntelligenceEvent(event: Dict) -> bool:
    required_fields = [
        "event_id",
        "vendor",
        "event_type",
        "severity",
        "risk_score",
        "confidence_score",
        "propagation_probability",
        "affected_systems",
        "recommended_mitigations",
        "executive_summary",
    ]
    return all(field in event for field in required_fields)


def extractEventFields(event: Dict) -> Dict:
    return {
        "event_id": event.get("event_id", ""),
        "vendor": event.get("vendor", ""),
        "event_type": event.get("event_type", ""),
        "severity": event.get("severity", "LOW"),
        "risk_score": float(event.get("risk_score", 0.0)),
        "confidence_score": float(event.get("confidence_score", 0.0)),
        "propagation_probability": float(event.get("propagation_probability", 0.0)),
        "affected_systems": event.get("affected_systems", []),
        "recommended_mitigations": event.get("recommended_mitigations", []),
        "executive_summary": event.get("executive_summary", ""),
    }


def runFullPropagationPipeline(event: Dict) -> Dict:
    graph = buildDependencyGraph()
    fields = extractEventFields(event)
    origin_vendor = fields["vendor"]
    initial_severity = fields["severity"]
    simulation_id = str(uuid.uuid4())

    propagation_result = runPropagationSimulation(origin_vendor, initial_severity, graph)
    propagated_scores = propagation_result.get("propagated_scores", {})

    attack_path_report = generateAttackPathReport(origin_vendor, propagated_scores, graph)
    attack_path = attack_path_report.get("attack_path", [origin_vendor])

    blast_radius_report = buildBlastRadiusReport(
        origin_vendor, initial_severity, propagated_scores, graph
    )
    initial_blast_radius = blast_radius_report.get("blast_radius", 0)

    monte_carlo_result = runMonteCarloSimulation(
        origin_vendor, initial_severity, graph, iterations=500
    )

    recommended_mitigations = selectMitigationsForSeverity(initial_severity)
    mitigation_result = applyMitigationSimulation(
        origin_vendor=origin_vendor,
        initial_severity=initial_severity,
        propagated_scores=propagated_scores,
        mitigations=recommended_mitigations,
        graph=graph,
    )

    reduced_blast_radius = mitigation_result.get("reduced_blast_radius", 0)
    severity_after = mitigation_result.get("severity_after", initial_severity)
    risk_reduction_pct = mitigation_result.get("risk_reduction_percentage", 0.0)
    mitigated_vendors = mitigation_result.get("mitigated_vendors", [])

    recommendation_report = generateFullRecommendationReport(
        origin_vendor, initial_severity, propagated_scores, graph
    )

    resilience_report = buildResilienceReport(
        origin_vendor, initial_severity, propagated_scores, graph
    )

    syncPropagationResultToNeo4j(origin_vendor, propagated_scores)
    syncMitigationResultToNeo4j(mitigated_vendors)

    graph_data = buildGraphDataForDashboard(
        propagated_scores, attack_path, mitigated_vendors, graph
    )

    simulation_output = {
        "attack_origin": origin_vendor,
        "attack_path": attack_path,
        "initial_blast_radius": initial_blast_radius,
        "severity_before": initial_severity,
        "mitigations": recommended_mitigations,
        "reduced_blast_radius": reduced_blast_radius,
        "severity_after": severity_after,
        "risk_reduction_percentage": risk_reduction_pct,
    }

    manager = getNeo4jManager()
    manager.createSimulationResult(simulation_id, simulation_output)

    return {
        "simulation_id": simulation_id,
        "event_id": fields["event_id"],
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


def buildSimulationOutputEvent(
    pipeline_result: Dict,
    original_event: Dict,
) -> Dict:
    simulation_output = pipeline_result.get("simulation_output", {})
    return {
        "event_id": original_event.get("event_id", ""),
        "simulation_id": pipeline_result.get("simulation_id", ""),
        "vendor": original_event.get("vendor", ""),
        "attack_origin": simulation_output.get("attack_origin", ""),
        "attack_path": simulation_output.get("attack_path", []),
        "initial_blast_radius": simulation_output.get("initial_blast_radius", 0),
        "severity_before": simulation_output.get("severity_before", ""),
        "mitigations": simulation_output.get("mitigations", []),
        "reduced_blast_radius": simulation_output.get("reduced_blast_radius", 0),
        "severity_after": simulation_output.get("severity_after", ""),
        "risk_reduction_percentage": simulation_output.get("risk_reduction_percentage", 0.0),
        "graph_data": pipeline_result.get("graph_data", {}),
        "executive_action_summary": pipeline_result.get(
            "recommendation_report", {}
        ).get("executive_action_summary", {}),
        "resilience_rating": pipeline_result.get(
            "resilience_report", {}
        ).get("resilience_rating", ""),
    }


def publishSimulationOutput(output_event: Dict) -> None:
    from kafka import KafkaProducer
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        key_serializer=lambda k: k.encode("utf-8"),
    )
    producer.send(
        KAFKA_TOPIC_SIMULATION_OUTPUT,
        key=output_event.get("vendor", "unknown"),
        value=output_event,
    )
    producer.flush()
    producer.close()


def processSingleEvent(event: Dict) -> None:
    if not validateIntelligenceEvent(event):
        return

    pipeline_result = runFullPropagationPipeline(event)
    output_event = buildSimulationOutputEvent(pipeline_result, event)
    publishSimulationOutput(output_event)


def startPropagationConsumer() -> None:
    consumer = buildKafkaConsumer([KAFKA_TOPIC_INTELLIGENCE, KAFKA_TOPIC_CRITICAL])
    try:
        for message in consumer:
            try:
                event = message.value
                if event:
                    processSingleEvent(event)
            except Exception:
                continue
    except KafkaError:
        pass
    finally:
        consumer.close()


async def startPropagationConsumerAsync():
    loop = asyncio.get_running_loop()

    try:
        await loop.run_in_executor(None, startPropagationConsumer)
    except Exception as e:
        print(f"[WARNING] Kafka consumer unavailable: {e}")
        print("[INFO] Running GARUDA without live Kafka threat ingestion.")