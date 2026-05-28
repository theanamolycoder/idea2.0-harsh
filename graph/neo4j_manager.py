import os
from typing import Dict, List, Optional
from neo4j import GraphDatabase, Driver, Session
from dotenv import load_dotenv

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "garuda")


class Neo4jManager:
    _instance: Optional["Neo4jManager"] = None
    _driver: Optional[Driver] = None

    def __new__(cls) -> "Neo4jManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def connect(self) -> None:
        if self._driver is None:
            self._driver = GraphDatabase.driver(
                NEO4J_URI,
                auth=(NEO4J_USERNAME, NEO4J_PASSWORD),
            )

    def disconnect(self) -> None:
        if self._driver is not None:
            self._driver.close()
            self._driver = None

    def getSession(self) -> Session:
        if self._driver is None:
            self.connect()
        return self._driver.session(database=NEO4J_DATABASE)

    def verifyConnectivity(self) -> bool:
        try:
            self._driver.verify_connectivity()
            return True
        except Exception:
            return False

    def runQuery(self, query: str, parameters: Dict = None) -> List[Dict]:
        with self.getSession() as session:
            result = session.run(query, parameters or {})
            return [record.data() for record in result]

    def runWriteQuery(self, query: str, parameters: Dict = None) -> None:
        with self.getSession() as session:
            session.execute_write(lambda tx: tx.run(query, parameters or {}))

    def clearDatabase(self) -> None:
        query = "MATCH (n) DETACH DELETE n"
        self.runWriteQuery(query)

    def createVendorNode(self, vendor: str, criticality: float, properties: Dict = None) -> None:
        props = properties or {}
        query = """
        MERGE (v:Vendor {name: $name})
        SET v.criticality = $criticality,
            v.created_at = timestamp()
        """
        for key, value in props.items():
            query += f", v.{key} = ${key}"
        params = {"name": vendor, "criticality": criticality, **props}
        self.runWriteQuery(query, params)

    def createDependencyRelationship(
        self,
        source: str,
        target: str,
        weight: float,
    ) -> None:
        query = """
        MATCH (s:Vendor {name: $source})
        MATCH (t:Vendor {name: $target})
        MERGE (s)-[r:DEPENDS_ON]->(t)
        SET r.weight = $weight,
            r.updated_at = timestamp()
        """
        self.runWriteQuery(query, {"source": source, "target": target, "weight": weight})

    def updateVendorRiskScore(self, vendor: str, risk_score: float, severity: str) -> None:
        query = """
        MATCH (v:Vendor {name: $name})
        SET v.risk_score = $risk_score,
            v.severity = $severity,
            v.updated_at = timestamp()
        """
        self.runWriteQuery(query, {"name": vendor, "risk_score": risk_score, "severity": severity})

    def markVendorInfected(self, vendor: str, attack_origin: str) -> None:
        query = """
        MATCH (v:Vendor {name: $name})
        SET v.infected = true,
            v.attack_origin = $attack_origin,
            v.infected_at = timestamp()
        """
        self.runWriteQuery(query, {"name": vendor, "attack_origin": attack_origin})

    def markVendorMitigated(self, vendor: str) -> None:
        query = """
        MATCH (v:Vendor {name: $name})
        SET v.mitigated = true,
            v.infected = false,
            v.mitigated_at = timestamp()
        """
        self.runWriteQuery(query, {"name": vendor})

    def getVendorNode(self, vendor: str) -> Optional[Dict]:
        query = "MATCH (v:Vendor {name: $name}) RETURN v"
        results = self.runQuery(query, {"name": vendor})
        if results:
            return results[0].get("v")
        return None

    def getAllVendorNodes(self) -> List[Dict]:
        query = "MATCH (v:Vendor) RETURN v ORDER BY v.criticality DESC"
        results = self.runQuery(query)
        return [r.get("v") for r in results]

    def getAllRelationships(self) -> List[Dict]:
        query = """
        MATCH (s:Vendor)-[r:DEPENDS_ON]->(t:Vendor)
        RETURN s.name AS source, t.name AS target, r.weight AS weight
        """
        return self.runQuery(query)

    def getInfectedVendors(self) -> List[Dict]:
        query = """
        MATCH (v:Vendor {infected: true})
        RETURN v ORDER BY v.risk_score DESC
        """
        results = self.runQuery(query)
        return [r.get("v") for r in results]

    def getMitigatedVendors(self) -> List[Dict]:
        query = """
        MATCH (v:Vendor {mitigated: true})
        RETURN v ORDER BY v.mitigated_at DESC
        """
        results = self.runQuery(query)
        return [r.get("v") for r in results]

    def getDownstreamVendors(self, vendor: str) -> List[str]:
        query = """
        MATCH (v:Vendor {name: $name})-[:DEPENDS_ON*1..]->(downstream:Vendor)
        RETURN DISTINCT downstream.name AS name
        """
        results = self.runQuery(query, {"name": vendor})
        return [r["name"] for r in results]

    def getUpstreamVendors(self, vendor: str) -> List[str]:
        query = """
        MATCH (upstream:Vendor)-[:DEPENDS_ON*1..]->(v:Vendor {name: $name})
        RETURN DISTINCT upstream.name AS name
        """
        results = self.runQuery(query, {"name": vendor})
        return [r["name"] for r in results]

    def createSimulationResult(self, simulation_id: str, result: Dict) -> None:
        query = """
        MERGE (s:SimulationResult {simulation_id: $simulation_id})
        SET s.attack_origin = $attack_origin,
            s.attack_path = $attack_path,
            s.initial_blast_radius = $initial_blast_radius,
            s.severity_before = $severity_before,
            s.mitigations = $mitigations,
            s.reduced_blast_radius = $reduced_blast_radius,
            s.severity_after = $severity_after,
            s.risk_reduction_percentage = $risk_reduction_percentage,
            s.created_at = timestamp()
        """
        self.runWriteQuery(query, {
            "simulation_id": simulation_id,
            "attack_origin": result.get("attack_origin", ""),
            "attack_path": result.get("attack_path", []),
            "initial_blast_radius": result.get("initial_blast_radius", 0),
            "severity_before": result.get("severity_before", ""),
            "mitigations": result.get("mitigations", []),
            "reduced_blast_radius": result.get("reduced_blast_radius", 0),
            "severity_after": result.get("severity_after", ""),
            "risk_reduction_percentage": result.get("risk_reduction_percentage", 0.0),
        })

    def getSimulationResult(self, simulation_id: str) -> Optional[Dict]:
        query = "MATCH (s:SimulationResult {simulation_id: $simulation_id}) RETURN s"
        results = self.runQuery(query, {"simulation_id": simulation_id})
        if results:
            return results[0].get("s")
        return None

    def getLatestSimulationResults(self, limit: int = 10) -> List[Dict]:
        query = """
        MATCH (s:SimulationResult)
        RETURN s ORDER BY s.created_at DESC LIMIT $limit
        """
        results = self.runQuery(query, {"limit": limit})
        return [r.get("s") for r in results]


def getNeo4jManager() -> Neo4jManager:
    manager = Neo4jManager()
    manager.connect()
    return manager