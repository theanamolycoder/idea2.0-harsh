from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional
from propagation.dependency_mapper import buildDependencyGraph
from propagation.animation_frame_builder import buildAnimatedSimulationPayload

router = APIRouter()

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

VALID_VENDORS = {
    "CloudServe", "AuthProvider", "PaymentAPI", "FraudSystem",
    "StorageAPI", "IdentityService", "TransactionDB", "AlertEngine",
    "ComplianceService", "LoggingService", "BackupService", "CDNProvider",
    "DirectoryService", "TokenService", "AuditService", "ReportingEngine",
    "NotificationService", "RegulatoryAPI", "MonitoringDashboard",
}


class AnimatedSimulationRequest(BaseModel):
    attack_origin: str = Field(..., description="The vendor where the attack originates")
    severity: str = Field(..., description="Severity level: LOW, MEDIUM, HIGH, CRITICAL")
    include_after_mitigation: Optional[bool] = Field(
        default=True,
        description="Whether to include after-mitigation frames in the response",
    )


@router.post("/simulate-animated")
async def simulateAnimated(request: AnimatedSimulationRequest):
    if request.severity.upper() not in VALID_SEVERITIES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid severity '{request.severity}'. Must be one of: {sorted(VALID_SEVERITIES)}",
        )

    if request.attack_origin not in VALID_VENDORS:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown vendor '{request.attack_origin}'. Must be one of: {sorted(VALID_VENDORS)}",
        )

    graph = buildDependencyGraph()
    payload = buildAnimatedSimulationPayload(request.attack_origin, request.severity.upper(), graph)

    if not request.include_after_mitigation:
        payload["after_mitigation_frames"] = []
        payload["show_after_mitigation_prompt"] = True

    return payload


@router.get("/simulate-animated/{attack_origin}/{severity}")
async def simulateAnimatedGet(attack_origin: str, severity: str):
    if severity.upper() not in VALID_SEVERITIES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid severity. Must be one of: {sorted(VALID_SEVERITIES)}",
        )
    if attack_origin not in VALID_VENDORS:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown vendor. Must be one of: {sorted(VALID_VENDORS)}",
        )

    graph = buildDependencyGraph()
    payload = buildAnimatedSimulationPayload(attack_origin, severity.upper(), graph)
    return payload


@router.get("/simulation-frames/{attack_origin}/{severity}/before")
async def getBeforeFrames(attack_origin: str, severity: str):
    if severity.upper() not in VALID_SEVERITIES:
        raise HTTPException(status_code=422, detail="Invalid severity")
    if attack_origin not in VALID_VENDORS:
        raise HTTPException(status_code=422, detail="Unknown vendor")

    graph = buildDependencyGraph()
    payload = buildAnimatedSimulationPayload(attack_origin, severity.upper(), graph)
    return {
        "attack_origin": attack_origin,
        "severity": severity.upper(),
        "phase": "before_mitigation",
        "frames": payload["before_mitigation_frames"],
        "total_frames": payload["animation_config"]["total_before_frames"],
        "frame_delay_ms": payload["animation_config"]["before_frame_delay_ms"],
    }


@router.get("/simulation-frames/{attack_origin}/{severity}/mitigation")
async def getMitigationFrames(attack_origin: str, severity: str):
    if severity.upper() not in VALID_SEVERITIES:
        raise HTTPException(status_code=422, detail="Invalid severity")
    if attack_origin not in VALID_VENDORS:
        raise HTTPException(status_code=422, detail="Unknown vendor")

    graph = buildDependencyGraph()
    payload = buildAnimatedSimulationPayload(attack_origin, severity.upper(), graph)
    return {
        "attack_origin": attack_origin,
        "severity": severity.upper(),
        "phase": "mitigation",
        "frames": payload["mitigation_frames"],
        "mitigation_phase": payload["mitigation_phase"],
        "show_after_mitigation_prompt": payload["show_after_mitigation_prompt"],
        "after_mitigation_prompt_text": payload["after_mitigation_prompt_text"],
        "total_frames": payload["animation_config"]["total_mitigation_frames"],
        "frame_delay_ms": payload["animation_config"]["mitigation_frame_delay_ms"],
    }


@router.get("/simulation-frames/{attack_origin}/{severity}/after")
async def getAfterFrames(attack_origin: str, severity: str):
    if severity.upper() not in VALID_SEVERITIES:
        raise HTTPException(status_code=422, detail="Invalid severity")
    if attack_origin not in VALID_VENDORS:
        raise HTTPException(status_code=422, detail="Unknown vendor")

    graph = buildDependencyGraph()
    payload = buildAnimatedSimulationPayload(attack_origin, severity.upper(), graph)
    return {
        "attack_origin": attack_origin,
        "severity": severity.upper(),
        "phase": "after_mitigation",
        "frames": payload["after_mitigation_frames"],
        "final_summary": payload["final_summary"],
        "total_frames": payload["animation_config"]["total_after_frames"],
        "frame_delay_ms": payload["animation_config"]["after_frame_delay_ms"],
    }


@router.get("/vendors/list")
async def listVendors():
    return {"vendors": sorted(VALID_VENDORS), "total": len(VALID_VENDORS)}