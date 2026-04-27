from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.core.config_loader import list_scenarios, load_scenario
from app.core.context import RunContext
from app.core.exceptions import ConfigError, ModuleLoadError, ScenarioNotFound
from app.core.scenario_loader import build_orchestrator
from app.vulnerabilities.registry import get_registry

logger = logging.getLogger(__name__)
router = APIRouter(tags=["scenarios"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class RunRequest(BaseModel):
    scenario_id: str
    user_input: str
    provider_override: str | None = None


class EvidenceItem(BaseModel):
    rule_id: str
    description: str
    passed: bool
    evidence: str
    severity: str = "info"
    source: str = "module"


class HookSummaryItem(BaseModel):
    hook_point: str
    module_id: str
    mutations: list[str]


class ScoreResult(BaseModel):
    total_rules: int
    triggered: int
    critical_triggered: int
    high_triggered: int
    overall_status: str
    evidence: list[EvidenceItem]


class RunResponse(BaseModel):
    session_id: str
    scenario_id: str
    final_response: str
    score_result: ScoreResult | None
    hook_summary: list[HookSummaryItem]
    events_count: int
    active_modules: list[str]


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/scenarios")
async def list_available_scenarios() -> dict:
    return {"scenarios": list_scenarios()}


@router.get("/scenarios/{scenario_id}")
async def get_scenario_info(scenario_id: str) -> dict:
    try:
        cfg = load_scenario(scenario_id)
    except ScenarioNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    scenario = cfg.get("scenario", cfg)
    return {
        "id": scenario_id,
        "name": scenario.get("name", scenario_id),
        "description": scenario.get("description", ""),
        "vulnerability_modules": [
            m["module_id"]
            for m in scenario.get("vulnerability_modules", [])
            if m.get("enabled", True)
        ],
        "tools": [t["id"] for t in scenario.get("tools", [])],
        "rag_enabled": scenario.get("rag", {}).get("enabled", False),
    }


@router.post("/run", response_model=RunResponse)
async def run_scenario(req: RunRequest) -> RunResponse:
    logger.info("Run request: scenario=%s input_len=%d", req.scenario_id, len(req.user_input))

    try:
        orchestrator = build_orchestrator(
            req.scenario_id,
            provider_override=req.provider_override,
        )
    except ScenarioNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except (ConfigError, ModuleLoadError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to build orchestrator for scenario %s", req.scenario_id)
        raise HTTPException(status_code=500, detail=f"Orchestrator build failed: {exc}")

    ctx = RunContext(scenario_id=req.scenario_id, user_input=req.user_input)

    try:
        ctx = await orchestrator.run(ctx)
    except Exception as exc:
        logger.exception("Run failed: session=%s", ctx.session_id)
        raise HTTPException(status_code=500, detail=f"Run failed: {exc}")

    score = ctx.score_result or {}
    return RunResponse(
        session_id=ctx.session_id,
        scenario_id=ctx.scenario_id,
        final_response=ctx.final_response,
        score_result=ScoreResult(
            total_rules=score.get("total_rules", 0),
            triggered=score.get("triggered", 0),
            critical_triggered=score.get("critical_triggered", 0),
            high_triggered=score.get("high_triggered", 0),
            overall_status=score.get("overall_status", "not_triggered"),
            evidence=[
                EvidenceItem(
                    rule_id=e.get("rule_id", ""),
                    description=e.get("description", ""),
                    passed=e.get("passed", False),
                    evidence=e.get("evidence", ""),
                    severity=e.get("severity", "info"),
                    source=e.get("source", "module"),
                )
                for e in score.get("evidence", [])
            ],
        ) if score else None,
        hook_summary=[
            HookSummaryItem(
                hook_point=t.hook_point,
                module_id=t.module_id,
                mutations=t.mutations,
            )
            for t in ctx.hook_traces
        ],
        events_count=len(ctx.telemetry_events),
        active_modules=ctx.active_modules,
    )


@router.post("/scenarios/{scenario_id}/reset")
async def reset_scenario(scenario_id: str) -> dict:
    """
    Reset a scenario: wipe and re-seed the ChromaDB collection.
    Safe to call between student runs.
    """
    try:
        cfg = load_scenario(scenario_id)
    except ScenarioNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    scenario = cfg.get("scenario", cfg)
    rag_cfg = scenario.get("rag", {})

    if not rag_cfg.get("enabled", False):
        return {"status": "ok", "message": "RAG not enabled for this scenario — nothing to reset"}

    try:
        from app.rag.pipeline import RAGPipeline, seed_scenario
        pipeline = RAGPipeline.from_config(rag_cfg)
        pipeline.reset()
        seeded = seed_scenario(pipeline, scenario)

    except Exception as exc:
        logger.exception("Reset failed for scenario %s", scenario_id)
        raise HTTPException(status_code=500, detail=f"Reset failed: {exc}")

    return {"status": "ok", "scenario_id": scenario_id, "documents_seeded": seeded}


@router.get("/modules")
async def list_modules() -> dict:
    return {"modules": get_registry().list_available()}
