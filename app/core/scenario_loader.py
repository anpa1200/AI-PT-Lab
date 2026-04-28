from __future__ import annotations

import logging
from typing import Any

from app.core.config_loader import load_provider, load_scenario
from app.core.orchestrator import ScenarioOrchestrator
from app.core.settings import settings
from app.models.router import build_llm_router
from app.rag.pipeline import RAGPipeline
from app.scoring.engine import ScoringEngine
from app.telemetry.writer import TelemetryWriter
from app.tools.executor import ToolExecutor
from app.vulnerabilities.registry import get_registry

logger = logging.getLogger(__name__)

_PROVIDER_OVERRIDE_SAFE_KEYS = {
    "temperature",
    "max_tokens",
    "timeout_seconds",
}


def _resolve_provider_config(
    scenario: dict[str, Any],
    provider_override: str | None = None,
) -> tuple[str, dict[str, Any]]:
    provider_block = dict(scenario.get("provider", {}))
    default_provider_name: str = provider_block.get("name", "openai")
    # Priority: CLI flag > LAB_PROVIDER env var > scenario YAML
    provider_name = provider_override or settings.provider or default_provider_name

    provider_cfg = load_provider(provider_name)
    # When provider is overridden (CLI or env var), only carry over inference
    # params from the scenario block — never the model name or provider name.
    if provider_name != default_provider_name:
        provider_cfg.update(
            {
                key: value
                for key, value in provider_block.items()
                if key in _PROVIDER_OVERRIDE_SAFE_KEYS
            }
        )
    else:
        provider_cfg.update(provider_block)

    provider_cfg["name"] = provider_name
    return provider_name, provider_cfg


def build_orchestrator(
    scenario_id: str,
    provider_override: str | None = None,
) -> ScenarioOrchestrator:
    """
    Load a scenario config and construct a fully wired ScenarioOrchestrator.

    Raises ScenarioNotFound if the scenario YAML does not exist.
    Raises ModuleLoadError if an enabled vulnerability module is unknown.
    """
    cfg = load_scenario(scenario_id)
    scenario: dict[str, Any] = cfg.get("scenario", cfg)

    logger.info("Building orchestrator for scenario: %s", scenario_id)

    # ── Vulnerability modules ────────────────────────────────────────────────
    registry = get_registry()
    modules = []
    for mod_cfg in scenario.get("vulnerability_modules", []):
        if not mod_cfg.get("enabled", True):
            logger.debug("Module %s is disabled, skipping", mod_cfg.get("module_id"))
            continue
        _reserved = {"module_id", "enabled", "priority"}
        mod_config = {k: v for k, v in mod_cfg.items() if k not in _reserved}
        instance = registry.instantiate(mod_cfg["module_id"], mod_config)
        instance._priority_override = mod_cfg.get("priority", instance.priority)
        modules.append(instance)

    modules.sort(key=lambda m: getattr(m, "_priority_override", m.priority))
    logger.info("Loaded modules: %s", [m.module_id for m in modules])

    # ── LLM provider ────────────────────────────────────────────────────────
    provider_name, provider_cfg = _resolve_provider_config(
        scenario,
        provider_override=provider_override,
    )
    llm_router = build_llm_router(provider_cfg)
    logger.info("LLM provider: %s model: %s", provider_name, provider_cfg.get("model"))

    # ── RAG pipeline ─────────────────────────────────────────────────────────
    rag_cfg: dict[str, Any] = scenario.get("rag", {})
    rag_pipeline: RAGPipeline | None = None
    if rag_cfg.get("enabled", False):
        rag_pipeline = RAGPipeline.from_config(rag_cfg)
        logger.info("RAG enabled: collection=%s", rag_cfg.get("collection"))

    # ── Tool executor ────────────────────────────────────────────────────────
    tools_config: list[dict[str, Any]] = scenario.get("tools", [])
    tool_executor: ToolExecutor | None = None
    if tools_config:
        tool_executor = ToolExecutor.from_config(tools_config)
        logger.info("Tools registered: %s", [t["id"] for t in tools_config])

    # ── Scoring + telemetry ──────────────────────────────────────────────────
    scoring_rules = scenario.get("scoring", {}).get("rules", [])
    scoring_engine = ScoringEngine(scoring_rules)
    telemetry_writer = TelemetryWriter.default()

    return ScenarioOrchestrator(
        modules=modules,
        llm_router=llm_router,
        rag_pipeline=rag_pipeline,
        tool_executor=tool_executor,
        scoring_engine=scoring_engine,
        telemetry_writer=telemetry_writer,
        scenario_config=scenario,
    )
