from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import health, scenarios
from app.core.config_loader import list_scenarios, load_scenario
from app.core.settings import settings
from app.vulnerabilities.registry import get_registry

logger = logging.getLogger(__name__)


async def _seed_all_scenarios() -> None:
    """
    For each RAG-enabled scenario, seed its ChromaDB collection if empty.
    If LAB_RESET_ON_STARTUP=true, wipe and re-seed every collection.
    Failures are logged as warnings — they must not prevent startup.
    """
    from app.rag.pipeline import RAGPipeline, seed_scenario

    for scenario_id in list_scenarios():
        try:
            cfg = load_scenario(scenario_id)
            scenario = cfg.get("scenario", cfg)
            rag_cfg = scenario.get("rag", {})
            if not rag_cfg.get("enabled", False):
                continue

            pipeline = RAGPipeline.from_config(rag_cfg)
            existing_docs = pipeline.count()

            if settings.reset_on_startup:
                pipeline.reset()
                logger.info("Collection reset (LAB_RESET_ON_STARTUP): scenario=%s", scenario_id)

            if existing_docs > 0 and not settings.reset_on_startup:
                logger.info(
                    "Collection already seeded (%d docs), skipping: scenario=%s",
                    existing_docs, scenario_id,
                )
                continue

            seeded = seed_scenario(pipeline, scenario)
            logger.info("Seeded %d documents: scenario=%s", seeded, scenario_id)

        except Exception:
            logger.warning(
                "Failed to seed scenario '%s' — RAG may return empty results",
                scenario_id, exc_info=True,
            )


_NOISY_LOGGERS = [
    "httpx", "httpcore", "huggingface_hub", "huggingface_hub.utils._http",
    "sentence_transformers", "transformers", "filelock",
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(level=settings.log_level)
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)
    logger.info("Vulnerable AI Lab starting up...")

    get_registry().autodiscover()
    registered = get_registry().list_available()
    logger.info("Registered vulnerability modules: %s", registered)

    if settings.seed_on_startup:
        await _seed_all_scenarios()
    else:
        logger.info("Skipping scenario auto-seed (LAB_SEED_ON_STARTUP=false)")

    yield
    logger.info("Vulnerable AI Lab shutting down.")


app = FastAPI(
    title="Vulnerable AI Lab",
    description="Intentionally vulnerable AI security training lab",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(scenarios.router, prefix="/api/v1")


@app.get("/")
async def root() -> dict:
    return {
        "name": "Vulnerable AI Lab",
        "version": "0.1.0",
        "docs": "/docs",
        "health": "/health",
        "api": "/api/v1",
    }
