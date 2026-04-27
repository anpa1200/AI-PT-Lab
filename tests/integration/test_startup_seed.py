"""
Integration tests for the startup auto-seed logic in app.api.main.

We test _seed_all_scenarios() directly with a mocked RAGPipeline so
no ChromaDB or disk I/O is required.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture
def mock_pipeline():
    p = MagicMock()
    p.count.return_value = 0
    p.seed_from_jsonl.return_value = 5
    p.seed_from_directory.return_value = 8
    p.reset.return_value = None
    return p


@pytest.fixture(autouse=True)
def _patch_rag(mock_pipeline):
    with patch("app.rag.pipeline.RAGPipeline") as cls:
        cls.from_config.return_value = mock_pipeline
        yield mock_pipeline


# ── Basic seeding ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_seed_runs_for_soc_copilot(mock_pipeline):
    from app.api.main import _seed_all_scenarios
    await _seed_all_scenarios()
    # RAGPipeline.from_config must have been called at least once
    assert mock_pipeline.count.called


@pytest.mark.asyncio
async def test_seed_calls_seed_from_directory_when_datasets_configured(mock_pipeline):
    from app.api.main import _seed_all_scenarios
    mock_pipeline.count.return_value = 0
    await _seed_all_scenarios()
    assert mock_pipeline.seed_from_directory.called or mock_pipeline.seed_from_jsonl.called


@pytest.mark.asyncio
async def test_seed_skips_already_seeded_collection(mock_pipeline):
    from app.api.main import _seed_all_scenarios
    mock_pipeline.count.return_value = 42  # already has docs
    await _seed_all_scenarios()
    mock_pipeline.seed_from_directory.assert_not_called()
    mock_pipeline.seed_from_jsonl.assert_not_called()


@pytest.mark.asyncio
async def test_seed_does_not_reset_by_default(mock_pipeline):
    from app.api.main import _seed_all_scenarios
    await _seed_all_scenarios()
    mock_pipeline.reset.assert_not_called()


@pytest.mark.asyncio
async def test_seed_resets_when_flag_set(mock_pipeline):
    from app.api.main import _seed_all_scenarios
    from app.core.settings import settings

    original = settings.reset_on_startup
    try:
        settings.reset_on_startup = True
        await _seed_all_scenarios()
        assert mock_pipeline.reset.called
    finally:
        settings.reset_on_startup = original


@pytest.mark.asyncio
async def test_seed_failure_does_not_raise(mock_pipeline):
    """A broken RAGPipeline must not crash startup."""
    from app.api.main import _seed_all_scenarios
    mock_pipeline.count.side_effect = RuntimeError("chromadb unavailable")
    # Should log a warning and continue — no exception propagated
    await _seed_all_scenarios()


# ── API health check still passes after seeding ───────────────────────────────

def test_health_endpoint_still_returns_ok(mock_pipeline):
    from fastapi.testclient import TestClient

    from app.api.main import app

    with TestClient(app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


# ── Scenario list reflects both scenarios ─────────────────────────────────────

def test_both_scenarios_listed(mock_pipeline):
    from fastapi.testclient import TestClient

    from app.api.main import app

    with TestClient(app) as client:
        resp = client.get("/api/v1/scenarios")
        assert resp.status_code == 200
        scenarios = resp.json()["scenarios"]
        assert "soc_copilot" in scenarios
        assert "code_assistant" in scenarios


def test_lifespan_skips_seed_when_disabled(mock_pipeline):
    from fastapi.testclient import TestClient

    from app.api.main import app
    from app.core.settings import settings

    original = settings.seed_on_startup
    try:
        settings.seed_on_startup = False
        with patch("app.api.main._seed_all_scenarios", new=AsyncMock()) as seed_mock:
            with TestClient(app) as client:
                resp = client.get("/health")

        assert resp.status_code == 200
        seed_mock.assert_not_awaited()
    finally:
        settings.seed_on_startup = original
