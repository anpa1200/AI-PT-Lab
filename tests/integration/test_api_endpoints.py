from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.models.router import LLMResponse


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def mock_llm():
    """Patch LLM router, RAGPipeline and TelemetryWriter for no real I/O."""
    llm_mock = AsyncMock()
    llm_mock.complete = AsyncMock(
        return_value=LLMResponse(content="Incident confirmed. No active threats.")
    )

    rag_mock = AsyncMock()
    rag_mock.retrieve = AsyncMock(return_value=[])

    telemetry_mock = AsyncMock()
    telemetry_mock.flush = AsyncMock()

    with (
        patch("app.core.scenario_loader.build_llm_router", return_value=llm_mock),
        patch("app.core.scenario_loader.RAGPipeline") as rag_cls,
        patch("app.core.scenario_loader.TelemetryWriter") as tel_cls,
    ):
        rag_cls.from_config.return_value = rag_mock
        tel_cls.default.return_value = telemetry_mock
        yield llm_mock


# ── Health ────────────────────────────────────────────────────────────────────

def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_root(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Vulnerable AI Lab" in resp.json()["name"]


# ── Scenarios list ────────────────────────────────────────────────────────────

def test_list_scenarios_returns_soc_copilot(client):
    resp = client.get("/api/v1/scenarios")
    assert resp.status_code == 200
    data = resp.json()
    assert "soc_copilot" in data["scenarios"]


def test_get_scenario_info(client):
    resp = client.get("/api/v1/scenarios/soc_copilot")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == "soc_copilot"
    assert "name" in data


def test_get_scenario_info_unknown_returns_404(client):
    resp = client.get("/api/v1/scenarios/does_not_exist")
    assert resp.status_code == 404


# ── Modules list ──────────────────────────────────────────────────────────────

def test_list_modules(client):
    resp = client.get("/api/v1/modules")
    assert resp.status_code == 200
    assert "modules" in resp.json()


# ── Run endpoint ──────────────────────────────────────────────────────────────

def test_run_returns_200_and_response(client, mock_llm):
    resp = client.post("/api/v1/run", json={
        "scenario_id": "soc_copilot",
        "user_input": "Check IOC 185.220.101.47",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["final_response"] == "Incident confirmed. No active threats."
    assert "session_id" in data
    assert data["scenario_id"] == "soc_copilot"


def test_run_returns_score_result(client, mock_llm):
    resp = client.post("/api/v1/run", json={
        "scenario_id": "soc_copilot",
        "user_input": "Search for brute force incidents",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "score_result" in data
    assert "overall_status" in data["score_result"]


def test_run_returns_hook_summary(client, mock_llm):
    resp = client.post("/api/v1/run", json={
        "scenario_id": "soc_copilot",
        "user_input": "hello",
    })
    assert resp.status_code == 200
    assert "hook_summary" in resp.json()
    assert "active_modules" in resp.json()


def test_run_unknown_scenario_returns_404(client):
    resp = client.post("/api/v1/run", json={
        "scenario_id": "no_such_scenario",
        "user_input": "test",
    })
    assert resp.status_code == 404


def test_run_missing_user_input_returns_422(client):
    resp = client.post("/api/v1/run", json={"scenario_id": "soc_copilot"})
    assert resp.status_code == 422
