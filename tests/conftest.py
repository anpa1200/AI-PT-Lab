from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.core.context import RunContext


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def run_ctx() -> RunContext:
    return RunContext(scenario_id="test", user_input="test input")


@pytest.fixture
def sample_retrieved_docs() -> list[dict]:
    return [
        {"content": "Brute force detected on VPN gateway.", "metadata": {"source": "incidents"}, "similarity": 0.91},
        {"content": "Phishing campaign targeting finance.", "metadata": {"source": "incidents"}, "similarity": 0.85},
    ]
