import json

import anthropic
import httpx
import pytest
from fastapi.testclient import TestClient

from app.deps import get_chunk_store, get_embedder, get_llm, get_store
from app.main import app
from app.store import MemoryStore
from tests.conftest import sysmon
from tests.test_retrieval_store import FakeEmbedder
from tests.test_triage import FakeChunks, ScriptedLLM, answer

H = {"X-Tenant-ID": "acme"}


@pytest.fixture
def setup():
    store, llm = MemoryStore(), ScriptedLLM(answer())
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_llm] = lambda: llm
    app.dependency_overrides[get_chunk_store] = lambda: FakeChunks()
    app.dependency_overrides[get_embedder] = lambda: FakeEmbedder()
    client = TestClient(app)
    alert_id = client.post("/alerts", headers=H, json={"source": "sysmon_json", "records": [sysmon()]}).json()["results"][0]["id"]
    yield client, alert_id, llm
    app.dependency_overrides.clear()


def test_triage_returns_a_recommendation(setup):
    client, alert_id, _ = setup
    response = client.post(f"/alerts/{alert_id}/triage", headers=H)
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"]["verdict"] == "malicious" and body["status"] == "ok"
    assert [r["ref"] for r in body["retrieved"]][0] == "T1003.001"
    assert set(body) == {"verdict", "status", "reason", "model_verdict", "model", "retrieved",
                         "quotes_verified", "quotes_total", "usage"}  # a recommendation, no action field


def test_unknown_alert_and_other_tenants_get_404(setup):
    client, alert_id, _ = setup
    assert client.post("/alerts/00000000-0000-0000-0000-000000000000/triage", headers=H).status_code == 404
    assert client.post(f"/alerts/{alert_id}/triage", headers={"X-Tenant-ID": "globex"}).status_code == 404


def test_tenant_header_is_required(setup):
    client, alert_id, _ = setup
    assert client.post(f"/alerts/{alert_id}/triage").status_code == 422


def test_provider_errors_become_502(setup):
    client, alert_id, _ = setup

    class Boom:
        model = "claude-haiku-5-5"

        def complete(self, *a, **k):
            raise anthropic.APIConnectionError(request=httpx.Request("POST", "https://api.anthropic.com"))

    app.dependency_overrides[get_llm] = lambda: Boom()
    assert client.post(f"/alerts/{alert_id}/triage", headers=H).status_code == 502


def test_missing_credentials_give_503(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    store = MemoryStore()
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_chunk_store] = lambda: FakeChunks()
    app.dependency_overrides[get_embedder] = lambda: FakeEmbedder()
    try:
        client = TestClient(app)
        alert_id = client.post("/alerts", headers=H, json={"source": "sysmon_json", "records": [sysmon()]}).json()["results"][0]["id"]
        response = client.post(f"/alerts/{alert_id}/triage", headers=H)
        assert response.status_code == 503 and "credentials" in response.json()["detail"]
    finally:
        app.dependency_overrides.clear()


def test_the_api_exposes_no_action_endpoint():
    """The system recommends only. No route executes, approves or enforces a response."""
    paths = {route.path for route in app.routes}
    assert not [p for p in paths if any(w in p for w in ("execute", "isolate", "block", "remediate", "respond"))]
    assert json.dumps(sorted(paths))  # keep the list visible in failures
