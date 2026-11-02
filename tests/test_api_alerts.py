from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.deps import get_store
from app.main import app
from app.store import MemoryStore
from tests.conftest import sysmon

H = {"X-Tenant-ID": "acme"}


@pytest.fixture
def client():
    store = MemoryStore()
    app.dependency_overrides[get_store] = lambda: store
    yield TestClient(app)
    app.dependency_overrides.clear()


def post(client, records, source="sysmon_json", headers=H):
    return client.post("/alerts", json={"source": source, "records": records}, headers=headers)


def test_post_then_get_round_trip(client):
    body = post(client, [sysmon()]).json()
    assert (body["ingested"], body["rejected"]) == (1, 0)
    alert_id = body["results"][0]["id"]
    got = client.get(f"/alerts/{alert_id}", headers=H)
    assert got.status_code == 200
    assert got.json()["tenant_id"] == "acme"
    assert got.json()["event_type"] == "process_create"


def test_duplicates_in_one_request_share_a_group(client):
    body = post(client, [sysmon("2026-11-01 10:00:00"), sysmon("2026-11-01 10:00:30")]).json()
    first, second = body["results"]
    assert first["group_id"] == second["group_id"]
    assert (first["new_group"], second["new_group"]) == (True, False)


def test_malformed_records_are_reported_per_record(client):
    response = post(client, [sysmon(), "junk", {"EventID": 1}])
    assert response.status_code == 200
    body = response.json()
    assert (body["ingested"], body["rejected"]) == (1, 2)
    assert body["results"][1]["status"] == "rejected"
    assert body["results"][1]["error"]


def test_empty_batch_is_rejected(client):
    assert post(client, []).status_code == 422


def test_oversized_batch_is_rejected(client):
    assert post(client, [sysmon()] * 1001).status_code == 422


def test_unknown_source_is_rejected(client):
    assert post(client, [sysmon()], source="carrier_pigeon").status_code == 422


def test_tenant_header_is_required_and_validated(client):
    assert post(client, [sysmon()], headers={}).status_code == 422
    assert post(client, [sysmon()], headers={"X-Tenant-ID": "bad tenant!"}).status_code == 422
    assert post(client, [sysmon()], headers={"X-Tenant-ID": "x" * 65}).status_code == 422


def test_other_tenant_gets_404_for_an_alert_it_does_not_own(client):
    alert_id = post(client, [sysmon()]).json()["results"][0]["id"]
    assert client.get(f"/alerts/{alert_id}", headers={"X-Tenant-ID": "globex"}).status_code == 404


def test_unknown_or_invalid_alert_id(client):
    assert client.get(f"/alerts/{uuid4()}", headers=H).status_code == 404
    assert client.get("/alerts/not-a-uuid", headers=H).status_code == 422


def test_syslog_through_the_api(client):
    line = "<38>Nov  1 10:00:05 web01 sshd[1]: Failed password for root from 198.51.100.7 port 51234 ssh2"
    body = post(client, [line, ""], source="syslog").json()
    assert (body["ingested"], body["rejected"]) == (1, 1)
