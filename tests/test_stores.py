"""Ingest + grouping behaviour. Runs against the memory store and, when reachable, Postgres."""

from uuid import uuid4

from app.ingest import ingest
from tests.conftest import REF_TIME, sysmon


def one(store, tenant, record, source="sysmon_json"):
    response = ingest(store, tenant, source, [record], now=REF_TIME)
    return response.results[0]


def test_duplicates_collapse_into_one_group(store, tenant):
    first = one(store, tenant, sysmon("2026-11-01 10:00:00"))
    second = one(store, tenant, sysmon("2026-11-01 10:01:30"))
    assert first.new_group is True
    assert second.new_group is False
    assert second.group_id == first.group_id
    assert second.fingerprint == first.fingerprint
    assert second.id != first.id  # both alerts are kept; only the group is shared


def test_alerts_differing_only_in_ephemeral_ids_still_collapse(store, tenant):
    a = one(store, tenant, sysmon(CommandLine="job 2026-11-01T10:00:00Z pid=1"))
    b = one(store, tenant, sysmon("2026-11-01 10:02:00", CommandLine="job 2026-11-01T10:02:00Z pid=2"))
    assert a.group_id == b.group_id


def test_alert_outside_the_window_starts_a_new_group(store, tenant):
    first = one(store, tenant, sysmon("2026-11-01 10:00:00"))
    late = one(store, tenant, sysmon("2026-11-01 10:10:01"))
    assert late.new_group is True
    assert late.group_id != first.group_id


def test_window_boundary_is_inclusive(store, tenant):
    first = one(store, tenant, sysmon("2026-11-01 10:00:00"))
    edge = one(store, tenant, sysmon("2026-11-01 10:10:00"))
    assert edge.group_id == first.group_id


def test_group_is_anchored_at_its_first_alert_not_chained(store, tenant):
    a = one(store, tenant, sysmon("2026-11-01 10:00:00"))
    b = one(store, tenant, sysmon("2026-11-01 10:08:00"))  # joins a
    c = one(store, tenant, sysmon("2026-11-01 10:16:00"))  # 8 min after b, 16 after a
    assert b.group_id == a.group_id
    assert c.group_id != a.group_id


def test_out_of_order_arrival_still_joins_the_group(store, tenant):
    later = one(store, tenant, sysmon("2026-11-01 10:05:00"))
    earlier = one(store, tenant, sysmon("2026-11-01 10:02:00"))
    assert earlier.group_id == later.group_id


def test_different_behaviour_does_not_group(store, tenant):
    a = one(store, tenant, sysmon())
    other_host = one(store, tenant, sysmon(Computer="WS02.corp.local"))
    other_cmd = one(store, tenant, sysmon(CommandLine="powershell.exe -enc AAAA"))
    assert len({a.group_id, other_host.group_id, other_cmd.group_id}) == 3


def test_same_alert_in_two_tenants_never_shares_a_group(store):
    t1, t2 = f"t-{uuid4().hex[:10]}", f"t-{uuid4().hex[:10]}"
    a = one(store, t1, sysmon())
    b = one(store, t2, sysmon())
    assert a.group_id != b.group_id
    assert a.fingerprint != b.fingerprint


def test_a_bad_record_does_not_block_the_rest_of_the_batch(store, tenant):
    records = [sysmon(), "not an object", {"EventID": 1}, sysmon("2026-11-01 10:01:00")]
    response = ingest(store, tenant, "sysmon_json", records, now=REF_TIME)
    assert (response.ingested, response.rejected) == (2, 2)
    assert [r.status for r in response.results] == ["ingested", "rejected", "rejected", "ingested"]
    assert [r.index for r in response.results] == [0, 1, 2, 3]
    assert response.results[0].group_id == response.results[3].group_id
    assert "JSON object" in response.results[1].error


def test_syslog_duplicates_group_per_source_ip(store, tenant):
    line = "Nov  1 10:00:0{s} web01 sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    lines = [
        line.format(s=1, pid=100, ip="198.51.100.7", port=51111),
        line.format(s=2, pid=101, ip="198.51.100.7", port=52222),  # same attacker: same group
        line.format(s=3, pid=102, ip="198.51.100.8", port=53333),  # new attacker: new group
    ]
    r = ingest(store, tenant, "syslog", lines, now=REF_TIME).results
    assert r[0].group_id == r[1].group_id
    assert r[2].group_id != r[0].group_id


def test_stored_alert_round_trips(store, tenant):
    result = one(store, tenant, sysmon(EventID=3, SourceIp="10.0.0.5", DestinationIp="203.0.113.9"))
    alert = store.get(tenant, result.id)
    assert alert.tenant_id == tenant
    assert (alert.src_ip, alert.dst_ip) == ("10.0.0.5", "203.0.113.9")
    assert alert.group_id == result.group_id
    assert alert.raw["Computer"] == "WS01.corp.local"


def test_get_never_returns_another_tenants_alert(store, tenant):
    result = one(store, tenant, sysmon())
    assert store.get(tenant, result.id) is not None
    assert store.get("some-other-tenant", result.id) is None
    assert store.get(tenant, uuid4()) is None
