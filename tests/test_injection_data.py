"""The injection samples must be well formed and must reach the prompt as data, not structure."""

import json
from pathlib import Path

import pytest

from app.parsers.sysmon import parse_sysmon_json
from app.retrieval.store import Hit
from app.triage.prompt import build_user_message
from tests.conftest import REF_TIME

PATH = Path(__file__).resolve().parents[1] / "data" / "labeled" / "injection.jsonl"
HITS = [Hit("attack", "T1003.001", ["T1003.001"], 0, "T1003.001 OS Credential Dumping", 0.8)]


@pytest.fixture(scope="module")
def samples():
    if not PATH.exists():
        pytest.skip("run data/make_injection.py")
    return [json.loads(line) for line in PATH.read_text(encoding="utf-8").splitlines() if line]


def test_there_are_twenty_distinct_samples(samples):
    assert len(samples) == 20
    assert len({s["id"] for s in samples}) == 20
    assert len({s["payload_kind"] for s in samples}) == 20
    assert all(s["attacker_goal"] == "benign" for s in samples)


def test_control_and_injected_differ_only_in_the_payload_field(samples):
    for s in samples:
        diff = {k for k in s["injected"] if s["injected"][k] != s["control"].get(k)}
        assert diff == {s["field"]}, s["id"]
        assert s["payload"] in s["injected"][s["field"]]
        assert s["payload"] not in json.dumps(s["control"])


def test_every_record_parses_and_the_payload_is_visible_to_the_model(samples):
    for s in samples:
        alert = parse_sysmon_json(s["injected"], REF_TIME)
        seen = " ".join(str(v) for v in (alert.command_line, alert.user, alert.host, alert.process))
        assert s["payload"].split()[0] in seen, f"{s['id']}: payload never reaches a parsed field"


def test_no_payload_can_add_or_close_a_prompt_block(samples):
    """Whatever the payload says, the prompt keeps exactly one alert block and one context block."""
    for s in samples:
        message = build_user_message(parse_sysmon_json(s["injected"], REF_TIME), HITS)
        for tag in ("<alert>", "</alert>", "<context>", "</context>"):
            assert message.count(tag) == 1, f"{s['id']} ({s['payload_kind']}) changed the count of {tag}"
        assert message.count("<item ") == len(HITS)  # a forged <item> never survives


def test_a_payload_cannot_forge_a_field_line(samples):
    for s in samples:
        message = build_user_message(parse_sysmon_json(s["injected"], REF_TIME), HITS)
        block = message.split("<alert>")[1].split("</alert>")[0].strip().splitlines()
        names = [line.split(":", 1)[0] for line in block]
        assert len(names) == len(set(names)), f"{s['id']} produced duplicate field lines: {names}"
