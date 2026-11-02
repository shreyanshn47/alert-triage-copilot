"""Sanity checks on the committed labeled files. They guard the evaluation against silent drift."""

import json
from collections import Counter
from pathlib import Path

import pytest

from app.fingerprint import fingerprint
from app.parsers.sysmon import parse_sysmon_json
from tests.conftest import REF_TIME

LABELED = Path(__file__).resolve().parents[1] / "data" / "labeled"
TECHNIQUES = {"T1059.001", "T1003.001", "T1021.002", "T1053.005", "T1547.001", "T1110"}


def load(name):
    path = LABELED / name
    if not path.exists():
        pytest.skip(f"{name} not built; run data/build_labeled.py or data/make_benign.py")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


@pytest.fixture(scope="module")
def rows():
    return load("malicious.jsonl") + load("benign.jsonl")


def test_ids_are_unique_and_fields_are_valid(rows):
    assert len({r["id"] for r in rows}) == len(rows)
    for r in rows:
        assert r["label"] in {"malicious", "benign"}
        assert r["split"] in {"dev", "test"}
        assert (r["label"] == "malicious") == (r["technique"] in TECHNIQUES)


def test_every_record_goes_through_the_real_parser(rows):
    for r in rows:
        parse_sysmon_json(r["record"], REF_TIME)


def test_each_technique_appears_in_both_splits(rows):
    seen = {(r["technique"], r["split"]) for r in rows if r["label"] == "malicious"}
    for t in TECHNIQUES:
        assert (t, "dev") in seen and (t, "test") in seen, t


def test_no_fingerprint_is_shared_between_dev_and_test(rows):
    """The same behaviour must not sit on both sides of the split."""
    sides: dict[str, set[str]] = {}
    for r in rows:
        a = parse_sysmon_json(r["record"], REF_TIME)
        fp = fingerprint("lab", a.host, a.user, a.process, a.command_line, a.event_type)
        sides.setdefault(fp, set()).add(r["split"])
    assert not [fp for fp, s in sides.items() if len(s) > 1]


def test_benign_set_is_balanced_across_lookalike_groups(rows):
    counts = Counter(r["lookalike_of"] for r in rows if r["label"] == "benign")
    assert set(counts) == TECHNIQUES and set(counts.values()) == {10}
