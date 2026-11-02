import json

import pytest

from app.retrieval.corpus import (
    clean_markdown,
    in_scope,
    load_attack,
    load_sigma,
    split_paragraphs,
)
from eval.retrieval import is_correct


def test_scope_covers_families_and_neighbours_only():
    assert in_scope("T1059.001") and in_scope("T1110") and in_scope("T1569.002")
    assert not in_scope("T1566.001") and not in_scope("T1190")


def test_clean_markdown_removes_citations_and_links():
    text = "Adversaries abuse [PowerShell](https://x.example) (Citation: Foo 2020) <code>-enc</code>."
    assert clean_markdown(text) == "Adversaries abuse PowerShell -enc."


def test_split_paragraphs_packs_without_exceeding_the_limit():
    paragraphs = ["a" * 400, "b" * 400, "c" * 400]
    pieces = split_paragraphs("\n\n".join(paragraphs), limit=900)
    assert pieces == ["a" * 400 + "\n\n" + "b" * 400, "c" * 400]
    assert split_paragraphs("x" * 2000, limit=900) == ["x" * 2000]  # one long paragraph stays whole
    assert split_paragraphs("") == []


def _technique(tid, name, desc, **extra):
    return {
        "type": "attack-pattern", "name": name, "description": desc,
        "kill_chain_phases": [{"phase_name": "credential-access"}],
        "external_references": [{"source_name": "mitre-attack", "external_id": tid}], **extra,
    }


def test_load_attack_filters_scope_and_revoked(tmp_path):
    bundle = {"objects": [
        _technique("T1003.001", "LSASS Memory", "Dump (Citation: x) lsass."),
        _technique("T1566.001", "Phishing", "out of scope"),
        _technique("T1003.002", "SAM", "revoked one", revoked=True),
        _technique("T1110.003", "Password Spraying", "spray", x_mitre_deprecated=True),
        {"type": "malware", "name": "not a technique"},
    ]}
    path = tmp_path / "attack.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    chunks = load_attack(path)
    assert [c.ref for c in chunks] == ["T1003.001"]
    assert chunks[0].technique_ids == ["T1003.001"]
    assert "Dump  lsass." in chunks[0].content or "Dump lsass." in chunks[0].content
    assert chunks[0].tenant_id == "public"


def test_load_sigma_keeps_in_scope_rules_and_dedups_titles(tmp_path):
    rules = tmp_path / "rules" / "windows" / "proc"
    rules.mkdir(parents=True)
    good = ("title: Suspicious LSASS Access\nstatus: test\ndescription: d\ntags: [attack.t1003.001, attack.credential-access]\n"
            "logsource: {product: windows, category: process_access}\ndetection: {sel: {TargetImage: lsass.exe}, condition: sel}\n"
            "falsepositives: [AV]\nlevel: high\n")
    (rules / "a.yml").write_text(good)
    (rules / "b.yml").write_text(good)  # same title: should be dropped
    (rules / "c.yml").write_text("title: Phishing\ntags: [attack.t1566.001]\ndetection: {c: x}\n")
    (rules / "d.yml").write_text("title: Old\nstatus: deprecated\ntags: [attack.t1003.001]\ndetection: {c: x}\n")
    (rules / "e.yml").write_text("::: not yaml :::\n\t- [")
    chunks = load_sigma(tmp_path)
    assert [c.ref for c in chunks] == ["Suspicious LSASS Access"]
    assert chunks[0].technique_ids == ["T1003.001"]
    assert "lsass.exe" in chunks[0].content and "AV" in chunks[0].content


@pytest.mark.parametrize(
    "label, ids, expected",
    [
        ("T1003.001", ["T1003.001"], True),
        ("T1003.001", ["T1003"], False),  # a parent chunk does not count for a sub-technique label
        ("T1110", ["T1110.003"], True),  # a sub-technique chunk counts for a parent label
        ("T1110", ["T1110"], True),
        ("T1110", ["T1105"], False),
        ("T1059.001", ["T1059.003", "T1003.001"], False),
    ],
)
def test_is_correct(label, ids, expected):
    assert is_correct(label, ids) is expected
