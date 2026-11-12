"""The CI smoke gate must pass on the committed repo, and must actually fail when something drifts."""

import json

from eval import smoke


def test_smoke_gate_passes_on_the_committed_results(capsys):
    assert smoke.main() == 0
    assert "passed" in capsys.readouterr().out


def test_smoke_gate_detects_a_changed_prompt(monkeypatch):
    monkeypatch.setattr(smoke, "prompt_hash", lambda: "0" * 64)
    problems = smoke.check_prompt_and_lock()
    assert any("system prompt changed" in p for p in problems)


def test_smoke_gate_detects_a_baseline_drift(monkeypatch):
    monkeypatch.setattr(smoke.baseline, "predict", lambda alert: ("benign", None))
    assert smoke.check_baseline("test")  # rules-only called 23 malicious on test; "always benign" differs


def test_smoke_gate_detects_stale_stored_summaries(monkeypatch):
    real = smoke._load

    def tampered(path):
        data = real(path)
        if path.name == "results_test.json":
            data = json.loads(json.dumps(data))
            data["systems"]["rules_only"]["summary"]["recall_strict"]["k"] += 1
        return data

    monkeypatch.setattr(smoke, "_load", tampered)
    assert any("recall_strict" in p for p in smoke.check_metrics("test"))
