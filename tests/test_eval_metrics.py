import pytest

from eval.metrics import percentile, prop, summarize, technique_match, threshold_sweep, wilson
from eval.run import check_freeze


def r(label, verdict, technique=None, predicted=None, confidence=0.9, model_verdict=None, **kw):
    base = {"label": label, "technique": technique, "verdict": verdict, "predicted_technique": predicted,
            "confidence": confidence, "model_verdict": model_verdict, "status": "ok", "seconds": 1.0,
            "cost_usd": 0.001, "calls": 1, "cached_calls": 0}
    return {**base, **kw}


def test_wilson_interval_matches_known_values():
    lo, hi = wilson(0, 20)
    assert lo == 0.0 and hi == pytest.approx(0.161, abs=0.002)  # the "up to about 15%" for 0/20
    lo, hi = wilson(10, 20)
    assert (lo, hi) == pytest.approx((0.299, 0.701), abs=0.002)
    assert wilson(0, 0) == (0.0, 0.0)
    assert wilson(20, 20)[1] == 1.0


def test_prop_carries_counts_and_interval():
    p = prop(3, 4)
    assert (p["k"], p["n"], p["rate"]) == (3, 4, 0.75) and p["lo"] < 0.75 < p["hi"]


@pytest.mark.parametrize(
    "label, predicted, expected",
    [("T1003.001", "T1003.001", True), ("T1003.001", "T1003", False), ("T1110", "T1110.003", True),
     ("T1110", "T1110", True), ("T1059.001", "T1053.005", False), ("T1059.001", None, False), (None, "T1110", False)],
)
def test_technique_match(label, predicted, expected):
    assert technique_match(label, predicted) is expected


def test_percentile():
    assert percentile([], 95) == 0.0
    assert percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 95) == 10
    assert percentile([5.0], 50) == 5.0


def test_summary_counts_and_the_two_recall_definitions():
    results = [
        r("malicious", "malicious", "T1003.001", "T1003.001"),
        r("malicious", "needs_human", "T1110"),
        r("malicious", "benign", "T1053.005"),
        r("malicious", "malicious", "T1110", "T1110.003"),
        r("benign", "benign"), r("benign", "benign"), r("benign", "malicious", predicted="T1003.001"),
        r("benign", "needs_human"),
    ]
    s = summarize(results)
    assert (s["n_malicious"], s["n_benign"]) == (4, 4)
    assert (s["recall_plan"]["k"], s["recall_strict"]["k"]) == (3, 2)  # needs_human counts only for the plan metric
    assert s["benign_fpr"]["k"] == 1 and s["benign_auto_closed"]["k"] == 2
    assert s["needs_human_rate"]["k"] == 2
    assert (s["technique_acc_all"]["k"], s["technique_acc_called"]["k"], s["technique_acc_called"]["n"]) == (2, 2, 2)
    assert s["confusion"]["malicious"] == {"malicious": 2, "needs_human": 1, "benign": 1}


def test_always_answering_needs_human_scores_perfect_plan_recall_but_zero_strict_recall():
    """Why the table shows both: the plan's definition alone can be gamed."""
    s = summarize([r("malicious", "needs_human"), r("malicious", "needs_human"), r("benign", "needs_human")])
    assert s["recall_plan"]["rate"] == 1.0 and s["recall_strict"]["rate"] == 0.0
    assert s["needs_human_rate"]["rate"] == 1.0


def test_cost_and_latency_only_reported_when_every_call_was_live():
    live = [r("malicious", "malicious", seconds=s, cost_usd=0.002) for s in (1.0, 2.0, 3.0)]
    s = summarize(live)
    assert s["all_live"] and s["cost_per_1000"] == pytest.approx(2.0) and s["latency_median"] == 2.0
    mixed = live + [r("benign", "benign", calls=1, cached_calls=1, cost_usd=0.0)]
    s = summarize(mixed)
    assert not s["all_live"] and s["cost_per_1000"] is None  # cached calls would understate the cost


def test_errors_are_counted_and_never_count_as_detections():
    s = summarize([r("malicious", "error"), r("malicious", "malicious", "T1110", "T1110")])
    assert s["errors"] == 1 and s["recall_plan"]["k"] == 1


def test_threshold_sweep_remaps_verdicts_without_new_calls():
    results = [
        r("malicious", "malicious", "T1110", "T1110", confidence=0.9),
        r("malicious", "malicious", "T1110", "T1110", confidence=0.65),
        r("malicious", "needs_human", "T1110", confidence=0.4, model_verdict="malicious"),  # overridden at 0.6
        r("benign", "benign", confidence=0.7),
        r("benign", "malicious", confidence=0.8),
    ]
    by_t = {row["threshold"]: row for row in threshold_sweep(results, [0.0, 0.6, 0.7, 0.95])}
    assert by_t[0.0]["recall_strict"]["k"] == 3 and by_t[0.0]["benign_fpr"]["k"] == 1
    assert by_t[0.6]["recall_strict"]["k"] == 2
    assert by_t[0.7]["recall_strict"]["k"] == 1 and by_t[0.7]["benign_auto_closed"]["k"] == 1
    assert by_t[0.95]["recall_strict"]["k"] == 0 and by_t[0.95]["benign_fpr"]["k"] == 0
    assert by_t[0.95]["recall_plan"]["k"] == 3  # lowering automation never loses a plan-metric detection


# ---- freeze guard --------------------------------------------------------------------------------------------


FROZEN = {"prompt_sha256": "abc", "threshold": 0.6, "effort": "low", "retrieval_k": 5,
          "models": ["claude-haiku-5-5", "claude-sonnet-5-5"], "commit": "deadbeef"}


def test_freeze_accepts_identical_settings():
    assert check_freeze(FROZEN, {**FROZEN, "models": ["claude-haiku-5-5"]}, "") == []


@pytest.mark.parametrize("key, value", [("prompt_sha256", "xyz"), ("threshold", 0.7), ("effort", "high"), ("retrieval_k", 8)])
def test_freeze_rejects_any_changed_setting(key, value):
    problems = check_freeze(FROZEN, {**FROZEN, key: value}, "")
    assert len(problems) == 1 and key in problems[0]


def test_freeze_rejects_unfrozen_models_and_changed_files():
    assert check_freeze(FROZEN, {**FROZEN, "models": ["some-new-model"]}, "")
    problems = check_freeze(FROZEN, FROZEN, "app/triage/prompt.py\n")
    assert problems and "app/triage/prompt.py" in problems[0]
