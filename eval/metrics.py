"""Metrics for the three-system comparison. Pure functions, no I/O, easy to test.

Each per-alert result is a dict with at least: label ("malicious"|"benign"), technique (label or
None), verdict ("malicious"|"benign"|"needs_human"|"error"), predicted_technique, confidence,
model_verdict (what the model said before the confidence threshold overrode it, else None), status,
seconds, cost_usd, calls, cached_calls.

Every proportion is returned with its counts and a 95% Wilson interval, because the sets are small.
"""

import math
import statistics
from collections import Counter

VERDICTS = ("malicious", "benign", "needs_human")


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for k successes in n trials."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def prop(k: int, n: int) -> dict:
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": (k / n) if n else 0.0, "lo": lo, "hi": hi}


def technique_match(label: str | None, predicted: str | None) -> bool:
    """Correct if equal, or if the prediction is a sub-technique of the label (T1110 accepts T1110.003)."""
    if not label or not predicted:
        return False
    return predicted == label or predicted.startswith(label + ".")


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, round(pct / 100 * (len(ordered) - 1)))]


def summarize(results: list[dict]) -> dict:
    mal = [r for r in results if r["label"] == "malicious"]
    ben = [r for r in results if r["label"] == "benign"]
    called_mal = [r for r in mal if r["verdict"] == "malicious"]

    live = [r for r in results if r.get("calls", 0) and r["cached_calls"] < r["calls"]]
    llm = [r for r in results if r.get("calls", 0)]
    all_live = bool(llm) and len(live) == len(llm)
    costs = [r["cost_usd"] for r in llm if r.get("cost_usd") is not None]

    return {
        "n": len(results),
        "n_malicious": len(mal),
        "n_benign": len(ben),
        "recall_plan": prop(sum(r["verdict"] in ("malicious", "needs_human") for r in mal), len(mal)),
        "recall_strict": prop(len(called_mal), len(mal)),
        "benign_fpr": prop(sum(r["verdict"] == "malicious" for r in ben), len(ben)),
        "benign_auto_closed": prop(sum(r["verdict"] == "benign" for r in ben), len(ben)),
        "needs_human_rate": prop(sum(r["verdict"] == "needs_human" for r in results), len(results)),
        "technique_acc_all": prop(sum(technique_match(r["technique"], r.get("predicted_technique")) for r in mal), len(mal)),
        "technique_acc_called": prop(
            sum(technique_match(r["technique"], r.get("predicted_technique")) for r in called_mal), len(called_mal)
        ),
        "confusion": {
            lab: dict(Counter(r["verdict"] for r in results if r["label"] == lab)) for lab in ("malicious", "benign")
        },
        "validity": dict(Counter(r.get("status", "n/a") for r in results)),
        "errors": sum(r["verdict"] == "error" for r in results),
        "quotes": {
            "verified": sum(r.get("quotes_verified", 0) for r in results),
            "total": sum(r.get("quotes_total", 0) for r in results),
        },
        # Cost and latency only mean something when every call was live (not served from the cache).
        "all_live": all_live,
        "cost_per_1000": (sum(costs) / len(costs) * 1000) if (all_live and costs) else None,
        "total_cost": sum(costs) if costs else 0.0,
        "latency_median": statistics.median([r["seconds"] for r in live]) if live else None,
        "latency_p95": percentile([r["seconds"] for r in live], 95) if live else None,
        "live_alerts": len(live),
        "tokens_in": sum(r.get("input_tokens", 0) for r in results),
        "tokens_out": sum(r.get("output_tokens", 0) for r in results),
    }


def threshold_sweep(results: list[dict], thresholds: list[float]) -> list[dict]:
    """What the verdicts would have been at other confidence thresholds (no new model calls needed).

    The threshold is applied after the model answers, so a stored result carries everything needed:
    the model's own verdict (model_verdict when it was overridden, else verdict) and its confidence.
    """
    rows = []
    for t in thresholds:
        remapped = []
        for r in results:
            raw = r.get("model_verdict") or r["verdict"]
            verdict = raw if (raw in ("needs_human", "error") or r["confidence"] >= t) else "needs_human"
            remapped.append({**r, "verdict": verdict})
        s = summarize(remapped)
        rows.append({
            "threshold": t,
            "recall_strict": s["recall_strict"], "recall_plan": s["recall_plan"],
            "benign_fpr": s["benign_fpr"], "benign_auto_closed": s["benign_auto_closed"],
            "needs_human_rate": s["needs_human_rate"],
        })
    return rows
