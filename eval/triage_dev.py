"""Run triage over the DEV set and report validity, outcomes, tokens and cost.

Usage: python -m eval.triage_dev [--model claude-haiku-5-5] [--no-retrieval] [--limit N]

Safety rails:
  * dev split only; the test split is run once, in step 6
  * prints an estimated cost first and stops if it exceeds --max-cost (default $5)
  * every call is cached on disk, so a repeated run makes no API calls and costs nothing
This is a diagnostic for step 4 (do verdicts validate? does the cache work?). The headline metrics
and the three-system comparison come from the step 6 harness.
"""

import argparse
import json
import os
import statistics
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from app.config import load_dotenv
from app.parsers.sysmon import parse_sysmon_json
from app.retrieval import retrieve
from app.retrieval.embed import Embedder
from app.retrieval.store import ChunkStore
from app.triage import triage
from app.triage.llm import PRICES, AnthropicLLM, estimate_cost
from app.triage.prompt import SYSTEM_PROMPT, build_user_message

ROOT = Path(__file__).resolve().parents[1]
LABELED = ROOT / "data" / "labeled"
REF = datetime(2026, 11, 1, tzinfo=UTC)
TENANT = "eval"
CHARS_PER_TOKEN = 3.2  # conservative for English plus logs; real counts are printed after the run
EST_OUTPUT_TOKENS = 700  # low-effort thinking plus the JSON answer


def load_dev_rows() -> list[dict]:
    rows = []
    for name in ("malicious.jsonl", "benign.jsonl"):
        rows += [json.loads(line) for line in (LABELED / name).read_text(encoding="utf-8").splitlines() if line]
    return [r for r in rows if r["split"] == "dev"]


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, round(pct / 100 * (len(ordered) - 1)))]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=None)
    parser.add_argument("--no-retrieval", action="store_true")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--max-cost", type=float, default=5.0)
    args = parser.parse_args()

    load_dotenv()
    llm = AnthropicLLM(model=args.model)
    rows = load_dev_rows()[: args.limit]
    store, embedder = ChunkStore(os.environ["DATABASE_URL"]), Embedder()
    use_retrieval = not args.no_retrieval

    # Estimate before spending anything. Cached calls are free, so count only the uncached ones.
    uncached_in = uncached = 0
    for row in rows:
        alert = parse_sysmon_json(row["record"], REF)
        hits = retrieve(alert, TENANT, store, embedder) if use_retrieval else []
        messages = [{"role": "user", "content": build_user_message(alert, hits)}]
        key = llm._key(SYSTEM_PROMPT, messages, 4000)
        if not (llm.cache_dir / f"{key}.json").exists():
            uncached += 1
            uncached_in += round((len(SYSTEM_PROMPT) + len(messages[0]["content"])) / CHARS_PER_TOKEN)
    estimate = estimate_cost(llm.model, uncached_in, uncached * EST_OUTPUT_TOKENS)
    retrieval_state = "on" if use_retrieval else "off"
    print(f"model {llm.model}, effort {llm.effort}, retrieval {retrieval_state}, {len(rows)} dev alerts")
    unpriced = f"unknown (no price for {llm.model}; known: {sorted(PRICES)})"
    shown = f"${estimate:.3f}" if estimate is not None else unpriced
    print(f"{uncached} need a live call; estimated cost {shown}")
    if estimate is None and uncached:
        print("Refusing to run an unpriced model without a price entry.")
        return 2
    if estimate is not None and estimate > args.max_cost:
        print(f"Estimated cost is over ${args.max_cost:.2f}. Stopping: ask the project owner before running this.")
        return 2
    if uncached and not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        print("No Anthropic credentials in the environment or .env. Set ANTHROPIC_API_KEY and re-run.")
        return 2

    results = []
    for row in rows:
        alert = parse_sysmon_json(row["record"], REF)
        start = time.perf_counter()
        r = triage(alert, TENANT, llm, store, embedder, use_retrieval=use_retrieval)
        results.append({
            "id": row["id"], "label": row["label"], "technique": row["technique"],
            "verdict": r.verdict.verdict, "predicted_technique": r.verdict.technique_id,
            "confidence": r.verdict.confidence, "status": r.status, "reason": r.reason,
            "model_verdict": r.model_verdict, "evidence": len(r.verdict.evidence),
            "quotes_verified": r.quotes_verified, "quotes_total": r.quotes_total,
            "calls": r.usage.calls, "cached_calls": r.usage.cached_calls,
            "input_tokens": r.usage.input_tokens, "output_tokens": r.usage.output_tokens,
            "cost_usd": r.usage.cost_usd, "seconds": round(time.perf_counter() - start, 3),
        })

    n = len(results)
    status = Counter(x["status"] for x in results)
    print(f"\nvalid first try {status['ok']}/{n}, valid after one retry {status['retried']}/{n}, "
          f"fell back to needs_human {status['fallback']}/{n}")
    print("\nconfusion counts (rows: true label, columns: verdict)")
    verdicts = ("malicious", "benign", "needs_human")
    print(f"  {'':10}" + "".join(f"{v:>13}" for v in verdicts))
    for label in ("malicious", "benign"):
        counts = Counter(x["verdict"] for x in results if x["label"] == label)
        print(f"  {label:10}" + "".join(f"{counts[v]:>13}" for v in verdicts))
    live = [x for x in results if x["cached_calls"] < x["calls"]]
    tokens_in, tokens_out = sum(x["input_tokens"] for x in results), sum(x["output_tokens"] for x in results)
    cost = estimate_cost(llm.model, tokens_in, tokens_out)
    print(f"\nlive calls for {len(live)}/{n} alerts; cached for the rest")
    print(f"tokens this run (live calls only): {tokens_in} in, {tokens_out} out; estimated cost "
          + (f"${cost:.4f}" if cost is not None else "unknown"))
    if live:
        seconds = [x["seconds"] for x in live]
        print(f"latency per live alert: median {statistics.median(seconds):.2f}s, p95 {percentile(seconds, 95):.2f}s")
    tv, tt = sum(x["quotes_verified"] for x in results), sum(x["quotes_total"] for x in results)
    print(f"evidence quotes found verbatim in their source: {tv}/{tt}")

    out = ROOT / "docs" / f"triage_dev_{llm.model}{'' if use_retrieval else '_noretrieval'}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"model": llm.model, "effort": llm.effort, "retrieval": use_retrieval,
                               "split": "dev", "results": results}, indent=1), encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
