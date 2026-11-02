"""Evaluation harness: rules only vs LLM without retrieval vs LLM with retrieval (and a larger model).

  python -m eval.run --split dev                 # tune and inspect on dev, as often as you like
  python -m eval.run --sweep                     # threshold sweep from stored dev results (no API calls)
  python -m eval.run --freeze                    # record prompt, threshold, models and commit
  python -m eval.run --split test --final        # the one test run (refuses if anything changed)

Safeguards, because the test set is only worth something if it is touched once:
  * `--freeze` writes docs/freeze.json. A test run refuses unless the prompt, threshold, effort and
    models are unchanged and `app/` and `data/labeled/` have not changed since the frozen commit.
  * A completed test run writes docs/test_run.lock.json; a second test run is refused. A run that is
    interrupted or hits an API error writes nothing and can simply be repeated: finished calls come
    from the on-disk cache, so repeating costs nothing and cannot change earlier answers.
  * Every run prints an estimated cost first and stops above --max-cost (default $5).
"""

import argparse
import hashlib
import json
import os
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

import anthropic

from app.config import load_dotenv
from app.parsers.sysmon import parse_sysmon_json
from app.retrieval import retrieve
from app.retrieval.embed import Embedder
from app.retrieval.store import ChunkStore
from app.triage import DEFAULT_THRESHOLD, triage
from app.triage.llm import AnthropicLLM, estimate_cost
from app.triage.prompt import SYSTEM_PROMPT, build_user_message
from eval import baseline
from eval.metrics import prop, summarize, threshold_sweep
from eval.retrieval import evaluate as retrieval_evaluate

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
LABELED = ROOT / "data" / "labeled"
FREEZE = DOCS / "freeze.json"
LOCK = DOCS / "test_run.lock.json"
REF = datetime(2026, 11, 1, tzinfo=UTC)
TENANT = "eval"
SMALL, LARGE = "claude-haiku-5-5", "claude-sonnet-5-5"
EFFORT = "low"

SYSTEMS = {
    "rules_only": {"title": "Rules only", "kind": "rules"},
    "llm_no_rag": {"title": "LLM, no retrieval", "kind": "llm", "retrieval": False, "model": SMALL},
    "llm_rag": {"title": "LLM + retrieval", "kind": "llm", "retrieval": True, "model": SMALL},
    "llm_rag_sonnet": {"title": "LLM + retrieval (Sonnet)", "kind": "llm", "retrieval": True, "model": LARGE},
}
DEFAULT_SYSTEMS = ["rules_only", "llm_no_rag", "llm_rag"]


# ---- data -------------------------------------------------------------------------------------------------------


def load_rows(split: str) -> list[dict]:
    rows = []
    for name in ("malicious.jsonl", "benign.jsonl"):
        rows += [json.loads(line) for line in (LABELED / name).read_text(encoding="utf-8").splitlines() if line]
    return [r for r in rows if r["split"] == split]


def prompt_hash() -> str:
    return hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest()


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()


# ---- freeze and lock --------------------------------------------------------------------------------------------


def current_settings(systems: list[str]) -> dict:
    return {
        "prompt_sha256": prompt_hash(),
        "threshold": DEFAULT_THRESHOLD,
        "effort": EFFORT,
        "retrieval_k": 5,
        "models": sorted({SYSTEMS[s]["model"] for s in systems if SYSTEMS[s]["kind"] == "llm"}),
    }


def write_freeze() -> int:
    dirty = git("status", "--porcelain", "--", "app", "data/labeled", "eval")
    if dirty:
        print("Commit your changes to app/, eval/ and data/labeled/ before freezing:\n" + dirty)
        return 2
    settings = current_settings(list(SYSTEMS))
    settings.update({"commit": git("rev-parse", "HEAD"), "frozen_at": datetime.now(UTC).isoformat(timespec="seconds"),
                     "note": "Prompt, threshold, effort, models and the code in app/ and data/labeled/ are fixed "
                             "from this commit on. The test set may be run once after this."})
    DOCS.mkdir(exist_ok=True)
    FREEZE.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    print(f"froze at {settings['commit'][:10]}: prompt {settings['prompt_sha256'][:12]}, threshold {settings['threshold']}, "
          f"models {settings['models']}")
    return 0


def check_freeze(frozen: dict, current: dict, changed_files: str) -> list[str]:
    """Reasons the test run must be refused (empty list = OK). Pure, so it can be tested."""
    problems = []
    for key in ("prompt_sha256", "threshold", "effort", "retrieval_k"):
        if frozen.get(key) != current.get(key):
            problems.append(f"{key} changed since the freeze ({frozen.get(key)!r} -> {current.get(key)!r})")
    unknown = set(current["models"]) - set(frozen.get("models", []))
    if unknown:
        problems.append(f"models not in the freeze: {sorted(unknown)}")
    if changed_files.strip():
        problems.append("files changed since the frozen commit:\n" + changed_files.strip())
    return problems


# ---- running one system ------------------------------------------------------------------------------------------


def make_llm(model: str) -> AnthropicLLM:
    return AnthropicLLM(model=model, effort=EFFORT)


def preflight(llm: AnthropicLLM, rows: list[dict], use_retrieval: bool, store, embedder) -> tuple[int, float | None]:
    uncached = chars = 0
    for row in rows:
        alert = parse_sysmon_json(row["record"], REF)
        hits = retrieve(alert, TENANT, store, embedder) if use_retrieval else []
        messages = [{"role": "user", "content": build_user_message(alert, hits)}]
        if not (llm.cache_dir / f"{llm._key(SYSTEM_PROMPT, messages, 4000)}.json").exists():
            uncached += 1
            chars += len(SYSTEM_PROMPT) + len(messages[0]["content"])
    return uncached, estimate_cost(llm.model, round(chars / 3.2), uncached * 700)


def run_system(name: str, rows: list[dict], store, embedder) -> list[dict]:
    cfg = SYSTEMS[name]
    llm = make_llm(cfg["model"]) if cfg["kind"] == "llm" else None
    results = []
    for row in rows:
        alert = parse_sysmon_json(row["record"], REF)
        base = {"id": row["id"], "label": row["label"], "technique": row["technique"],
                "lookalike_of": row.get("lookalike_of")}
        start = time.perf_counter()
        if cfg["kind"] == "rules":
            verdict, technique = baseline.predict(alert)
            results.append({**base, "verdict": verdict, "predicted_technique": technique, "confidence": 1.0,
                            "model_verdict": None, "status": "n/a", "seconds": time.perf_counter() - start,
                            "cost_usd": 0.0, "calls": 0, "cached_calls": 0, "evidence": []})
            continue
        try:
            r = triage(alert, TENANT, llm, store, embedder, use_retrieval=cfg["retrieval"], threshold=DEFAULT_THRESHOLD)
        except anthropic.APIError as exc:
            results.append({**base, "verdict": "error", "predicted_technique": None, "confidence": 0.0,
                            "model_verdict": None, "status": f"error: {type(exc).__name__}",
                            "seconds": time.perf_counter() - start, "cost_usd": None, "calls": 1, "cached_calls": 0,
                            "evidence": []})
            continue
        results.append({
            **base, "verdict": r.verdict.verdict, "predicted_technique": r.verdict.technique_id,
            "confidence": r.verdict.confidence, "model_verdict": r.model_verdict, "status": r.status,
            "reason": r.reason, "seconds": time.perf_counter() - start, "cost_usd": r.usage.cost_usd,
            "input_tokens": r.usage.input_tokens, "output_tokens": r.usage.output_tokens,
            "calls": r.usage.calls, "cached_calls": r.usage.cached_calls,
            "quotes_verified": r.quotes_verified, "quotes_total": r.quotes_total,
            "rationale": r.verdict.rationale,
            "evidence": [e.model_dump() for e in r.verdict.evidence],
            "retrieved": [x.ref for x in r.retrieved],
        })
    return results


# ---- report -----------------------------------------------------------------------------------------------------


def fmt(p: dict) -> str:
    if not p["n"]:
        return "n/a"
    return f"{p['k']}/{p['n']} ({p['rate']:.0%}; {p['lo']:.0%}-{p['hi']:.0%})"


def injection_cell(model: str, retrieval: bool) -> str:
    path = DOCS / f"injection_{model}{'' if retrieval else '_noretrieval'}.json"
    if not path.exists():
        return "not measured"
    d = json.loads(path.read_text(encoding="utf-8"))
    return fmt(prop(d["n"] - d["fooled"], d["n"]))


def build_report(split: str, summaries: dict, hit5: dict | None, notes: list[str]) -> str:
    cols = list(summaries)
    head = "| Measure | " + " | ".join(SYSTEMS[c]["title"] for c in cols) + " |\n"
    head += "|---|" + "---|" * len(cols) + "\n"

    def row(label: str, fn) -> str:
        return f"| {label} | " + " | ".join(fn(c, summaries[c]) for c in cols) + " |\n"

    def cost(c, s):
        if SYSTEMS[c]["kind"] == "rules":
            return "$0"
        return f"${s['cost_per_1000']:.2f}" if s["cost_per_1000"] is not None else "n/a (cache)"

    def lat(c, s):
        if SYSTEMS[c]["kind"] == "rules":
            return "<0.01 s"
        return f"{s['latency_median']:.1f} s / {s['latency_p95']:.1f} s" if s["latency_median"] is not None else "n/a"

    def quotes(c, s):
        q = s["quotes"]
        return f"{q['verified']}/{q['total']}" if SYSTEMS[c]["kind"] == "llm" else "n/a"

    def validity(c, s):
        v = s["validity"]
        return f"{v.get('ok', 0)} / {v.get('retried', 0)} / {v.get('fallback', 0)}" if SYSTEMS[c]["kind"] == "llm" else "n/a"

    out = f"# Results: {split} set\n\n"
    first = next(iter(summaries.values()))
    out += (f"{first['n_malicious']} malicious and {first['n_benign']} benign alerts. Rates show counts and a 95% Wilson "
            f"interval. With sets this small the intervals are wide: read them before reading the percentages.\n\n")
    out += head
    out += row("Malicious recall, plan definition (malicious or needs_human)", lambda c, s: fmt(s["recall_plan"]))
    out += row("Malicious actually called `malicious`", lambda c, s: fmt(s["recall_strict"]))
    out += row("Benign false-positive rate (benign called malicious)", lambda c, s: fmt(s["benign_fpr"]))
    out += row("Benign auto-closed as benign", lambda c, s: fmt(s["benign_auto_closed"]))
    out += row("Sent to a human (needs_human, all alerts)", lambda c, s: fmt(s["needs_human_rate"]))
    out += row("Technique accuracy, top-1 (all malicious)", lambda c, s: fmt(s["technique_acc_all"]))
    out += row("Technique accuracy (among those called malicious)", lambda c, s: fmt(s["technique_acc_called"]))
    out += row("Retrieval hit@5", lambda c, s: fmt(hit5) if (hit5 and SYSTEMS[c].get("retrieval")) else "n/a")
    out += row("Evidence quotes found word for word in source", quotes)
    out += row("Answers valid first try / after retry / fell back", validity)
    out += row("Injection resistance (20 samples)",
               lambda c, s: injection_cell(SYSTEMS[c]["model"], SYSTEMS[c]["retrieval"]) if SYSTEMS[c]["kind"] == "llm" else "n/a")
    out += row("Cost per 1,000 alerts", cost)
    out += row("Latency per alert, median / 95th percentile", lat)
    out += "\n## Confusion counts (rows: true label; columns: verdict)\n\n"
    for c in cols:
        conf = summaries[c]["confusion"]
        out += f"**{SYSTEMS[c]['title']}**\n\n| true \\ verdict | malicious | benign | needs_human | error |\n|---|---|---|---|---|\n"
        for lab in ("malicious", "benign"):
            counts = conf.get(lab, {})
            out += f"| {lab} | " + " | ".join(str(counts.get(v, 0)) for v in ("malicious", "benign", "needs_human", "error")) + " |\n"
        out += "\n"
    out += "## Notes and limitations\n\n" + "\n".join(f"- {n}" for n in notes) + "\n"
    return out


NOTES = [
    "Small samples: the confidence intervals above are the honest uncertainty. A difference between two systems "
    "smaller than the intervals is not evidence of a real difference.",
    "Labels come from the dataset an event is filed under, not from a judgement about each event. Some \"malicious\" "
    "events look harmless alone, so a model that calls one benign may be right. See DATA_SOURCES.md.",
    "The plan's recall counts needs_human as caught. That is easy to inflate (always answer needs_human), so the "
    "table also shows how many malicious alerts were actually called malicious and how much work goes to a human.",
    "Benign alerts are synthetic look-alikes written by this project's author. Public datasets and Sigma rules may "
    "have been seen by the model during training, and Sigma rules were written for the same behaviours.",
    "The rules-only baseline was written by the same author who built the labeled sets and is illustrative, not an "
    "independent benchmark.",
    "Cost and latency come from live calls with `effort: low`; latency includes embedding the query and the database "
    "search. Prices are Anthropic's published rates; check them before quoting a total.",
]


# ---- faithfulness review sheet ----------------------------------------------------------------------------------


def write_faithfulness_sheet(results: list[dict], rows_by_id: dict, store, embedder, path: Path, n: int = 20) -> None:
    import random

    candidates = [r for r in results if r["evidence"]]
    random.Random(20261103).shuffle(candidates)
    picked = sorted(candidates[:n], key=lambda r: r["id"])
    out = ["# Evidence faithfulness review (to be filled in by a person)\n",
           f"{len(picked)} verdicts from the LLM + retrieval system, drawn at random (fixed seed) from those with evidence. "
           "For each evidence item, check whether the quoted source really supports the claim being made, and write "
           "`yes`, `partly` or `no`. Then record the counts at the bottom. The `verbatim` flag is only an automated "
           "text match, not a judgement of support.\n"]
    for r in picked:
        alert = parse_sysmon_json(rows_by_id[r["id"]]["record"], REF)
        hits = {h.ref: h for h in retrieve(alert, TENANT, store, embedder)}
        out.append(f"\n## {r['id']}  (true label: {r['label']}, verdict: **{r['verdict']}**, confidence {r['confidence']:.2f})\n")
        out.append(f"- Alert: `{alert.event_type}` | process `{alert.process}` | details `{(alert.command_line or '')[:300]}`")
        out.append(f"- Rationale: {r['rationale']}\n")
        for i, ev in enumerate(r["evidence"], 1):
            if ev["source"] == "alert_field":
                source_text = str(getattr(alert, ev["ref"], "") or "")
            else:
                hit = hits.get(ev["ref"]) or next((h for h in hits.values() if ev["ref"] in h.technique_ids), None)
                source_text = hit.content if hit else "(source not found)"
            verbatim = " ".join(ev["quote"].lower().split()) in " ".join(source_text.lower().split())
            out.append(f"  {i}. **{ev['source']} / {ev['ref']}**; quote: \"{ev['quote']}\" (verbatim: {'yes' if verbatim else 'no'})")
            out.append(f"     - Source text: {source_text[:600].replace(chr(10), ' ')}")
            out.append("     - Supports the claim? ____")
    out.append("\n## Totals (fill in)\n\nEvidence items checked: ____  yes: ____  partly: ____  no: ____\n")
    path.write_text("\n".join(out), encoding="utf-8")


# ---- main -------------------------------------------------------------------------------------------------------


def sweep() -> int:
    stored = DOCS / "results_dev.json"
    if not stored.exists():
        print("Run `python -m eval.run --split dev` first.")
        return 2
    data = json.loads(stored.read_text(encoding="utf-8"))
    ts = [0.0, 0.5, 0.6, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95]
    for name, block in data["systems"].items():
        if SYSTEMS[name]["kind"] != "llm":
            continue
        print(f"\n{SYSTEMS[name]['title']} (dev, {block['summary']['n']} alerts). Threshold applied after the model answers.")
        print(f"{'thr':>5} {'called malicious':>18} {'plan recall':>13} {'benign->mal':>13} {'benign closed':>15} {'to human':>10}")
        for r in threshold_sweep(block["results"], ts):
            print(f"{r['threshold']:>5.2f} {r['recall_strict']['k']:>9}/{r['recall_strict']['n']:<8}"
                  f"{r['recall_plan']['k']:>6}/{r['recall_plan']['n']:<6}{r['benign_fpr']['k']:>6}/{r['benign_fpr']['n']:<6}"
                  f"{r['benign_auto_closed']['k']:>8}/{r['benign_auto_closed']['n']:<6}{r['needs_human_rate']['k']:>5}/{r['needs_human_rate']['n']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", choices=["dev", "test"])
    parser.add_argument("--systems", default=",".join(DEFAULT_SYSTEMS))
    parser.add_argument("--with-sonnet", action="store_true")
    parser.add_argument("--final", action="store_true", help="required for the test split")
    parser.add_argument("--freeze", action="store_true")
    parser.add_argument("--sweep", action="store_true")
    parser.add_argument("--max-cost", type=float, default=5.0)
    args = parser.parse_args()

    if args.freeze:
        return write_freeze()
    if args.sweep:
        return sweep()
    if not args.split:
        parser.error("--split is required")

    systems = args.systems.split(",") + (["llm_rag_sonnet"] if args.with_sonnet else [])
    unknown = [s for s in systems if s not in SYSTEMS]
    if unknown:
        parser.error(f"unknown systems: {unknown}")

    if args.split == "test":
        if not args.final:
            print("The test split needs --final. It is run once, after `--freeze`.")
            return 2
        if LOCK.exists():
            print(f"{LOCK.name} exists: the test set was already run (see docs/results.md). Refusing a second run.")
            return 2
        if not FREEZE.exists():
            print("No docs/freeze.json. Run `python -m eval.run --freeze` first.")
            return 2
        frozen = json.loads(FREEZE.read_text(encoding="utf-8"))
        changed = git("diff", "--name-only", frozen["commit"], "--", "app", "data/labeled") + git("status", "--porcelain", "--", "app", "data/labeled")
        problems = check_freeze(frozen, current_settings(systems), changed)
        if problems:
            print("Refusing the test run:\n- " + "\n- ".join(problems))
            return 2

    load_dotenv()
    rows = load_rows(args.split)
    store, embedder = ChunkStore(os.environ["DATABASE_URL"]), Embedder()

    # Cost guard before any live call.
    total = 0.0
    for name in systems:
        cfg = SYSTEMS[name]
        if cfg["kind"] != "llm":
            continue
        uncached, est = preflight(make_llm(cfg["model"]), rows, cfg["retrieval"], store, embedder)
        total += est or 0.0
        print(f"{cfg['title']:28} {uncached:3} live calls, estimated ${est or 0:.3f}")
    print(f"estimated total ${total:.3f} for {len(rows)} {args.split} alerts")
    if total > args.max_cost:
        print(f"Over ${args.max_cost:.2f}. Stopping: ask the project owner before running this.")
        return 2
    if total > 0 and not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        print("No Anthropic credentials in the environment or .env.")
        return 2

    all_results, summaries = {}, {}
    for name in systems:
        print(f"running {SYSTEMS[name]['title']} ...", flush=True)
        all_results[name] = run_system(name, rows, store, embedder)
        summaries[name] = summarize(all_results[name])

    if args.split == "test" and any(s["errors"] for s in summaries.values()):
        print("Some calls failed (provider errors). Nothing was written. Repeat the command: finished calls are cached.")
        return 3

    mal_rows = [r for r in rows if r["label"] == "malicious"]
    hit = retrieval_evaluate(mal_rows, store, embedder)["attack + sigma"]["ALL"]
    hit5 = prop(hit["hit5"], hit["n"])

    DOCS.mkdir(exist_ok=True)
    stem = "results" if args.split == "test" else "results_dev"
    notes = list(NOTES)
    if args.split == "dev":
        notes.insert(0, "DEV set: used while building. Numbers here are for inspection and are not the headline result.")
    report = build_report(args.split, summaries, hit5, notes)
    (DOCS / f"{stem}.md").write_text(report, encoding="utf-8")
    payload = {"split": args.split, "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
               "threshold": DEFAULT_THRESHOLD, "prompt_sha256": prompt_hash(), "retrieval_hit5": hit5,
               "systems": {n: {"summary": summaries[n], "results": all_results[n]} for n in systems}}
    (DOCS / f"results_{args.split}.json").write_text(json.dumps(payload, indent=1), encoding="utf-8")
    print(report)

    if args.split == "test":
        rows_by_id = {r["id"]: r for r in rows}
        if "llm_rag" in all_results:
            write_faithfulness_sheet(all_results["llm_rag"], rows_by_id, store, embedder, DOCS / "faithfulness_review.md")
        LOCK.write_text(json.dumps({"ran_at": datetime.now(UTC).isoformat(timespec="seconds"),
                                    "commit": git("rev-parse", "HEAD"), "systems": systems,
                                    "note": "The test set has been run. Do not run it again."}, indent=2) + "\n",
                        encoding="utf-8")
        print(f"wrote docs/results.md, docs/results_test.json, docs/faithfulness_review.md and {LOCK.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
