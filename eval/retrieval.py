"""Retrieval quality: is the correct technique among the top results for each malicious alert?

Usage: python -m eval.retrieval --split dev

Definitions (also in PLAN.md):
  * A retrieved chunk is correct if one of its technique ids equals the alert's label, or is a
    sub-technique of it (label T1110 accepts T1110.003). A parent chunk does NOT count for a
    sub-technique label.
  * hit@5: a correct chunk is among the 5 best. hit@1: it is the best. MRR@5: mean of
    1 / rank of the first correct chunk, 0 when there is none.
Only malicious alerts are scored; benign alerts have no correct technique.
"""

import argparse
import json
import os
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from app.parsers.sysmon import parse_sysmon_json
from app.retrieval import query_text
from app.retrieval.embed import Embedder
from app.retrieval.store import ChunkStore

LABELED = Path(__file__).resolve().parents[1] / "data" / "labeled"
REF = datetime(2026, 11, 1, tzinfo=UTC)
EVAL_TENANT = "eval"
VARIANTS = {"attack + sigma": None, "attack only": ["attack"], "sigma only": ["sigma"]}


def is_correct(label: str, technique_ids: list[str]) -> bool:
    return any(t == label or t.startswith(label + ".") for t in technique_ids)


def load_rows(split: str) -> list[dict]:
    rows = []
    for name in ("malicious.jsonl", "benign.jsonl"):
        path = LABELED / name
        if path.exists():
            rows += [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    return [r for r in rows if r["split"] == split and r["label"] == "malicious"]


def evaluate(rows: list[dict], store: ChunkStore, embedder: Embedder, k: int = 5) -> dict:
    results = {v: defaultdict(lambda: {"n": 0, "hit1": 0, "hit5": 0, "rr": 0.0}) for v in VARIANTS}
    for row in rows:
        alert = parse_sysmon_json(row["record"], REF)
        vector = embedder.embed_query(query_text(alert))
        for variant, sources in VARIANTS.items():
            hits = store.search(EVAL_TENANT, vector, k, sources)
            rank = next((i for i, h in enumerate(hits, 1) if is_correct(row["technique"], h.technique_ids)), None)
            for key in (row["technique"], "ALL"):
                cell = results[variant][key]
                cell["n"] += 1
                if rank == 1:
                    cell["hit1"] += 1
                if rank is not None:
                    cell["hit5"] += 1
                    cell["rr"] += 1 / rank
    return results


def print_report(results: dict, split: str) -> None:
    print(f"Retrieval on the {split} set (malicious alerts only)")
    for variant, per_technique in results.items():
        print(f"\n{variant}")
        print(f"  {'technique':10} {'n':>3} {'hit@1':>7} {'hit@5':>7} {'MRR@5':>7}")
        for key in sorted(per_technique, key=lambda t: (t == "ALL", t)):
            c = per_technique[key]
            n, mrr = c["n"], c["rr"] / c["n"]
            print(f"  {key:10} {n:3} {c['hit1']:>3}/{n:<3} {c['hit5']:>3}/{n:<3} {mrr:7.2f}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", choices=["dev", "test"], default="dev")
    args = parser.parse_args()
    if args.split == "test":
        raise SystemExit("The test split is only run once, in step 6 (eval.run). Refusing.")
    store = ChunkStore(os.environ["DATABASE_URL"])
    results = evaluate(load_rows(args.split), store, Embedder())
    print_report(results, args.split)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
