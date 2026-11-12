"""Eval smoke gate for CI: python -m eval.smoke

Runs with no API key, no database and no network, so it is free and safe on every push. It does not
call the model, so it cannot see model drift; the live evaluation is a manual, costed step (see README).
What it does catch: a change to the parser, the rules baseline or the metrics code that would make the
published numbers in docs/ stop matching the code, and a prompt that no longer matches what was measured.

Checks
  1. Labeled data has the expected shape (52 malicious, 60 benign, 20 injection samples, fixed splits).
  2. The rules-only baseline, run on every dev and test alert, reproduces the stored per-alert verdicts.
  3. The metrics code, run on the stored per-alert results, reproduces the stored summaries.
  4. The system prompt hash equals the one in docs/freeze.json and docs/results_test.json.
  5. The test set was run exactly once (lock file present) and no injection sample turned `benign`.
"""

import json
import sys

from app.parsers.sysmon import parse_sysmon_json
from eval import baseline
from eval.metrics import summarize
from eval.run import DOCS, FREEZE, LABELED, LOCK, REF, load_rows, prompt_hash

EXPECTED_ROWS = {("malicious", "dev"): 18, ("malicious", "test"): 34, ("benign", "dev"): 18, ("benign", "test"): 42}
COUNT_KEYS = ("recall_plan", "recall_strict", "benign_fpr", "benign_auto_closed", "needs_human_rate",
              "technique_acc_all", "technique_acc_called")


def _load(path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def check_data() -> list[str]:
    problems = []
    for split in ("dev", "test"):
        rows = load_rows(split)
        for label in ("malicious", "benign"):
            got = sum(r["label"] == label for r in rows)
            want = EXPECTED_ROWS[(label, split)]
            if got != want:
                problems.append(f"{label}/{split}: {got} rows, expected {want}")
    injection = (LABELED / "injection.jsonl").read_text(encoding="utf-8").splitlines()
    if len([line for line in injection if line]) != 20:
        problems.append("injection.jsonl should have 20 samples")
    return problems


def check_baseline(split: str) -> list[str]:
    stored = _load(DOCS / f"results_{split}.json")["systems"]["rules_only"]["results"]
    by_id = {r["id"]: r for r in stored}
    problems = []
    for row in load_rows(split):
        verdict, technique = baseline.predict(parse_sysmon_json(row["record"], REF))
        old = by_id.get(row["id"])
        if old is None:
            problems.append(f"{split}/{row['id']}: not in stored results")
        elif (verdict, technique) != (old["verdict"], old["predicted_technique"]):
            problems.append(f"{split}/{row['id']}: rules now say {verdict}/{technique}, "
                            f"stored {old['verdict']}/{old['predicted_technique']}")
    return problems


def check_metrics(split: str) -> list[str]:
    problems = []
    for name, block in _load(DOCS / f"results_{split}.json")["systems"].items():
        fresh, stored = summarize(block["results"]), block["summary"]
        for key in COUNT_KEYS:
            if (fresh[key]["k"], fresh[key]["n"]) != (stored[key]["k"], stored[key]["n"]):
                problems.append(f"{split}/{name}/{key}: recomputed {fresh[key]['k']}/{fresh[key]['n']}, "
                                f"stored {stored[key]['k']}/{stored[key]['n']}")
        if fresh["confusion"] != stored["confusion"]:
            problems.append(f"{split}/{name}: confusion counts differ from the stored summary")
    return problems


def check_prompt_and_lock() -> list[str]:
    problems = []
    current = prompt_hash()
    for label, path in (("freeze.json", FREEZE), ("results_test.json", DOCS / "results_test.json")):
        stored = _load(path)["prompt_sha256"]
        if stored != current:
            problems.append(f"system prompt changed since {label} ({stored[:12]} -> {current[:12]}). "
                            "Re-run the evaluation and update the results before merging.")
    if not LOCK.exists():
        problems.append("docs/test_run.lock.json is missing: the single test run is not recorded")
    for path in sorted(DOCS.glob("injection_*.json")):
        fooled = _load(path)["fooled"]
        if fooled:
            problems.append(f"{path.name}: {fooled} injection sample(s) turned the verdict benign")
    return problems


def main() -> int:
    stages = [("labeled data shape", check_data)]
    for split in ("dev", "test"):
        stages.append((f"rules baseline reproduces stored {split} verdicts", lambda s=split: check_baseline(s)))
        stages.append((f"metrics reproduce stored {split} summaries", lambda s=split: check_metrics(s)))
    stages.append(("prompt hash, test lock, injection results", check_prompt_and_lock))

    failed = 0
    for title, fn in stages:
        problems = fn()
        print(f"{'FAIL' if problems else 'ok  '}  {title}")
        for p in problems:
            print(f"        - {p}")
        failed += bool(problems)
    print("eval smoke gate:", "FAILED" if failed else "passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
