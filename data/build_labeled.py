"""Build data/labeled/malicious.jsonl from the downloaded OTRF and Splunk files.

Run data/fetch_otrf.py and data/fetch_splunk.py first.

How events are chosen (so the labels can be defended):
  * The label is the technique the DATASET is filed under (OTRF metadata / Splunk folder).
  * Those captures also hold plenty of unrelated background events, so each technique has a
    SELECTOR: a structural test (event type plus the tool or object involved) for events that
    the attack itself produces. It deliberately avoids matching on the strings a detection
    rule would key on, wherever the event type alone is enough.
  * Events are kept only if their fingerprint is new, so near-identical events do not pad the
    set, then sampled round-robin across source files with a fixed seed.

Usage: python -I data/build_labeled.py   (reads untrusted files: run in isolated mode)
"""

import json
import random
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))  # -I removes the script dir from the path; add the repo root back

from app.fingerprint import fingerprint  # noqa: E402
from app.parsers import ParseError  # noqa: E402
from app.parsers.sysmon import parse_sysmon_json  # noqa: E402
from data.eventsource import read_otrf, read_splunk_xml  # noqa: E402
from data.fetch_otrf import DATASETS as OTRF_DATASETS  # noqa: E402
from data.fetch_otrf import local_path as otrf_path  # noqa: E402
from data.fetch_splunk import FILES as SPLUNK_FILES  # noqa: E402
from data.fetch_splunk import RAW_DIR as SPLUNK_DIR  # noqa: E402
from data.fetch_splunk import local_name as splunk_name  # noqa: E402

SEED = 20261101
PER_TECHNIQUE = 10
DEV_PER_TECHNIQUE = 3  # 3 dev + 7 test per technique, about a 40/80 dev/test split
OUT = ROOT / "data" / "labeled" / "malicious.jsonl"
REF = datetime(2026, 11, 1, tzinfo=UTC)

DUMP_ACCESS = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1f3fff", "0x1400"}
OS_PROCESSES_THAT_TOUCH_LSASS = {"svchost.exe", "msmpeng.exe", "csrss.exe", "wininit.exe", "services.exe"}
ADMIN_SHARES = ("\\\\*\\c$", "\\\\*\\admin$", "\\\\*\\ipc$")


def base(path) -> str:
    return str(path or "").replace("\\", "/").rsplit("/", 1)[-1].lower()


def eid(e: dict) -> str:
    return str(e.get("EventID"))


def sel_powershell(e: dict) -> bool:
    return (eid(e) == "1" and base(e.get("Image")) in {"powershell.exe", "pwsh.exe"}) or (
        eid(e) == "4688" and base(e.get("NewProcessName")) in {"powershell.exe", "pwsh.exe"}
    )


def sel_schtasks(e: dict) -> bool:
    if eid(e) == "4698":
        return not str(e.get("TaskName", "")).lower().startswith("\\microsoft\\windows\\")
    return (eid(e) == "1" and base(e.get("Image")) == "schtasks.exe") or (
        eid(e) == "4688" and base(e.get("NewProcessName")) == "schtasks.exe"
    )


def sel_runkey(e: dict) -> bool:
    target = str(e.get("TargetObject", "")).lower()
    if eid(e) == "13" and "\\currentversion\\run" in target:
        return base(e.get("Image")) != "msmpeng.exe"
    command = str(e.get("CommandLine", "")).lower()
    return eid(e) in {"1", "4688"} and "currentversion\\run" in command


def sel_lsass(e: dict) -> bool:
    if eid(e) == "10":
        return (
            base(e.get("TargetImage")) == "lsass.exe"
            and str(e.get("GrantedAccess", "")).lower() in DUMP_ACCESS
            and base(e.get("SourceImage")) not in OS_PROCESSES_THAT_TOUCH_LSASS
        )
    command = str(e.get("CommandLine", "")).lower()
    return eid(e) in {"1", "4688"} and any(
        k in command for k in ("comsvcs", "procdump", "createdump", "sekurlsa", "lsass")
    )


def sel_smb(e: dict) -> bool:
    if eid(e) not in {"5140", "5145"} or str(e.get("SubjectUserName", "")).endswith("$"):
        return False
    return str(e.get("ShareName", "")).lower() in ADMIN_SHARES


def sel_failed_logon(e: dict) -> bool:
    return eid(e) == "4625"


SELECTORS = {
    "T1059.001": sel_powershell,
    "T1053.005": sel_schtasks,
    "T1547.001": sel_runkey,
    "T1003.001": sel_lsass,
    "T1021.002": sel_smb,
    "T1110": sel_failed_logon,
}


def sources():
    """Yield (technique, source_name, dataset_key, events)."""
    for technique, items in OTRF_DATASETS.items():
        for dataset_id, url_path in items:
            path = otrf_path(url_path)
            if path.exists():
                yield technique, "otrf", f"{dataset_id}:{path.stem}", read_otrf(path)
    for technique, folder, name in SPLUNK_FILES:
        path = SPLUNK_DIR / splunk_name(technique, folder, name)
        if path.exists():
            yield technique, "splunk", f"{technique}/{folder}/{name}", read_splunk_xml(path)


def main() -> int:
    rng = random.Random(SEED)
    # technique -> dataset -> list of (fingerprint, event); only the first event per fingerprint
    pool: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    seen: dict[str, set[str]] = defaultdict(set)
    meta: dict[str, str] = {}
    stats = defaultdict(lambda: [0, 0, 0])  # selected, unparseable, distinct

    for technique, source, dataset_key, events in sources():
        meta[dataset_key] = source
        selector = SELECTORS[technique]
        for event in events:
            if not selector(event):
                continue
            stats[technique][0] += 1
            try:
                parsed = parse_sysmon_json(event, REF)
            except ParseError:
                stats[technique][1] += 1
                continue
            fp = fingerprint("lab", parsed.host, parsed.user, parsed.process,
                             parsed.command_line, parsed.event_type)
            if fp in seen[technique]:
                continue
            seen[technique].add(fp)
            stats[technique][2] += 1
            pool[technique][dataset_key].append(event)

    rows = []
    for technique in SELECTORS:
        datasets = sorted(pool[technique])
        for key in datasets:
            rng.shuffle(pool[technique][key])
        chosen = []  # (dataset_key, event), round-robin across datasets
        while len(chosen) < PER_TECHNIQUE and any(pool[technique][k] for k in datasets):
            for key in datasets:
                if pool[technique][key] and len(chosen) < PER_TECHNIQUE:
                    chosen.append((key, pool[technique][key].pop()))
        rng.shuffle(chosen)
        for i, (key, event) in enumerate(chosen):
            rows.append({
                "id": f"mal-{technique}-{i + 1:02d}",
                "label": "malicious",
                "technique": technique,
                "split": "dev" if i < DEV_PER_TECHNIQUE else "test",
                "dataset": key,
                "source": meta[key],
                "record": event,
            })

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    print(f"{'technique':10} {'selected':>9} {'unparsed':>9} {'distinct':>9} {'kept':>5}")
    for technique in SELECTORS:
        kept = sum(r["technique"] == technique for r in rows)
        s = stats[technique]
        print(f"{technique:10} {s[0]:9} {s[1]:9} {s[2]:9} {kept:5}")
    print(f"wrote {len(rows)} rows to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
