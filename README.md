# Alert Triage Copilot

A small, measured prototype that triages security alerts. It ingests raw Windows (Sysmon / Security) and syslog
records, normalizes them, groups duplicates, retrieves reference material (MITRE ATT&CK and SigmaHQ rules) from
pgvector, asks an LLM for a **recommended** verdict, and then checks that answer in code before returning it.
A person decides; nothing in this repository acts on a verdict.

It is a weekend portfolio project, not a product. Every number below was measured on a small labeled set and the
limits are listed in [Limitations](#limitations). It has never run in production.

## What it does

| Stage | What happens | Where |
|---|---|---|
| Ingest | Parse Sysmon-style JSON or a syslog line into one normalized alert. Bad records are rejected one by one. | `app/parsers/`, `app/ingest.py` |
| Dedup | Fingerprint = hash of tenant, host, user, process, normalized command line, event type (no timestamps). Same fingerprint within 10 minutes of a group's first alert shares a `group_id`. Every alert row is kept. | `app/fingerprint.py`, `app/store.py` |
| Retrieve | Embed a description of what the alert did with a local model (`BAAI/bge-small-en-v1.5`), take the 5 nearest chunks from pgvector, filtered to the shared corpus plus the caller's tenant. | `app/retrieval/` |
| Triage | Untrusted alert text goes in a delimited block. The model returns strict JSON. Code checks the schema, that every cited item was actually provided, and that `malicious` has evidence. One retry, then `needs_human`. Confidence under 0.6 becomes `needs_human`. | `app/triage/` |
| Evaluate | Compare rules only, LLM without retrieval and LLM with retrieval on a held-out test set that is run once. | `eval/` |

```mermaid
flowchart LR
    S[Sysmon JSON / syslog] -->|POST /alerts| P[Parsers<br/>normalize]
    P --> F[Fingerprint<br/>+ 10 min grouping]
    F --> DB[(Postgres 16<br/>alerts + pgvector)]
    DB -->|POST /alerts/id/triage| Q[Query text<br/>what the alert did]
    Q --> E[Local embedder<br/>bge-small, 384-d]
    E -->|top 5, tenant filter| DB
    DB --> PR[Prompt<br/>context + untrusted alert block]
    PR --> C{{Disk cache<br/>by input hash}}
    C -->|miss| L[Claude Haiku 5.5]
    L --> C
    C --> V[Validate in code<br/>schema, citations,<br/>malicious needs evidence]
    V -->|invalid: retry once| C
    V --> T[Confidence below 0.6<br/>becomes needs_human]
    T --> R[Recommendation<br/>a person decides]
```

## Results

Held-out test set: 34 malicious and 42 benign alerts, run once after the prompt, threshold, models and code were
frozen (`docs/freeze.json`, one-shot lock in `docs/test_run.lock.json`). Rates show counts and 95% Wilson
intervals. Full table, confusion counts and commentary: [`docs/results.md`](docs/results.md).

| Measure | Rules only | LLM, no retrieval | **LLM + retrieval** | LLM + retrieval (Sonnet) |
|---|---|---|---|---|
| Malicious called `malicious` | 23/34 (68%; 51-81%) | 17/34 (50%; 34-66%) | **27/34 (79%; 63-90%)** | 16/34 (47%; 31-63%) |
| Malicious silently called `benign` | 11/34 | 2/34 | **4/34** | 4/34 |
| Benign called `malicious` (false positive) | 3/42 (7%) | 1/42 (2%) | **3/42 (7%)** | 1/42 (2%) |
| Benign auto-closed | 39/42 (93%) | 7/42 (17%) | **24/42 (57%)** | 18/42 (43%) |
| Sent to a human (all 76 alerts) | 0 (0%) | 49 (64%) | **18 (24%)** | 37 (49%) |
| Technique accuracy, top-1 (of 34 malicious) | 22 | 17 | **27** | 18 |
| Cost per 1,000 alerts | $0 | $0.41 | **$0.77** | $10.94 |
| Latency per alert, median / p95 | <0.01 s | 3.4 / 4.7 s | **4.5 / 8.4 s** | 4.5 / 7.8 s |

Other measured numbers: retrieval hit@5 was 34/34 on test (18/18 on dev); the injection samples turned a verdict
to `benign` 0 of 20 times with and without retrieval; 68 of 76 answers were valid first try, 8 after the retry, 0
fell back; 181 of 196 evidence quotes appear word for word in their source.

**Evidence faithfulness** (does the cited source support the claim?) has two checks. A fresh Claude Sonnet 5.5
reviewer, blinded to labels and verdicts, judged 49 evidence items from 20 verdicts: 44 yes, 5 partly, 0 no
([`docs/faithfulness_review_model.md`](docs/faithfulness_review_model.md)). Four of the 44 yes were given without
seeing the cut-off source text, and the weak spot was ATT&CK-sourced evidence (4 of 6 items partly). The human
review sheet ([`docs/faithfulness_review.md`](docs/faithfulness_review.md)) is separate and not yet complete, so
quote the model-judged numbers as model-judged.

**How to read these numbers**

* The intervals are wide. The LLM-with-retrieval and rules-only rates for "called malicious" overlap, so that
  difference is a hint, not a demonstration.
* The clearest effects are different in kind: retrieval cut the share sent to a human from 64% to 24%, and the
  LLM sends far fewer attacks silently to "benign" than the rules (4 vs 11 of 34).
* The LLM is cautious: it sends 15 of 42 benign alerts to a person, where rules close almost all of them.
* The larger model did not help with this prompt (written and checked on the small model).

## Limitations

* **Small sets.** 34 malicious and 42 benign test alerts, 36 on dev. Differences inside the intervals are not evidence.
* **Labels are per dataset, not per event.** Some "malicious" events look harmless alone (an OS-version query filed
  under PowerShell). Two of the four malicious alerts called benign are of this kind, so recall is probably understated.
* **Benign data is synthetic** and written by the author. One template (an installer pointing a Run key at
  `C:\Users\Public`) produced 2 of the 3 false positives.
* **Public data may be in the model's training set**, and the Sigma rules were written to detect the same behaviours
  the datasets contain. Both flatter retrieval and the LLM. The rules baseline was also written by the author.
* **Six techniques, Windows events only.** The syslog parser is tested but no syslog data is in the evaluation.
* **Confidence is the model's own number.** On test it barely separated right calls (mean 0.79) from wrong ones (0.74,
  n = 7). Treat it as a hint, not a probability.
* **Injection resistance is 0 of 20**, so the attacker's true success rate could be up to about 16%. The base attacks
  are blatant, one model and one prompt were tested, and injection did push some alerts to `needs_human`.
* **Not production.** No auth beyond a tenant header, no queue, no UI, no load test. Grouping does not yet reduce LLM
  calls, because triage runs per alert.

## Quick start

Prerequisites: Docker Desktop, Python 3.12 or newer, an Anthropic API key. Commands are PowerShell; the Linux/macOS
equivalents differ only in activating the venv and setting variables.

```powershell
git clone <this repo>; cd alert-triage-copilot
copy .env.example .env                      # then put your key in ANTHROPIC_API_KEY=
docker compose up -d --build                # Postgres 16 + pgvector, and the API on :8000
                                            # first build downloads CPU torch and the embedding model (several minutes)
curl http://localhost:8000/health           # {"status":"ok"}

python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e ".[dev,retrieval]"
python data/fetch_attack.py                 # downloads MITRE ATT&CK v20.0 (pinned by checksum)
python data/fetch_sigma.py                  # downloads SigmaHQ at the pinned commit
$env:DATABASE_URL = "postgresql://triage:triage_dev_password@localhost:5432/triage"
python -m app.retrieval.index               # 837 chunks (123 ATT&CK + 714 Sigma) into pgvector
```

Tests and lint (the tests need the database from `docker compose up -d db`):

```powershell
ruff check .
pytest -q                                   # 195 tests; Postgres tests skip if the database is unreachable
python -m eval.smoke                        # the CI eval gate: no key, no network
```

Reproducing the evaluation (costs money, see the guard below):

```powershell
python data/fetch_otrf.py; python data/fetch_splunk.py     # raw malicious captures (large downloads)
python -I data/build_labeled.py                             # rebuilds data/labeled/malicious.jsonl
python -m eval.run --split dev                              # as often as you like; estimates cost first, stops above $5
python -m eval.run --sweep                                  # threshold sweep from stored dev results, no API calls
# The test set cannot be re-run in this repository: docs/test_run.lock.json exists.
```

## Three-minute demo

Uses `docs/demo_alerts.json`: the same procdump LSASS dump twice (three minutes apart) and a CrowdStrike service
reading LSASS. Real output from a run on 2026-11-08 is shown after each command; model wording varies run to run.

**1. Ingest and dedup (30 s).**

```powershell
curl.exe -s -X POST localhost:8000/alerts -H "X-Tenant-ID: demo" -H "Content-Type: application/json" -d "@docs/demo_alerts.json"
```

`ingested: 3`. The first two alerts share one `group_id` (`new_group: false` on the second), the CrowdStrike alert
starts its own. Say: *the fingerprint ignores timestamps, so repeats collapse, and every row is still stored.*

**2. Triage the attack (60 s).**

```powershell
curl.exe -s -X POST localhost:8000/alerts/<id of alert 1>/triage -H "X-Tenant-ID: demo"
```

Result: `malicious`, `T1003.001`, confidence 0.9, status `retried` (the first answer failed a check, the retry
passed), evidence from the Sigma rule "Procdump Execution" and the alert's `command_line`, 2 of 2 quotes verbatim,
about $0.001. Say: *the answer is validated in code, citations must exist in what the model was given, and a
failed check gets one retry and then `needs_human`.* Point out the `retrieved` list with similarity scores: they
are close together, which is why we retrieve five and measure hit@5.

**3. Triage the look-alike (45 s).**

```powershell
curl.exe -s -X POST localhost:8000/alerts/<id of alert 3>/triage -H "X-Tenant-ID: demo"
```

Result: `benign`, confidence 0.7, rationale cites the Sigma rule's Program Files exclusion and still tells the
analyst to confirm the binary is the signed one. Say: *same LSASS access mask as an attack, different meaning.*

**4. The numbers and the honesty (45 s).** Open `docs/results.md`: rules called 23/34 attacks and silently closed
11; LLM + retrieval called 27/34 and silently closed 4, sending 24% of alerts to a human. Then the limitations: the
sets are tiny, the intervals overlap, the benign data is synthetic. Show `docs/freeze.json` and the lock file: the
test set was run once, after the prompt was frozen.

## Safeguards worth knowing

* **Untrusted log text.** Alert fields are data inside `<alert>` tags; tag-like text in a field is neutralized so it
  cannot close the block. 20 synthetic injection samples (`data/make_injection.py`) test this.
* **Tenant isolation.** Every row has a `tenant_id` and every query filters on it, including retrieval. A mutation
  check (remove the filter, tests fail) proves the tests can catch it.
* **Cost control.** Every model call is cached on disk by a hash of its full input; runs print tokens and cost; the
  harness stops above $5 estimated.
* **Honest evaluation.** One pre-registered dev prompt iteration, a freeze, a one-shot test lock, intervals on every
  rate, and bad results kept in the table.
* **No secrets.** Keys come from the environment; `.env` is ignored and only `.env.example` is tracked.

## Layout

```
app/            API, parsers, fingerprint, stores, retrieval, triage
data/           download scripts with checksums, label builders, labeled JSONL (see DATA_SOURCES.md)
eval/           harness (run.py), metrics, rules baseline, retrieval and injection runs, CI smoke gate
tests/          unit and integration tests (fake LLM, real Postgres)
docs/           results, freeze and lock files, review sheets, prompt iteration record, demo alerts
```

## Data and licenses

No data from any employer, lab or client is used. Malicious slices come from OTRF Security-Datasets (MIT) and Splunk
attack_data (Apache 2.0); the corpus is MITRE ATT&CK and SigmaHQ (Detection Rule License 1.1); benign and
injection data are generated by scripts here. Details and notices: [`DATA_SOURCES.md`](DATA_SOURCES.md).
