# A note on this repository's history

Before the repository was published, its history was rewritten once to remove personal and project-management
context from three text files (`CLAUDE.md`, `PLAN.md`, `DATA_SOURCES.md`): a few lines that named a prospective
employer and the author's other affiliations were reworded or deleted. Nothing else changed. Every commit, commit
message, author and date is kept, and the code, data, results and tests are byte for byte the ones that were
measured. The only effect on the record is that commit ids changed.

Afterwards, in an ordinary commit, `CLAUDE.md` and `PLAN.md` were removed from the repository (earlier commits still
hold their reworded versions). Four code comments that pointed at the plan were reworded; no executable code changed.

Some files cite commit ids from before the rewrite (for example `docs/freeze.json`, `docs/test_run.lock.json`,
`docs/results.md`, `docs/prompt_iteration.md`, and the progress log in the removed `PLAN.md`). Use this table to find
the commit.

| Cited id (before) | Id in this repository | Commit |
|---|---|---|
| 227fb72 | 7e9b19c | Step 1: repo, FastAPI health, pgvector compose, ruff/pytest, CI |
| 941439f | 0f75e66 | Step 2: ingest, normalize and dedup alerts |
| 68bf3d2 | 6d244f2 | Step 3: labeled data, retrieval corpus, pgvector search, dev hit@5 |
| 59a65e4 | f51f825 | Step 4: triage service with code-enforced guardrails, LLM cache, API endpoint |
| b10aefd | 2d254b4 | Step 5: injection samples, injection-resistance eval, guardrail tests |
| 2dbf64e | 74b8c45 | Step 6 (part 1): evaluation harness, rules baseline, metrics, dev results |
| 06cda6f | 5cc04d7 | Pre-register the dev prompt iteration and its adoption rule |
| ece14b5 | 81a8a5b | Adopt the dev-tuned prompt per the pre-registered rule (the freeze commit) |
| 92098b7 | 7283363 | Freeze prompt, threshold, models and code before the test run (the test-run commit) |
| d6bd5ad | 02b6c25 | Step 6: test-set results (run once, frozen), faithfulness sheet, commentary |
| 2ea1fa3 | e5fb517 | Step 6: blinded model-judged faithfulness check |
| 0b3de80 | eafe2c3 | Step 7: README, 3-minute demo, offline eval smoke gate in CI |
| a010f62 | 5982b00 | CI: fix invalid YAML in the smoke gate step name |
| 5bd3083 | 4b51573 | PLAN: record remote, green CI on GitHub and what is still unverified |

The freeze and the one-shot test lock are unaffected by the new ids: the freeze check compares the prompt hash,
threshold and models, and the lock file's existence is what refuses a second test run.
