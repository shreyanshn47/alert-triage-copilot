# Prompt iteration on the dev set (decided before running)

Written and committed before any run of the changed prompt, so the rule cannot be bent to fit the result.

## Why

On the dev set the first-draft prompt (hash `815bd1595ff6` as of commit 2dbf64e) sends 53% of alerts to a human with
retrieval and 69% without. Reading the rationales, the model often chose `needs_human` because a single alert
lacked follow-on telemetry, or because the activity "could be authorized". Both are normal for one alert.

## The one change

Only the verdict definitions in the system prompt. `needs_human` is restricted to genuinely mixed evidence or
missing fields needed to judge. Absent extra telemetry, or the bare possibility of authorization, is stated not
to be a reason on its own. The untrusted-data rules, the output schema and the citation rules are untouched.

## Dev results before (LLM + retrieval / LLM, no retrieval), 36 alerts, 18 malicious and 18 benign

| | with retrieval | no retrieval |
|---|---|---|
| malicious called `malicious` | 9/18 | 5/18 |
| benign called `malicious` | 2/18 | 0/18 |
| sent to a human | 19/36 | 25/36 |
| fell back (invalid twice) | 0/36 | 0/36 |

## Adoption rule (LLM + retrieval system, dev set)

Adopt the changed prompt only if ALL hold:

1. malicious alerts called `malicious` rises (strictly more than 9/18);
2. benign alerts called `malicious` rises by at most 1 (at most 3/18);
3. no alert falls back to the invalid-answer default (0/36 stays 0/36);
4. the injection evaluation, re-run with the new prompt, still shows 0 of 20 turned `benign` for both LLM systems.

Otherwise the original prompt is restored and used for the test run. Only one iteration is made. The no-retrieval
system is reported for information and does not decide adoption.

## Caveats stated in advance

Dev has 36 alerts, so a gain of a few alerts is weak evidence. Adopting a change that satisfies the rule is a choice
made on dev; the test set is where it is checked.
