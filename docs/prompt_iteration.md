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

## Result (same 36 dev alerts, new prompt hash `a52c231caf87`)

| LLM + retrieval | before | after |
|---|---|---|
| malicious called `malicious` | 9/18 | 16/18 |
| malicious called `benign` | 0/18 | 2/18 |
| malicious sent to a human | 9/18 | 0/18 |
| benign called `malicious` | 2/18 | 3/18 |
| benign auto-closed as benign | 6/18 | 7/18 |
| sent to a human, all alerts | 19/36 | 8/36 |
| fell back / retried / valid first try | 0 / 2 / 34 | 0 / 1 / 35 |
| injection: turned `benign` | 0/20 | 0/20 |

Without retrieval the change helped little: malicious called `malicious` 5/18 -> 6/18, 72% still sent to a human.
Retrieval is what lets the model be decisive.

## Decision: adopted

All four conditions of the rule hold. The prompt in `app/triage/prompt.py` is the one frozen for the test run.

## What the rule missed, and what the two new misses are

The rule did not limit malicious alerts called `benign`. That is the costly error in triage, and it went from 0 to 2.
Both are `mal-T1059.001-01` and `-02`, from the same dataset folder:

* `-01` is `Get-CimInstance Win32_OperatingSystem | ConvertTo-Json`, an OS-version query. The model called it routine inventory.
* `-02` is an `-EncodedCommand` payload. The model decoded it and found `shutdown /r /t 2 /c "Reboot initiated by Ansible"`.

Neither looks malicious on its own; they are in the "malicious" set only because the dataset they come from is
filed under T1059.001 (see DATA_SOURCES.md). I read the model's calls as defensible, so these are label noise and
not a demonstrated hole. They are not proof the model would catch a subtle real attack either. Before the change
the same alerts went to a human, which is the safer behaviour. The trade is real: fewer alerts for people, at the
price of two auto-closed alerts that happen to be harmless-looking.

## Caveats stated in advance

Dev has 36 alerts, so a gain of a few alerts is weak evidence. Adopting a change that satisfies the rule is a choice
made on dev; the test set is where it is checked.
