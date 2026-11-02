# Results: test set

34 malicious and 42 benign alerts. Rates show counts and a 95% Wilson interval. With sets this small the intervals are wide: read them before reading the percentages.

| Measure | Rules only | LLM, no retrieval | LLM + retrieval | LLM + retrieval (Sonnet) |
|---|---|---|---|---|
| Malicious recall, plan definition (malicious or needs_human) | 23/34 (68%; 51%-81%) | 32/34 (94%; 81%-98%) | 30/34 (88%; 73%-95%) | 30/34 (88%; 73%-95%) |
| Malicious actually called `malicious` | 23/34 (68%; 51%-81%) | 17/34 (50%; 34%-66%) | 27/34 (79%; 63%-90%) | 16/34 (47%; 31%-63%) |
| Benign false-positive rate (benign called malicious) | 3/42 (7%; 2%-19%) | 1/42 (2%; 0%-12%) | 3/42 (7%; 2%-19%) | 1/42 (2%; 0%-12%) |
| Benign auto-closed as benign | 39/42 (93%; 81%-98%) | 7/42 (17%; 8%-31%) | 24/42 (57%; 42%-71%) | 18/42 (43%; 29%-58%) |
| Sent to a human (needs_human, all alerts) | 0/76 (0%; 0%-5%) | 49/76 (64%; 53%-74%) | 18/76 (24%; 16%-34%) | 37/76 (49%; 38%-60%) |
| Technique accuracy, top-1 (all malicious) | 22/34 (65%; 48%-79%) | 17/34 (50%; 34%-66%) | 27/34 (79%; 63%-90%) | 18/34 (53%; 37%-69%) |
| Technique accuracy (among those called malicious) | 22/23 (96%; 79%-99%) | 17/17 (100%; 82%-100%) | 27/27 (100%; 88%-100%) | 16/16 (100%; 81%-100%) |
| Retrieval hit@5 | n/a | n/a | 34/34 (100%; 90%-100%) | 34/34 (100%; 90%-100%) |
| Evidence quotes found word for word in source | n/a | 120/125 | 181/196 | 200/206 |
| Answers valid first try / after retry / fell back | n/a | 76 / 0 / 0 | 68 / 8 / 0 | 73 / 3 / 0 |
| Injection resistance (20 samples) | n/a | 20/20 (100%; 84%-100%) | 20/20 (100%; 84%-100%) | not measured |
| Cost per 1,000 alerts | $0 | $0.41 | $0.77 | $10.94 |
| Latency per alert, median / 95th percentile | <0.01 s | 3.4 s / 4.7 s | 4.5 s / 8.4 s | 4.5 s / 7.8 s |

## Confusion counts (rows: true label; columns: verdict)

**Rules only**

| true \ verdict | malicious | benign | needs_human | error |
|---|---|---|---|---|
| malicious | 23 | 11 | 0 | 0 |
| benign | 3 | 39 | 0 | 0 |

**LLM, no retrieval**

| true \ verdict | malicious | benign | needs_human | error |
|---|---|---|---|---|
| malicious | 17 | 2 | 15 | 0 |
| benign | 1 | 7 | 34 | 0 |

**LLM + retrieval**

| true \ verdict | malicious | benign | needs_human | error |
|---|---|---|---|---|
| malicious | 27 | 4 | 3 | 0 |
| benign | 3 | 24 | 15 | 0 |

**LLM + retrieval (Sonnet)**

| true \ verdict | malicious | benign | needs_human | error |
|---|---|---|---|---|
| malicious | 16 | 4 | 14 | 0 |
| benign | 1 | 18 | 23 | 0 |

## Notes and limitations

- Small samples: the confidence intervals above are the honest uncertainty. A difference between two systems smaller than the intervals is not evidence of a real difference.
- Labels come from the dataset an event is filed under, not from a judgement about each event. Some "malicious" events look harmless alone, so a model that calls one benign may be right. See DATA_SOURCES.md.
- The plan's recall counts needs_human as caught. That is easy to inflate (always answer needs_human), so the table also shows how many malicious alerts were actually called malicious and how much work goes to a human.
- Benign alerts are synthetic look-alikes written by this project's author. Public datasets and Sigma rules may have been seen by the model during training, and Sigma rules were written for the same behaviours.
- The rules-only baseline was written by the same author who built the labeled sets and is illustrative, not an independent benchmark.
- Cost and latency come from live calls with `effort: low`; latency includes embedding the query and the database search. Prices are Anthropic's published rates; check them before quoting a total.

## Reading the results (written by hand after the run; the numbers above are as generated)

The test set was run once, after `docs/freeze.json` fixed the prompt, threshold, models and code
(commit `ece14b5`). Nothing was changed afterwards. Intervals are 95% Wilson intervals.

**LLM + retrieval (Haiku) against rules only**

* Malicious called `malicious`: 27/34 (79%) against 23/34 (68%). The intervals overlap (63-90% and 51-81%), so this
  is a hint, not a demonstrated difference.
* Malicious alerts silently auto-closed as benign: 4/34 (12%) against 11/34 (32%). Rules-only auto-closes more
  attacks quietly. The LLM sends 3 more malicious alerts to a human.
* Benign false positives are equal, 3/42 each. But rules-only auto-closes far more benign alerts (39/42, 93%) than
  the LLM (24/42, 57%): the LLM sends 15 benign alerts to a person. That is the price of its caution, and the
  intervals do not overlap (81-98% against 42-71%).
* Technique accuracy 27/34 (79%) against 22/34 (65%), and the LLM gives a cited rationale.
* Overall the LLM system sends 18 of 76 alerts (24%) to a human; rules-only sends none.

**Retrieval matters.** Without retrieval the same model calls only 17/34 malicious and sends 64% of alerts to a
human, against 79% and 24% with it. The decisiveness prompt change was developed on the retrieval system, so part
of this gap is that tuning.

**A larger model did not help here.** Sonnet 5.5, same prompt and threshold, called 16/34 malicious and sent 49% of
alerts to a human, at about 14 times the cost per alert ($10.94 against $0.77 per 1,000). The prompt was written
and checked on Haiku, so this says little about what Sonnet could do with its own prompt.

**What the errors look like (retrieval system).** Of the 4 malicious alerts called benign, two are the harmless-looking
PowerShell commands described in `prompt_iteration.md` (a read-only event-log query and a decoded Ansible reboot),
one is a Run-key deletion the model read as attack-simulation cleanup, and one is Task Manager opening LSASS with a
query-only access mask, which is the closest to a real miss. Two of the 3 benign false positives are installer
entries whose Run-key value points at `C:\Users\Public`, an implausible path that is a flaw in the synthetic benign
set; the third writes an executable into `ADMIN$`. Per technique, malicious called malicious: T1053.005 7/7,
T1110 4/4, T1003.001 6/7, T1547.001 5/7, T1059.001 4/7, T1021.002 1/2.

**Development against test.** On dev the same system called 16/18 malicious (89%); on test 27/34 (79%). A drop is
expected after tuning on dev.

**Not shown by these numbers.** Evidence faithfulness has not been judged: `faithfulness_review.md` is waiting for a
person. The automated check only shows that 181 of 196 quotes appear word for word. Injection resistance was
measured on the small model only. Retries were 8 of 76 for the retrieval system (0 fell back). Latency includes
embedding and the database search. The sets are small, the labels are per dataset, and the benign alerts and the
rules baseline were written by the project's author.
