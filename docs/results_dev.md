# Results: dev set

18 malicious and 18 benign alerts. Rates show counts and a 95% Wilson interval. With sets this small the intervals are wide: read them before reading the percentages.

| Measure | Rules only | LLM, no retrieval | LLM + retrieval |
|---|---|---|---|
| Malicious recall, plan definition (malicious or needs_human) | 13/18 (72%; 49%-88%) | 17/18 (94%; 74%-99%) | 18/18 (100%; 82%-100%) |
| Malicious actually called `malicious` | 13/18 (72%; 49%-88%) | 5/18 (28%; 12%-51%) | 9/18 (50%; 29%-71%) |
| Benign false-positive rate (benign called malicious) | 4/18 (22%; 9%-45%) | 0/18 (0%; 0%-18%) | 2/18 (11%; 3%-33%) |
| Benign auto-closed as benign | 14/18 (78%; 55%-91%) | 5/18 (28%; 12%-51%) | 6/18 (33%; 16%-56%) |
| Sent to a human (needs_human, all alerts) | 0/36 (0%; 0%-10%) | 25/36 (69%; 53%-82%) | 19/36 (53%; 37%-68%) |
| Technique accuracy, top-1 (all malicious) | 12/18 (67%; 44%-84%) | 5/18 (28%; 12%-51%) | 9/18 (50%; 29%-71%) |
| Technique accuracy (among those called malicious) | 12/13 (92%; 67%-99%) | 5/5 (100%; 57%-100%) | 9/9 (100%; 70%-100%) |
| Retrieval hit@5 | n/a | n/a | 18/18 (100%; 82%-100%) |
| Evidence quotes found word for word in source | n/a | 51/52 | 86/92 |
| Answers valid first try / after retry / fell back | n/a | 36 / 0 / 0 | 34 / 2 / 0 |
| Injection resistance (20 samples) | n/a | not measured | 20/20 (100%; 84%-100%) |
| Cost per 1,000 alerts | $0 | $0.31 | n/a (cache) |
| Latency per alert, median / 95th percentile | <0.01 s | 1.8 s / 4.4 s | 3.4 s / 3.8 s |

## Confusion counts (rows: true label; columns: verdict)

**Rules only**

| true \ verdict | malicious | benign | needs_human | error |
|---|---|---|---|---|
| malicious | 13 | 5 | 0 | 0 |
| benign | 4 | 14 | 0 | 0 |

**LLM, no retrieval**

| true \ verdict | malicious | benign | needs_human | error |
|---|---|---|---|---|
| malicious | 5 | 1 | 12 | 0 |
| benign | 0 | 5 | 13 | 0 |

**LLM + retrieval**

| true \ verdict | malicious | benign | needs_human | error |
|---|---|---|---|---|
| malicious | 9 | 0 | 9 | 0 |
| benign | 2 | 6 | 10 | 0 |

## Notes and limitations

- DEV set: used while building. Numbers here are for inspection and are not the headline result.
- Small samples: the confidence intervals above are the honest uncertainty. A difference between two systems smaller than the intervals is not evidence of a real difference.
- Labels come from the dataset an event is filed under, not from a judgement about each event. Some "malicious" events look harmless alone, so a model that calls one benign may be right. See DATA_SOURCES.md.
- The plan's recall counts needs_human as caught. That is easy to inflate (always answer needs_human), so the table also shows how many malicious alerts were actually called malicious and how much work goes to a human.
- Benign alerts are synthetic look-alikes written by this project's author. Public datasets and Sigma rules may have been seen by the model during training, and Sigma rules were written for the same behaviours.
- The rules-only baseline was written by the same author who built the labeled sets and is illustrative, not an independent benchmark.
- Cost and latency come from live calls with `effort: low`; latency includes embedding the query and the database search. Prices are Anthropic's published rates; check them before quoting a total.
