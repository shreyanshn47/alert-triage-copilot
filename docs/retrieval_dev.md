# Retrieval hit@5, dev set (measured 2026-11-01)

Corpus: ATT&CK v20.0 (123 chunks) + SigmaHQ commit 05d1031f537e (714 rules). Embeddings: BAAI/bge-small-en-v1.5.
Dev set: 18 malicious alerts (3 per technique). The test split has not been touched.
Read with care: n is tiny, labels are per dataset, and Sigma rules were written for these behaviours. See DATA_SOURCES.md.

```
Retrieval on the dev set (malicious alerts only)

attack + sigma
  technique    n   hit@1   hit@5   MRR@5
  T1003.001    3   2/3     3/3      0.83
  T1021.002    3   3/3     3/3      1.00
  T1053.005    3   3/3     3/3      1.00
  T1059.001    3   2/3     3/3      0.83
  T1110        3   3/3     3/3      1.00
  T1547.001    3   3/3     3/3      1.00
  ALL         18  16/18   18/18     0.94

attack only
  technique    n   hit@1   hit@5   MRR@5
  T1003.001    3   0/3     2/3      0.23
  T1021.002    3   2/3     2/3      0.67
  T1053.005    3   2/3     3/3      0.78
  T1059.001    3   3/3     3/3      1.00
  T1110        3   3/3     3/3      1.00
  T1547.001    3   3/3     3/3      1.00
  ALL         18  13/18   16/18     0.78

sigma only
  technique    n   hit@1   hit@5   MRR@5
  T1003.001    3   3/3     3/3      1.00
  T1021.002    3   3/3     3/3      1.00
  T1053.005    3   3/3     3/3      1.00
  T1059.001    3   2/3     3/3      0.83
  T1110        3   3/3     3/3      1.00
  T1547.001    3   1/3     2/3      0.50
  ALL         18  15/18   17/18     0.89
```
