# AI Triage Engine — Evaluation Report

## Sample

- Target: 1925 total (385 malicious floor-targeted)
- Achieved: 1925 total (385 malicious / 1540 benign)
- 385-malicious floor (+/-5pp 95% CI on malicious-class recall) met: True

## Run metadata

- **prompt_template_version**: phase-2-single-agent-v1
- **eval_seed**: 20260818
- **benign_ratio**: 4.0
- **mitigate_shortcuts**: True
- **baselines_only**: False
- **classical_ml_split_malicious_strategy**: capture_level_exclusion
- **classical_ml_split_benign_strategy**: record_level_holdout_fallback
- **model**: qwen2.5:7b-instruct-q4_K_M
- **temperature**: 0.0

## Corpus metadata

- **corpus_size**: 137619
- **benign_ratio**: 4.0
- **mitigate_shortcuts**: True
- **eval_seed**: 20260818

## Headline table (pooled, all systems, headline policy = `conservative`)

| System | n | MCC | PR-AUC | ROC-AUC (secondary) | Balanced acc. | Recall [Wilson 95% CI] | Accuracy (context only) |
|---|---|---|---|---|---|---|---|
| llm | 1923 | 0.014 | 0.223 | 0.519 | 0.508 | 69.6% [64.8%, 74.0%] (n=385) | 0.396 |
| majority_class | 1925 | undefined | 0.200 | 0.500 | 0.500 | 0.0% [0.0%, 1.0%] (n=385) | 0.800 |
| stratified_random | 1925 | -0.049 | 0.220 | 0.534 | 0.475 | 17.1% [13.7%, 21.2%] (n=385) | 0.657 |
| rules_heuristic | 1925 | -0.028 | 0.199 | 0.489 | 0.489 | 9.1% [6.6%, 12.4%] (n=385) | 0.728 |
| classical_ml | 1925 | 0.054 | 0.326 | 0.536 | 0.532 | 40.5% [35.7%, 45.5%] (n=385) | 0.608 |

## Per-system detail

### llm

Pooled n=1925 (malicious=385, benign=1540)

#### Policy: `conservative`  (HEADLINE)
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 268 | 1045 | 117 | 493 | 1923 |

| Metric | Value |
|---|---|
| MCC | 0.014 |
| PR-AUC | 0.223 |
| ROC-AUC (secondary) | 0.519 |
| Balanced accuracy | 0.508 |
| Precision | 0.204 [0.183, 0.227] (n=1313) |
| Recall | 0.696 [0.648, 0.740] (n=385) |
| F1 | 0.316 |
| FPR = FP/(FP+TN) | 0.679 [0.656, 0.702] (n=1538) |
| FNR = FN/(FN+TP) | 0.304 |
| Accuracy (context only, NOT a headline) | 0.396 |

#### Policy: `high_precision`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 41 | 68 | 344 | 1470 | 1923 |

| Metric | Value |
|---|---|
| MCC | 0.108 |
| PR-AUC | 0.223 |
| ROC-AUC (secondary) | 0.519 |
| Balanced accuracy | 0.531 |
| Precision | 0.376 [0.291, 0.470] (n=109) |
| Recall | 0.106 [0.079, 0.141] (n=385) |
| F1 | 0.166 |
| FPR = FP/(FP+TN) | 0.044 [0.035, 0.056] (n=1538) |
| FNR = FN/(FN+TP) | 0.894 |
| Accuracy (context only, NOT a headline) | 0.786 |

#### Policy: `abstention`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 41 | 68 | 117 | 493 | 719 |

| Metric | Value |
|---|---|
| MCC | 0.160 |
| PR-AUC | 0.261 |
| ROC-AUC (secondary) | 0.569 |
| Balanced accuracy | 0.569 |
| Precision | 0.376 [0.291, 0.470] (n=109) |
| Recall | 0.259 [0.197, 0.333] (n=158) |
| F1 | 0.307 |
| FPR = FP/(FP+TN) | 0.121 [0.097, 0.151] (n=561) |
| FNR = FN/(FN+TP) | 0.741 |
| Accuracy (context only, NOT a headline) | 0.743 |

#### Abstention / selective-prediction detail
- Coverage: 37.4% (719/1925 committed, 1206 abstained)
- Selective accuracy (on committed subset): 0.743
- AURC (area under risk-coverage curve, lower=better): 0.2628

#### LLM-specific metrics

- Parse-failure rate: 0.1% [0.0%, 0.4%] (n=1925) (2/1925 attempted)
- Expected Calibration Error (ECE) on self-reported `confidence`: 0.4434
  - Reliability bins (low-high: n, avg_confidence, empirical accuracy):
    - [0.7-0.8): n=931, avg_conf=0.750, acc=0.199
    - [0.8-0.9): n=270, avg_conf=0.850, acc=0.156
    - [0.9-1.0): n=722, avg_conf=0.950, acc=0.740
- Run-to-run determinism (3 repeats x 25 items): 44.0% [26.7%, 62.9%] (n=25)

#### Per-EventID

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| 1 | 208 (34/174) | 0.695 | 61.8% [45.0%, 76.1%] (n=34) | 87.5% [69.0%, 95.7%] (n=24) |
| 10 | 208 (34/174) | -0.218 | 50.0% [34.1%, 65.9%] (n=34) | 11.3% [7.2%, 17.4%] (n=150) |
| 11 | 208 (34/174) | -0.435 | 52.9% [36.7%, 68.5%] (n=34) | 10.0% [6.4%, 15.3%] (n=180) |
| 12 | 208 (34/174) | -0.369 | 73.5% [56.9%, 85.4%] (n=34) | 12.8% [8.8%, 18.2%] (n=195) |
| 13 | 208 (34/174) | -0.693 | 44.1% [28.9%, 60.5%] (n=34) | 8.1% [4.9%, 12.9%] (n=186) |
| 3 | 101 (35/66) | 0.362 | 91.4% [77.6%, 97.0%] (n=35) | 46.4% [35.1%, 58.0%] (n=69) |
| 4104 | 12 (7/5) | 0.293 | 85.7% [48.7%, 97.4%] (n=7) | 66.7% [35.4%, 87.9%] (n=9) |
| 4624 | 74 (35/39) | 0.705 | 97.1% [85.5%, 99.5%] (n=35) | 75.6% [61.3%, 85.8%] (n=45) |
| 4672 | 71 (35/36) | undefined | 100.0% [90.1%, 100.0%] (n=35) | 49.3% [38.0%, 60.7%] (n=71) |
| 4688 | 208 (34/174) | 0.146 | 91.2% [77.0%, 97.0%] (n=34) | 19.3% [13.9%, 26.0%] (n=161) |
| 4689 | 209 (34/175) | 0.079 | 52.9% [36.7%, 68.5%] (n=34) | 19.6% [12.7%, 28.8%] (n=92) |
| 5 | 210 (35/175) | -0.154 | 45.7% [30.5%, 61.8%] (n=35) | 12.2% [7.7%, 18.9%] (n=131) |

#### Per-event_type

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| authentication | 145 (70/75) | 0.449 | 98.6% [92.3%, 99.7%] (n=70) | 59.5% [50.4%, 68.0%] (n=116) |
| file | 207 (33/174) | -0.419 | 54.5% [38.0%, 70.2%] (n=33) | 10.0% [6.4%, 15.3%] (n=180) |
| network | 101 (35/66) | 0.362 | 91.4% [77.6%, 97.0%] (n=35) | 46.4% [35.1%, 58.0%] (n=69) |
| other | 1 (1/0) | undefined | 0.0% [0.0%, 79.3%] (n=1) | n/a |
| process | 1055 (178/877) | 0.068 | 61.2% [53.9%, 68.1%] (n=178) | 19.2% [16.2%, 22.7%] (n=567) |
| registry | 416 (68/348) | -0.544 | 58.8% [47.0%, 69.7%] (n=68) | 10.5% [7.8%, 14.0%] (n=381) |

#### Per-technique (sentinel EXCLUDED, see below)

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| T1053 | 1 (1/0) | undefined | 100.0% [20.7%, 100.0%] (n=1) | 100.0% [20.7%, 100.0%] (n=1) |
| T1087 | 2 (2/0) | undefined | 100.0% [34.2%, 100.0%] (n=2) | 100.0% [34.2%, 100.0%] (n=2) |
| T1123 | 4 (4/0) | undefined | 50.0% [15.0%, 85.0%] (n=4) | 100.0% [34.2%, 100.0%] (n=2) |
| T1547 | 47 (47/0) | undefined | 83.0% [69.9%, 91.1%] (n=47) | 100.0% [91.0%, 100.0%] (n=39) |
| benign | 1540 (0/1540) | undefined | n/a | 0.0% [0.0%, 0.4%] (n=1045) |

#### MULTI_TECHNIQUE_UNRESOLVED sentinel bucket (reported separately, never scored per-technique)
n=331 malicious records whose source capture (OTRF APT29 compound scenarios) has no OTRF-published per-event technique mapping. No per-technique claim is made for these records.
Aggregate recall under `conservative` policy: 0.677 [0.625, 0.725] (n=331)

### majority_class

Pooled n=1925 (malicious=385, benign=1540)

#### Policy: `conservative`  (HEADLINE)
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 0 | 0 | 385 | 1540 | 1925 |

| Metric | Value |
|---|---|
| MCC | undefined |
| PR-AUC | 0.200 |
| ROC-AUC (secondary) | 0.500 |
| Balanced accuracy | 0.500 |
| Precision | n/a |
| Recall | 0.000 [0.000, 0.010] (n=385) |
| F1 | undefined |
| FPR = FP/(FP+TN) | 0.000 [0.000, 0.002] (n=1540) |
| FNR = FN/(FN+TP) | 1.000 |
| Accuracy (context only, NOT a headline) | 0.800 |

#### Policy: `high_precision`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 0 | 0 | 385 | 1540 | 1925 |

| Metric | Value |
|---|---|
| MCC | undefined |
| PR-AUC | 0.200 |
| ROC-AUC (secondary) | 0.500 |
| Balanced accuracy | 0.500 |
| Precision | n/a |
| Recall | 0.000 [0.000, 0.010] (n=385) |
| F1 | undefined |
| FPR = FP/(FP+TN) | 0.000 [0.000, 0.002] (n=1540) |
| FNR = FN/(FN+TP) | 1.000 |
| Accuracy (context only, NOT a headline) | 0.800 |

#### Policy: `abstention`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 0 | 0 | 385 | 1540 | 1925 |

| Metric | Value |
|---|---|
| MCC | undefined |
| PR-AUC | 0.200 |
| ROC-AUC (secondary) | 0.500 |
| Balanced accuracy | 0.500 |
| Precision | n/a |
| Recall | 0.000 [0.000, 0.010] (n=385) |
| F1 | undefined |
| FPR = FP/(FP+TN) | 0.000 [0.000, 0.002] (n=1540) |
| FNR = FN/(FN+TP) | 1.000 |
| Accuracy (context only, NOT a headline) | 0.800 |

#### Abstention / selective-prediction detail
- Coverage: 100.0% (1925/1925 committed, 0 abstained)
- Selective accuracy (on committed subset): 0.800
- AURC: not computed (no confidence scores available for this system)

#### Per-EventID

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| 1 | 208 (34/174) | undefined | 0.0% [0.0%, 10.2%] (n=34) | n/a |
| 10 | 208 (34/174) | undefined | 0.0% [0.0%, 10.2%] (n=34) | n/a |
| 11 | 208 (34/174) | undefined | 0.0% [0.0%, 10.2%] (n=34) | n/a |
| 12 | 208 (34/174) | undefined | 0.0% [0.0%, 10.2%] (n=34) | n/a |
| 13 | 208 (34/174) | undefined | 0.0% [0.0%, 10.2%] (n=34) | n/a |
| 3 | 101 (35/66) | undefined | 0.0% [0.0%, 9.9%] (n=35) | n/a |
| 4104 | 12 (7/5) | undefined | 0.0% [0.0%, 35.4%] (n=7) | n/a |
| 4624 | 74 (35/39) | undefined | 0.0% [0.0%, 9.9%] (n=35) | n/a |
| 4672 | 71 (35/36) | undefined | 0.0% [0.0%, 9.9%] (n=35) | n/a |
| 4688 | 208 (34/174) | undefined | 0.0% [0.0%, 10.2%] (n=34) | n/a |
| 4689 | 209 (34/175) | undefined | 0.0% [0.0%, 10.2%] (n=34) | n/a |
| 5 | 210 (35/175) | undefined | 0.0% [0.0%, 9.9%] (n=35) | n/a |

#### Per-event_type

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| authentication | 145 (70/75) | undefined | 0.0% [0.0%, 5.2%] (n=70) | n/a |
| file | 207 (33/174) | undefined | 0.0% [0.0%, 10.4%] (n=33) | n/a |
| network | 101 (35/66) | undefined | 0.0% [0.0%, 9.9%] (n=35) | n/a |
| other | 1 (1/0) | undefined | 0.0% [0.0%, 79.3%] (n=1) | n/a |
| process | 1055 (178/877) | undefined | 0.0% [0.0%, 2.1%] (n=178) | n/a |
| registry | 416 (68/348) | undefined | 0.0% [0.0%, 5.3%] (n=68) | n/a |

#### Per-technique (sentinel EXCLUDED, see below)

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| T1053 | 1 (1/0) | undefined | 0.0% [0.0%, 79.3%] (n=1) | n/a |
| T1087 | 2 (2/0) | undefined | 0.0% [0.0%, 65.8%] (n=2) | n/a |
| T1123 | 4 (4/0) | undefined | 0.0% [0.0%, 49.0%] (n=4) | n/a |
| T1547 | 47 (47/0) | undefined | 0.0% [0.0%, 7.6%] (n=47) | n/a |
| benign | 1540 (0/1540) | undefined | n/a | n/a |

#### MULTI_TECHNIQUE_UNRESOLVED sentinel bucket (reported separately, never scored per-technique)
n=331 malicious records whose source capture (OTRF APT29 compound scenarios) has no OTRF-published per-event technique mapping. No per-technique claim is made for these records.
Aggregate recall under `conservative` policy: 0.000 [0.000, 0.011] (n=331)

### stratified_random

Pooled n=1925 (malicious=385, benign=1540)

#### Policy: `conservative`  (HEADLINE)
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 66 | 341 | 319 | 1199 | 1925 |

| Metric | Value |
|---|---|
| MCC | -0.049 |
| PR-AUC | 0.220 |
| ROC-AUC (secondary) | 0.534 |
| Balanced accuracy | 0.475 |
| Precision | 0.162 [0.130, 0.201] (n=407) |
| Recall | 0.171 [0.137, 0.212] (n=385) |
| F1 | 0.167 |
| FPR = FP/(FP+TN) | 0.221 [0.201, 0.243] (n=1540) |
| FNR = FN/(FN+TP) | 0.829 |
| Accuracy (context only, NOT a headline) | 0.657 |

#### Policy: `high_precision`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 66 | 341 | 319 | 1199 | 1925 |

| Metric | Value |
|---|---|
| MCC | -0.049 |
| PR-AUC | 0.220 |
| ROC-AUC (secondary) | 0.534 |
| Balanced accuracy | 0.475 |
| Precision | 0.162 [0.130, 0.201] (n=407) |
| Recall | 0.171 [0.137, 0.212] (n=385) |
| F1 | 0.167 |
| FPR = FP/(FP+TN) | 0.221 [0.201, 0.243] (n=1540) |
| FNR = FN/(FN+TP) | 0.829 |
| Accuracy (context only, NOT a headline) | 0.657 |

#### Policy: `abstention`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 66 | 341 | 319 | 1199 | 1925 |

| Metric | Value |
|---|---|
| MCC | -0.049 |
| PR-AUC | 0.220 |
| ROC-AUC (secondary) | 0.534 |
| Balanced accuracy | 0.475 |
| Precision | 0.162 [0.130, 0.201] (n=407) |
| Recall | 0.171 [0.137, 0.212] (n=385) |
| F1 | 0.167 |
| FPR = FP/(FP+TN) | 0.221 [0.201, 0.243] (n=1540) |
| FNR = FN/(FN+TP) | 0.829 |
| Accuracy (context only, NOT a headline) | 0.657 |

#### Abstention / selective-prediction detail
- Coverage: 100.0% (1925/1925 committed, 0 abstained)
- Selective accuracy (on committed subset): 0.657
- AURC: not computed (no confidence scores available for this system)

#### Per-EventID

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| 1 | 208 (34/174) | -0.060 | 14.7% [6.4%, 30.1%] (n=34) | 11.9% [5.2%, 25.0%] (n=42) |
| 10 | 208 (34/174) | 0.046 | 26.5% [14.6%, 43.1%] (n=34) | 19.6% [10.7%, 33.2%] (n=46) |
| 11 | 208 (34/174) | -0.139 | 11.8% [4.7%, 26.6%] (n=34) | 7.5% [3.0%, 17.9%] (n=53) |
| 12 | 208 (34/174) | 0.010 | 23.5% [12.4%, 40.0%] (n=34) | 17.0% [8.9%, 30.1%] (n=47) |
| 13 | 208 (34/174) | -0.074 | 11.8% [4.7%, 26.6%] (n=34) | 10.5% [4.2%, 24.1%] (n=38) |
| 3 | 101 (35/66) | -0.050 | 14.3% [6.3%, 29.4%] (n=35) | 29.4% [13.3%, 53.1%] (n=17) |
| 4104 | 12 (7/5) | -0.076 | 14.3% [2.6%, 51.3%] (n=7) | 50.0% [9.5%, 90.5%] (n=2) |
| 4624 | 74 (35/39) | -0.037 | 20.0% [10.0%, 35.9%] (n=35) | 43.8% [23.1%, 66.8%] (n=16) |
| 4672 | 71 (35/36) | -0.156 | 8.6% [3.0%, 22.4%] (n=35) | 30.0% [10.8%, 60.3%] (n=10) |
| 4688 | 208 (34/174) | 0.111 | 35.3% [21.5%, 52.1%] (n=34) | 23.5% [14.0%, 36.8%] (n=51) |
| 4689 | 209 (34/175) | -0.092 | 11.8% [4.7%, 26.6%] (n=34) | 9.5% [3.8%, 22.1%] (n=42) |
| 5 | 210 (35/175) | -0.100 | 11.4% [4.5%, 26.0%] (n=35) | 9.3% [3.7%, 21.6%] (n=43) |

#### Per-event_type

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| authentication | 145 (70/75) | -0.092 | 14.3% [7.9%, 24.3%] (n=70) | 38.5% [22.4%, 57.5%] (n=26) |
| file | 207 (33/174) | -0.135 | 12.1% [4.8%, 27.3%] (n=33) | 7.5% [3.0%, 17.9%] (n=53) |
| network | 101 (35/66) | -0.050 | 14.3% [6.3%, 29.4%] (n=35) | 29.4% [13.3%, 53.1%] (n=17) |
| other | 1 (1/0) | undefined | 0.0% [0.0%, 79.3%] (n=1) | n/a |
| process | 1055 (178/877) | -0.019 | 19.7% [14.5%, 26.1%] (n=178) | 15.5% [11.4%, 20.8%] (n=226) |
| registry | 416 (68/348) | -0.031 | 17.6% [10.4%, 28.4%] (n=68) | 14.1% [8.3%, 23.1%] (n=85) |

#### Per-technique (sentinel EXCLUDED, see below)

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| T1053 | 1 (1/0) | undefined | 0.0% [0.0%, 79.3%] (n=1) | n/a |
| T1087 | 2 (2/0) | undefined | 50.0% [9.5%, 90.5%] (n=2) | 100.0% [20.7%, 100.0%] (n=1) |
| T1123 | 4 (4/0) | undefined | 50.0% [15.0%, 85.0%] (n=4) | 100.0% [34.2%, 100.0%] (n=2) |
| T1547 | 47 (47/0) | undefined | 19.1% [10.4%, 32.5%] (n=47) | 100.0% [70.1%, 100.0%] (n=9) |
| benign | 1540 (0/1540) | undefined | n/a | 0.0% [0.0%, 1.1%] (n=341) |

#### MULTI_TECHNIQUE_UNRESOLVED sentinel bucket (reported separately, never scored per-technique)
n=331 malicious records whose source capture (OTRF APT29 compound scenarios) has no OTRF-published per-event technique mapping. No per-technique claim is made for these records.
Aggregate recall under `conservative` policy: 0.163 [0.127, 0.207] (n=331)

### rules_heuristic

Pooled n=1925 (malicious=385, benign=1540)

#### Policy: `conservative`  (HEADLINE)
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 35 | 174 | 350 | 1366 | 1925 |

| Metric | Value |
|---|---|
| MCC | -0.028 |
| PR-AUC | 0.199 |
| ROC-AUC (secondary) | 0.489 |
| Balanced accuracy | 0.489 |
| Precision | 0.167 [0.123, 0.224] (n=209) |
| Recall | 0.091 [0.066, 0.124] (n=385) |
| F1 | 0.118 |
| FPR = FP/(FP+TN) | 0.113 [0.098, 0.130] (n=1540) |
| FNR = FN/(FN+TP) | 0.909 |
| Accuracy (context only, NOT a headline) | 0.728 |

#### Policy: `high_precision`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 35 | 174 | 350 | 1366 | 1925 |

| Metric | Value |
|---|---|
| MCC | -0.028 |
| PR-AUC | 0.199 |
| ROC-AUC (secondary) | 0.489 |
| Balanced accuracy | 0.489 |
| Precision | 0.167 [0.123, 0.224] (n=209) |
| Recall | 0.091 [0.066, 0.124] (n=385) |
| F1 | 0.118 |
| FPR = FP/(FP+TN) | 0.113 [0.098, 0.130] (n=1540) |
| FNR = FN/(FN+TP) | 0.909 |
| Accuracy (context only, NOT a headline) | 0.728 |

#### Policy: `abstention`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 35 | 174 | 350 | 1366 | 1925 |

| Metric | Value |
|---|---|
| MCC | -0.028 |
| PR-AUC | 0.199 |
| ROC-AUC (secondary) | 0.489 |
| Balanced accuracy | 0.489 |
| Precision | 0.167 [0.123, 0.224] (n=209) |
| Recall | 0.091 [0.066, 0.124] (n=385) |
| F1 | 0.118 |
| FPR = FP/(FP+TN) | 0.113 [0.098, 0.130] (n=1540) |
| FNR = FN/(FN+TP) | 0.909 |
| Accuracy (context only, NOT a headline) | 0.728 |

#### Abstention / selective-prediction detail
- Coverage: 100.0% (1925/1925 committed, 0 abstained)
- Selective accuracy (on committed subset): 0.728
- AURC: not computed (no confidence scores available for this system)

#### Per-EventID

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| 1 | 208 (34/174) | 0.157 | 2.9% [0.5%, 14.9%] (n=34) | 100.0% [20.7%, 100.0%] (n=1) |
| 10 | 208 (34/174) | undefined | 100.0% [89.8%, 100.0%] (n=34) | 16.3% [11.9%, 22.0%] (n=208) |
| 11 | 208 (34/174) | undefined | 0.0% [0.0%, 10.2%] (n=34) | n/a |
| 12 | 208 (34/174) | undefined | 0.0% [0.0%, 10.2%] (n=34) | n/a |
| 13 | 208 (34/174) | undefined | 0.0% [0.0%, 10.2%] (n=34) | n/a |
| 3 | 101 (35/66) | undefined | 0.0% [0.0%, 9.9%] (n=35) | n/a |
| 4104 | 12 (7/5) | undefined | 0.0% [0.0%, 35.4%] (n=7) | n/a |
| 4624 | 74 (35/39) | undefined | 0.0% [0.0%, 9.9%] (n=35) | n/a |
| 4672 | 71 (35/36) | undefined | 0.0% [0.0%, 9.9%] (n=35) | n/a |
| 4688 | 208 (34/174) | undefined | 0.0% [0.0%, 10.2%] (n=34) | n/a |
| 4689 | 209 (34/175) | undefined | 0.0% [0.0%, 10.2%] (n=34) | n/a |
| 5 | 210 (35/175) | undefined | 0.0% [0.0%, 9.9%] (n=35) | n/a |

#### Per-event_type

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| authentication | 145 (70/75) | undefined | 0.0% [0.0%, 5.2%] (n=70) | n/a |
| file | 207 (33/174) | undefined | 0.0% [0.0%, 10.4%] (n=33) | n/a |
| network | 101 (35/66) | undefined | 0.0% [0.0%, 9.9%] (n=35) | n/a |
| other | 1 (1/0) | undefined | 0.0% [0.0%, 79.3%] (n=1) | n/a |
| process | 1055 (178/877) | -0.002 | 19.7% [14.5%, 26.1%] (n=178) | 16.7% [12.3%, 22.4%] (n=209) |
| registry | 416 (68/348) | undefined | 0.0% [0.0%, 5.3%] (n=68) | n/a |

#### Per-technique (sentinel EXCLUDED, see below)

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| T1053 | 1 (1/0) | undefined | 0.0% [0.0%, 79.3%] (n=1) | n/a |
| T1087 | 2 (2/0) | undefined | 0.0% [0.0%, 65.8%] (n=2) | n/a |
| T1123 | 4 (4/0) | undefined | 25.0% [4.6%, 69.9%] (n=4) | 100.0% [20.7%, 100.0%] (n=1) |
| T1547 | 47 (47/0) | undefined | 2.1% [0.4%, 11.1%] (n=47) | 100.0% [20.7%, 100.0%] (n=1) |
| benign | 1540 (0/1540) | undefined | n/a | 0.0% [0.0%, 2.2%] (n=174) |

#### MULTI_TECHNIQUE_UNRESOLVED sentinel bucket (reported separately, never scored per-technique)
n=331 malicious records whose source capture (OTRF APT29 compound scenarios) has no OTRF-published per-event technique mapping. No per-technique claim is made for these records.
Aggregate recall under `conservative` policy: 0.100 [0.072, 0.137] (n=331)

### classical_ml

Pooled n=1925 (malicious=385, benign=1540)

#### Policy: `conservative`  (HEADLINE)
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 156 | 525 | 229 | 1015 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.054 |
| PR-AUC | 0.326 |
| ROC-AUC (secondary) | 0.536 |
| Balanced accuracy | 0.532 |
| Precision | 0.229 [0.199, 0.262] (n=681) |
| Recall | 0.405 [0.357, 0.455] (n=385) |
| F1 | 0.293 |
| FPR = FP/(FP+TN) | 0.341 [0.318, 0.365] (n=1540) |
| FNR = FN/(FN+TP) | 0.595 |
| Accuracy (context only, NOT a headline) | 0.608 |

#### Policy: `high_precision`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 156 | 525 | 229 | 1015 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.054 |
| PR-AUC | 0.326 |
| ROC-AUC (secondary) | 0.536 |
| Balanced accuracy | 0.532 |
| Precision | 0.229 [0.199, 0.262] (n=681) |
| Recall | 0.405 [0.357, 0.455] (n=385) |
| F1 | 0.293 |
| FPR = FP/(FP+TN) | 0.341 [0.318, 0.365] (n=1540) |
| FNR = FN/(FN+TP) | 0.595 |
| Accuracy (context only, NOT a headline) | 0.608 |

#### Policy: `abstention`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 156 | 525 | 229 | 1015 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.054 |
| PR-AUC | 0.326 |
| ROC-AUC (secondary) | 0.536 |
| Balanced accuracy | 0.532 |
| Precision | 0.229 [0.199, 0.262] (n=681) |
| Recall | 0.405 [0.357, 0.455] (n=385) |
| F1 | 0.293 |
| FPR = FP/(FP+TN) | 0.341 [0.318, 0.365] (n=1540) |
| FNR = FN/(FN+TP) | 0.595 |
| Accuracy (context only, NOT a headline) | 0.608 |

#### Abstention / selective-prediction detail
- Coverage: 100.0% (1925/1925 committed, 0 abstained)
- Selective accuracy (on committed subset): 0.608
- AURC: not computed (no confidence scores available for this system)

#### Per-EventID

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| 1 | 208 (34/174) | 0.350 | 17.6% [8.3%, 33.5%] (n=34) | 85.7% [48.7%, 97.4%] (n=7) |
| 10 | 208 (34/174) | undefined | 100.0% [89.8%, 100.0%] (n=34) | 16.3% [11.9%, 22.0%] (n=208) |
| 11 | 208 (34/174) | undefined | 100.0% [89.8%, 100.0%] (n=34) | 16.3% [11.9%, 22.0%] (n=208) |
| 12 | 208 (34/174) | 0.355 | 14.7% [6.4%, 30.1%] (n=34) | 100.0% [56.6%, 100.0%] (n=5) |
| 13 | 208 (34/174) | undefined | 0.0% [0.0%, 10.2%] (n=34) | n/a |
| 3 | 101 (35/66) | 0.480 | 31.4% [18.6%, 48.0%] (n=35) | 100.0% [74.1%, 100.0%] (n=11) |
| 4104 | 12 (7/5) | undefined | 0.0% [0.0%, 35.4%] (n=7) | n/a |
| 4624 | 74 (35/39) | undefined | 0.0% [0.0%, 9.9%] (n=35) | n/a |
| 4672 | 71 (35/36) | undefined | 0.0% [0.0%, 9.9%] (n=35) | n/a |
| 4688 | 208 (34/174) | 0.947 | 91.2% [77.0%, 97.0%] (n=34) | 100.0% [89.0%, 100.0%] (n=31) |
| 4689 | 209 (34/175) | undefined | 100.0% [89.8%, 100.0%] (n=34) | 16.3% [11.9%, 21.9%] (n=209) |
| 5 | 210 (35/175) | 0.088 | 2.9% [0.5%, 14.5%] (n=35) | 50.0% [9.5%, 90.5%] (n=2) |

#### Per-event_type

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| authentication | 145 (70/75) | undefined | 0.0% [0.0%, 5.2%] (n=70) | n/a |
| file | 207 (33/174) | undefined | 100.0% [89.6%, 100.0%] (n=33) | 15.9% [11.6%, 21.5%] (n=207) |
| network | 101 (35/66) | 0.480 | 31.4% [18.6%, 48.0%] (n=35) | 100.0% [74.1%, 100.0%] (n=11) |
| other | 1 (1/0) | undefined | 100.0% [20.7%, 100.0%] (n=1) | 100.0% [20.7%, 100.0%] (n=1) |
| process | 1055 (178/877) | 0.148 | 59.6% [52.2%, 66.5%] (n=178) | 23.2% [19.6%, 27.3%] (n=457) |
| registry | 416 (68/348) | 0.250 | 7.4% [3.2%, 16.1%] (n=68) | 100.0% [56.6%, 100.0%] (n=5) |

#### Per-technique (sentinel EXCLUDED, see below)

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| T1053 | 1 (1/0) | undefined | 0.0% [0.0%, 79.3%] (n=1) | n/a |
| T1087 | 2 (2/0) | undefined | 50.0% [9.5%, 90.5%] (n=2) | 100.0% [20.7%, 100.0%] (n=1) |
| T1123 | 4 (4/0) | undefined | 50.0% [15.0%, 85.0%] (n=4) | 100.0% [34.2%, 100.0%] (n=2) |
| T1547 | 47 (47/0) | undefined | 53.2% [39.2%, 66.7%] (n=47) | 100.0% [86.7%, 100.0%] (n=25) |
| benign | 1540 (0/1540) | undefined | n/a | 0.0% [0.0%, 0.7%] (n=525) |

#### MULTI_TECHNIQUE_UNRESOLVED sentinel bucket (reported separately, never scored per-technique)
n=331 malicious records whose source capture (OTRF APT29 compound scenarios) has no OTRF-published per-event technique mapping. No per-technique claim is made for these records.
Aggregate recall under `conservative` policy: 0.387 [0.336, 0.440] (n=331)

## Significance: LLM vs. each baseline (headline policy)

| Baseline | McNemar method | b (LLM right, base wrong) | c (base right, LLM wrong) | p-value | Bootstrap accuracy diff [95% CI] |
|---|---|---|---|---|---|
| majority_class | chi_squared_continuity_corrected | 268 | 1045 | 9.569e-102 | -0.404 [-0.436, -0.371] |
| stratified_random | chi_squared_continuity_corrected | 317 | 819 | 5.608e-50 | -0.261 [-0.293, -0.228] |
| rules_heuristic | chi_squared_continuity_corrected | 292 | 930 | 3.432e-74 | -0.332 [-0.364, -0.299] |
| classical_ml | chi_squared_continuity_corrected | 323 | 731 | 4.717e-36 | -0.212 [-0.244, -0.180] |

## What must be disclosed (honest-limitations section)

1. **This is a static, offline, labeled-corpus evaluation**, not a live-SOC
   measurement. MTTD/MTTR/dwell-time/analyst-touch-time remain uncomputable
   and unclaimed here — Phase 0's finding, not re-derived, only inherited.
2. **The `suspicious`-collapse policy used for the headline number** is
   `conservative` (`suspicious` -> `malicious`), chosen because a triage
   system's cost asymmetry favors extra human review over a missed
   intrusion. The other two policies' (`high_precision`, `abstention`) full
   tables are published alongside it above — never read the headline number
   as the only honest collapse of `suspicious`.
3. **Exact temperature, seed, model name+version, and prompt template
   version**: see the corpus/run metadata block emitted alongside this
   report by `scripts/run_eval.py` — an unversioned, undisclosed prompt
   makes every downstream number irreproducible by definition.
4. **Parse-failure rate** is reported above as an ACTUAL measured number for
   this run, not an assumed near-zero; the design brief's requested
   grammar-vs-semantic-validation split is not separately measurable from
   outside `triage_alert` in its current form (`TriageError` does not
   currently distinguish HTTP/transport failure, JSON-grammar failure, and
   `TriageVerdict` semantic-validation failure from each other) — this run's
   parse-failure rate is the union of all three failure surfaces, not solely
   surface (b). Splitting them further would require a change to
   `src/agents/triage.py`, which is out of scope for this task (see "What I
   could not do").
5. **ECE / calibration on the `confidence` field** is reported above,
   including if it turns out poorly calibrated — if ECE is high, the
   abstention/selective-prediction thresholding in the pooled section above
   is correspondingly less trustworthy at whatever confidence threshold a
   downstream consumer might pick, because it inherits the same field.
6. **Sample size (n) is reported next to every metric above**, at every
   stratification level, including per-technique breakdowns with small n
   and their (necessarily wide) Wilson CIs — never omitted for being thin.
7. **Corpus construction choices**: `benign_ratio=4.0` is a stated design
   choice (`src/corpus.py`'s own docstring), not a claim of matching real
   ~99:1 SOC prevalence. `mitigate_shortcuts=True` was used to assemble the
   corpus this run scored — see `src/ingest/leakage.py` for exactly what
   that mitigation changes (hostname pseudonymization, timestamp
   neutralization, raw_event field-set ablation to the cross-source
   intersection, and a capped per-EventID class ratio). The
   `MULTI_TECHNIQUE_UNRESOLVED` sentinel bucket's own aggregate metrics are
   reported separately above; no per-technique claim is made for those
   records.
8. **What this does not measure**: MTTD, MTTR, dwell-time, and
   analyst-touch-time are NOT computed anywhere in this report, and cannot
   be honestly computed from a static labeled corpus (no real analyst, no
   real alert arrival-time distribution) — named explicitly here so the
   omission reads as a stated limitation, not an oversight.
9. **No claim of comparability to any external published SOC-LLM benchmark's
   numbers** (e.g. Simbian's "AI SOC LLM Benchmark", n=100, no visible CIs
   or significance testing found in that prior art). Different corpus,
   different ground-truth construction, different task framing — this
   report's numbers stand on their own terms.
