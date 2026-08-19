# AI Triage Engine — Context-Richness Hypothesis Experiment

Tests the run-1 subgroup observation (`reports/evaluation-run1.md`) that the LLM's performance splits sharply between EventIDs carrying a semantic actor/object and EventIDs carrying only bare machine state, on a FRESH, independently-seeded sample not reused from run 1.

## Result

**CONFIRMED.**

All four pre-registered CONFIRM conditions (see "Pre-registered prediction" below,
committed before the LLM was run on either bucket) are met, on a fresh sample drawn
with a different seed (20260819) than run 1 (20260818):

1. **MCC(context_rich) = 0.165, 95% one-sample bootstrap CI [0.123, 0.209]** (10,000
   resamples, `conservative` policy, n=1925/bucket) — positive and meaningfully above
   chance; CI excludes 0.
2. **MCC(context_poor) = -0.188, 95% CI [-0.235, -0.142]** — not merely "at chance," but
   *significantly worse than chance* (CI excludes 0 on the negative side): a stronger
   result than the pre-registration's minimum bar for this leg ("point estimate <= 0,
   or a CI that includes 0" would have sufficed; the data instead shows the LLM is a
   measurably harmful predictor on context-poor records).
3. **Unpaired (two-sample) bootstrap CI on the MCC difference:
   context_rich − context_poor = +0.353, 95% CI [+0.292, +0.417]** (10,000 resamples) —
   excludes 0. The pooled-run-1 gap survives being re-tested on a disjoint, freshly
   drawn sample; it is not an artifact of the sample run 1 happened to draw.
4. **On context_rich, the LLM (MCC 0.165) beats every baseline evaluated on the SAME
   context_rich sample**: classical_ml 0.057, rules_heuristic 0.064, stratified_random
   0.023, majority_class undefined (recall 0 by construction). This is the "does it
   beat the baselines THERE, when it lost everywhere pooled" claim the task brief
   calls the actually-interesting question — answered yes, not merely "LLM MCC > 0."
   (For contrast: on context_poor, classical_ml (MCC 0.049) beats the LLM (-0.188) —
   the LLM is the worst-performing system of the five on context-poor records, not
   just a non-winner.)

The mechanism proposed in run 1's subgroup finding — the model reasons well over a
named actor/object and fails on bare machine-state identifiers — held up under a
predicate defined from field presence alone (never from the EventID list it was
originally observed on) and re-tested on non-overlapping data.

## Pre-registered prediction

Committed BEFORE running the LLM on either bucket's sample.

**Hypothesis under test:** the LLM performs well when a record names a
semantic actor/object it can reason about, and performs at-or-below chance
when the record is bare machine state with no such field (see module
docstring / this report's introduction for the full statement, carried over
verbatim from the run-1 observation this experiment tests).

**CONFIRMS the hypothesis** if, on the headline (`conservative`) policy:
  - MCC(context_rich) is positive AND meaningfully above chance (its 95% CI
    excludes 0), AND
  - MCC(context_poor) is at-or-below chance (point estimate <= 0, or a 95%
    CI that includes 0), AND
  - the unpaired bootstrap 95% CI on MCC(context_rich) - MCC(context_poor)
    excludes 0 (the gap itself is not explainable by sampling noise), AND
  - on context_rich, the LLM beats the best-performing baseline's MCC by a
    margin larger than that baseline's own year-over-run noise would explain
    (reported qualitatively against each baseline's MCC + CI, since a single
    run has no repeated-baseline variance estimate) -- this is the "does it
    beat the baselines THERE, when it lost everywhere pooled" claim the task
    brief calls the actually-interesting question, not merely "LLM MCC > 0
    on context_rich".

**REFUTES the hypothesis** if:
  - MCC(context_rich) is NOT meaningfully above chance (its CI includes 0 or
    is negative), regardless of what context_poor does -- the "it does well
    with context" half fails on its own account, independent of the
    poor-bucket comparison, OR
  - the unpaired bootstrap CI on the MCC difference includes 0 -- the
    pooled-run gap observed in run 1 does not survive being tested on a
    disjoint, freshly-drawn sample, OR
  - context_rich's LLM MCC is statistically indistinguishable from (or worse
    than) its own best baseline's MCC on the SAME context_rich sample -- i.e.
    even if the LLM is "less bad" on context-rich data, it is not
    demonstrating genuine semantic reasoning if a baseline gets there too.

**INCONCLUSIVE** if the achieved malicious floor in either bucket falls
meaningfully short of 385 (wide CIs prevent either CONFIRM or REFUTE from
being asserted honestly), or if context_poor's own CI is too wide to
distinguish "at chance" from "meaningfully negative" -- reported as
inconclusive rather than forced into a verdict the data cannot support.

## Bucket definition

`src/eval/context_bucket.py::is_context_rich(record)` — a record is **context-rich** iff its (post shortcut-mitigation) `raw_event` carries at least one non-empty, non-placeholder value for one of the fields below; otherwise it is **context-poor**. Defined from FIELD PRESENCE only — never from `EventID` or `event_type` — see that module's docstring for the full per-field rationale.

- ACTOR fields (who/what specifically acted): `CommandLine, ParentCommandLine, ParentImage, User, SubjectUserName, TargetUserName, ScriptBlockText`
- OBJECT fields (a specific external destination/target): `DestinationIp, DestinationHostname`
- Excluded on purpose: a bare `Image`/`SourceImage`/`TargetImage` path alone (present on nearly every EventID in this corpus, so it carries no discriminating signal by itself), and opaque identifiers (`TargetObject`, `TargetFilename`, `CallTrace`, `ProcessGuid`, `ProcessId`, `LogonGuid`).

### EventID membership, AS A CONSEQUENCE of the predicate (not an input to it)

| EventID | n in context_rich sample | n in context_poor sample |
|---|---|---|
| 1 | 532 | 11 |
| 3 | 133 | 0 |
| 5 | 0 | 374 |
| 10 | 0 | 373 |
| 11 | 0 | 374 |
| 12 | 0 | 374 |
| 13 | 0 | 373 |
| 4104 | 10 | 2 |
| 4624 | 97 | 0 |
| 4672 | 90 | 0 |
| 4688 | 531 | 44 |
| 4689 | 532 | 0 |

## Run metadata

- **prompt_template_version**: phase-2-single-agent-v1
- **experiment_seed**: 20260819
- **run1_eval_seed_for_comparison**: 20260818
- **benign_ratio**: 4.0
- **mitigate_shortcuts**: True
- **model**: qwen2.5:7b-instruct-q4_K_M
- **temperature**: 0.0
- **per_bucket_sample_target**: 1925
- **malicious_floor_per_bucket**: 385
- **context_rich_classical_ml_split**: malicious=capture_level_exclusion, benign=record_level_holdout_fallback
- **context_poor_classical_ml_split**: malicious=capture_level_exclusion, benign=record_level_holdout_fallback

## Results

### Bucket: `context_rich`

Sample: target 1925 total (385 malicious floor-targeted), achieved 1925 total (385 malicious / 1540 benign), 385-floor met: True

#### `context_rich` headline table (headline policy = `conservative`)

| System | n | MCC | PR-AUC | ROC-AUC (secondary) | Balanced acc. | Recall [Wilson 95% CI] | Precision [Wilson 95% CI] |
|---|---|---|---|---|---|---|---|
| llm | 1925 | 0.165 | 0.365 | 0.664 | 0.603 | 67.5% [62.7%, 72.0%] (n=385) | 26.5% [23.8%, 29.3%] (n=982) |
| majority_class | 1925 | undefined | 0.200 | 0.500 | 0.500 | 0.0% [0.0%, 1.0%] (n=385) | n/a |
| stratified_random | 1925 | 0.023 | 0.200 | 0.494 | 0.511 | 20.5% [16.8%, 24.8%] (n=385) | 21.9% [17.9%, 26.4%] (n=361) |
| rules_heuristic | 1925 | 0.064 | 0.204 | 0.503 | 0.503 | 0.5% [0.1%, 1.9%] (n=385) | 100.0% [34.2%, 100.0%] (n=2) |
| classical_ml | 1925 | 0.057 | 0.385 | 0.648 | 0.535 | 48.3% [43.4%, 53.3%] (n=385) | 22.6% [19.9%, 25.6%] (n=822) |

### context_rich / llm

Pooled n=1925 (malicious=385, benign=1540)

#### Policy: `conservative`  (HEADLINE)
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 260 | 722 | 125 | 818 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.165 |
| PR-AUC | 0.365 |
| ROC-AUC (secondary) | 0.664 |
| Balanced accuracy | 0.603 |
| Precision | 0.265 [0.238, 0.293] (n=982) |
| Recall | 0.675 [0.627, 0.720] (n=385) |
| F1 | 0.380 |
| FPR = FP/(FP+TN) | 0.469 [0.444, 0.494] (n=1540) |
| FNR = FN/(FN+TP) | 0.325 |
| Accuracy (context only, NOT a headline) | 0.560 |

#### Policy: `high_precision`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 60 | 38 | 325 | 1502 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.239 |
| PR-AUC | 0.365 |
| ROC-AUC (secondary) | 0.664 |
| Balanced accuracy | 0.566 |
| Precision | 0.612 [0.513, 0.703] (n=98) |
| Recall | 0.156 [0.123, 0.195] (n=385) |
| F1 | 0.248 |
| FPR = FP/(FP+TN) | 0.025 [0.018, 0.034] (n=1540) |
| FNR = FN/(FN+TP) | 0.844 |
| Accuracy (context only, NOT a headline) | 0.811 |

#### Policy: `abstention`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 60 | 38 | 125 | 818 | 1041 |

| Metric | Value |
|---|---|
| MCC | 0.366 |
| PR-AUC | 0.319 |
| ROC-AUC (secondary) | 0.640 |
| Balanced accuracy | 0.640 |
| Precision | 0.612 [0.513, 0.703] (n=98) |
| Recall | 0.324 [0.261, 0.395] (n=185) |
| F1 | 0.424 |
| FPR = FP/(FP+TN) | 0.044 [0.033, 0.060] (n=856) |
| FNR = FN/(FN+TP) | 0.676 |
| Accuracy (context only, NOT a headline) | 0.843 |

#### Abstention / selective-prediction detail
- Coverage: 54.1% (1041/1925 committed, 884 abstained)
- Selective accuracy (on committed subset): 0.843
- AURC (area under risk-coverage curve, lower=better): 0.1510

#### LLM-specific metrics

- Parse-failure rate: 0.0% [0.0%, 0.2%] (n=1925) (0/1925 attempted)
- Expected Calibration Error (ECE) on self-reported `confidence`: 0.3029
  - Reliability bins (low-high: n, avg_confidence, empirical accuracy):
    - [0.7-0.8): n=797, avg_conf=0.750, acc=0.171
    - [0.8-0.9): n=81, avg_conf=0.850, acc=0.778
    - [0.9-1.0): n=1047, avg_conf=0.950, acc=0.840
- Run-to-run determinism: NOT MEASURED in this run (see limitations section)

#### Per-EventID

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| 1 | 532 (67/465) | 0.232 | 14.9% [8.3%, 25.3%] (n=67) | 52.6% [31.7%, 72.7%] (n=19) |
| 3 | 133 (67/66) | 0.139 | 95.5% [87.6%, 98.5%] (n=67) | 52.5% [43.7%, 61.1%] (n=122) |
| 4104 | 10 (5/5) | -0.408 | 40.0% [11.8%, 76.9%] (n=5) | 33.3% [9.7%, 70.0%] (n=6) |
| 4624 | 97 (58/39) | 0.806 | 94.8% [85.9%, 98.2%] (n=58) | 90.2% [80.2%, 95.4%] (n=61) |
| 4672 | 90 (54/36) | undefined | 100.0% [93.4%, 100.0%] (n=54) | 60.0% [49.7%, 69.5%] (n=90) |
| 4688 | 531 (67/464) | -0.074 | 86.6% [76.4%, 92.8%] (n=67) | 11.9% [9.3%, 15.1%] (n=488) |
| 4689 | 532 (67/465) | -0.090 | 25.4% [16.5%, 36.9%] (n=67) | 8.7% [5.5%, 13.5%] (n=196) |

#### Per-event_type

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| authentication | 187 (112/75) | 0.514 | 97.3% [92.4%, 99.1%] (n=112) | 72.2% [64.6%, 78.7%] (n=151) |
| network | 133 (67/66) | 0.139 | 95.5% [87.6%, 98.5%] (n=67) | 52.5% [43.7%, 61.1%] (n=122) |
| process | 1605 (206/1399) | -0.015 | 42.2% [35.7%, 49.1%] (n=206) | 12.3% [10.1%, 14.9%] (n=709) |

#### Per-technique (sentinel EXCLUDED, see below)

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| T1053 | 5 (5/0) | undefined | 100.0% [56.6%, 100.0%] (n=5) | 100.0% [56.6%, 100.0%] (n=5) |
| T1069 | 1 (1/0) | undefined | 100.0% [20.7%, 100.0%] (n=1) | 100.0% [20.7%, 100.0%] (n=1) |
| T1123 | 3 (3/0) | undefined | 66.7% [20.8%, 93.9%] (n=3) | 100.0% [34.2%, 100.0%] (n=2) |
| T1547 | 65 (65/0) | undefined | 63.1% [50.9%, 73.8%] (n=65) | 100.0% [91.4%, 100.0%] (n=41) |
| benign | 1540 (0/1540) | undefined | n/a | 0.0% [0.0%, 0.5%] (n=722) |

#### MULTI_TECHNIQUE_UNRESOLVED sentinel bucket (reported separately, never scored per-technique)
n=311 malicious records whose source capture (OTRF APT29 compound scenarios) has no OTRF-published per-event technique mapping. No per-technique claim is made for these records.
Aggregate recall under `conservative` policy: 0.678 [0.625, 0.728] (n=311)

### context_rich / majority_class

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
| 1 | 532 (67/465) | undefined | 0.0% [0.0%, 5.4%] (n=67) | n/a |
| 3 | 133 (67/66) | undefined | 0.0% [0.0%, 5.4%] (n=67) | n/a |
| 4104 | 10 (5/5) | undefined | 0.0% [0.0%, 43.4%] (n=5) | n/a |
| 4624 | 97 (58/39) | undefined | 0.0% [0.0%, 6.2%] (n=58) | n/a |
| 4672 | 90 (54/36) | undefined | 0.0% [0.0%, 6.6%] (n=54) | n/a |
| 4688 | 531 (67/464) | undefined | 0.0% [0.0%, 5.4%] (n=67) | n/a |
| 4689 | 532 (67/465) | undefined | 0.0% [0.0%, 5.4%] (n=67) | n/a |

#### Per-event_type

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| authentication | 187 (112/75) | undefined | 0.0% [0.0%, 3.3%] (n=112) | n/a |
| network | 133 (67/66) | undefined | 0.0% [0.0%, 5.4%] (n=67) | n/a |
| process | 1605 (206/1399) | undefined | 0.0% [0.0%, 1.8%] (n=206) | n/a |

#### Per-technique (sentinel EXCLUDED, see below)

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| T1053 | 5 (5/0) | undefined | 0.0% [0.0%, 43.4%] (n=5) | n/a |
| T1069 | 1 (1/0) | undefined | 0.0% [0.0%, 79.3%] (n=1) | n/a |
| T1123 | 3 (3/0) | undefined | 0.0% [0.0%, 56.1%] (n=3) | n/a |
| T1547 | 65 (65/0) | undefined | 0.0% [0.0%, 5.6%] (n=65) | n/a |
| benign | 1540 (0/1540) | undefined | n/a | n/a |

#### MULTI_TECHNIQUE_UNRESOLVED sentinel bucket (reported separately, never scored per-technique)
n=311 malicious records whose source capture (OTRF APT29 compound scenarios) has no OTRF-published per-event technique mapping. No per-technique claim is made for these records.
Aggregate recall under `conservative` policy: 0.000 [0.000, 0.012] (n=311)

### context_rich / stratified_random

Pooled n=1925 (malicious=385, benign=1540)

#### Policy: `conservative`  (HEADLINE)
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 79 | 282 | 306 | 1258 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.023 |
| PR-AUC | 0.200 |
| ROC-AUC (secondary) | 0.494 |
| Balanced accuracy | 0.511 |
| Precision | 0.219 [0.179, 0.264] (n=361) |
| Recall | 0.205 [0.168, 0.248] (n=385) |
| F1 | 0.212 |
| FPR = FP/(FP+TN) | 0.183 [0.165, 0.203] (n=1540) |
| FNR = FN/(FN+TP) | 0.795 |
| Accuracy (context only, NOT a headline) | 0.695 |

#### Policy: `high_precision`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 79 | 282 | 306 | 1258 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.023 |
| PR-AUC | 0.200 |
| ROC-AUC (secondary) | 0.494 |
| Balanced accuracy | 0.511 |
| Precision | 0.219 [0.179, 0.264] (n=361) |
| Recall | 0.205 [0.168, 0.248] (n=385) |
| F1 | 0.212 |
| FPR = FP/(FP+TN) | 0.183 [0.165, 0.203] (n=1540) |
| FNR = FN/(FN+TP) | 0.795 |
| Accuracy (context only, NOT a headline) | 0.695 |

#### Policy: `abstention`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 79 | 282 | 306 | 1258 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.023 |
| PR-AUC | 0.200 |
| ROC-AUC (secondary) | 0.494 |
| Balanced accuracy | 0.511 |
| Precision | 0.219 [0.179, 0.264] (n=361) |
| Recall | 0.205 [0.168, 0.248] (n=385) |
| F1 | 0.212 |
| FPR = FP/(FP+TN) | 0.183 [0.165, 0.203] (n=1540) |
| FNR = FN/(FN+TP) | 0.795 |
| Accuracy (context only, NOT a headline) | 0.695 |

#### Abstention / selective-prediction detail
- Coverage: 100.0% (1925/1925 committed, 0 abstained)
- Selective accuracy (on committed subset): 0.695
- AURC: not computed (no confidence scores available for this system)

#### Per-EventID

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| 1 | 532 (67/465) | -0.003 | 16.4% [9.4%, 27.1%] (n=67) | 12.4% [7.0%, 20.8%] (n=89) |
| 3 | 133 (67/66) | -0.042 | 17.9% [10.6%, 28.7%] (n=67) | 46.2% [28.8%, 64.5%] (n=26) |
| 4104 | 10 (5/5) | 0.500 | 40.0% [11.8%, 76.9%] (n=5) | 100.0% [34.2%, 100.0%] (n=2) |
| 4624 | 97 (58/39) | -0.019 | 19.0% [10.9%, 30.9%] (n=58) | 57.9% [36.3%, 76.9%] (n=19) |
| 4672 | 90 (54/36) | -0.025 | 14.8% [7.7%, 26.6%] (n=54) | 57.1% [32.6%, 78.6%] (n=14) |
| 4688 | 531 (67/464) | 0.029 | 22.4% [14.1%, 33.7%] (n=67) | 14.6% [9.0%, 22.6%] (n=103) |
| 4689 | 532 (67/465) | 0.090 | 29.9% [20.2%, 41.7%] (n=67) | 18.5% [12.3%, 26.9%] (n=108) |

#### Per-event_type

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| authentication | 187 (112/75) | -0.022 | 17.0% [11.1%, 25.0%] (n=112) | 57.6% [40.8%, 72.8%] (n=33) |
| network | 133 (67/66) | -0.042 | 17.9% [10.6%, 28.7%] (n=67) | 46.2% [28.8%, 64.5%] (n=26) |
| process | 1605 (206/1399) | 0.044 | 23.3% [18.0%, 29.5%] (n=206) | 15.9% [12.2%, 20.4%] (n=302) |

#### Per-technique (sentinel EXCLUDED, see below)

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| T1053 | 5 (5/0) | undefined | 20.0% [3.6%, 62.4%] (n=5) | 100.0% [20.7%, 100.0%] (n=1) |
| T1069 | 1 (1/0) | undefined | 0.0% [0.0%, 79.3%] (n=1) | n/a |
| T1123 | 3 (3/0) | undefined | 33.3% [6.1%, 79.2%] (n=3) | 100.0% [20.7%, 100.0%] (n=1) |
| T1547 | 65 (65/0) | undefined | 24.6% [15.8%, 36.3%] (n=65) | 100.0% [80.6%, 100.0%] (n=16) |
| benign | 1540 (0/1540) | undefined | n/a | 0.0% [0.0%, 1.3%] (n=282) |

#### MULTI_TECHNIQUE_UNRESOLVED sentinel bucket (reported separately, never scored per-technique)
n=311 malicious records whose source capture (OTRF APT29 compound scenarios) has no OTRF-published per-event technique mapping. No per-technique claim is made for these records.
Aggregate recall under `conservative` policy: 0.196 [0.156, 0.244] (n=311)

### context_rich / rules_heuristic

Pooled n=1925 (malicious=385, benign=1540)

#### Policy: `conservative`  (HEADLINE)
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 2 | 0 | 383 | 1540 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.064 |
| PR-AUC | 0.204 |
| ROC-AUC (secondary) | 0.503 |
| Balanced accuracy | 0.503 |
| Precision | 1.000 [0.342, 1.000] (n=2) |
| Recall | 0.005 [0.001, 0.019] (n=385) |
| F1 | 0.010 |
| FPR = FP/(FP+TN) | 0.000 [0.000, 0.002] (n=1540) |
| FNR = FN/(FN+TP) | 0.995 |
| Accuracy (context only, NOT a headline) | 0.801 |

#### Policy: `high_precision`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 2 | 0 | 383 | 1540 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.064 |
| PR-AUC | 0.204 |
| ROC-AUC (secondary) | 0.503 |
| Balanced accuracy | 0.503 |
| Precision | 1.000 [0.342, 1.000] (n=2) |
| Recall | 0.005 [0.001, 0.019] (n=385) |
| F1 | 0.010 |
| FPR = FP/(FP+TN) | 0.000 [0.000, 0.002] (n=1540) |
| FNR = FN/(FN+TP) | 0.995 |
| Accuracy (context only, NOT a headline) | 0.801 |

#### Policy: `abstention`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 2 | 0 | 383 | 1540 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.064 |
| PR-AUC | 0.204 |
| ROC-AUC (secondary) | 0.503 |
| Balanced accuracy | 0.503 |
| Precision | 1.000 [0.342, 1.000] (n=2) |
| Recall | 0.005 [0.001, 0.019] (n=385) |
| F1 | 0.010 |
| FPR = FP/(FP+TN) | 0.000 [0.000, 0.002] (n=1540) |
| FNR = FN/(FN+TP) | 0.995 |
| Accuracy (context only, NOT a headline) | 0.801 |

#### Abstention / selective-prediction detail
- Coverage: 100.0% (1925/1925 committed, 0 abstained)
- Selective accuracy (on committed subset): 0.801
- AURC: not computed (no confidence scores available for this system)

#### Per-EventID

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| 1 | 532 (67/465) | undefined | 0.0% [0.0%, 5.4%] (n=67) | n/a |
| 3 | 133 (67/66) | undefined | 0.0% [0.0%, 5.4%] (n=67) | n/a |
| 4104 | 10 (5/5) | undefined | 0.0% [0.0%, 43.4%] (n=5) | n/a |
| 4624 | 97 (58/39) | undefined | 0.0% [0.0%, 6.2%] (n=58) | n/a |
| 4672 | 90 (54/36) | undefined | 0.0% [0.0%, 6.6%] (n=54) | n/a |
| 4688 | 531 (67/464) | 0.162 | 3.0% [0.8%, 10.2%] (n=67) | 100.0% [34.2%, 100.0%] (n=2) |
| 4689 | 532 (67/465) | undefined | 0.0% [0.0%, 5.4%] (n=67) | n/a |

#### Per-event_type

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| authentication | 187 (112/75) | undefined | 0.0% [0.0%, 3.3%] (n=112) | n/a |
| network | 133 (67/66) | undefined | 0.0% [0.0%, 5.4%] (n=67) | n/a |
| process | 1605 (206/1399) | 0.092 | 1.0% [0.3%, 3.5%] (n=206) | 100.0% [34.2%, 100.0%] (n=2) |

#### Per-technique (sentinel EXCLUDED, see below)

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| T1053 | 5 (5/0) | undefined | 0.0% [0.0%, 43.4%] (n=5) | n/a |
| T1069 | 1 (1/0) | undefined | 0.0% [0.0%, 79.3%] (n=1) | n/a |
| T1123 | 3 (3/0) | undefined | 0.0% [0.0%, 56.1%] (n=3) | n/a |
| T1547 | 65 (65/0) | undefined | 0.0% [0.0%, 5.6%] (n=65) | n/a |
| benign | 1540 (0/1540) | undefined | n/a | n/a |

#### MULTI_TECHNIQUE_UNRESOLVED sentinel bucket (reported separately, never scored per-technique)
n=311 malicious records whose source capture (OTRF APT29 compound scenarios) has no OTRF-published per-event technique mapping. No per-technique claim is made for these records.
Aggregate recall under `conservative` policy: 0.006 [0.002, 0.023] (n=311)

### context_rich / classical_ml

Pooled n=1925 (malicious=385, benign=1540)

#### Policy: `conservative`  (HEADLINE)
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 186 | 636 | 199 | 904 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.057 |
| PR-AUC | 0.385 |
| ROC-AUC (secondary) | 0.648 |
| Balanced accuracy | 0.535 |
| Precision | 0.226 [0.199, 0.256] (n=822) |
| Recall | 0.483 [0.434, 0.533] (n=385) |
| F1 | 0.308 |
| FPR = FP/(FP+TN) | 0.413 [0.389, 0.438] (n=1540) |
| FNR = FN/(FN+TP) | 0.517 |
| Accuracy (context only, NOT a headline) | 0.566 |

#### Policy: `high_precision`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 186 | 636 | 199 | 904 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.057 |
| PR-AUC | 0.385 |
| ROC-AUC (secondary) | 0.648 |
| Balanced accuracy | 0.535 |
| Precision | 0.226 [0.199, 0.256] (n=822) |
| Recall | 0.483 [0.434, 0.533] (n=385) |
| F1 | 0.308 |
| FPR = FP/(FP+TN) | 0.413 [0.389, 0.438] (n=1540) |
| FNR = FN/(FN+TP) | 0.517 |
| Accuracy (context only, NOT a headline) | 0.566 |

#### Policy: `abstention`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 186 | 636 | 199 | 904 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.057 |
| PR-AUC | 0.385 |
| ROC-AUC (secondary) | 0.648 |
| Balanced accuracy | 0.535 |
| Precision | 0.226 [0.199, 0.256] (n=822) |
| Recall | 0.483 [0.434, 0.533] (n=385) |
| F1 | 0.308 |
| FPR = FP/(FP+TN) | 0.413 [0.389, 0.438] (n=1540) |
| FNR = FN/(FN+TP) | 0.517 |
| Accuracy (context only, NOT a headline) | 0.566 |

#### Abstention / selective-prediction detail
- Coverage: 100.0% (1925/1925 committed, 0 abstained)
- Selective accuracy (on committed subset): 0.566
- AURC: not computed (no confidence scores available for this system)

#### Per-EventID

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| 1 | 532 (67/465) | 0.503 | 77.6% [66.3%, 85.9%] (n=67) | 43.7% [35.1%, 52.7%] (n=119) |
| 3 | 133 (67/66) | undefined | 100.0% [94.6%, 100.0%] (n=67) | 50.4% [42.0%, 58.7%] (n=133) |
| 4104 | 10 (5/5) | undefined | 0.0% [0.0%, 43.4%] (n=5) | n/a |
| 4624 | 97 (58/39) | undefined | 100.0% [93.8%, 100.0%] (n=58) | 59.8% [49.8%, 69.0%] (n=97) |
| 4672 | 90 (54/36) | undefined | 0.0% [0.0%, 6.6%] (n=54) | n/a |
| 4688 | 531 (67/464) | -0.922 | 13.4% [7.2%, 23.6%] (n=67) | 1.9% [1.0%, 3.6%] (n=473) |
| 4689 | 532 (67/465) | undefined | 0.0% [0.0%, 5.4%] (n=67) | n/a |

#### Per-event_type

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| authentication | 187 (112/75) | -0.002 | 51.8% [42.6%, 60.8%] (n=112) | 59.8% [49.8%, 69.0%] (n=97) |
| network | 133 (67/66) | undefined | 100.0% [94.6%, 100.0%] (n=67) | 50.4% [42.0%, 58.7%] (n=133) |
| process | 1605 (206/1399) | -0.058 | 29.6% [23.8%, 36.2%] (n=206) | 10.3% [8.1%, 13.0%] (n=592) |

#### Per-technique (sentinel EXCLUDED, see below)

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| T1053 | 5 (5/0) | undefined | 80.0% [37.6%, 96.4%] (n=5) | 100.0% [51.0%, 100.0%] (n=4) |
| T1069 | 1 (1/0) | undefined | 0.0% [0.0%, 79.3%] (n=1) | n/a |
| T1123 | 3 (3/0) | undefined | 33.3% [6.1%, 79.2%] (n=3) | 100.0% [20.7%, 100.0%] (n=1) |
| T1547 | 65 (65/0) | undefined | 27.7% [18.3%, 39.6%] (n=65) | 100.0% [82.4%, 100.0%] (n=18) |
| benign | 1540 (0/1540) | undefined | n/a | 0.0% [0.0%, 0.6%] (n=636) |

#### MULTI_TECHNIQUE_UNRESOLVED sentinel bucket (reported separately, never scored per-technique)
n=311 malicious records whose source capture (OTRF APT29 compound scenarios) has no OTRF-published per-event technique mapping. No per-technique claim is made for these records.
Aggregate recall under `conservative` policy: 0.524 [0.469, 0.579] (n=311)

### Bucket: `context_poor`

Sample: target 1925 total (385 malicious floor-targeted), achieved 1925 total (385 malicious / 1540 benign), 385-floor met: True

#### `context_poor` headline table (headline policy = `conservative`)

| System | n | MCC | PR-AUC | ROC-AUC (secondary) | Balanced acc. | Recall [Wilson 95% CI] | Precision [Wilson 95% CI] |
|---|---|---|---|---|---|---|---|
| llm | 1925 | -0.188 | 0.182 | 0.366 | 0.387 | 45.7% [40.8%, 50.7%] (n=385) | 14.3% [12.5%, 16.4%] (n=1228) |
| majority_class | 1925 | undefined | 0.200 | 0.500 | 0.500 | 0.0% [0.0%, 1.0%] (n=385) | n/a |
| stratified_random | 1925 | 0.026 | 0.197 | 0.494 | 0.513 | 20.8% [17.0%, 25.1%] (n=385) | 22.2% [18.2%, 26.7%] (n=361) |
| rules_heuristic | 1925 | -0.025 | 0.196 | 0.488 | 0.488 | 17.4% [13.9%, 21.5%] (n=385) | 18.0% [14.4%, 22.2%] (n=373) |
| classical_ml | 1925 | 0.049 | 0.219 | 0.517 | 0.530 | 66.2% [61.4%, 70.8%] (n=385) | 21.5% [19.3%, 24.0%] (n=1184) |

### context_poor / llm

Pooled n=1925 (malicious=385, benign=1540)

#### Policy: `conservative`  (HEADLINE)
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 176 | 1052 | 209 | 488 | 1925 |

| Metric | Value |
|---|---|
| MCC | -0.188 |
| PR-AUC | 0.182 |
| ROC-AUC (secondary) | 0.366 |
| Balanced accuracy | 0.387 |
| Precision | 0.143 [0.125, 0.164] (n=1228) |
| Recall | 0.457 [0.408, 0.507] (n=385) |
| F1 | 0.218 |
| FPR = FP/(FP+TN) | 0.683 [0.659, 0.706] (n=1540) |
| FNR = FN/(FN+TP) | 0.543 |
| Accuracy (context only, NOT a headline) | 0.345 |

#### Policy: `high_precision`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 7 | 3 | 378 | 1537 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.090 |
| PR-AUC | 0.182 |
| ROC-AUC (secondary) | 0.366 |
| Balanced accuracy | 0.508 |
| Precision | 0.700 [0.397, 0.892] (n=10) |
| Recall | 0.018 [0.009, 0.037] (n=385) |
| F1 | 0.035 |
| FPR = FP/(FP+TN) | 0.002 [0.001, 0.006] (n=1540) |
| FNR = FN/(FN+TP) | 0.982 |
| Accuracy (context only, NOT a headline) | 0.802 |

#### Policy: `abstention`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 7 | 3 | 209 | 488 | 707 |

| Metric | Value |
|---|---|
| MCC | 0.103 |
| PR-AUC | 0.318 |
| ROC-AUC (secondary) | 0.513 |
| Balanced accuracy | 0.513 |
| Precision | 0.700 [0.397, 0.892] (n=10) |
| Recall | 0.032 [0.016, 0.065] (n=216) |
| F1 | 0.062 |
| FPR = FP/(FP+TN) | 0.006 [0.002, 0.018] (n=491) |
| FNR = FN/(FN+TP) | 0.968 |
| Accuracy (context only, NOT a headline) | 0.700 |

#### Abstention / selective-prediction detail
- Coverage: 36.7% (707/1925 committed, 1218 abstained)
- Selective accuracy (on committed subset): 0.700
- AURC (area under risk-coverage curve, lower=better): 0.2796

#### LLM-specific metrics

- Parse-failure rate: 0.0% [0.0%, 0.2%] (n=1925) (0/1925 attempted)
- Expected Calibration Error (ECE) on self-reported `confidence`: 0.4925
  - Reliability bins (low-high: n, avg_confidence, empirical accuracy):
    - [0.7-0.8): n=949, avg_conf=0.750, acc=0.166
    - [0.8-0.9): n=269, avg_conf=0.850, acc=0.041
    - [0.9-1.0): n=707, avg_conf=0.950, acc=0.700
- Run-to-run determinism: NOT MEASURED in this run (see limitations section)

#### Per-EventID

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| 1 | 11 (11/0) | undefined | 0.0% [0.0%, 25.9%] (n=11) | n/a |
| 10 | 373 (67/306) | -0.000 | 76.1% [64.7%, 84.7%] (n=67) | 18.0% [13.9%, 22.8%] (n=284) |
| 11 | 374 (68/306) | 0.006 | 79.4% [68.4%, 87.3%] (n=68) | 18.3% [14.3%, 23.1%] (n=295) |
| 12 | 374 (68/306) | -0.588 | 27.9% [18.7%, 39.6%] (n=68) | 6.4% [4.2%, 9.8%] (n=295) |
| 13 | 373 (68/305) | -0.755 | 11.8% [6.1%, 21.5%] (n=68) | 2.7% [1.4%, 5.3%] (n=291) |
| 4104 | 2 (2/0) | undefined | 0.0% [0.0%, 65.8%] (n=2) | n/a |
| 4688 | 44 (33/11) | 0.000 | 18.2% [8.6%, 34.4%] (n=33) | 75.0% [40.9%, 92.9%] (n=8) |
| 5 | 374 (68/306) | 0.548 | 55.9% [44.1%, 67.1%] (n=68) | 69.1% [56.0%, 79.7%] (n=55) |

#### Per-event_type

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| file | 374 (68/306) | 0.006 | 79.4% [68.4%, 87.3%] (n=68) | 18.3% [14.3%, 23.1%] (n=295) |
| other | 10 (10/0) | undefined | 0.0% [0.0%, 27.8%] (n=10) | n/a |
| process | 794 (171/623) | 0.125 | 55.6% [48.1%, 62.8%] (n=171) | 27.4% [23.0%, 32.3%] (n=347) |
| registry | 747 (136/611) | -0.672 | 19.9% [14.0%, 27.3%] (n=136) | 4.6% [3.2%, 6.6%] (n=586) |

#### Per-technique (sentinel EXCLUDED, see below)

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| T1069 | 1 (1/0) | undefined | 100.0% [20.7%, 100.0%] (n=1) | 100.0% [20.7%, 100.0%] (n=1) |
| T1123 | 4 (4/0) | undefined | 75.0% [30.1%, 95.4%] (n=4) | 100.0% [43.9%, 100.0%] (n=3) |
| T1547 | 33 (33/0) | undefined | 36.4% [22.2%, 53.4%] (n=33) | 100.0% [75.8%, 100.0%] (n=12) |
| benign | 1540 (0/1540) | undefined | n/a | 0.0% [0.0%, 0.4%] (n=1052) |

#### MULTI_TECHNIQUE_UNRESOLVED sentinel bucket (reported separately, never scored per-technique)
n=347 malicious records whose source capture (OTRF APT29 compound scenarios) has no OTRF-published per-event technique mapping. No per-technique claim is made for these records.
Aggregate recall under `conservative` policy: 0.461 [0.409, 0.514] (n=347)

### context_poor / majority_class

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
| 1 | 11 (11/0) | undefined | 0.0% [0.0%, 25.9%] (n=11) | n/a |
| 10 | 373 (67/306) | undefined | 0.0% [0.0%, 5.4%] (n=67) | n/a |
| 11 | 374 (68/306) | undefined | 0.0% [0.0%, 5.3%] (n=68) | n/a |
| 12 | 374 (68/306) | undefined | 0.0% [0.0%, 5.3%] (n=68) | n/a |
| 13 | 373 (68/305) | undefined | 0.0% [0.0%, 5.3%] (n=68) | n/a |
| 4104 | 2 (2/0) | undefined | 0.0% [0.0%, 65.8%] (n=2) | n/a |
| 4688 | 44 (33/11) | undefined | 0.0% [0.0%, 10.4%] (n=33) | n/a |
| 5 | 374 (68/306) | undefined | 0.0% [0.0%, 5.3%] (n=68) | n/a |

#### Per-event_type

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| file | 374 (68/306) | undefined | 0.0% [0.0%, 5.3%] (n=68) | n/a |
| other | 10 (10/0) | undefined | 0.0% [0.0%, 27.8%] (n=10) | n/a |
| process | 794 (171/623) | undefined | 0.0% [0.0%, 2.2%] (n=171) | n/a |
| registry | 747 (136/611) | undefined | 0.0% [0.0%, 2.7%] (n=136) | n/a |

#### Per-technique (sentinel EXCLUDED, see below)

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| T1069 | 1 (1/0) | undefined | 0.0% [0.0%, 79.3%] (n=1) | n/a |
| T1123 | 4 (4/0) | undefined | 0.0% [0.0%, 49.0%] (n=4) | n/a |
| T1547 | 33 (33/0) | undefined | 0.0% [0.0%, 10.4%] (n=33) | n/a |
| benign | 1540 (0/1540) | undefined | n/a | n/a |

#### MULTI_TECHNIQUE_UNRESOLVED sentinel bucket (reported separately, never scored per-technique)
n=347 malicious records whose source capture (OTRF APT29 compound scenarios) has no OTRF-published per-event technique mapping. No per-technique claim is made for these records.
Aggregate recall under `conservative` policy: 0.000 [0.000, 0.011] (n=347)

### context_poor / stratified_random

Pooled n=1925 (malicious=385, benign=1540)

#### Policy: `conservative`  (HEADLINE)
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 80 | 281 | 305 | 1259 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.026 |
| PR-AUC | 0.197 |
| ROC-AUC (secondary) | 0.494 |
| Balanced accuracy | 0.513 |
| Precision | 0.222 [0.182, 0.267] (n=361) |
| Recall | 0.208 [0.170, 0.251] (n=385) |
| F1 | 0.214 |
| FPR = FP/(FP+TN) | 0.182 [0.164, 0.203] (n=1540) |
| FNR = FN/(FN+TP) | 0.792 |
| Accuracy (context only, NOT a headline) | 0.696 |

#### Policy: `high_precision`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 80 | 281 | 305 | 1259 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.026 |
| PR-AUC | 0.197 |
| ROC-AUC (secondary) | 0.494 |
| Balanced accuracy | 0.513 |
| Precision | 0.222 [0.182, 0.267] (n=361) |
| Recall | 0.208 [0.170, 0.251] (n=385) |
| F1 | 0.214 |
| FPR = FP/(FP+TN) | 0.182 [0.164, 0.203] (n=1540) |
| FNR = FN/(FN+TP) | 0.792 |
| Accuracy (context only, NOT a headline) | 0.696 |

#### Policy: `abstention`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 80 | 281 | 305 | 1259 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.026 |
| PR-AUC | 0.197 |
| ROC-AUC (secondary) | 0.494 |
| Balanced accuracy | 0.513 |
| Precision | 0.222 [0.182, 0.267] (n=361) |
| Recall | 0.208 [0.170, 0.251] (n=385) |
| F1 | 0.214 |
| FPR = FP/(FP+TN) | 0.182 [0.164, 0.203] (n=1540) |
| FNR = FN/(FN+TP) | 0.792 |
| Accuracy (context only, NOT a headline) | 0.696 |

#### Abstention / selective-prediction detail
- Coverage: 100.0% (1925/1925 committed, 0 abstained)
- Selective accuracy (on committed subset): 0.696
- AURC: not computed (no confidence scores available for this system)

#### Per-EventID

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| 1 | 11 (11/0) | undefined | 45.5% [21.3%, 72.0%] (n=11) | 100.0% [56.6%, 100.0%] (n=5) |
| 10 | 373 (67/306) | 0.008 | 19.4% [11.7%, 30.4%] (n=67) | 18.6% [11.2%, 29.2%] (n=70) |
| 11 | 374 (68/306) | 0.015 | 19.1% [11.5%, 30.0%] (n=68) | 19.4% [11.7%, 30.4%] (n=67) |
| 12 | 374 (68/306) | 0.072 | 25.0% [16.2%, 36.4%] (n=68) | 23.9% [15.5%, 35.0%] (n=71) |
| 13 | 373 (68/305) | 0.019 | 20.6% [12.7%, 31.6%] (n=68) | 19.7% [12.1%, 30.4%] (n=71) |
| 4104 | 2 (2/0) | undefined | 0.0% [0.0%, 65.8%] (n=2) | n/a |
| 4688 | 44 (33/11) | -0.152 | 21.2% [10.7%, 37.8%] (n=33) | 63.6% [35.4%, 84.8%] (n=11) |
| 5 | 374 (68/306) | -0.018 | 16.2% [9.3%, 26.7%] (n=68) | 16.7% [9.6%, 27.4%] (n=66) |

#### Per-event_type

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| file | 374 (68/306) | 0.015 | 19.1% [11.5%, 30.0%] (n=68) | 19.4% [11.7%, 30.4%] (n=67) |
| other | 10 (10/0) | undefined | 50.0% [23.7%, 76.3%] (n=10) | 100.0% [56.6%, 100.0%] (n=5) |
| process | 794 (171/623) | -0.005 | 18.1% [13.1%, 24.6%] (n=171) | 21.1% [15.3%, 28.4%] (n=147) |
| registry | 747 (136/611) | 0.046 | 22.8% [16.5%, 30.5%] (n=136) | 21.8% [15.8%, 29.3%] (n=142) |

#### Per-technique (sentinel EXCLUDED, see below)

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| T1069 | 1 (1/0) | undefined | 0.0% [0.0%, 79.3%] (n=1) | n/a |
| T1123 | 4 (4/0) | undefined | 25.0% [4.6%, 69.9%] (n=4) | 100.0% [20.7%, 100.0%] (n=1) |
| T1547 | 33 (33/0) | undefined | 33.3% [19.8%, 50.4%] (n=33) | 100.0% [74.1%, 100.0%] (n=11) |
| benign | 1540 (0/1540) | undefined | n/a | 0.0% [0.0%, 1.3%] (n=281) |

#### MULTI_TECHNIQUE_UNRESOLVED sentinel bucket (reported separately, never scored per-technique)
n=347 malicious records whose source capture (OTRF APT29 compound scenarios) has no OTRF-published per-event technique mapping. No per-technique claim is made for these records.
Aggregate recall under `conservative` policy: 0.196 [0.158, 0.241] (n=347)

### context_poor / rules_heuristic

Pooled n=1925 (malicious=385, benign=1540)

#### Policy: `conservative`  (HEADLINE)
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 67 | 306 | 318 | 1234 | 1925 |

| Metric | Value |
|---|---|
| MCC | -0.025 |
| PR-AUC | 0.196 |
| ROC-AUC (secondary) | 0.488 |
| Balanced accuracy | 0.488 |
| Precision | 0.180 [0.144, 0.222] (n=373) |
| Recall | 0.174 [0.139, 0.215] (n=385) |
| F1 | 0.177 |
| FPR = FP/(FP+TN) | 0.199 [0.180, 0.219] (n=1540) |
| FNR = FN/(FN+TP) | 0.826 |
| Accuracy (context only, NOT a headline) | 0.676 |

#### Policy: `high_precision`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 67 | 306 | 318 | 1234 | 1925 |

| Metric | Value |
|---|---|
| MCC | -0.025 |
| PR-AUC | 0.196 |
| ROC-AUC (secondary) | 0.488 |
| Balanced accuracy | 0.488 |
| Precision | 0.180 [0.144, 0.222] (n=373) |
| Recall | 0.174 [0.139, 0.215] (n=385) |
| F1 | 0.177 |
| FPR = FP/(FP+TN) | 0.199 [0.180, 0.219] (n=1540) |
| FNR = FN/(FN+TP) | 0.826 |
| Accuracy (context only, NOT a headline) | 0.676 |

#### Policy: `abstention`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 67 | 306 | 318 | 1234 | 1925 |

| Metric | Value |
|---|---|
| MCC | -0.025 |
| PR-AUC | 0.196 |
| ROC-AUC (secondary) | 0.488 |
| Balanced accuracy | 0.488 |
| Precision | 0.180 [0.144, 0.222] (n=373) |
| Recall | 0.174 [0.139, 0.215] (n=385) |
| F1 | 0.177 |
| FPR = FP/(FP+TN) | 0.199 [0.180, 0.219] (n=1540) |
| FNR = FN/(FN+TP) | 0.826 |
| Accuracy (context only, NOT a headline) | 0.676 |

#### Abstention / selective-prediction detail
- Coverage: 100.0% (1925/1925 committed, 0 abstained)
- Selective accuracy (on committed subset): 0.676
- AURC: not computed (no confidence scores available for this system)

#### Per-EventID

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| 1 | 11 (11/0) | undefined | 0.0% [0.0%, 25.9%] (n=11) | n/a |
| 10 | 373 (67/306) | undefined | 100.0% [94.6%, 100.0%] (n=67) | 18.0% [14.4%, 22.2%] (n=373) |
| 11 | 374 (68/306) | undefined | 0.0% [0.0%, 5.3%] (n=68) | n/a |
| 12 | 374 (68/306) | undefined | 0.0% [0.0%, 5.3%] (n=68) | n/a |
| 13 | 373 (68/305) | undefined | 0.0% [0.0%, 5.3%] (n=68) | n/a |
| 4104 | 2 (2/0) | undefined | 0.0% [0.0%, 65.8%] (n=2) | n/a |
| 4688 | 44 (33/11) | undefined | 0.0% [0.0%, 10.4%] (n=33) | n/a |
| 5 | 374 (68/306) | undefined | 0.0% [0.0%, 5.3%] (n=68) | n/a |

#### Per-event_type

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| file | 374 (68/306) | undefined | 0.0% [0.0%, 5.3%] (n=68) | n/a |
| other | 10 (10/0) | undefined | 0.0% [0.0%, 27.8%] (n=10) | n/a |
| process | 794 (171/623) | -0.082 | 39.2% [32.2%, 46.7%] (n=171) | 18.0% [14.4%, 22.2%] (n=373) |
| registry | 747 (136/611) | undefined | 0.0% [0.0%, 2.7%] (n=136) | n/a |

#### Per-technique (sentinel EXCLUDED, see below)

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| T1069 | 1 (1/0) | undefined | 0.0% [0.0%, 79.3%] (n=1) | n/a |
| T1123 | 4 (4/0) | undefined | 50.0% [15.0%, 85.0%] (n=4) | 100.0% [34.2%, 100.0%] (n=2) |
| T1547 | 33 (33/0) | undefined | 0.0% [0.0%, 10.4%] (n=33) | n/a |
| benign | 1540 (0/1540) | undefined | n/a | 0.0% [0.0%, 1.2%] (n=306) |

#### MULTI_TECHNIQUE_UNRESOLVED sentinel bucket (reported separately, never scored per-technique)
n=347 malicious records whose source capture (OTRF APT29 compound scenarios) has no OTRF-published per-event technique mapping. No per-technique claim is made for these records.
Aggregate recall under `conservative` policy: 0.187 [0.150, 0.232] (n=347)

### context_poor / classical_ml

Pooled n=1925 (malicious=385, benign=1540)

#### Policy: `conservative`  (HEADLINE)
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 255 | 929 | 130 | 611 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.049 |
| PR-AUC | 0.219 |
| ROC-AUC (secondary) | 0.517 |
| Balanced accuracy | 0.530 |
| Precision | 0.215 [0.193, 0.240] (n=1184) |
| Recall | 0.662 [0.614, 0.708] (n=385) |
| F1 | 0.325 |
| FPR = FP/(FP+TN) | 0.603 [0.579, 0.627] (n=1540) |
| FNR = FN/(FN+TP) | 0.338 |
| Accuracy (context only, NOT a headline) | 0.450 |

#### Policy: `high_precision`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 255 | 929 | 130 | 611 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.049 |
| PR-AUC | 0.219 |
| ROC-AUC (secondary) | 0.517 |
| Balanced accuracy | 0.530 |
| Precision | 0.215 [0.193, 0.240] (n=1184) |
| Recall | 0.662 [0.614, 0.708] (n=385) |
| F1 | 0.325 |
| FPR = FP/(FP+TN) | 0.603 [0.579, 0.627] (n=1540) |
| FNR = FN/(FN+TP) | 0.338 |
| Accuracy (context only, NOT a headline) | 0.450 |

#### Policy: `abstention`
| TP | FP | FN | TN | n |
|---|---|---|---|---|
| 255 | 929 | 130 | 611 | 1925 |

| Metric | Value |
|---|---|
| MCC | 0.049 |
| PR-AUC | 0.219 |
| ROC-AUC (secondary) | 0.517 |
| Balanced accuracy | 0.530 |
| Precision | 0.215 [0.193, 0.240] (n=1184) |
| Recall | 0.662 [0.614, 0.708] (n=385) |
| F1 | 0.325 |
| FPR = FP/(FP+TN) | 0.603 [0.579, 0.627] (n=1540) |
| FNR = FN/(FN+TP) | 0.338 |
| Accuracy (context only, NOT a headline) | 0.450 |

#### Abstention / selective-prediction detail
- Coverage: 100.0% (1925/1925 committed, 0 abstained)
- Selective accuracy (on committed subset): 0.450
- AURC: not computed (no confidence scores available for this system)

#### Per-EventID

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| 1 | 11 (11/0) | undefined | 100.0% [74.1%, 100.0%] (n=11) | 100.0% [74.1%, 100.0%] (n=11) |
| 10 | 373 (67/306) | undefined | 100.0% [94.6%, 100.0%] (n=67) | 18.0% [14.4%, 22.2%] (n=373) |
| 11 | 374 (68/306) | undefined | 100.0% [94.7%, 100.0%] (n=68) | 18.2% [14.6%, 22.4%] (n=374) |
| 12 | 374 (68/306) | 0.271 | 8.8% [4.1%, 17.9%] (n=68) | 100.0% [61.0%, 100.0%] (n=6) |
| 13 | 373 (68/305) | undefined | 0.0% [0.0%, 5.3%] (n=68) | n/a |
| 4104 | 2 (2/0) | undefined | 100.0% [34.2%, 100.0%] (n=2) | 100.0% [34.2%, 100.0%] (n=2) |
| 4688 | 44 (33/11) | undefined | 100.0% [89.6%, 100.0%] (n=33) | 75.0% [60.6%, 85.4%] (n=44) |
| 5 | 374 (68/306) | undefined | 100.0% [94.7%, 100.0%] (n=68) | 18.2% [14.6%, 22.4%] (n=374) |

#### Per-event_type

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| file | 374 (68/306) | undefined | 100.0% [94.7%, 100.0%] (n=68) | 18.2% [14.6%, 22.4%] (n=374) |
| other | 10 (10/0) | undefined | 100.0% [72.2%, 100.0%] (n=10) | 100.0% [72.2%, 100.0%] (n=10) |
| process | 794 (171/623) | undefined | 100.0% [97.8%, 100.0%] (n=171) | 21.5% [18.8%, 24.5%] (n=794) |
| registry | 747 (136/611) | 0.191 | 4.4% [2.0%, 9.3%] (n=136) | 100.0% [61.0%, 100.0%] (n=6) |

#### Per-technique (sentinel EXCLUDED, see below)

| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |
|---|---|---|---|---|
| T1069 | 1 (1/0) | undefined | 100.0% [20.7%, 100.0%] (n=1) | 100.0% [20.7%, 100.0%] (n=1) |
| T1123 | 4 (4/0) | undefined | 100.0% [51.0%, 100.0%] (n=4) | 100.0% [51.0%, 100.0%] (n=4) |
| T1547 | 33 (33/0) | undefined | 78.8% [62.2%, 89.3%] (n=33) | 100.0% [87.1%, 100.0%] (n=26) |
| benign | 1540 (0/1540) | undefined | n/a | 0.0% [0.0%, 0.4%] (n=929) |

#### MULTI_TECHNIQUE_UNRESOLVED sentinel bucket (reported separately, never scored per-technique)
n=347 malicious records whose source capture (OTRF APT29 compound scenarios) has no OTRF-published per-event technique mapping. No per-technique claim is made for these records.
Aggregate recall under `conservative` policy: 0.646 [0.594, 0.694] (n=347)

## Significance

**Method: unpaired (two-sample) bootstrap CI on MCC(context_rich) - MCC(context_poor), headline `conservative` policy.** McNemar's test and the harness's existing `significance.paired_bootstrap_ci` both require the SAME items scored by two systems, paired by index — that assumption does not hold here (context_rich and context_poor are disjoint record sets scored by the same system). A two-sample bootstrap resamples each bucket's committed items independently (with replacement, at its own size) and takes the percentile CI of the resampled MCC difference — the standard nonparametric tool for comparing a statistic between two independent samples (Efron & Tibshirani 1993, ch. 16).

MCC(context_rich) - MCC(context_poor) = +0.353 [+0.292, +0.417] (95% CI, 10000 resamples)

CI excludes 0: **True**

For completeness, one-sample bootstrap CIs on each bucket's own LLM MCC (10,000
resamples, same `conservative` policy, resampling that bucket's 1,925 committed items
with replacement) — computed post-hoc from the checkpointed verdicts
(`reports/context-experiment.md.context_{rich,poor}.verdicts.json`) to state the
pre-registration's "meaningfully above/below chance" language numerically rather than
qualitatively:

| Bucket | MCC | 95% CI |
|---|---|---|
| context_rich | 0.165 | [0.123, 0.209] |
| context_poor | -0.188 | [-0.235, -0.142] |

## Judgment calls

- **Field taxonomy (ACTOR/OBJECT lists in `src/eval/context_bucket.py`)**: chosen by
  reading the actual field sets present per EventID in the assembled corpus (see that
  module's docstring), then fixed BEFORE running the predicate against the corpus to
  see the EventID consequence. `Image`/`SourceImage`/`TargetImage` were deliberately
  excluded from the context fields because they are present on nearly every EventID in
  this corpus (a bare executable path, without a command line or named parent, is an
  opaque identifier per the hypothesis's own framing) — this is a judgment call about
  where "opaque identifier" ends and "semantic actor" begins, not a fact derivable from
  the data alone. A reader could reasonably draw that line differently (e.g. treating
  `Image` alone as weak context); this predicate draws it conservatively (requiring a
  command line, a named parent, or a named account/destination, not just any path).
- **`"-"` and similar dash placeholders treated as absent**: measured on the real
  corpus that several Security-log subject/account fields populate a literal `"-"`
  when the value does not apply (e.g. `TargetOutboundUserName`), rather than being
  null/absent. Counting a placeholder dash as "context present" would have inflated
  the context-rich bucket with records that in fact carry no real actor information.
  This is a judgment call, disclosed and tested directly
  (`TestIsContextRich::test_dash_sentinel_does_not_count_as_present`), not silently
  assumed.
- **Per-bucket sample size (1925 total / 385-malicious floor per bucket, matching run
  1's own sizing exactly)**: chosen to reuse the project's own established statistical
  justification (`+/-5pp 95% CI on malicious-class recall`,
  `src/eval/sampling.py::MALICIOUS_FLOOR_FOR_5PP_CI`) rather than inventing a new
  number, and because a pre-run corpus check (this task's step 3) confirmed both
  buckets could support the full floor (context_rich pool: 4,398 malicious available;
  context_poor pool: 23,126 malicious available) — so there was no need to accept a
  smaller floor for either bucket. Total run: 3,850 sequential LLM calls, ~2h32m at the
  measured ~2.44s/call, within the "a few hours at most" budget.
- **Significance test choice (unpaired two-sample bootstrap, not McNemar)**: McNemar's
  test and the harness's existing `significance.paired_bootstrap_ci` both require the
  identical set of items scored by two systems, paired by index. context_rich and
  context_poor are disjoint records (no record appears in both buckets), so pairing is
  not defined between them — an unpaired two-sample bootstrap
  (`scripts/run_context_experiment.py::unpaired_bootstrap_mcc_diff_ci`) was written
  instead, resampling each bucket's committed items independently at its own size. This
  is new code, not a reuse of `significance.py`'s paired procedure, because it is
  genuinely solving a different (unpaired) problem — reusing the paired function on
  disjoint, differently-sized samples would have been a silent methodology error.
- **`load_corpus` re-imports `scripts/run_eval.py`'s `load_full_corpus` rather than
  duplicating it**: `run_eval.py` was explicitly out of scope to MODIFY, but importing
  its existing loader (unchanged) guarantees the malicious/benign record CONSTRUCTION
  is byte-identical to run 1's — only the downstream sampling seed differs, which is
  the intended controlled variable. `run_llm`'s checkpoint/resume logic, however, is
  duplicated rather than imported (same rationale/mechanics as `run_eval.py`'s own,
  see that function's docstring) because it needed a bucket-specific progress path
  `run_eval.py`'s own version does not parameterize, and adding that parameter would
  have meant modifying `run_eval.py`.
- **Classical-ML baseline fit pool, per bucket**: each bucket's `ClassicalMLBaseline`
  was fit on a leakage-safe split drawn from THAT bucket's own corpus-wide pool (not
  the other bucket's, and not the full un-split corpus), via
  `harness.classical_ml_train_test_split` reused unmodified. This means context_rich's
  classical-ML baseline never sees context_poor records (or vice versa) at fit time,
  keeping the two buckets' baseline comparisons genuinely independent rather than
  accidentally sharing training signal across the boundary the experiment is testing.

## What I could not do

- **A true apples-to-apples "same record, context stripped" ablation** (re-triaging the
  identical context_rich records with their actor/object fields removed) was NOT run.
  This experiment answers "do context-rich and context-poor records score differently"
  — a between-subjects comparison — not "does REMOVING context from the SAME record
  degrade its score" — a within-subject causal manipulation that would isolate the
  causal mechanism more tightly (ruling out any residual confound between "has this
  field" and "is otherwise a different kind of event," since EventID and field presence
  are almost perfectly correlated in this corpus, per the EventID-consequence table
  above). That stronger, causal version of this test is a natural next step but was out
  of this task's scope (it would need new prompt-construction code, not just new
  sampling/scoring code, and risks its own confound: an ablated record may look
  suspicious in a NEW way, e.g. "why is CommandLine missing").
- **Determinism / run-to-run agreement** was not re-measured for this experiment (the
  per-bucket LLM-specific report correctly states "NOT MEASURED in this run" rather
  than reusing run 1's number, which was measured on a different sample). Re-measuring
  it here would have added a second multi-repeat pass this task's time budget did not
  allocate for; run 1's own measured 44.0% [26.7%, 62.9%] agreement rate is the best
  available estimate and is not re-derived or assumed to transfer unchanged to this
  sample.
- **A held-out THIRD sample to further replicate the confirmed result** was not drawn —
  a single fresh, pre-registered, independently-seeded replication is what this task
  asked for and what was delivered; a second independent replication would strengthen
  confidence further but was not requested and would roughly double the already
  multi-hour LLM budget.
- **EventID 1's context_rich sample is thinner on the malicious side than most other
  EventIDs within that bucket in absolute per-stratum terms** is not a limitation of
  this experiment's HEADLINE result (which is pooled across the whole 385-malicious
  bucket, not per-EventID), but the per-EventID breakdown tables above inherit the same
  small-n/wide-CI caveat run 1's own report disclosed — read those sub-tables with
  their own reported n and Wilson CIs, not as an independent confirmation at EventID
  granularity.
