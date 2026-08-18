# Phase 3 — Rigorous Evaluation Design for the LLM Alert-Triage Classifier

**Date:** 2026-08-18
**Researcher:** researcher subagent (director session)
**Predecessor:** builds directly on `projects/wshearer-site/research/phase-0-metrics.md` (Phase 0 —
established that MTTD/MTTR/dwell-time/analyst-touch-time cannot be honestly computed from a static
labeled corpus; that finding is NOT re-derived here, only cited and extended). Phase 0 covered
metric selection, ATT&CK coverage scoring, and baseline/significance framing at a general level; this
brief is the concrete, corpus-specific evaluation design for `src/agents/triage.py`'s three-class
(`benign|suspicious|malicious`) output against `src/schema.py`'s binary `is_malicious` ground truth,
on the actual 220,190-record corpus assembled by `src/corpus.py::assemble_corpus`.
**Sources consulted:** primary — scikit-learn `model_evaluation.html` (fetched directly), Chicco &
Jurman 2020 (BMC Genomics / PMC6941312, fetched directly), Arp et al. USENIX Sec'22 (dodo-mlsec.org +
usenix.org, fetched directly), Davis & Goadrich ICML 2006 (confirmed via ACM/UW-Madison listings),
Dietterich 1998 (McNemar's test recommendation, confirmed via multiple secondary summaries of the
primary paper), Tian et al. "Just Ask for Calibration" EMNLP 2023 (arXiv:2305.14975), Zheng et al.
"MT-Bench" arXiv:2306.05685 (already cited in Phase 0), three-way-classification/selective-prediction
literature (Zaffalon et al. line of work on ambiguity/abstention; Geifman & El-Yaniv NeurIPS 2017,
already cited in Phase 0), Cohen's kappa paradox literature (PMC5712640, arXiv:2403.01571). Secondary,
directional-only: Simbian AI SOC LLM benchmark blog post (used as a negative example — see Q3).

---

## Verdict

1. **Score `suspicious` via multiple reported operating points, not a single silent collapse to one
   binary side — HIGH confidence.** There is no literature consensus that maps a 3-way LLM verdict onto
   binary truth via a single rule. Report the confusion matrix at three named policies
   (`suspicious→malicious` "conservative/high-recall", `suspicious→benign` "high-precision", and
   `suspicious`-as-abstention scored via selective-prediction metrics) rather than picking one and
   hiding the other two. Never report only the collapsed number.
2. **Treat `suspicious` primarily as a reject/abstention class, using selective-prediction metrics
   (coverage, selective accuracy, risk-coverage curve, AURC) — HIGH confidence.** This is the one
   framing with a real, decades-old academic apparatus behind it (Chow's rejection rule; Geifman &
   El-Yaniv 2017 formalization, already cited in Phase 0 Finding 1A.4). It is more defensible than
   inventing a novel binary-collapse rule, because it doesn't force a judgment call the ground truth
   schema itself doesn't support.
3. **Lead every headline with MCC and PR-AUC; never lead with accuracy or ROC-AUC alone —
   HIGH confidence.** Confirmed against Chicco & Jurman's own formula and scikit-learn's own docs.
   At 80/20 imbalance (`benign_ratio=4.0`), a majority-class classifier already gets 80% accuracy —
   accuracy alone is actively misleading here, not just suboptimal.
4. **Report ROC-AUC too, but as a secondary number, and only alongside PR-AUC on the same slice —
   MEDIUM confidence.** Phase 0 already flagged that the strict "PR > ROC" claim is a widely-cited
   inference from the metric math (confirmed independently by Davis & Goadrich's formal ROC/PR
   dominance-equivalence result), not a verbatim scikit-learn sentence — this brief could not find a
   sklearn sentence making that exact claim either, so state the argument as "supported by Davis &
   Goadrich 2006's formal treatment," not "scikit-learn says so."
5. **The majority-class (always-benign) baseline and a rules-only heuristic baseline are non-negotiable;
   a classical-ML baseline (logistic regression/gradient boosting on structured fields) is next priority;
   a second LLM size is nice-to-have — HIGH confidence.** This ranking follows directly from Arp et al.'s
   "Inappropriate Baseline" pitfall (USENIX Sec'22): the paper's own guidance is that simple/non-learning
   baselines must be run alongside sophisticated ones, and the majority-class + rules-only pair is what
   makes the "does AI help" claim falsifiable at minimum cost.
6. **Minimum ~385 malicious-class records evaluated for a ±5pp CI on recall, ~1,925 total records at the
   corpus's 20% malicious rate — HIGH confidence, standard formula.** This is a hard floor from the
   binomial sample-size formula at p=0.5 (worst case), 95% CI, since the malicious-class recall is the
   single most safety-relevant number this project reports and the worst-case variance assumption is the
   only defensible one absent a pilot estimate.
7. **Report metrics per-EventID (or per event_type) in addition to pooled — HIGH confidence, already
   evidenced by this project's own corpus composition.** EventID 12/13 (registry writes) dominate the
   corpus by raw count while EventID 1 (process creation, the richest triage signal per the project's own
   corpus notes) is 2,452/220,190 = 1.78%. A pooled metric is a weighted average dominated by registry
   noise; it can hide a classifier that is excellent on registry events and poor on process-creation
   events — exactly the slice a SOC reviewer would care about most.
8. **Use McNemar's test (or its mid-p/exact variant for small discordant-pair counts) for LLM-vs-baseline
   comparison on the SAME sampled items, plus a bootstrap CI on the metric difference — HIGH confidence.**
   Confirmed as the standard paired-classifier-comparison approach since Dietterich 1998; McNemar
   specifically fits because both systems are being scored on identical items (paired, not independent
   samples) from a single test draw, which Dietterich's own analysis is about.
9. **Disclose parse-failure rate, run-to-run non-determinism, and calibration error (ECE) on the model's
   self-reported `confidence` field as first-class metrics, not appendix notes — HIGH confidence.** These
   have no classical-ML analogue and their absence is the most obvious tell of an evaluation written by
   someone unfamiliar with LLM-specific failure modes; Tian et al. (EMNLP 2023) is direct primary
   evidence that verbalized LLM confidence is frequently miscalibrated and must be checked, not assumed.
10. **Do not claim this evaluation is comparable to any published SOC-LLM benchmark's numbers — MEDIUM
    confidence, evidenced by direct inspection of prior art.** The one closely comparable public
    benchmark found (Simbian's "AI SOC LLM Benchmark," n=100 cases) reports human-vs-LLM completion rates
    with no visible confidence intervals or significance testing — i.e. it is exactly the kind of
    prior-art gap this project's stated differentiator is supposed to fill, and numbers should be reported
    on their own terms, not framed as beating a specific external score.

---

## Findings

### 1. The three-class problem: scoring `suspicious` against binary truth

There is no single, universally cited rule in the classification literature for collapsing a three-way
model output onto a binary ground truth. Two genuinely distinct academic framings apply, and rigorous
practice does not pick one to the exclusion of the other:

**(a) Selective prediction / classification-with-rejection.** The classical origin is Chow's rejection
rule (trading misclassification cost against a rejection cost), formalized for modern deep classifiers by
[Geifman & El-Yaniv, "Selective Classification for Deep Neural Networks" (NeurIPS 2017)](https://proceedings.neurips.cc/paper/2017/hash/4a8423d5e91fda00bb7e46540e2b0cf1-Abstract.html)
— already the citation used in Phase 0 Finding 1A.4 for the critic-agent escalation logic, and it applies
identically here to the triage agent's own `suspicious` output. Under this framing, `suspicious` is not a
wrong or right answer; it is a refusal to answer, and is scored via **coverage** (fraction of cases the
classifier commits on), **selective accuracy** (accuracy restricted to the committed subset), and the
**risk-coverage curve** with its scalar summary **AURC**. A 2024 refinement,
["Overcoming Common Flaws in the Evaluation of Selective Classification Systems" (NeurIPS 2024)](https://proceedings.neurips.cc/paper_files/paper/2024/hash/047c84f7d19f5b8138873e6410ab1660-Abstract-Conference.html),
specifically warns against reporting a single coverage/accuracy operating point as if it were the whole
story — a single point is cherry-pickable; report the curve.

**(b) Three-way decision / ambiguity-and-abstention theory.** A parallel, more theoretical line
(three-way decision theory, credal classification, e.g. the line of work summarized in
["Three-Way Classification: Ambiguity and Abstention in Machine Learning" (Springer, IJCAI/ISIPTA-adjacent
line, Zaffalon et al.)](https://link.springer.com/chapter/10.1007/978-3-030-22815-6_22)) explicitly
distinguishes **outlier-driven** abstention (input dissimilar to training data) from **ambiguity-driven**
abstention (multiple outputs equally likely given the input) — a distinction directly relevant here
because an LLM triage agent can emit `suspicious` for either reason (an alert that looks nothing like
training examples vs. one that genuinely straddles the benign/malicious line), and this project's
`reasoning`/`key_indicators` fields on `TriageVerdict` are the mechanism to actually tell the two apart in
a qualitative review pass, which the pure selective-prediction framing does not by itself require.

**Recommended concrete scoring protocol (synthesizing both framings):**
- Report the **3×2 confusion table** (verdict ∈ {benign, suspicious, malicious} × truth ∈
  {benign, malicious}) as the ground-truth artifact — never collapse before showing this.
- From it, derive and report **three named policies**, each producing a full 2×2 confusion matrix and
  full metric set (Section "Recommended metric set" below): **(i) conservative** —
  `suspicious→malicious` (models a SOC that escalates anything not confidently benign; maximizes
  recall, is the safety-appropriate default for a triage system whose failure mode of concern is a missed
  intrusion); **(ii) precision-oriented** — `suspicious→benign` (models a SOC that only acts on
  confident malicious calls; useful for measuring alert-fatigue-reduction potential); **(iii) abstention**
  — `suspicious` scored via coverage/selective-accuracy/AURC per (a) above, with benign/malicious verdicts
  scored as the committed subset.
- State explicitly, in the eval report, which of the three is the "headline" policy and why (recommend
  (i), conservative, as headline, given a triage system's cost asymmetry — a missed intrusion is generally
  costlier than an extra human review) — but publish all three tables, not just the headline.

### 2. Metrics under class imbalance (80% benign at `benign_ratio=4.0`)

**Accuracy is actively misleading here, not merely suboptimal.** At an 80/20 benign/malicious split, an
always-benign classifier scores 80% accuracy while having 0% recall on the class that matters. This is
the textbook case both Arp et al. (Pitfall 8, "Base Rate Fallacy") and Chicco & Jurman warn about by name.

**Matthews Correlation Coefficient (MCC).** Primary source:
[Chicco & Jurman, "The advantages of the Matthews correlation coefficient (MCC) over F1 score and
accuracy in binary classification evaluation," BMC Genomics 21:6 (2020)](https://pmc.ncbi.nlm.nih.gov/articles/PMC6941312/).
Their central, quotable claim: *"MCC is the only binary classification rate that generates a high score
only if the binary predictor was able to correctly predict the majority of positive data instances and
the majority of negative data instances"* — i.e. it cannot be gamed by a classifier that ignores one
class, unlike accuracy or F1. Formula (confirmed identically on
[scikit-learn's `matthews_corrcoef` docs](https://scikit-learn.org/stable/modules/model_evaluation.html)):
`MCC = (TP·TN − FP·FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))`, range [-1, +1], 0 = random. **Caveat the
authors themselves state:** MCC is undefined (0/0) when a whole row or column of the confusion matrix is
zero (e.g., the classifier never predicts one class at all) — this project's implementation must handle
that degenerate case explicitly (report as "undefined," not silently coerce to 0 or 1) since a
`suspicious`-heavy classifier could plausibly hit this if a collapse policy drives one predicted class to
zero. Multiclass MCC exists (generalizes via the confusion matrix) but scikit-learn's own docs note the
range is no longer symmetric ([-something, +1]) in the multiclass case — relevant only if reporting MCC
on the raw 3-way output rather than a collapsed 2-way one, which this brief does not recommend as the
headline (see Q1).

**PR-AUC vs ROC-AUC.** Primary source for the formal argument:
[Davis & Goadrich, "The Relationship Between Precision-Recall and ROC Curves," ICML 2006](https://dl.acm.org/doi/10.1145/1143844.1143874)
— proves a curve dominates in ROC space iff it dominates in PR space, and separately shows PR curves
cannot be linearly interpolated between points (unlike ROC), a common implementation error. The intuitive
imbalance argument (ROC's false-positive-rate denominator is the huge negative class, so many false
positives barely move the curve, while precision's denominator directly reflects them) is the standard
inference from the metric definitions, cross-checked against Chicco & Jurman's independent argument for
the same conclusion — but per Phase 0's own "what I could not verify" note, this brief also did not find
scikit-learn's docs making the head-to-head "PR beats ROC under imbalance" claim in so many words; cite
Davis & Goadrich as the formal source, not scikit-learn, for that specific claim.

**Balanced accuracy** — confirmed via scikit-learn docs: macro-average of per-class recall, i.e. the
arithmetic mean of sensitivity and specificity in the binary case; explicitly designed to "avoid inflated
performance estimates on imbalanced datasets" (direct quote). Cheap, interpretable, worth reporting
alongside MCC, but weaker than MCC because it ignores precision entirely (a classifier could have high
balanced accuracy while producing many false positives if false negatives are proportionally rare too) —
report both, not one instead of the other.

**Cohen's kappa — do not use as a headline metric.** Multiple sources
([Cohen's kappa paradox literature, PMC5712640](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC5712640/);
[Delgado & Tibau, "Why Cohen's Kappa should be avoided as performance measure in classification," PLOS
ONE 2019](https://journals.plos.org/plosone/article?id=10.1371%2Fjournal.pone.0222916)) document two
independent paradoxes: the **prevalence paradox** (kappa can be low even with high raw agreement when
the classes are highly imbalanced, because the chance-agreement baseline itself becomes inflated) and the
**bias paradox** (kappa can be inflated by imbalanced marginal distributions in the opposite direction).
Given this project's 80/20 split sits exactly in the imbalance regime where both paradoxes are documented
to bite, kappa should be omitted from the headline set entirely (MCC is the direct, better-behaved
substitute for the same "agreement corrected for chance" intuition) — mention only in a footnote if a
reviewer specifically expects to see it.

### 3. Baselines — ranked

Arp et al.'s [USENIX Security 2022 paper](https://www.usenix.org/system/files/sec22-arp.pdf)
("Dos and Don'ts of Machine Learning in Computer Security") names **"Inappropriate Baseline"** as one of
its 10 pitfalls, with the explicit guidance: *"Instead of focusing solely on complex models for
comparison, simple models should also be considered throughout the evaluation"* — i.e. verify whether a
non-learning solution addresses the problem before crediting the learned system. Two other named
pitfalls are directly load-bearing here: **"Base Rate Fallacy"** (matches Q2's accuracy-under-imbalance
finding above) and **"Lab-Only Evaluation"** (a caution this project should heed by disclosing that the
corpus is a static offline sample, not live traffic — already Phase 0's own framing, reinforced
independently by Arp et al.).

Ranked baselines, essential → nice-to-have:

| # | Baseline | What it proves | Effort | Essential? |
|---|---|---|---|---|
| 1 | **Majority-class (always-benign)** | The accuracy floor / imbalance magnitude; makes the base-rate fallacy visible by construction (Arp et al. Pitfall 8) | Trivial (~1 line) | **Essential** |
| 2 | **Random/stratified-random guess** | The true chance floor accounting for class prevalence, distinct from #1 (useful mainly as a sanity check that #1 is in fact stronger, which it always will be at 80/20) | Trivial | Essential but low marginal value beyond #1 — run it, report briefly |
| 3 | **Rules/keyword heuristic** (e.g. static severity thresholds on `raw_event` fields, IOC/keyword allow-deny lists, no LLM) | Isolates the LLM's marginal contribution — this is the single comparison the "does AI help" claim rests on, per Arp et al.'s core guidance | Low-medium (a few hours; corpus's `raw_event` fields already available) | **Essential** |
| 4 | **Classical ML on structured features** (logistic regression or gradient-boosted trees, e.g. scikit-learn `GradientBoostingClassifier`, over engineered features from `raw_event`/`event_type`/EventID) | Tests whether the *LLM* specifically is earning its cost over a fast, cheap, well-understood learned baseline — the comparison a rigorous ML reviewer will ask for first, since it isolates "learned model" from "LLM specifically" | Medium (feature engineering + train/eval split with no leakage — corpus's own leakage-mitigation work in `src/ingest/leakage.py` should already inform what features are safe to use) | **High priority, not nice-to-have** — this is the comparison Arp et al.'s guidance most directly targets, and its absence is the most likely single objection from an ML-literate reviewer |
| 5 | **A smaller and/or larger LLM** (e.g. a distilled/quantized model as floor, a frontier model as ceiling) | Establishes where this project's model choice sits on a cost/accuracy frontier — useful context, not required for the core "AI helps vs. not-AI" claim | Medium-high (repeat the ~10k-alert, ~12-hour sequential run per model) | **Nice-to-have** — valuable but should not consume the eval budget before #1-4 are done |

Baseline #4 is the single highest-value addition beyond what Phase 0 already specified (Phase 0's Section
5 named majority-class and rules-only but not a classical-ML baseline) — flagged as a **correction/
addition to Phase 0**, see final section.

### 4. Statistical significance

**Sample size for a defensible CI.** Standard formula for a binomial proportion at 95% CI:
`n = z² · p(1-p) / E²`, z=1.96. Worked values (this project's actual regime, p=0.5 is the conservative/
worst-case variance assumption used absent a pilot estimate):

| Target margin (±) | n needed (p=0.5, worst case) | n needed (p=0.2, e.g. estimating malicious-class share within a mixed sample) |
|---|---|---|
| ±10 pp | 97 | 62 |
| ±5 pp | 385 | 246 |
| ±3 pp | 1,068 | 683 |

Applied to this project's corpus (20% malicious at `benign_ratio=4.0`): to get **recall on the malicious
class** to ±5pp at 95% CI, **385 malicious records must actually be evaluated** (recall's denominator is
malicious-only, so this is a floor on malicious-class n specifically, not total n). At the corpus's fixed
20% malicious rate, drawing enough total records to guarantee 385 malicious ones by chance would need
~1,925 total sampled alerts; **stratified sampling (oversample the malicious class deliberately, matching
this project's own corpus-assembly precedent of stratified-by-EventID sampling in `corpus.py`) is more
efficient than proportional random sampling** and should be used to hit the malicious-class floor without
inflating benign-side sample size unnecessarily. Given the measured 2.5–4.2s/call sequential LLM latency,
1,925 calls ≈ 1.3–2.2 hours — feasible within a single run, unlike the full 10k-alert / 12-hour sweep.

**Per-EventID breakdown (Q6) sample sizes are a harder constraint.** EventID 1 (process creation) is only
2,452/220,190 records total (1.78%). Getting a ±5pp CI on recall *within that stratum alone* needs 385
malicious EventID-1 records — check against the actual malicious/benign split within that stratum before
committing to a target CI; if the stratum's malicious count is smaller than 385, report the CI at
whatever margin the available n actually supports (compute it, don't assume ±5pp is reachable) rather than
silently under-reporting the true uncertainty on the highest-value stratum.

**CI construction: use Wilson score intervals, not the normal (Wald) approximation.** The Wald interval
is documented to be unstable and to understate the true interval width for small n or for proportions
near 0 or 1 — both conditions likely apply to per-technique or per-EventID breakdowns with small strata.
Wilson score intervals are the standard fix (stable from roughly n≥10) and should be the default CI
method for every proportion-based metric (precision, recall, FPR, FNR) reported at any granularity finer
than the full corpus.

**Comparing LLM vs. baseline on paired items: McNemar's test.** Primary source: Dietterich, "Approximate
Statistical Tests for Comparing Supervised Classification Learning Algorithms" (Neural Computation,
1998) — the paper Phase 0 already cited for this recommendation; independently confirmed here via
scikit-learn-ecosystem tooling documentation (`mlxtend`'s McNemar implementation, built explicitly for
this comparison pattern) and multiple methodology summaries. McNemar's test is the correct choice
specifically because both systems being compared are scored on the **same items** (paired, not
independent samples) — it operates on the discordant-pair 2×2 table (cases where exactly one of the two
systems was correct) and tests whether those disagreements are symmetric. Use the **exact binomial
McNemar** when the discordant-pair count is small (a commonly cited rule of thumb is n<25 discordant
pairs; use exact/mid-p there) and the standard chi-squared-with-continuity-correction form above that
threshold. **Supplement, do not replace, McNemar with a bootstrap CI on the metric difference itself**
(e.g., paired bootstrap resampling of the difference in F1 or MCC between LLM and baseline) — McNemar
gives a significance verdict on raw agreement/disagreement, while a bootstrap CI on the *effect size*
(how much better, not just whether-significantly-different) is what a reviewer needs to judge practical,
not just statistical, significance. A paired permutation test (sign-flip on per-item differences under
the null of exchangeability) is an acceptable alternative to the bootstrap CI and is mentioned in current
tooling (e.g. the `evalci` library for LM evaluation comparisons) as functionally equivalent for this
purpose — either is fine; do not run all three redundantly, McNemar (verdict) + one of
{bootstrap CI, permutation test} (effect size) is sufficient.

### 5. LLM-specific evaluation concerns

Four disclosures a classical-ML evaluation would not need, all with direct primary-source backing:

1. **Nondeterminism / reproducibility.** Recent primary evidence
   ([arXiv:2606.26185, "Necessary but Not Sufficient: Temperature Control and Reproducibility in
   LLM-as-Judge Safety Evaluations"](https://arxiv.org/abs/2606.26185)) directly measured that
   pinning `temperature=0` **reduces but does not eliminate** run-to-run flips — in their test, 1–2 of 7
   borderline items remained non-reproducible even under forced greedy decoding across 690 calls. This
   project must (a) state the exact temperature/seed/model-version used, (b) not assume `temperature=0`
   guarantees identical output across runs, and (c) report the observed run-to-run agreement rate
   empirically (N=5-10 repeats on a subsample, per Phase 0 Finding 7) rather than asserting determinism
   from the parameter setting alone.
2. **Output-parse failure rate as its own reported metric**, not folded silently into "wrong answers."
   Already specified in Phase 0 (Finding 6); this project's `TriageVerdict` schema has two independent
   failure surfaces worth distinguishing: (a) grammar-level failures the Ollama `format`-constrained
   decoding should prevent by construction, and (b) semantic-validation failures that pass the grammar but
   fail `src/agents/schema.py`'s own `_technique_id_shape` / `_benign_has_no_technique` validators (e.g. a
   hallucinated non-ATT&CK-shaped string, or a benign verdict with a technique attached) — report both
   rates separately, since (b) is evidence of a *reasoning* failure the grammar constraint cannot catch,
   which is a materially different and more interesting failure mode than (a).
3. **Confidence calibration (ECE) on the self-reported `confidence` field.** Primary evidence that this
   is a real, non-hypothetical risk: [Tian et al., "Just Ask for Calibration," EMNLP 2023
   (arXiv:2305.14975)](https://arxiv.org/abs/2305.14975) found that RLHF-tuned models' raw token
   probabilities are poorly calibrated, but that verbalized (self-reported, in-text) confidence — exactly
   this project's `TriageVerdict.confidence` field — is *often* better calibrated, with roughly 50%
   relative ECE reduction versus raw logprobs in their tests, and that prompting the model to consider
   multiple answers before stating confidence further improves it. This is a double-edged finding for
   this project: it means verbalized confidence is *plausibly* usable (not automatically noise), but "often
   better calibrated" is not "guaranteed calibrated" — ECE must be measured on this project's own
   corpus/model/prompt combination, not assumed from the literature. Report ECE with a reliability diagram
   (binned confidence vs. empirical accuracy), and if ECE is poor, say so explicitly rather than
   downplaying the confidence field's usefulness for the selective-prediction analysis in Q1.
4. **Prompt sensitivity.** Current literature is more nuanced than "LLMs are fragile to prompt wording" —
   recent work ([arXiv:2509.01790, "Flaw or Artifact? Rethinking Prompt Sensitivity in Evaluating
   LLMs"](https://arxiv.org/html/2509.01790)) argues much observed prompt sensitivity in prior benchmarks
   is itself an artifact of sloppy heuristic parsing/scoring rather than genuine model instability, while
   other work ([arXiv:2607.09665, "Format Sensitivity Index"](https://arxiv.org/abs/2607.09665)) finds
   mean sensitivity varying >30x across models purely from prompt *formatting* changes. Net practical
   guidance for this project: (a) fix and version the triage prompt template, (b) run at minimum a small
   ablation (2-3 semantically-equivalent phrasings of the same prompt on a fixed subsample) to bound how
   much of the reported metric spread is prompt-artifact vs. genuine classifier behavior, and (c) disclose
   the exact prompt text and version alongside the results — an unversioned, undisclosed prompt makes
   every downstream number irreproducible by definition, independent of any model-quality question.
   Position/verbosity bias (LLM-as-judge-specific) does not directly apply to this single-agent classifier
   evaluation unless an LLM-judge is later used to grade `reasoning`/`key_indicators` quality — if that
   happens, Phase 0's existing Zheng et al. citation and mitigations already cover it; no new citation
   needed here.

### 6. Stratification (per-EventID / per-technique)

Given the corpus composition stated in the task (EventID 12/13 registry writes dominate by count; EventID
1 process-creation events, the richest triage signal, are 2,452/220,190 = 1.78%), a **pooled metric is a
prevalence-weighted average that is structurally dominated by whichever EventID has the most records** —
here, registry writes. A classifier that is excellent at spotting malicious registry-persistence patterns
but mediocre at process-creation-based technique detection (arguably the harder, more informative signal)
would still show a strong pooled score, silently hiding its weakest and most decision-relevant slice.

This is not a novel methodological point specific to this corpus — it is the same logic behind
scikit-learn's macro-vs-weighted averaging distinction (already cited in Phase 0: *"macro-averaging...
assumption that all classes are equally important is often untrue"* vs. weighted reflecting the actual
mix) — but applied here one level down, to EventID/event_type strata rather than to the benign/malicious
class split. **Recommendation:** report the full metric set (Section "Recommended metric set") at three
levels: (a) pooled/overall (the headline), (b) per-`event_type` (the six-value coarse enum already in
`src/schema.py` — PROCESS, NETWORK, AUTHENTICATION, FILE, REGISTRY, SCHEDULED_TASK, OTHER — cheap and
already available without new engineering), and (c) per-ATT&CK-technique where per-technique n is large
enough to support a CI (using the Wilson-interval sample-size guidance from Q4; small-n techniques should
be grouped or reported with explicit wide CIs rather than omitted, per Phase 0's own "report negative/thin
findings, don't silently omit" principle). The `technique_unresolved`/`MULTI_TECHNIQUE_UNRESOLVED`
sentinel already defined in `src/schema.py` gives this stratification a natural, honest bucket for the
compound APT29 captures that cannot be attributed to one technique — report that bucket's own aggregate
metrics separately rather than dropping those records from the per-technique table entirely.

---

## Recommended metric set

Compute and report at every stratification level in Q6 (pooled, per-event_type, per-technique where n
supports it):

1. **3×2 raw confusion table** (verdict × truth) — the un-collapsed ground-truth artifact everything else derives from (Q1).
2. **MCC** — single scalar robust to imbalance, cannot be gamed by ignoring one class (Chicco & Jurman 2020).
3. **Balanced accuracy** — cheap, interpretable sanity check alongside MCC; explicitly designed against imbalance inflation (sklearn docs).
4. **Precision / Recall / F1, per-class + macro + weighted** — standard, but never accuracy alone; macro surfaces minority-class weakness, weighted reflects the real mix (both needed, per Phase 0).
5. **PR-AUC as primary threshold curve; ROC-AUC as secondary** — PR is sensitive to false positives under imbalance in a way ROC's huge-negative-denominator is not (Davis & Goadrich 2006).
6. **Coverage, selective accuracy, risk-coverage curve, AURC** for the `suspicious`-as-abstention framing — the correct academic apparatus for a reject-option output (Geifman & El-Yaniv 2017; NeurIPS 2024 follow-up).
7. **Confusion matrices under all three `suspicious`-collapse policies** (conservative / precision-oriented / abstention) — no single collapse is literature-mandated; showing all three prevents cherry-picking (Q1).
8. **False Positive Rate and False Negative Rate, each with its exact formula stated inline** — FP/(FP+TN) and FN/(FN+TP) respectively; state explicitly to avoid the FPR-vs-false-discovery-rate ambiguity Phase 0 already flagged as industry-inconsistent.
9. **Expected Calibration Error (ECE) + reliability diagram** on the `confidence` field — required because verbalized LLM confidence is only "often," not reliably, calibrated (Tian et al. 2023); without this, the selective-prediction thresholding in #6 has no basis.
10. **Schema-validity / parse-failure rate**, split into grammar-level vs. semantic-validation failures — an LLM-specific failure surface with no classical-ML analogue (Phase 0 Finding 6, refined in Q5 above).
11. **Run-to-run agreement rate** (N≥5 repeats on a fixed subsample at production temperature) — nondeterminism is empirically documented even at `temperature=0` (arXiv:2606.26185); report as a distribution, not a point estimate.
12. **Wilson-score 95% CIs on every proportion-based metric above**, at every stratification level where reported — Wald/normal-approximation CIs are documented unstable at small n or extreme proportions, both of which occur in the per-technique breakdowns.
13. **McNemar's test result + bootstrap CI (or permutation test) on the effect size**, for LLM vs. each essential baseline — the paired-comparison significance apparatus (Dietterich 1998), giving both a "is this real" verdict and a "how much better" magnitude.

Explicitly excluded from the headline set: **plain accuracy** (misleading under 80/20 imbalance — report only as context next to the majority-class baseline) and **Cohen's kappa** (two independent, well-documented paradoxes make it unreliable in exactly this imbalance regime; MCC is the better-behaved substitute).

---

## Recommended baselines

Ranked essential → nice-to-have (see Q3 for full rationale and citations):

1. **Majority-class / always-benign** — trivial effort (~1 line); makes the base-rate fallacy visible by construction; **essential**.
2. **Random/stratified-random guess** — trivial effort; true chance floor; **essential but low marginal value beyond #1**, report briefly.
3. **Rules/keyword heuristic baseline** (static thresholds / IOC allow-deny on `raw_event` fields, no LLM) — low-medium effort (hours); isolates the LLM's marginal contribution, the crux of the "AI helps" claim; **essential**, per Arp et al.'s core guidance.
4. **Classical ML on structured features** (logistic regression or gradient-boosted trees over engineered `raw_event`/`event_type`/EventID features, with the same leakage mitigations already applied in `src/ingest/leakage.py`) — medium effort (feature engineering + leakage-safe split); tests whether the *LLM specifically* earns its cost over a fast, well-understood learned baseline; **high priority, not nice-to-have** — the single most likely gap an ML-literate reviewer will flag, and **not present in Phase 0's own baseline list** (correction/addition, see below).
5. **A smaller and/or larger LLM** — medium-high effort (repeats the full sequential run per model, ~12h at 10k alerts or ~1.3-2.2h at the 1,925-record statistically-sufficient sample from Q4); useful cost/accuracy-frontier context; **nice-to-have**, should not consume budget before #1-4 are complete.

---

## Sample size

Standard 95% CI binomial sample-size formula, `n = 1.96² · p(1-p) / E²`:

| Target margin (±) | n (p=0.5, worst case) | n (p=0.2) |
|---|---|---|
| ±10 pp | 97 | 62 |
| ±5 pp | **385** | 246 |
| ±3 pp | 1,068 | 683 |

**Concrete recommendation for this project:**
- **Floor: 385 malicious-class records actually evaluated**, to get recall on the malicious class (the
  single most safety-relevant metric) to ±5pp at 95% CI, using the p=0.5 worst-case variance assumption
  (no pilot estimate exists yet to justify a tighter assumption).
- At the corpus's fixed 20% malicious rate, hitting 385 malicious records via **proportional random
  sampling** would require ~1,925 total records; **stratified sampling** (deliberately oversampling the
  malicious class, consistent with this project's own precedent of stratified-by-EventID sampling
  already implemented in `corpus.py`'s `_stratified_sample_by_event_id`) is more efficient and should be
  preferred — it hits the 385-malicious floor without inflating benign-side sample size past what's
  needed for the benign-side CI (which, being 4x larger at the same ratio, will already comfortably clear
  its own ±5pp bar with far fewer than 1,540 benign records needed).
- At measured 2.5–4.2s/call, sequential (`OLLAMA_NUM_PARALLEL=1`), **1,925 calls ≈ 1.3–2.2 hours** — feasible in one sitting, unlike the full 10k-alert/~12-hour sweep, and should be the default eval-run size rather than either extreme.
- **Per-EventID-1 stratum (2,452 records total, 1.78% of corpus) is a harder constraint**: the 385-malicious floor for a ±5pp CI *within that stratum alone* may not be reachable if the stratum's actual malicious count is smaller — check the real split before committing to a target margin, and if 385 malicious EventID-1 records aren't available, report whatever wider CI the actual n supports rather than silently presenting a falsely-precise number.
- Use **Wilson score intervals**, not the normal/Wald approximation, for every reported CI — Wilson remains stable at small n and near-0/near-1 proportions, both of which will occur in the finer per-technique breakdowns.

---

## What must be disclosed

Mirroring Phase 0's "canonical SOC metrics NOT claimed" disclosure discipline, this evaluation must ship
with an explicit limitations section covering, at minimum:

1. **This is a static, offline, labeled-corpus evaluation**, not a live-SOC measurement — inherits Phase
   0's finding verbatim; MTTD/MTTR/dwell-time/analyst-touch-time remain uncomputable and unclaimed here too.
2. **The `suspicious`-collapse policy used for the headline number**, with the other two policies'
   full tables available alongside it — never present one collapse as if it were the only honest reading.
3. **The exact temperature, seed, model name+version, and prompt template version** used for the reported
   run — and the empirically observed run-to-run agreement rate from the N≥5 repeat check, not an assumed
   100% determinism from `temperature=0` alone (arXiv:2606.26185 direct evidence this assumption fails).
4. **Parse-failure rate**, split grammar-level vs. semantic-validation, as an actual measured number, not
   an assumed near-zero.
5. **ECE / calibration result on the `confidence` field**, including if it turns out poorly calibrated —
   and, if poor, an explicit statement that the selective-prediction thresholding in Q1/#6 is correspondingly
   less trustworthy at the chosen threshold.
6. **Sample size (n) next to every reported metric, at every stratification level**, including per-technique
   breakdowns with small n reported with their (necessarily wide) Wilson CIs rather than omitted.
7. **The corpus's own known construction choices and their limits**: `benign_ratio=4.0` is a stated design
   choice, not a claim of matching real 99:1 SOC prevalence (per `corpus.py`'s own docstring); the
   `MULTI_TECHNIQUE_UNRESOLVED` sentinel bucket's own aggregate metrics, reported separately, with a note
   that no per-technique claim is made for those records; and the shortcut-mitigation applied in
   `src/ingest/leakage.py` (state that `mitigate_shortcuts=True` was used and what it changes, since the
   corpus assembly code itself flags that turning it off reproduces a shortcut-leaking corpus on purpose
   for audit comparison — the reported numbers must state which corpus variant they're from).
8. **A named "what this does not measure" section** (per Phase 0 Finding in "Reporting standards")
   explicitly listing MTTD/MTTR/dwell-time/analyst-touch-time as NOT computed and why — silent omission
   reads as either unawareness or evasion; naming them preempts the question.
9. **No claim of comparability to any specific external published benchmark's numbers** (e.g. Simbian's
   AI SOC LLM benchmark) — different corpus, different ground truth construction, different task framing;
   at most, note that the closest public comparator (n=100 cases, no visible CIs or significance testing
   in what could be found) is itself an example of the rigor gap this project's differentiator claim rests
   on closing, not a number to be matched or beaten.

---

## Corrections to prior assumptions

Phase 0 (`projects/wshearer-site/research/phase-0-metrics.md`) remains correct on everything it asserted
and is not contradicted here. Two additions/refinements, not corrections of an error:

1. **Phase 0's Section 5 baseline list (no-op, random, majority-class, rules-only, McNemar) did not
   include a classical-ML baseline** (logistic regression / gradient boosting on structured features).
   This brief adds it as priority #4, ranked above "a smaller/larger LLM," because it is the comparison
   most directly targeted by Arp et al.'s "Inappropriate Baseline" guidance (which Phase 0 did not cite —
   Phase 0 cited arXiv:1503.06952 for baseline methodology generally, not Arp et al. specifically for this
   point) and is the gap most likely to be flagged by an ML-literate reviewer. This is an **addition**,
   not a contradiction — Phase 0 never said "don't add a classical-ML baseline," it simply didn't reach
   this specific baseline in its own list.
2. **Phase 0's own flagged open item — the PR-vs-ROC claim not being a verbatim scikit-learn sentence —
   is confirmed still true** on this brief's independent re-check of the same scikit-learn docs page; this
   brief additionally fetched Davis & Goadrich (2006) directly (which Phase 0's "suggested next step"
   asked for) and confirms it as the correct primary citation for the formal PR/ROC dominance-equivalence
   argument, closing that open item.

Nothing else in Phase 0 (the MTTD/MTTR exclusion list, the ATT&CK-coverage-scoring methodology, the
Model-Cards/Datasheets-for-Datasets reporting-standards guidance) is contradicted or revised by this
brief's research into the three-class-scoring, imbalance-metric, baseline, significance, LLM-specific, and
stratification questions.
