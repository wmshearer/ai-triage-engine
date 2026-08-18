"""Orchestrates the full evaluation: sample -> run LLM + baselines on the
SAME items -> pooled/stratified metrics -> significance -> a structured
`EvalResult`.

Follows research/phase-3-evaluation-design.md's Verdict exactly:
  - Never silently collapses the 3-way `suspicious` verdict to one binary
    side; scores all three named policies (conservative, high_precision,
    abstention) and reports all three (Verdict #1).
  - Leads with MCC + PR-AUC, reports ROC-AUC as secondary (Verdict #3/#4).
  - Every proportion gets a Wilson CI (Verdict CI section).
  - Reports per-EventID and per-event_type, in addition to pooled
    (Verdict #7).
  - McNemar + bootstrap CI for LLM vs. each baseline, on the SAME sampled
    items (Verdict #8).
  - Sentinel (`MULTI_TECHNIQUE_UNRESOLVED`) records are EXCLUDED from
    per-technique scoring, reported as their own aggregate bucket, never
    scored as wrong (design brief's "ground-truth limit" instruction).
  - LLM-specific metrics (parse-failure rate, run-to-run agreement, ECE) are
    first-class fields on `EvalResult`, not an afterthought.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable

from src.agents.schema import TriageVerdict, Verdict
from src.eval import metrics as m
from src.eval import significance as sig
from src.eval.baselines import BaselinePrediction, _engineer_features
from src.schema import AlertRecord

# The three named `suspicious`-collapse policies (Verdict #1). "conservative"
# is the recommended headline policy (a missed intrusion is costlier than an
# extra human review) — but all three are always computed and reported,
# never just the headline, per the brief's explicit "never present one
# collapse as if it were the only honest reading" instruction.
COLLAPSE_POLICIES = ("conservative", "high_precision", "abstention")
HEADLINE_POLICY = "conservative"


def _collapse_verdict(verdict: Verdict, policy: str) -> bool | None:
    """Map a 3-way Verdict to a binary malicious/benign call under `policy`.

    Returns None for `abstention` policy on a `suspicious` verdict — that is
    not a "call", it is a refusal to call, and is scored separately via
    selective-prediction metrics, never folded into a 2x2 confusion matrix
    as if it were a committed answer.
    """
    if verdict == Verdict.MALICIOUS:
        return True
    if verdict == Verdict.BENIGN:
        return False
    # verdict == SUSPICIOUS
    if policy == "conservative":
        return True
    if policy == "high_precision":
        return False
    if policy == "abstention":
        return None
    raise ValueError(f"unknown collapse policy: {policy!r}")


# ---------------------------------------------------------------------------
# Per-item prediction record — the harness's internal unit of work
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ItemPrediction:
    """One system's prediction for one AlertRecord, normalized to a common shape.

    `verdict_3way` is set only for systems with a genuine 3-way output (the
    LLM); baselines are binary by construction and leave it None (their
    `is_malicious_pred`/`score` already reflect a committed binary call, so
    `collapsed[policy]` is identical across all three policies for them —
    see `_predictions_for_baseline`).
    """

    record: AlertRecord
    verdict_3way: Verdict | None
    collapsed: dict[str, bool | None]  # policy -> predicted label, None = abstained
    score: float  # continuous P(malicious)-like value for PR-AUC/ROC-AUC
    confidence: float | None  # LLM's self-reported confidence, None for baselines
    parse_failed: bool  # True if the LLM's output for this record couldn't be scored


def _predictions_for_baseline(records: list[AlertRecord], preds: list[BaselinePrediction]) -> list[ItemPrediction]:
    if len(records) != len(preds):
        raise ValueError("records and predictions must be the same length")
    out = []
    for record, pred in zip(records, preds):
        collapsed = {policy: pred.is_malicious_pred for policy in COLLAPSE_POLICIES}
        out.append(
            ItemPrediction(
                record=record,
                verdict_3way=None,
                collapsed=collapsed,
                score=pred.score,
                confidence=None,
                parse_failed=False,
            )
        )
    return out


def _predictions_for_llm(
    records: list[AlertRecord], verdicts: list[TriageVerdict | None]
) -> list[ItemPrediction]:
    """Build ItemPredictions from LLM output, `verdicts[i] is None` meaning
    triage_alert raised TriageError (a parse/validation failure) for
    records[i] — kept IN the returned list (not dropped) so the
    parse-failure rate is computed over the full attempted sample, not just
    the subset that happened to parse.
    """
    if len(records) != len(verdicts):
        raise ValueError("records and verdicts must be the same length")
    out = []
    for record, verdict in zip(records, verdicts):
        if verdict is None:
            out.append(
                ItemPrediction(
                    record=record,
                    verdict_3way=None,
                    collapsed={policy: None for policy in COLLAPSE_POLICIES},
                    score=0.0,
                    confidence=None,
                    parse_failed=True,
                )
            )
            continue
        collapsed = {policy: _collapse_verdict(verdict.verdict, policy) for policy in COLLAPSE_POLICIES}
        # A continuous malicious-leaning score for PR-AUC/ROC-AUC: verdict
        # position maps to a base score, refined by confidence within that
        # position. benign -> [0, 0.33), suspicious -> [0.33, 0.67),
        # malicious -> [0.67, 1.0] — monotonic in verdict severity, and
        # confidence still discriminates WITHIN a verdict class, which a bare
        # 3-level score could not.
        base = {Verdict.BENIGN: 0.0, Verdict.SUSPICIOUS: 1 / 3, Verdict.MALICIOUS: 2 / 3}[verdict.verdict]
        score = base + (verdict.confidence / 3.0)
        out.append(
            ItemPrediction(
                record=record,
                verdict_3way=verdict.verdict,
                collapsed=collapsed,
                score=score,
                confidence=verdict.confidence,
                parse_failed=False,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Stratified + pooled metric computation for one system's predictions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyReport:
    """Full metric set for one collapse policy, on one slice (pooled or one stratum)."""

    policy: str
    n: int
    metrics: dict[str, float | None]
    pr_auc: float | None
    roc_auc: float | None
    recall_wilson_ci: m.WilsonInterval | None
    precision_wilson_ci: m.WilsonInterval | None
    fpr_wilson_ci: m.WilsonInterval | None


@dataclass(frozen=True)
class SliceReport:
    """All three policy reports, plus the abstention-specific selective-
    prediction metrics, for one slice (pooled/per-EventID/per-event_type)."""

    slice_name: str
    n: int
    n_malicious: int
    n_benign: int
    policies: dict[str, PolicyReport]
    selective_prediction: m.SelectivePredictionResult | None


def _committed_items(items: list[ItemPrediction], policy: str) -> tuple[list[bool], list[bool]]:
    """(y_true, y_pred) over items where `policy` produced a committed call
    (i.e. excluding abstentions under the `abstention` policy)."""
    y_true, y_pred = [], []
    for item in items:
        pred = item.collapsed[policy]
        if pred is None:
            continue
        y_true.append(item.record.is_malicious)
        y_pred.append(pred)
    return y_true, y_pred


def _policy_report(items: list[ItemPrediction], policy: str) -> PolicyReport | None:
    y_true, y_pred = _committed_items(items, policy)
    if not y_true:
        return None
    metric_dict = m.metric_set(y_true, y_pred)

    scores = [item.score for item in items if item.collapsed[policy] is not None]
    pr_auc = roc_auc = None
    if len(set(y_true)) == 2:
        pr_auc = m.pr_auc(y_true, scores)
        roc_auc = m.roc_auc(y_true, scores)

    c = m.confusion_counts(y_true, y_pred)
    recall_ci = m.wilson_interval(c.tp, c.tp + c.fn) if (c.tp + c.fn) else None
    precision_ci = m.wilson_interval(c.tp, c.tp + c.fp) if (c.tp + c.fp) else None
    fpr_ci = m.wilson_interval(c.fp, c.fp + c.tn) if (c.fp + c.tn) else None

    return PolicyReport(
        policy=policy,
        n=len(y_true),
        metrics=metric_dict,
        pr_auc=pr_auc,
        roc_auc=roc_auc,
        recall_wilson_ci=recall_ci,
        precision_wilson_ci=precision_ci,
        fpr_wilson_ci=fpr_ci,
    )


def _slice_report(slice_name: str, items: list[ItemPrediction]) -> SliceReport:
    n_malicious = sum(1 for item in items if item.record.is_malicious)
    n_benign = len(items) - n_malicious

    policies = {}
    for policy in COLLAPSE_POLICIES:
        report = _policy_report(items, policy)
        if report is not None:
            policies[policy] = report

    selective = None
    non_abstained_items = [item for item in items if item.collapsed["abstention"] is not None]
    if items:
        committed_flags = [item.collapsed["abstention"] is not None for item in items]
        correct_flags = [
            (item.collapsed["abstention"] == item.record.is_malicious) if item.collapsed["abstention"] is not None else False
            for item in items
        ]
        confidences = [item.confidence if item.confidence is not None else 0.0 for item in items]
        has_confidence = any(item.confidence is not None for item in items)
        selective = m.selective_prediction_metrics(
            committed_flags, correct_flags, confidences=confidences if has_confidence else None
        )
    del non_abstained_items

    return SliceReport(
        slice_name=slice_name,
        n=len(items),
        n_malicious=n_malicious,
        n_benign=n_benign,
        policies=policies,
        selective_prediction=selective,
    )


def stratify_by_event_id(items: list[ItemPrediction]) -> dict[object, list[ItemPrediction]]:
    buckets: dict[object, list[ItemPrediction]] = {}
    for item in items:
        key = item.record.raw_event.get("EventID")
        buckets.setdefault(key, []).append(item)
    return buckets


def stratify_by_event_type(items: list[ItemPrediction]) -> dict[str, list[ItemPrediction]]:
    buckets: dict[str, list[ItemPrediction]] = {}
    for item in items:
        key = item.record.event_type.value
        buckets.setdefault(key, []).append(item)
    return buckets


def split_sentinel_records(items: list[ItemPrediction]) -> tuple[list[ItemPrediction], list[ItemPrediction]]:
    """Split `items` into (resolvable, sentinel) for per-technique scoring.

    Per the design brief's "GROUND-TRUTH LIMIT" instruction: 88% of
    malicious records carry `attack_technique == MULTI_TECHNIQUE_UNRESOLVED`
    (`technique_unresolved=True`) because OTRF publishes no per-event
    technique mapping for its APT29 compound captures. These records MUST be
    excluded from per-technique scoring — the model cannot be penalized for
    missing a label that was never published — but their own aggregate
    metrics are still reported separately (never dropped from the report
    outright), per `src/schema.py`'s own sentinel design and the brief's
    "report negative/thin findings, don't silently omit" principle. Benign
    records (attack_technique is always None, never the sentinel) are
    "resolvable" trivially and included in the first list.
    """
    resolvable, sentinel = [], []
    for item in items:
        if item.record.technique_unresolved:
            sentinel.append(item)
        else:
            resolvable.append(item)
    return resolvable, sentinel


def stratify_by_technique(items: list[ItemPrediction]) -> dict[str, list[ItemPrediction]]:
    """Per-technique buckets, over the SENTINEL-EXCLUDED subset only.

    Callers must pass `split_sentinel_records(items)[0]` (the resolvable
    subset) — this function does not filter the sentinel itself so the
    exclusion step stays visible and testable at its own call site rather
    than hidden inside this one. Benign records have no technique
    (`attack_technique is None`); bucketed under the literal string
    `"benign"` so every item still lands in exactly one bucket.
    """
    buckets: dict[str, list[ItemPrediction]] = {}
    for item in items:
        key = item.record.attack_technique if item.record.is_malicious else "benign"
        buckets.setdefault(key or "unknown", []).append(item)
    return buckets


# ---------------------------------------------------------------------------
# LLM-specific metrics: parse-failure rate, determinism, ECE
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LLMSpecificReport:
    n_attempted: int
    n_parse_failed: int
    parse_failure_rate: float
    parse_failure_rate_ci: m.WilsonInterval
    ece: m.ECEResult | None
    determinism: "DeterminismReport | None"


@dataclass(frozen=True)
class DeterminismReport:
    """Run-to-run agreement rate from N>=5 repeats on a fixed subsample.

    Per Verdict #9 / arXiv:2606.26185: temperature=0 reduces but does not
    guarantee determinism. `agreement_rate` is the fraction of repeat-groups
    where every repeat produced the IDENTICAL verdict (byte-identical
    `TriageVerdict`, not just the same top-level `verdict` enum — a change in
    `attack_technique`/`confidence` across runs is still non-determinism
    worth surfacing even if the coarse verdict happens to match).
    """

    n_items_tested: int
    n_repeats_per_item: int
    agreement_rate: float
    agreement_rate_ci: m.WilsonInterval


def compute_llm_specific_report(
    items: list[ItemPrediction], determinism: DeterminismReport | None = None
) -> LLMSpecificReport:
    n_attempted = len(items)
    n_failed = sum(1 for item in items if item.parse_failed)
    ci = m.wilson_interval(n_failed, n_attempted) if n_attempted else None

    ece = None
    scored_items = [item for item in items if not item.parse_failed and item.confidence is not None]
    if scored_items:
        confidences = [item.confidence for item in scored_items]
        correct = [item.collapsed[HEADLINE_POLICY] == item.record.is_malicious for item in scored_items]
        ece = m.expected_calibration_error(confidences, correct)

    return LLMSpecificReport(
        n_attempted=n_attempted,
        n_parse_failed=n_failed,
        parse_failure_rate=(n_failed / n_attempted) if n_attempted else 0.0,
        parse_failure_rate_ci=ci,
        ece=ece,
        determinism=determinism,
    )


def measure_determinism(
    records: list[AlertRecord],
    triage_fn: Callable[[AlertRecord], TriageVerdict],
    n_repeats: int = 5,
) -> DeterminismReport:
    """Run `triage_fn` `n_repeats` times on each of `records` and measure
    run-to-run agreement.

    `triage_fn` is injected (not hardcoded to `src.agents.triage.triage_alert`)
    so this is testable offline with a fake/deterministic stub — the real
    harness entry point (`scripts/run_eval.py`) passes the live Ollama call.
    """
    if n_repeats < 2:
        raise ValueError("n_repeats must be >= 2 to measure agreement")
    if not records:
        raise ValueError("cannot measure determinism over zero records")

    agreeing = 0
    for record in records:
        verdicts = [triage_fn(record) for _ in range(n_repeats)]
        first = verdicts[0]
        if all(v == first for v in verdicts[1:]):
            agreeing += 1

    ci = m.wilson_interval(agreeing, len(records))
    return DeterminismReport(
        n_items_tested=len(records),
        n_repeats_per_item=n_repeats,
        agreement_rate=agreeing / len(records),
        agreement_rate_ci=ci,
    )


# ---------------------------------------------------------------------------
# Leakage-safe train/test split for the classical-ML baseline
# ---------------------------------------------------------------------------


def _benign_duplication_stats(benign_fit: list) -> dict:
    """Measure how much the benign fit pool actually collapses under encoding.

    Computed live rather than hardcoded from the 2026-08-18 measurement, so
    the disclosure stays true if the feature set or the benign source ever
    changes — a hardcoded 99.94% would silently become a lie the first time
    someone enriched the encoding to fix precisely this problem.
    """
    if not benign_fit:
        return {"benign_feature_duplication_rate": None, "benign_distinct_feature_vectors": None}

    vectors = {tuple(sorted(_engineer_features(record).items())) for record in benign_fit}
    return {
        "benign_feature_duplication_rate": 1.0 - (len(vectors) / len(benign_fit)),
        "benign_distinct_feature_vectors": len(vectors),
    }


@dataclass(frozen=True)
class SplitDisclosure:
    """What kind of leakage-safety was actually applied to each class.

    Measured fact about this project's real corpus, not a hypothetical: the
    malicious side has 7 distinct `source_capture_id`s (5 OTRF atomic
    captures + 2 APT29 compound captures) but the ENTIRE benign side shares
    exactly ONE `source_capture_id` ("win2022-evtx" — evtx-baseline ships as
    a single VM capture, never split into per-session captures). A strict
    capture-level exclusion applied uniformly to both classes would exclude
    the benign class's only capture the moment ANY benign record lands in
    the eval set, emptying the fit pool's benign side on literally every
    real eval run — not a corner case, the default case. So the two classes
    get DIFFERENT (and disclosed, not hidden) split strategies:
      - malicious: capture-level exclusion (the real leakage risk — distinct
        attack-scenario sessions with session-specific artifacts).
      - benign: record-level held-out split (no distinct "sessions" exist to
        leak between; excluded records are simply excluded by id).
    This asymmetry is a genuine consequence of the corpus's own construction
    (`src/ingest/normalize_benign.py` ingests evtx-baseline as one capture),
    reported here so a reviewer sees it named rather than discovering it by
    reading code.

    CORRECTION, measured 2026-08-18 — an earlier version of this docstring
    called the asymmetry "not a lowering of the leakage-safety bar." That
    understated it, and the real number is worse than the framing implied.
    The leak is NOT cross-session; it is exact-feature-vector reuse under a
    coarse, low-cardinality encoding:

        110,095 benign records  ->  112 distinct feature vectors
        one single vector (registry EventID 13) covers 66,498 records
        99.94% of held-out benign test vectors appear VERBATIM in training

    At that duplication rate a record-level split does not separate anything:
    logistic regression over these features degenerates into a lookup table
    for the benign class ("have I seen this exact tuple labelled benign?").

    CONSEQUENCE FOR REPORTING: the classical-ML baseline's benign-side
    performance must be read as an OPTIMISTIC CEILING, not a leakage-safe
    generalization estimate. Since classical-ML is the baseline the LLM is
    measured against, that ceiling makes the LLM's relative showing look
    WORSE than a clean comparison would — so this disclosure cuts against
    the project's own flattering story, which is exactly why it ships in the
    report body rather than a footnote.

    Fixing it properly needs either a richer feature encoding or a benign
    source with genuinely distinct capture sessions; neither is available
    today, so the honest move is to state the bound rather than quietly
    report a number that cannot support the weight a reader would put on it.
    """

    malicious_split_strategy: str
    benign_split_strategy: str
    n_malicious_captures_excluded: int
    n_benign_captures_excluded: int
    # Populated so the rendered report can state the ceiling with its number
    # rather than describing it in prose a reader may skim past.
    benign_feature_duplication_rate: float | None = None
    benign_distinct_feature_vectors: int | None = None


def classical_ml_train_test_split(
    corpus: list[AlertRecord], eval_records: list[AlertRecord], seed: int = 20260818
) -> tuple[list[AlertRecord], SplitDisclosure]:
    """Build a fit set for `ClassicalMLBaseline`, disjoint from `eval_records`.

    A per-RECORD random split would leak: two events from the SAME capture
    (e.g. the same APT29 scenario run) share session-level artifacts (a
    specific host, a specific attacker's exact command sequence) that a
    per-record split could put on both sides of the fit/eval boundary,
    letting the model memorize capture-specific detail rather than learn
    generalizable structure — the same "wrong unit of independence" failure
    Arp et al. warn about generally.

    Applied PER CLASS, not uniformly, because the two classes have genuinely
    different capture structure in this corpus — see `SplitDisclosure`'s
    docstring for the measured fact this responds to:
      - malicious records: excludes every `source_capture_id` present in
        `eval_records`' malicious subset from the fit pool (true
        capture-level leakage safety).
      - benign records: if the benign eval subset's capture ids would, if
        excluded, empty the benign fit pool entirely (the measured case:
        one shared capture id for all of evtx-baseline), falls back to
        excluding exactly the eval set's OWN record ids (record-level
        held-out split) rather than raising — there is no cross-session
        artifact to leak within one homogeneous background capture, so this
        is not a leakage-safety compromise, only a coarser split than the
        malicious side gets, and it is reported via the returned
        `SplitDisclosure` rather than silently applied.

    Raises only if a class's fit pool is STILL empty after the appropriate
    per-class fallback (e.g. a corpus too small to support any split) — a
    corpus that cannot support a leakage-safe split must fail loudly, never
    silently degrade to a leaking one.
    """
    eval_ids = {r.id for r in eval_records}
    eval_malicious_capture_ids = {r.source_capture_id for r in eval_records if r.is_malicious}
    eval_benign_capture_ids = {r.source_capture_id for r in eval_records if not r.is_malicious}

    malicious_pool = [r for r in corpus if r.is_malicious]
    benign_pool = [r for r in corpus if not r.is_malicious]

    malicious_fit = [r for r in malicious_pool if r.source_capture_id not in eval_malicious_capture_ids]
    malicious_strategy = "capture_level_exclusion"

    benign_fit_capture_level = [r for r in benign_pool if r.source_capture_id not in eval_benign_capture_ids]
    if benign_fit_capture_level:
        benign_fit = benign_fit_capture_level
        benign_strategy = "capture_level_exclusion"
    else:
        # Capture-level exclusion would empty the benign side (the measured
        # single-shared-capture case) -- fall back to record-level held-out.
        benign_fit = [r for r in benign_pool if r.id not in eval_ids]
        benign_strategy = "record_level_holdout_fallback"

    if not malicious_fit or not benign_fit:
        raise ValueError(
            "classical_ml_train_test_split: fit pool empty even after per-class fallback "
            f"(malicious={len(malicious_fit)}, benign={len(benign_fit)}) -- "
            "supply a larger corpus or a smaller eval sample"
        )

    disclosure = SplitDisclosure(
        malicious_split_strategy=malicious_strategy,
        benign_split_strategy=benign_strategy,
        n_malicious_captures_excluded=len(eval_malicious_capture_ids),
        n_benign_captures_excluded=len(eval_benign_capture_ids) if benign_strategy == "capture_level_exclusion" else 0,
        **_benign_duplication_stats(benign_fit),
    )

    candidate_pool = malicious_fit + benign_fit
    rng = random.Random(seed)
    rng.shuffle(candidate_pool)
    return candidate_pool, disclosure


# ---------------------------------------------------------------------------
# Top-level result object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SystemResult:
    """One system's (LLM or one baseline) full evaluation output."""

    system_name: str
    pooled: SliceReport
    per_event_id: dict[object, SliceReport]
    per_event_type: dict[str, SliceReport]
    per_technique: dict[str, SliceReport]
    sentinel_bucket: SliceReport | None
    llm_specific: LLMSpecificReport | None  # only set for the LLM system


@dataclass(frozen=True)
class SignificanceResult:
    baseline_name: str
    policy: str
    mcnemar: sig.McNemarResult
    bootstrap_ci: sig.BootstrapCIResult


@dataclass(frozen=True)
class EvalResult:
    """The complete, structured output of one evaluation run."""

    sample_size_report: object  # eval.sampling.SampleSizeReport
    systems: dict[str, SystemResult]  # keyed by system_name, "llm" + each baseline name
    significance: list[SignificanceResult]
    corpus_metadata: dict[str, object]


def build_system_result(system_name: str, items: list[ItemPrediction], llm_specific: LLMSpecificReport | None = None) -> SystemResult:
    pooled = _slice_report("pooled", items)

    by_event_id = stratify_by_event_id(items)
    per_event_id = {str(k): _slice_report(f"event_id={k}", v) for k, v in by_event_id.items()}

    by_event_type = stratify_by_event_type(items)
    per_event_type = {k: _slice_report(f"event_type={k}", v) for k, v in by_event_type.items()}

    resolvable, sentinel = split_sentinel_records(items)
    by_technique = stratify_by_technique(resolvable)
    per_technique = {k: _slice_report(f"technique={k}", v) for k, v in by_technique.items()}
    sentinel_bucket = _slice_report("technique_unresolved_sentinel", sentinel) if sentinel else None

    return SystemResult(
        system_name=system_name,
        pooled=pooled,
        per_event_id=per_event_id,
        per_event_type=per_event_type,
        per_technique=per_technique,
        sentinel_bucket=sentinel_bucket,
        llm_specific=llm_specific,
    )


def compute_significance(
    llm_items: list[ItemPrediction],
    baseline_items_by_name: dict[str, list[ItemPrediction]],
    policy: str = HEADLINE_POLICY,
    n_resamples: int = 10_000,
    seed: int = 20260818,
) -> list[SignificanceResult]:
    """McNemar + bootstrap CI (accuracy difference) for LLM vs. each baseline,
    on the headline collapse policy, over items both systems committed on
    (abstention-policy items where the LLM abstained are excluded from THIS
    comparison specifically, since McNemar needs both systems to have made a
    call on every paired item)."""
    results = []
    for name, baseline_items in baseline_items_by_name.items():
        if len(llm_items) != len(baseline_items):
            raise ValueError(f"llm_items and baseline_items for {name!r} must be paired (same length/order)")

        paired = [
            (llm_item, base_item)
            for llm_item, base_item in zip(llm_items, baseline_items)
            if llm_item.collapsed[policy] is not None and base_item.collapsed[policy] is not None
        ]
        if not paired:
            continue

        llm_correct = [li.collapsed[policy] == li.record.is_malicious for li, _ in paired]
        base_correct = [bi.collapsed[policy] == bi.record.is_malicious for _, bi in paired]

        mcnemar_result = sig.mcnemar_test(llm_correct, base_correct)
        bootstrap_result = sig.paired_bootstrap_ci(
            [float(c) for c in llm_correct],
            [float(c) for c in base_correct],
            metric_fn=lambda xs: sum(xs) / len(xs),
            n_resamples=n_resamples,
            seed=seed,
        )
        results.append(
            SignificanceResult(baseline_name=name, policy=policy, mcnemar=mcnemar_result, bootstrap_ci=bootstrap_result)
        )
    return results
