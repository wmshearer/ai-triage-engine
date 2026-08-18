"""Metrics for the triage evaluation, per research/phase-3-evaluation-design.md.

Headline order matters and is enforced by convention throughout this project
(never by this module alone): MCC and PR-AUC lead, ROC-AUC is secondary and
always reported alongside PR-AUC on the same slice, and plain accuracy is
never reported as a standalone headline (Verdict #3). This module computes
the numbers; `report.py` is responsible for the presentation order.

All binary metrics here assume the convention `positive == malicious`,
matching `src.schema.AlertRecord.is_malicious`.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    matthews_corrcoef,
    roc_auc_score,
)

# ---------------------------------------------------------------------------
# Confusion matrix + derived rate metrics
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConfusionCounts:
    """A binary confusion matrix, `positive == malicious`.

    Named fields rather than a bare 2x2 array so every call site is
    self-documenting about which cell is which — the FPR-vs-FDR ambiguity
    the design brief explicitly calls out (Verdict item 8 / recommended
    metric set item 8) is exactly the kind of mistake an unlabeled matrix
    invites.
    """

    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.fn + self.tn


def confusion_counts(y_true: list[bool], y_pred: list[bool]) -> ConfusionCounts:
    """Build a `ConfusionCounts` from parallel true/predicted boolean lists.

    `True` means malicious in both lists, matching `AlertRecord.is_malicious`
    and every baseline/agent's `predict` interface (see baselines.py).
    """
    if len(y_true) != len(y_pred):
        raise ValueError(f"length mismatch: {len(y_true)} true vs {len(y_pred)} pred")
    if not y_true:
        raise ValueError("cannot compute a confusion matrix over zero records")
    tp = fp = fn = tn = 0
    for t, p in zip(y_true, y_pred):
        if t and p:
            tp += 1
        elif not t and p:
            fp += 1
        elif t and not p:
            fn += 1
        else:
            tn += 1
    return ConfusionCounts(tp=tp, fp=fp, fn=fn, tn=tn)


def precision(c: ConfusionCounts) -> float | None:
    """TP / (TP + FP). None (undefined) if the model never predicted positive."""
    denom = c.tp + c.fp
    return c.tp / denom if denom else None


def recall(c: ConfusionCounts) -> float | None:
    """TP / (TP + FN), i.e. true positive rate / sensitivity.

    None (undefined) only if there are zero actual positives in the slice —
    a degenerate stratum, not a modeling failure.
    """
    denom = c.tp + c.fn
    return c.tp / denom if denom else None


def f1(c: ConfusionCounts) -> float | None:
    p, r = precision(c), recall(c)
    if p is None or r is None or (p + r) == 0:
        return None
    return 2 * p * r / (p + r)


def false_positive_rate(c: ConfusionCounts) -> float | None:
    """FP / (FP + TN) — stated inline per the design brief's explicit
    instruction to avoid the FPR-vs-false-discovery-rate ambiguity."""
    denom = c.fp + c.tn
    return c.fp / denom if denom else None


def false_negative_rate(c: ConfusionCounts) -> float | None:
    """FN / (FN + TP)."""
    denom = c.fn + c.tp
    return c.fn / denom if denom else None


def specificity(c: ConfusionCounts) -> float | None:
    """TN / (TN + FP), i.e. true negative rate. 1 - FPR when defined."""
    denom = c.tn + c.fp
    return c.tn / denom if denom else None


def accuracy(c: ConfusionCounts) -> float:
    """Plain accuracy. NEVER report this alone as a headline (Verdict #3) —
    at benign_ratio=4.0 a majority-class classifier scores 0.80 while having
    zero recall on the class that matters. Exists here only so it can be
    shown explicitly alongside the majority-class baseline as context, per
    the design brief's 'report accuracy only next to the majority-class
    baseline' instruction.
    """
    return (c.tp + c.tn) / c.n


def balanced_accuracy(c: ConfusionCounts) -> float | None:
    """Macro-average of per-class recall: mean(sensitivity, specificity).

    None if either class is entirely absent from the slice (both recall and
    specificity require a nonzero denominator) — an honest "undefined", not
    a silently substituted 0 or 1.
    """
    r, s = recall(c), specificity(c)
    if r is None or s is None:
        return None
    return (r + s) / 2


def mcc(c: ConfusionCounts) -> float | None:
    """Matthews Correlation Coefficient.

    MCC = (TP*TN - FP*FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))

    Range [-1, +1], 0 = random. Chicco & Jurman (BMC Genomics 2020, PMC6941312):
    "MCC is the only binary classification rate that generates a high score
    only if the binary predictor was able to correctly predict the majority
    of positive data instances and the majority of negative data instances."

    Returns None (explicitly, per the paper's own caveat) when any of the
    four marginal sums (TP+FP, TP+FN, TN+FP, TN+FN) is zero — i.e. the
    confusion matrix has a fully-zero row or column, meaning one class was
    never predicted or never occurred. Never silently coerced to 0 or 1; a
    `suspicious`-heavy collapse policy that drives one predicted class to
    zero is exactly the case this guards.
    """
    denom_sq = (c.tp + c.fp) * (c.tp + c.fn) * (c.tn + c.fp) * (c.tn + c.fn)
    if denom_sq == 0:
        return None
    numerator = c.tp * c.tn - c.fp * c.fn
    return numerator / math.sqrt(denom_sq)


def mcc_sklearn_cross_check(y_true: list[bool], y_pred: list[bool]) -> float:
    """Cross-check `mcc()` against scikit-learn's `matthews_corrcoef`.

    Used only in tests (never in the harness's own reporting path) to prove
    the hand-rolled formula above agrees with the reference implementation.
    sklearn returns 0.0 in the degenerate zero-marginal case rather than
    raising/None, which is exactly the silent-coercion behavior `mcc()`
    above deliberately refuses to replicate for production reporting — see
    `mcc()`'s docstring.
    """
    return float(matthews_corrcoef(y_true, y_pred))


# ---------------------------------------------------------------------------
# Wilson score confidence intervals
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WilsonInterval:
    point: float
    low: float
    high: float
    n: int


def wilson_interval(successes: int, n: int, confidence: float = 0.95) -> WilsonInterval:
    """Wilson score interval for a binomial proportion.

    Used instead of the normal/Wald approximation everywhere in this project
    (Verdict item on CIs): Wald is documented unstable at small n and near
    proportions of 0 or 1, both of which occur in per-EventID / per-technique
    breakdowns. Formula (Wilson 1927, the standard textbook form):

        center = (p_hat + z^2/(2n)) / (1 + z^2/n)
        half_width = z/(1+z^2/n) * sqrt(p_hat(1-p_hat)/n + z^2/(4n^2))
        interval = center +/- half_width

    z is the two-sided normal critical value for `confidence` (1.959964 for
    95%). Raises on n=0 rather than returning a degenerate/undefined
    interval silently.
    """
    if n <= 0:
        raise ValueError("wilson_interval requires n > 0")
    if not (0 <= successes <= n):
        raise ValueError(f"successes={successes} must be in [0, n={n}]")

    z = _normal_two_sided_critical_value(confidence)
    p_hat = successes / n
    z2 = z * z

    denom = 1 + z2 / n
    center = (p_hat + z2 / (2 * n)) / denom
    half_width = (z / denom) * math.sqrt(p_hat * (1 - p_hat) / n + z2 / (4 * n * n))

    low = max(0.0, center - half_width)
    high = min(1.0, center + half_width)
    return WilsonInterval(point=p_hat, low=low, high=high, n=n)


def _normal_two_sided_critical_value(confidence: float) -> float:
    """Two-sided normal critical value z for a given confidence level.

    Uses scipy's inverse-CDF rather than a hardcoded table so any confidence
    level works, not just 95% — but 95% (z=1.959963985...) is what every
    call site in this project actually uses, matching the design brief's
    "95% CI" specification throughout.
    """
    from scipy.stats import norm

    alpha = 1 - confidence
    return float(norm.ppf(1 - alpha / 2))


# ---------------------------------------------------------------------------
# Threshold-free ranking metrics: PR-AUC (primary) and ROC-AUC (secondary)
# ---------------------------------------------------------------------------


def pr_auc(y_true: list[bool], y_score: list[float]) -> float | None:
    """Average precision (PR-AUC), positive == malicious.

    Primary threshold-independent metric per Verdict #3/#4 — sensitive to
    false positives under imbalance in a way ROC's huge-negative-denominator
    is not (Davis & Goadrich, ICML 2006). Requires a continuous score per
    record (e.g. P(malicious) from the classical-ML baseline, or a
    verdict-derived score for the LLM/rules baselines — see baselines.py for
    how each baseline exposes one).
    """
    if len(set(y_true)) < 2:
        # Single-class slice: average_precision_score returns 0.0 here, which
        # reads as "terrible performance" when the truth is "undefined". That
        # is exactly the silent-coercion this module refuses elsewhere (see
        # mcc()). Plausible on small per-EventID/per-technique strata, so it
        # must be None rather than a number a reader could quote.
        return None
    return float(average_precision_score(np.asarray(y_true, dtype=int), np.asarray(y_score, dtype=float)))


def roc_auc(y_true: list[bool], y_score: list[float]) -> float | None:
    """ROC-AUC, positive == malicious.

    Reported as a SECONDARY number, always alongside PR-AUC on the same
    slice (Verdict #4) — never as a standalone headline. Davis & Goadrich
    2006 is the cited formal source for why PR is the more informative of
    the two under class imbalance; this project does not attribute that
    specific head-to-head claim to scikit-learn's own docs (neither Phase 0
    nor this brief found that exact sentence there).
    """
    if len(set(y_true)) < 2:
        # roc_auc_score returns NaN here (with an UndefinedMetricWarning). NaN
        # propagates silently through arithmetic and renders as "nan" in a
        # report, so return an explicit None instead — same reasoning as
        # pr_auc above.
        return None
    return float(roc_auc_score(np.asarray(y_true, dtype=int), np.asarray(y_score, dtype=float)))


# ---------------------------------------------------------------------------
# Expected Calibration Error (ECE) on the model's self-reported confidence
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CalibrationBin:
    low: float
    high: float
    n: int
    avg_confidence: float | None
    accuracy: float | None


@dataclass(frozen=True)
class ECEResult:
    ece: float
    bins: list[CalibrationBin]


def expected_calibration_error(
    confidences: list[float], correct: list[bool], n_bins: int = 10
) -> ECEResult:
    """Expected Calibration Error over equal-width confidence bins.

    ECE = sum_b (n_b / N) * |accuracy(b) - avg_confidence(b)|

    Standard binned-ECE definition (Guo et al. 2017; used here per Tian et
    al. EMNLP 2023's finding that verbalized LLM confidence is only "often",
    not reliably, calibrated — Verdict #9). `confidences` is the model's
    self-reported `TriageVerdict.confidence` field; `correct` is whether
    that record's (collapsed) verdict matched ground truth. Empty bins
    contribute zero to the ECE sum (per Guo et al.'s own definition) and are
    still returned in `bins` with `avg_confidence=None`/`accuracy=None` so a
    reliability diagram can show the gap honestly rather than omitting it.
    """
    if len(confidences) != len(correct):
        raise ValueError("confidences and correct must be the same length")
    if not confidences:
        raise ValueError("cannot compute ECE over zero records")
    if n_bins < 1:
        raise ValueError("n_bins must be >= 1")

    edges = [i / n_bins for i in range(n_bins + 1)]
    bins: list[CalibrationBin] = []
    ece = 0.0
    n_total = len(confidences)

    for i in range(n_bins):
        low, high = edges[i], edges[i + 1]
        is_last = i == n_bins - 1
        idx = [
            j
            for j, c in enumerate(confidences)
            if (low <= c < high) or (is_last and c == high)
        ]
        if not idx:
            bins.append(CalibrationBin(low=low, high=high, n=0, avg_confidence=None, accuracy=None))
            continue
        bin_conf = [confidences[j] for j in idx]
        bin_correct = [correct[j] for j in idx]
        avg_conf = sum(bin_conf) / len(bin_conf)
        acc = sum(bin_correct) / len(bin_correct)
        bins.append(CalibrationBin(low=low, high=high, n=len(idx), avg_confidence=avg_conf, accuracy=acc))
        ece += (len(idx) / n_total) * abs(acc - avg_conf)

    return ECEResult(ece=ece, bins=bins)


# ---------------------------------------------------------------------------
# Selective prediction (the `suspicious`-as-abstention framing, Verdict #2)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SelectivePredictionResult:
    coverage: float
    selective_accuracy: float | None
    n_committed: int
    n_abstained: int
    n_total: int
    risk_coverage_curve: list[tuple[float, float]] = field(default_factory=list)
    aurc: float | None = None


def selective_prediction_metrics(
    committed: list[bool],
    correct: list[bool],
    confidences: list[float] | None = None,
) -> SelectivePredictionResult:
    """Coverage, selective accuracy, risk-coverage curve, and AURC.

    `committed[i]` is True iff the classifier did NOT abstain (verdict !=
    suspicious) on record i; `correct[i]` is only meaningful for committed
    records (whether the committed verdict matched ground truth) — pass any
    boolean for abstained records, it is ignored. Implements Geifman &
    El-Yaniv 2017's selective classification apparatus, the framing the
    design brief recommends as primary for `suspicious` (Verdict #2).

    If `confidences` is provided (the model's self-reported confidence on
    committed predictions), a full risk-coverage curve is computed by
    sorting committed predictions from most- to least-confident and sweeping
    the operating threshold, per the NeurIPS 2024 follow-up's warning against
    reporting a single coverage/accuracy point as if it were the whole story
    (Verdict #2 citation). AURC (area under the risk-coverage curve, lower is
    better) is its scalar summary. Without `confidences`, only the single
    coverage/selective-accuracy operating point is returned (curve/AURC left
    empty/None) — still a valid partial report, per the design brief's
    "report negative/thin findings, don't silently omit" principle.
    """
    n_total = len(committed)
    if n_total == 0:
        raise ValueError("cannot compute selective-prediction metrics over zero records")
    if len(correct) != n_total:
        raise ValueError("committed and correct must be the same length")

    n_committed = sum(committed)
    n_abstained = n_total - n_committed
    coverage = n_committed / n_total
    if n_committed == 0:
        selective_acc = None
    else:
        selective_acc = sum(c for c, comm in zip(correct, committed) if comm) / n_committed

    curve: list[tuple[float, float]] = []
    aurc = None
    if confidences is not None:
        if len(confidences) != n_total:
            raise ValueError("confidences must be the same length as committed/correct")
        committed_items = [
            (confidences[i], correct[i]) for i in range(n_total) if committed[i]
        ]
        if committed_items:
            # Most-confident first: the classifier commits on its most
            # confident predictions first as coverage is swept down from 1.0.
            committed_items.sort(key=lambda item: item[0], reverse=True)
            n_c = len(committed_items)
            cum_correct = 0
            for k, (_, is_correct) in enumerate(committed_items, start=1):
                cum_correct += int(is_correct)
                cov = k / n_c
                risk = 1 - (cum_correct / k)
                curve.append((cov, risk))
            # AURC: area under risk(coverage) via the trapezoid rule over the
            # observed (coverage, risk) points, integrated from coverage->0
            # up to the full committed-subset coverage. Standard scalar
            # summary of the risk-coverage curve (Geifman & El-Yaniv 2017;
            # El-Yaniv & Wiener 2010 for the original AURC definition).
            xs = [0.0] + [c for c, _ in curve]
            ys = [curve[0][1]] + [r for _, r in curve]
            aurc = float(np.trapezoid(ys, xs))

    return SelectivePredictionResult(
        coverage=coverage,
        selective_accuracy=selective_acc,
        n_committed=n_committed,
        n_abstained=n_abstained,
        n_total=n_total,
        risk_coverage_curve=curve,
        aurc=aurc,
    )


# ---------------------------------------------------------------------------
# Precision/recall/F1 macro + weighted averages (per-class already covered
# by the ConfusionCounts helpers above for the binary case; this section is
# for the raw 3-class verdict distribution against binary truth is handled
# by the policy-collapse layer in harness.py, not here)
# ---------------------------------------------------------------------------


def metric_set(y_true: list[bool], y_pred: list[bool]) -> dict[str, float | None]:
    """Convenience bundle of every threshold-based scalar metric for one
    (y_true, y_pred) pair, keyed by name. Does not include PR-AUC/ROC-AUC
    (those need scores, not hard predictions) or CIs (need Wilson-interval
    call sites to know which count is the numerator) — callers needing those
    call `pr_auc`/`roc_auc`/`wilson_interval` directly.
    """
    c = confusion_counts(y_true, y_pred)
    return {
        "n": c.n,
        "tp": c.tp,
        "fp": c.fp,
        "fn": c.fn,
        "tn": c.tn,
        "accuracy": accuracy(c),
        "balanced_accuracy": balanced_accuracy(c),
        "mcc": mcc(c),
        "precision": precision(c),
        "recall": recall(c),
        "f1": f1(c),
        "fpr": false_positive_rate(c),
        "fnr": false_negative_rate(c),
        "specificity": specificity(c),
    }
