"""Paired-classifier significance testing: McNemar's test + bootstrap CI.

Per research/phase-3-evaluation-design.md Verdict item 8 / Section 4:
McNemar's test is the standard paired-comparison apparatus (Dietterich 1998)
for two classifiers scored on the SAME items, since it operates on the
discordant-pair 2x2 table. Use the exact binomial form when discordant pairs
are few (commonly cited rule of thumb: n<25) and chi-squared with continuity
correction above that. Supplement (never replace) with a bootstrap CI on the
metric difference itself, which answers "how much better", a question
McNemar's significance verdict does not.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from scipy.stats import binomtest, chi2

# Rule of thumb cited in the design brief for switching to the exact/mid-p
# form: discordant-pair count below this uses the exact binomial test.
EXACT_TEST_DISCORDANT_THRESHOLD = 25


@dataclass(frozen=True)
class McNemarResult:
    """Result of McNemar's test on one paired discordant-pair table.

    `b` = count where system A was correct and B was wrong; `c` = count
    where B was correct and A was wrong (the two discordant cells). Only
    discordant pairs carry information for this test — concordant pairs
    (both right or both wrong) are irrelevant to whether the two systems
    disagree asymmetrically.
    """

    b: int
    c: int
    n_discordant: int
    statistic: float | None
    p_value: float
    method: str  # "exact_binomial" or "chi_squared_continuity_corrected"


def mcnemar_test(
    a_correct: list[bool], b_correct: list[bool], exact_threshold: int = EXACT_TEST_DISCORDANT_THRESHOLD
) -> McNemarResult:
    """McNemar's test comparing two classifiers scored on the SAME items.

    `a_correct[i]`/`b_correct[i]` are whether classifier A/B was correct on
    item i (paired by index — both lists must describe the identical item
    order). Automatically selects the exact binomial form when the
    discordant-pair count is below `exact_threshold` (design brief's cited
    rule of thumb, default 25) and the standard chi-squared-with-continuity-
    correction form otherwise.

    Exact form: two-sided binomial test of `b` successes out of `b+c` trials
    under the null p=0.5 (Fisher's exact framing of McNemar, sometimes called
    "mid-p McNemar" when using the mid-p correction; this implementation uses
    scipy's `binomtest`, which reports the standard two-sided exact p-value —
    the more conservative and more commonly reported of the two small-sample
    variants, and an acceptable choice per the design brief's "exact/mid-p
    variant" phrasing, which treats the two as interchangeable at this
    threshold).

    Chi-squared form (n_discordant >= exact_threshold):
        statistic = (|b - c| - 1)^2 / (b + c)
    with 1 degree of freedom, the classic continuity-corrected McNemar
    statistic (Edwards 1948 correction, the version in standard use since
    Dietterich 1998's own citation of it).

    If b + c == 0 (the two classifiers agree on every single item), returns
    p_value=1.0 and statistic=None — there is no discordance to test, which
    is a valid outcome, not an error.
    """
    if len(a_correct) != len(b_correct):
        raise ValueError("a_correct and b_correct must be the same length (paired items)")
    if not a_correct:
        raise ValueError("cannot run McNemar's test on zero paired items")

    b = sum(1 for a, bb in zip(a_correct, b_correct) if a and not bb)
    c = sum(1 for a, bb in zip(a_correct, b_correct) if not a and bb)
    n_discordant = b + c

    if n_discordant == 0:
        return McNemarResult(b=b, c=c, n_discordant=0, statistic=None, p_value=1.0, method="exact_binomial")

    if n_discordant < exact_threshold:
        result = binomtest(b, n_discordant, p=0.5, alternative="two-sided")
        return McNemarResult(
            b=b, c=c, n_discordant=n_discordant, statistic=None, p_value=float(result.pvalue), method="exact_binomial"
        )

    statistic = (abs(b - c) - 1) ** 2 / n_discordant
    p_value = float(chi2.sf(statistic, df=1))
    return McNemarResult(
        b=b, c=c, n_discordant=n_discordant, statistic=statistic, p_value=p_value, method="chi_squared_continuity_corrected"
    )


@dataclass(frozen=True)
class BootstrapCIResult:
    point_estimate: float
    low: float
    high: float
    n_resamples: int
    confidence: float


def paired_bootstrap_ci(
    values_a: list[float],
    values_b: list[float],
    metric_fn,
    n_resamples: int = 10_000,
    confidence: float = 0.95,
    seed: int = 20260818,
) -> BootstrapCIResult:
    """Bootstrap CI on a paired metric difference (system A - system B).

    Supplements McNemar's significance verdict with an effect-size estimate,
    per the design brief's "McNemar (verdict) + bootstrap CI (effect size)"
    guidance. `values_a`/`values_b` are PER-ITEM values in the same paired
    order (e.g. per-item 0/1 correctness, or any other per-item scalar the
    metric is computed from); `metric_fn(values)` reduces a list of per-item
    values to the scalar metric (e.g. `lambda xs: sum(xs) / len(xs)` for
    accuracy). Resamples item INDICES with replacement (the standard paired
    bootstrap: the same resampled index set is applied to both A and B so
    pairing is preserved across the resample, not broken by independently
    resampling each side) and returns the empirical difference's point
    estimate plus a percentile CI.
    """
    if len(values_a) != len(values_b):
        raise ValueError("values_a and values_b must be the same length (paired items)")
    if not values_a:
        raise ValueError("cannot bootstrap over zero paired items")
    if n_resamples < 1:
        raise ValueError("n_resamples must be >= 1")

    n = len(values_a)
    rng = random.Random(seed)

    point_estimate = metric_fn(values_a) - metric_fn(values_b)

    diffs: list[float] = []
    for _ in range(n_resamples):
        idx = [rng.randrange(n) for _ in range(n)]
        resampled_a = [values_a[i] for i in idx]
        resampled_b = [values_b[i] for i in idx]
        diffs.append(metric_fn(resampled_a) - metric_fn(resampled_b))

    diffs.sort()
    alpha = 1 - confidence
    low_idx = max(0, int((alpha / 2) * n_resamples))
    high_idx = min(n_resamples - 1, int((1 - alpha / 2) * n_resamples) - 1)
    low = diffs[low_idx]
    high = diffs[high_idx]

    return BootstrapCIResult(
        point_estimate=point_estimate, low=low, high=high, n_resamples=n_resamples, confidence=confidence
    )
