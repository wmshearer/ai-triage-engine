"""Stratified evaluation-set sampling with a malicious-class floor.

Per research/phase-3-evaluation-design.md's "Sample size" section: a
proportional random sample at the corpus's 20% malicious rate would need
~1,925 total records to hit the 385-malicious floor for a +/-5pp 95% CI on
malicious-class recall. Stratified sampling (deliberately oversample the
malicious class, consistent with `src/corpus.py`'s own precedent of
stratified-by-EventID sampling) hits that floor far more efficiently.

This module stratifies on TWO axes at once, both cheap and already present
on every `AlertRecord` without new feature engineering:
  1. `is_malicious` (the floor constraint itself), and
  2. `raw_event["EventID"]` within each label (mirrors `corpus.py`'s own
     `_stratified_sample_by_event_id`, so rare-but-rich EventIDs like
     EventID 1 are not swamped by registry-write volume in the eval sample
     either — the same allocation logic the corpus-assembly step already
     established as this project's precedent for exactly this problem).

Deterministic given a seed: same seed + same input corpus -> byte-identical
sample, required so a reported eval run is reproducible from its seed alone.
"""

from __future__ import annotations

import random
from collections import defaultdict
from dataclasses import dataclass

from src.schema import AlertRecord

# Floor from the design brief's binomial sample-size formula (n = z^2 *
# p(1-p) / E^2, z=1.96, p=0.5 worst case) for a +/-5pp 95% CI on
# malicious-class recall. This is a floor on malicious-class n specifically
# (recall's denominator), not a floor on total n.
MALICIOUS_FLOOR_FOR_5PP_CI = 385

# Default eval-run size per the design brief: proportional to the floor at
# the corpus's ~20% malicious rate (385 / 0.20 ~= 1,925), the size the brief
# recommends as "feasible within a single run" at measured sequential LLM
# latency (~1.3-2.2h at 2.5-4.2s/call).
DEFAULT_SAMPLE_SIZE = 1925

# Fraction of `DEFAULT_SAMPLE_SIZE` deliberately allocated to the malicious
# class, oversampling relative to the corpus's own ~20% base rate so the
# 385-malicious floor is hit without inflating the benign side past what its
# own (already-easier, 4x larger at the same ratio) CI needs. Chosen so that
# at DEFAULT_SAMPLE_SIZE, exactly MALICIOUS_FLOOR_FOR_5PP_CI malicious
# records are targeted: 385 / 1925 = 0.2 -- i.e. this mirrors the corpus's
# natural ratio at the default size, but stratified sampling still matters
# because within-EventID rarity (e.g. EventID 1) would otherwise be diluted
# away by a uniform draw, exactly as `corpus.py`'s own docstring measured.
DEFAULT_MALICIOUS_FRACTION = MALICIOUS_FLOOR_FOR_5PP_CI / DEFAULT_SAMPLE_SIZE


@dataclass(frozen=True)
class SampleSizeReport:
    """What was actually achieved vs. what was targeted, for honest disclosure.

    Per the design brief's per-EventID-1 warning: the 385-malicious floor may
    not be reachable in every stratum. Callers (report.py) must show the
    ACHIEVED count and its resulting CI margin, never silently assume the
    target was met.
    """

    target_total: int
    target_malicious: int
    achieved_total: int
    achieved_malicious: int
    achieved_benign: int
    floor_met: bool


def stratified_eval_sample(
    records: list[AlertRecord],
    sample_size: int = DEFAULT_SAMPLE_SIZE,
    malicious_fraction: float = DEFAULT_MALICIOUS_FRACTION,
    seed: int = 20260818,
) -> tuple[list[AlertRecord], SampleSizeReport]:
    """Draw a deterministic, EventID-stratified evaluation sample.

    Allocates `sample_size * malicious_fraction` (rounded) to the malicious
    class and the remainder to benign, then within EACH label independently
    applies the same "fill rare EventIDs first" allocation `corpus.py`'s
    `_stratified_sample_by_event_id` uses — reimplemented here (not imported)
    because `corpus.py` is explicitly out of scope for this task ("Do NOT
    modify... src/corpus.py"); duplicating a small, stable algorithm is
    preferable to importing a private underscored helper from a module this
    task must not touch.

    If either label's pool is smaller than its target allocation, takes the
    whole pool for that label (never raises) and reports the shortfall via
    the returned `SampleSizeReport` — silently shipping a smaller-than-
    requested malicious count without saying so would be exactly the kind of
    "falsely precise" CI the design brief warns against.
    """
    if sample_size <= 0:
        raise ValueError("sample_size must be positive")
    if not (0.0 < malicious_fraction < 1.0):
        raise ValueError("malicious_fraction must be in (0, 1)")
    if not records:
        raise ValueError("cannot sample from an empty record list")

    rng = random.Random(seed)

    malicious_pool = [r for r in records if r.is_malicious]
    benign_pool = [r for r in records if not r.is_malicious]

    target_malicious = round(sample_size * malicious_fraction)
    target_benign = sample_size - target_malicious

    chosen_malicious = _stratified_sample_by_event_id(malicious_pool, target_malicious, rng)
    chosen_benign = _stratified_sample_by_event_id(benign_pool, target_benign, rng)

    combined = chosen_malicious + chosen_benign
    rng.shuffle(combined)

    report = SampleSizeReport(
        target_total=sample_size,
        target_malicious=target_malicious,
        achieved_total=len(combined),
        achieved_malicious=len(chosen_malicious),
        achieved_benign=len(chosen_benign),
        floor_met=len(chosen_malicious) >= MALICIOUS_FLOOR_FOR_5PP_CI,
    )
    return combined, report


def _stratified_sample_by_event_id(
    records: list[AlertRecord], target_count: int, rng: random.Random
) -> list[AlertRecord]:
    """Subsample `records` to `target_count`, preserving rare EventIDs.

    Same allocation strategy as `src.corpus._stratified_sample_by_event_id`
    (fill scarce buckets first, redistribute leftover budget to buckets that
    still have room) — deliberately reimplemented rather than imported, see
    this module's docstring. Returns the whole list unchanged if
    `target_count >= len(records)`, and clamps a negative/zero target to an
    empty list rather than raising, since a caller may legitimately request
    zero of one label (e.g. baselines-only smoke tests).
    """
    if target_count <= 0:
        return []
    if target_count >= len(records):
        return list(records)

    by_event_id: dict[object, list[AlertRecord]] = defaultdict(list)
    for record in records:
        by_event_id[record.raw_event.get("EventID")].append(record)

    allocation: dict[object, int] = dict.fromkeys(by_event_id, 0)
    remaining = target_count
    open_buckets = sorted(by_event_id, key=lambda eid: len(by_event_id[eid]))

    while remaining > 0 and open_buckets:
        fair_share = max(1, remaining // len(open_buckets))
        for event_id in list(open_buckets):
            if remaining <= 0:
                break
            capacity = len(by_event_id[event_id]) - allocation[event_id]
            take = min(fair_share, capacity, remaining)
            allocation[event_id] += take
            remaining -= take
            if allocation[event_id] >= len(by_event_id[event_id]):
                open_buckets.remove(event_id)

    sampled: list[AlertRecord] = []
    for event_id, count in allocation.items():
        if count:
            sampled.extend(rng.sample(by_event_id[event_id], count))
    return sampled
