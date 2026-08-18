"""Assemble the combined malicious + benign corpus used for evaluation.

This is the one place OTRF's malicious records and evtx-baseline's benign
records are actually mixed together — everything upstream (normalize.py,
normalize_benign.py) only ever knows about one source at a time. Two things
happen here that deliberately do NOT happen in either per-source normalizer:

1. **Ratio control** (subsample the majority class to a stated ratio) —
   because building at OTRF's raw malicious count (202,845) against however
   many benign events evtx-baseline happens to yield would be an arbitrary
   accident of corpus sizes, not a deliberate evaluation design choice.
2. **Corpus-wide leakage mitigation** (src/ingest/leakage.py's hostname
   pseudonymization, timestamp neutralization, and shared-support
   restriction) — applied to EVERY record regardless of source, per the
   "asymmetric treatment is itself a leak" requirement. See leakage.py's
   module docstring for why this can't live inside either normalizer.

Phase 1b (research/phase-1b-shortcut-mitigation.md) added three more
mitigations, all wired in here behind `mitigate_shortcuts` (default `True`):
absolute-timestamp neutralization, raw_event field-set ablation to the
cross-source intersection, and restriction to shared EventIDs with a capped
per-EventID class ratio. `mitigate_shortcuts=False` reproduces the
pre-mitigation, shortcut-leaking corpus on purpose — see
`tests/test_shortcut_audit.py` for the audit this exists to satisfy, and
keep this parameter reachable rather than deleting the leaking path outright:
being able to show the before/after is itself part of this project's
evidence.

Class ratio — chosen and justified here, not assumed:
Real SOC alert queues run around 99:1 benign:malicious (Alahmadi et al.,
USENIX Security 2022, cited in the Phase 1 research brief) — but building
this project's eval corpus at that exact ratio would need ~20 million benign
events to match OTRF's 202,845 malicious events, which is not realistic to
source (evtx-baseline's win2022-evtx capture alone yields ~110K), and the
Phase 1 research brief's own citation (Saito & Rehmsmeier, PLOS ONE 2015)
flags extreme imbalance as making precision/recall estimates noisy at small
absolute counts — the realistic base rate and a *statistically stable eval
corpus* are two different design goals, and this project explicitly picks
the latter over blindly mirroring the former. DEFAULT_BENIGN_RATIO = 4.0
(4 benign : 1 malicious) is chosen as a value that is (a) still meaningfully
imbalanced toward benign, matching the qualitative direction of real SOC
data without claiming to reproduce its exact magnitude, and (b) large enough
relative to a few thousand malicious events that neither class becomes a
statistically thin sliver. This is a stated DESIGN CHOICE, not a
literature-mandated number (the brief is explicit that no single ratio in
the 90:10-99:1 range is independently mandated) — callers who want to study
sensitivity to this choice should vary `benign_ratio` and re-run, not treat
4.0 as load-bearing truth.
"""

from __future__ import annotations

import random
from collections import defaultdict

from src.ingest.leakage import (
    DEFAULT_MAX_CLASS_RATIO,
    neutralize_timestamps,
    pseudonymize_record_hostname,
    restrict_to_shared_support,
)
from src.schema import AlertRecord

DEFAULT_BENIGN_RATIO = 4.0

# Fixed, not read from system entropy, so "which benign events got kept when
# the benign pool is larger than the target ratio needs" is reproducible
# across runs — required for stable test fixtures and for anyone re-running
# this project's own eval to get the same corpus this project reported on.
DEFAULT_RANDOM_SEED = 20260818


def assemble_corpus(
    malicious_records: list[AlertRecord],
    benign_records: list[AlertRecord],
    benign_ratio: float = DEFAULT_BENIGN_RATIO,
    seed: int = DEFAULT_RANDOM_SEED,
    pseudonymize_hosts: bool = True,
    mitigate_shortcuts: bool = True,
    max_class_ratio: float = DEFAULT_MAX_CLASS_RATIO,
) -> list[AlertRecord]:
    """Combine malicious + benign records at a stated benign:malicious ratio.

    Subsamples whichever side is oversupplied relative to the target ratio
    (deterministically, via `seed`) rather than truncating by taking the
    first N records — a truncation-by-order sample would silently bias
    toward whatever capture happened to be normalized first, which is a
    subtler version of the same "accidental corpus composition" problem the
    ratio control exists to avoid in the first place.

    Raises rather than silently building a smaller-than-requested corpus if
    one side has too few records to hit the target ratio — a corpus that
    quietly shipped at a different ratio than the one reported alongside it
    would itself be a small credibility leak.

    `mitigate_shortcuts` (default `True`) applies, in order, BEFORE ratio
    control: `leakage.restrict_to_shared_support` (EventID + raw_event field
    ablation, with a per-EventID class-ratio cap) and
    `leakage.neutralize_timestamps` (rebase to a shared epoch). Applied
    before ratio control rather than after so the requested `benign_ratio`
    describes the FINAL, shortcut-mitigated corpus a caller actually gets,
    not an intermediate one that support restriction then perturbs further.
    Set `mitigate_shortcuts=False` to reproduce the pre-Phase-1b, leak-bearing
    corpus on purpose (see tests/test_shortcut_audit.py and
    research/phase-1b-shortcut-mitigation.md) — this parameter is what keeps
    the before/after comparison reachable rather than deleting the leaking
    path outright.
    """
    if not malicious_records:
        raise ValueError("no malicious records to assemble a corpus from")
    if not benign_records:
        raise ValueError("no benign records to assemble a corpus from")

    if mitigate_shortcuts:
        malicious_records, benign_records = restrict_to_shared_support(
            malicious_records, benign_records, max_class_ratio=max_class_ratio, seed=seed
        )
        if not malicious_records:
            raise ValueError(
                "shortcut mitigation left zero malicious records -- no EventID is shared "
                "between the two inputs, so there is no shortcut-free corpus to assemble"
            )
        if not benign_records:
            raise ValueError(
                "shortcut mitigation left zero benign records -- no EventID is shared "
                "between the two inputs, so there is no shortcut-free corpus to assemble"
            )
        malicious_records = neutralize_timestamps(malicious_records)
        benign_records = neutralize_timestamps(benign_records)

    rng = random.Random(seed)

    target_benign_count = round(len(malicious_records) * benign_ratio)
    if target_benign_count <= len(benign_records):
        chosen_malicious = list(malicious_records)
        chosen_benign = rng.sample(benign_records, target_benign_count)
    else:
        # Not enough benign records to hit the ratio at full malicious
        # volume — shrink the malicious side instead of silently shipping a
        # weaker ratio than requested, so `benign_ratio` is always an exact
        # contract, not a best-effort approximation.
        target_malicious_count = round(len(benign_records) / benign_ratio)
        if target_malicious_count < 1:
            raise ValueError(
                f"benign_ratio={benign_ratio} with only {len(benign_records)} benign records "
                "leaves zero malicious records — lower the ratio or supply more benign records"
            )
        chosen_malicious = _stratified_sample_by_event_id(
            malicious_records, target_malicious_count, rng
        )
        chosen_benign = list(benign_records)

    combined = chosen_malicious + chosen_benign
    if pseudonymize_hosts:
        combined = [pseudonymize_record_hostname(r) for r in combined]
    rng.shuffle(combined)
    return combined


def _stratified_sample_by_event_id(
    records: list[AlertRecord], target_count: int, rng: random.Random
) -> list[AlertRecord]:
    """Subsample `records` to `target_count`, preserving RARE EventIDs.

    A uniform `rng.sample` over the whole pool draws each EventID in
    proportion to its share, which quietly destroys exactly the event types
    this corpus most needs. Measured: after adding the APT29 captures
    specifically to improve process-creation coverage, 1,178 EventID-1
    records survived shortcut mitigation -- and uniform ratio-control
    sampling cut them to 206, because EventID 1 is only ~0.72% of the
    malicious pool. The corpus was doing the right thing at every step and
    still threw away most of the signal it had just been given.

    This allocates the budget EVENLY across EventIDs instead, capped by what
    each bucket actually holds, then redistributes any leftover budget to
    buckets that still have records. Common EventIDs (registry writes) are
    plentiful and lose only what they can spare; rare-but-rich ones
    (process creation) are retained in full until the budget forces
    otherwise.

    Deliberately NOT weighted toward malicious-looking event types: the
    allocation looks only at EventID, never at `is_malicious` or
    `attack_technique`. Preferentially keeping event types that happen to
    correlate with the label would be a sampling-induced shortcut of exactly
    the kind `tests/test_shortcut_audit.py` exists to catch.
    """
    if target_count >= len(records):
        return list(records)

    by_event_id: dict[object, list[AlertRecord]] = defaultdict(list)
    for record in records:
        by_event_id[record.raw_event.get("EventID")].append(record)

    allocation: dict[object, int] = dict.fromkeys(by_event_id, 0)
    remaining = target_count
    # Buckets are filled smallest-first so the scarcest EventIDs are made
    # whole before the abundant ones consume the budget.
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


def corpus_composition(records: list[AlertRecord]) -> dict[str, int]:
    """Report per-source, per-label counts — the numbers any FPR claim must
    be reported alongside, per the task's "report corpus composition"
    requirement."""
    composition: dict[str, int] = {}
    for record in records:
        key = f"{record.source_dataset}:{'malicious' if record.is_malicious else 'benign'}"
        composition[key] = composition.get(key, 0) + 1
    return composition
