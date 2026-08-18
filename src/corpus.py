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
   pseudonymization) — applied to EVERY record regardless of source, per the
   "asymmetric treatment is itself a leak" requirement. See leakage.py's
   module docstring for why this can't live inside either normalizer.

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

from src.ingest.leakage import pseudonymize_record_hostname
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
    """
    if not malicious_records:
        raise ValueError("no malicious records to assemble a corpus from")
    if not benign_records:
        raise ValueError("no benign records to assemble a corpus from")

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
        chosen_malicious = rng.sample(malicious_records, target_malicious_count)
        chosen_benign = list(benign_records)

    combined = chosen_malicious + chosen_benign
    if pseudonymize_hosts:
        combined = [pseudonymize_record_hostname(r) for r in combined]
    rng.shuffle(combined)
    return combined


def corpus_composition(records: list[AlertRecord]) -> dict[str, int]:
    """Report per-source, per-label counts — the numbers any FPR claim must
    be reported alongside, per the task's "report corpus composition"
    requirement."""
    composition: dict[str, int] = {}
    for record in records:
        key = f"{record.source_dataset}:{'malicious' if record.is_malicious else 'benign'}"
        composition[key] = composition.get(key, 0) + 1
    return composition
