"""Adversarial shortcut audit: can a DUMB classifier separate the classes?

This test exists because `test_field_parity.py` — which is careful, correct,
and passing — answers the wrong question. It asks "is every field-name
mismatch between the two sources explainable?" and the answer is yes, each
one is a documented NXLog/Winlogbeat shipper artifact.

But a feature can be perfectly explainable AND a perfect shortcut. Schema
parity says nothing about DISTRIBUTIONS. Measured on the real corpus
(~40,569 malicious / ~107,459 benign) on 2026-08-18:

    timestamp year : malicious 100% 2020, benign 100% 2022
                     -> a year-only classifier scores accuracy 1.0000
    raw field count: malicious 35-46, benign 21-28
                     -> and the gap PERSISTS INSIDE every shared Sysmon
                        EventID (EID 13: 39 vs 24; EID 10: 43 vs 28;
                        EID 1: 53 vs 38), so restricting to shared event
                        types does not fix it by itself
    EventID        : 4658/4656/5447 appear ONLY on the malicious side

The root cause is that the two classes differ by COLLECTION STACK, not by
behavior: OTRF ships through an NXLog enricher, evtx-baseline is raw .evtx.
Any precision/recall/F1 computed over such a corpus measures "which parser
produced this record."

This is "shortcut learning" / "Clever Hans" in the ML literature. The
mitigation strategy is tracked in research/phase-1b-shortcut-mitigation.md.

WHY THIS IS A PERMANENT TEST AND NOT A ONE-OFF SCRIPT: every new data source
re-opens the question. The audit must run in CI so a future source cannot
silently reintroduce a shortcut. The generalizable rule: don't assert that
schemas match — BUILD THE DUMB CLASSIFIER AND MEASURE IT.

Each test below is written to FAIL while the corresponding leak is present.
They are the acceptance criteria for the Phase 1b fix, so they are expected
to fail until that mitigation lands. That is deliberate: a red test that
names the defect is worth more than a green one that dodges it.
"""

from __future__ import annotations

import pytest

from src.schema import AlertRecord

# Accuracy of a single-feature classifier above which we call a feature a
# shortcut. 0.65 is deliberately far below the measured 1.0000 so the test
# targets "trivially predictive", not "carries some signal" -- real security
# features SHOULD carry signal, and this must not punish that.
SHORTCUT_ACCURACY_THRESHOLD = 0.65


def single_feature_accuracy(
    records: list[AlertRecord],
    feature_fn,
) -> float:
    """Accuracy of the best possible classifier that sees ONE feature.

    For each observed feature value, this predicts whichever label is in the
    majority for that value -- the theoretical ceiling for that feature
    alone. If this scores high, the feature leaks the label on its own and
    no model needs to reason about behavior to exploit it.

    Uses majority-vote-per-value rather than fitting an actual model so the
    result is exact and deterministic, with no training-time randomness to
    make the audit flaky.
    """
    if not records:
        raise ValueError("cannot audit an empty record set")

    buckets: dict[object, list[int]] = {}
    for record in records:
        key = feature_fn(record)
        buckets.setdefault(key, [0, 0])[int(record.is_malicious)] += 1

    correct = sum(max(benign_n, malicious_n) for benign_n, malicious_n in buckets.values())
    return correct / len(records)


def assert_not_a_shortcut(records: list[AlertRecord], feature_fn, feature_name: str) -> None:
    accuracy = single_feature_accuracy(records, feature_fn)
    assert accuracy < SHORTCUT_ACCURACY_THRESHOLD, (
        f"SHORTCUT DETECTED: '{feature_name}' alone predicts the label with "
        f"accuracy {accuracy:.4f} (threshold {SHORTCUT_ACCURACY_THRESHOLD}). "
        "A model can score well on this corpus without any security reasoning, "
        "so every downstream metric is invalid. Fix the corpus, not this test: "
        "see research/phase-1b-shortcut-mitigation.md."
    )


@pytest.fixture
def mixed_corpus() -> list[AlertRecord]:
    """Both classes, as the eval harness will actually see them.

    Skips rather than fails when the corpora are absent so the suite still
    runs on a machine that has not downloaded ~330MB of telemetry; the audit
    is meaningless without real data and a hand-built fixture would only
    prove the fixture.
    """
    pytest.importorskip("evtx")
    records = _load_real_corpus()
    if not records:
        pytest.skip("real corpora not present on this machine; run the fetch scripts first")
    return records


def _load_real_corpus(limit_per_class: int = 5000) -> list[AlertRecord]:
    """Load both classes and assemble them THROUGH THE PRODUCTION PATH.

    The first version of this helper concatenated the two class lists with
    `+` and never called `assemble_corpus`. That made the audit measure a
    corpus no consumer of this project ever actually receives, so the tests
    stayed red even once the real mitigation was in place and working --
    they were auditing the wrong artifact.

    Routing through `assemble_corpus` is what makes this a real regression
    gate: it audits exactly what ingest hands to the eval harness, so a
    future change that silently disables mitigation turns these tests red.
    Deliberately passes no `mitigate_shortcuts` argument -- the audit must
    exercise the DEFAULT, since a default that leaks is the actual danger.
    """
    import glob

    from src.corpus import assemble_corpus
    from src.ingest.normalize import normalize_capture
    from src.ingest.normalize_benign import normalize_evtx_file

    metadata_paths = sorted(glob.glob("data/raw/otrf/metadata/*.yaml"))
    capture_zips = sorted(glob.glob("data/raw/otrf/captures/*.zip"))
    evtx_paths = sorted(glob.glob("data/raw/evtx_baseline/**/*.evtx", recursive=True))
    if not metadata_paths or not capture_zips or not evtx_paths:
        return []

    malicious: list[AlertRecord] = []
    for metadata_path in metadata_paths:
        if len(malicious) >= limit_per_class:
            break
        try:
            malicious.extend(normalize_capture(metadata_path, capture_zips[:1]))
        except Exception:  # a single unreadable capture must not abort the audit
            continue

    benign: list[AlertRecord] = []
    for evtx_path in evtx_paths:
        if len(benign) >= limit_per_class:
            break
        try:
            benign.extend(normalize_evtx_file(evtx_path, "win2022-evtx", start_index=len(benign)))
        except Exception:
            continue

    if not malicious or not benign:
        return []

    # benign_ratio=1.0 keeps the base rate at 50/50 so a single-feature
    # accuracy is directly comparable against a 0.5 coin-flip floor. At the
    # production 4.0 ratio a do-nothing "always benign" classifier already
    # scores 0.80, which would sit above the threshold and make every
    # result unreadable -- the audit would flag class imbalance rather than
    # the source shortcuts it exists to catch.
    return assemble_corpus(
        malicious[:limit_per_class],
        benign[:limit_per_class],
        benign_ratio=1.0,
    )


def test_timestamp_year_is_not_a_shortcut(mixed_corpus: list[AlertRecord]) -> None:
    """Measured at accuracy 1.0000 on 2026-08-18 -- a perfect classifier.

    OTRF captures were recorded in 2020 and evtx-baseline in 2022. Absolute
    time is an artifact of when each dataset was collected and carries no
    security meaning across sources, so it must not be label-predictive.
    """
    assert_not_a_shortcut(mixed_corpus, lambda r: r.timestamp.year, "timestamp.year")


def test_raw_field_count_is_not_a_shortcut(mixed_corpus: list[AlertRecord]) -> None:
    """The NXLog enrichment tell: malicious records simply carry more fields."""
    assert_not_a_shortcut(mixed_corpus, lambda r: len(r.raw_event), "len(raw_event)")


def test_field_count_is_not_a_shortcut_within_shared_event_ids(
    mixed_corpus: list[AlertRecord],
) -> None:
    """The load-bearing one: restricting to shared EventIDs is NOT enough.

    It would be reasonable to assume the field-count gap is just an artifact
    of the two sources covering different event types, and that filtering to
    the EventIDs both sides share would remove it. Measured, it does not --
    within EventID 13 alone the split is 39 fields vs 24. This test pins
    that down so the cheaper fix is not mistaken for a sufficient one.
    """
    event_ids_by_label: dict[bool, set[object]] = {True: set(), False: set()}
    for record in mixed_corpus:
        event_ids_by_label[record.is_malicious].add(record.raw_event.get("EventID"))
    shared_event_ids = event_ids_by_label[True] & event_ids_by_label[False]
    if not shared_event_ids:
        pytest.skip("no EventIDs shared between classes in this sample")

    shared_records = [r for r in mixed_corpus if r.raw_event.get("EventID") in shared_event_ids]
    assert_not_a_shortcut(
        shared_records,
        lambda r: (r.raw_event.get("EventID"), len(r.raw_event)),
        "(EventID, field count) on the shared-EventID subset",
    )


def test_no_raw_event_value_prefix_is_a_shortcut(mixed_corpus: list[AlertRecord]) -> None:
    """Sweep every key for a leaking VALUE, not just a leaking type.

    Added after a third leak got through both prior rounds: rebasing
    `AlertRecord.timestamp` left the date STRINGS inside `raw_event`
    untouched, and raw_event is what actually gets serialized into a prompt.
    Measured before the fix: raw_event['@timestamp'] and ['EventTime'] each
    predicted the label at accuracy 1.0000, ['UtcTime'] at 0.9748.

    Every earlier test keys on the normalized `record.timestamp` field or on
    a value's type, so none of them could see inside raw_event at all. This
    one audits where the model reads.

    Uses a 4-character prefix rather than the whole value: full values are
    near-unique (paths, GUIDs), which would make every key look perfectly
    predictive and the test useless. A 4-char prefix is enough to catch a
    year ('2020' vs '2022') or a fixed format marker while staying blind to
    per-record uniqueness.

    Scoped to TIMESTAMP keys specifically, and that scope is deliberate.
    An earlier draft swept every key and flagged `Image` at 0.87 alongside
    the real artifacts -- but Image is the executable path, the most
    legitimate triage feature in the corpus, and attacks genuinely do run
    different binaries than an idle baseline VM. A single-feature accuracy
    number cannot distinguish "source artifact" from "real signal"; only
    knowing what the field MEANS can. So this test audits the fields whose
    values are known to carry no security meaning, and the judgment call
    about behavioral fields stays explicit in
    `src/ingest/leakage.py:UNMAPPABLE_KEYS` where it can be read and argued
    with, rather than hidden inside a threshold.
    """
    timestamp_keys = [
        key
        for key in sorted({k for r in mixed_corpus for k in r.raw_event})
        if "time" in key.lower() or key == "@timestamp"
    ]
    if not timestamp_keys:
        pytest.skip("no timestamp-bearing raw_event keys in this corpus")

    offenders: list[tuple[str, float]] = []
    for key in timestamp_keys:
        accuracy = single_feature_accuracy(
            mixed_corpus, lambda r, k=key: str(r.raw_event.get(k))[:4]
        )
        if accuracy >= SHORTCUT_ACCURACY_THRESHOLD:
            offenders.append((key, accuracy))

    assert not offenders, (
        "SHORTCUT DETECTED via raw_event timestamp VALUE: "
        + ", ".join(f"{k}={a:.4f}" for k, a in offenders)
        + f" (threshold {SHORTCUT_ACCURACY_THRESHOLD}). raw_event is what gets "
        "serialized into the model's prompt, so a date leak here is live regardless "
        "of how clean the normalized AlertRecord.timestamp is. Rebase it in "
        "src/ingest/leakage.py:_rebase_raw_event_timestamps -- do not weaken this test."
    )


def test_no_raw_event_value_type_is_a_shortcut(mixed_corpus: list[AlertRecord]) -> None:
    """Sweep EVERY shared key for a value-TYPE tell, not just field count.

    Added after an adversarial audit found what the first four tests missed:
    the two sources serialize the same value differently, so `type(value)`
    alone predicted the label at accuracy 1.0000 -- even within one EventID.

        Keywords: -9223372036854775808 (int) vs '0x8000000000000000' (str)
        Opcode:   'Info' (str)          vs 0 (int)

    The first four tests all key on presence or count. None of them could
    ever have caught a leak carried by representation, which is why this
    sweeps all keys rather than naming the two that were found -- a future
    source will differ on some third field nobody predicted.
    """
    all_keys: set[str] = set()
    for record in mixed_corpus:
        all_keys.update(record.raw_event)

    offenders: list[tuple[str, float]] = []
    for key in sorted(all_keys):
        accuracy = single_feature_accuracy(
            mixed_corpus, lambda r, k=key: type(r.raw_event.get(k)).__name__
        )
        if accuracy >= SHORTCUT_ACCURACY_THRESHOLD:
            offenders.append((key, accuracy))

    assert not offenders, (
        "SHORTCUT DETECTED via raw_event value TYPE: "
        + ", ".join(f"{k}={a:.4f}" for k, a in offenders)
        + f" (threshold {SHORTCUT_ACCURACY_THRESHOLD}). The two sources serialize "
        "the same value differently, so a model can separate the classes without "
        "reading any field's meaning. Normalize the representation in "
        "src/ingest/leakage.py:_canonicalize_value -- do not weaken this test."
    )


def test_event_id_is_not_a_shortcut(mixed_corpus: list[AlertRecord]) -> None:
    """EventIDs 4658/4656/5447 were present only on the malicious side.

    Some EventID signal is legitimate -- attacks really do skew toward
    certain event types. The threshold is set well below the measured leak
    so this flags source-exclusive event types without punishing that.
    """
    assert_not_a_shortcut(mixed_corpus, lambda r: r.raw_event.get("EventID"), "EventID")
