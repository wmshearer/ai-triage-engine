"""Corpus-wide leakage mitigations, applied identically to BOTH sources.

Phase 1 research (wshearer-site/research/phase-1-benign-corpus.md, Section 5)
enumerates six concrete leakage vectors from pairing OTRF (malicious) with
evtx-baseline (benign). This module holds the ones that need code, not just
documentation, and — critically — every function here is applied to the
FULL assembled corpus in corpus.py, never to one source only. Per the task's
own framing: "whatever you do to one corpus you must do to the other —
asymmetric treatment is itself a leak." A hostname-pseudonymization pass that
only touched the benign side (or vice versa) would still let a classifier
learn "pseudonymized-looking string = one class," which is just the same
leak wearing a disguise.

Deliberately NOT done in normalize.py / normalize_benign.py themselves: those
modules' existing tests assert the raw, un-pseudonymized `source_host` value
(e.g. `WORKSTATION5.theshire.local`) is preserved verbatim from the source
event — changing that would both violate "existing 13 tests must still pass,
unmodified" and would defeat the raw_event field's own documented purpose
("kept as the raw, unmodified source event", schema.py). Mitigation therefore
happens one layer up, in corpus.py's assembly step, over the combined set of
records from both sources at once.

Phase 1b (research/phase-1b-shortcut-mitigation.md) adds three more vectors,
all confirmed on the real corpus and all sharing the same root cause — the
two classes differ by COLLECTION STACK (OTRF: WEF -> NXLog CE -> Logstash ->
Kafkacat -> JSON; evtx-baseline: raw `Copy-Item *.evtx`, no shipper), not by
behavior:

  timestamp year : malicious 100% 2020, benign 100% 2022 -> year alone is a
                    perfect classifier (accuracy 1.0000)
  raw_event field count: malicious 35-46, benign 21-28, and the gap PERSISTS
                    inside every shared Sysmon EventID (EID 13: 39 vs 24;
                    EID 10: 43 vs 28; EID 1: 53 vs 38) -- so restricting to
                    shared EventIDs alone does not close it
  EventID          : 4658/4656/5447 appear ONLY on the malicious side

Per Arp et al. ("Dos and Don'ts of ML in Computer Security", USENIX Security
2022) Pitfall #4 (Spurious Correlations) and Pitfall #1 (Sampling Bias), the
correct remedy is feature ablation + restricting to the overlap support, not
relabeling or deleting the affected classes outright — see the research brief
for the full citation trail. `shared_raw_event_keys`, `shared_event_ids`, and
`restrict_to_shared_support` below implement that; `neutralize_timestamps`
implements the timestamp half. All four take/return whole record lists (never
one source in isolation) for the same "asymmetric treatment is a leak" reason
hostname pseudonymization already established above.
"""

from __future__ import annotations

import hashlib
import random
from collections import defaultdict
from datetime import datetime, timezone

from src.schema import AlertRecord

# --- Vector 1: hostname/domain ------------------------------------------
# OTRF's Windows atomics are a fixed lab ("theshire.local"/"mordor.local",
# hosts WORKSTATION5/6, MORDORDC — confirmed directly from downloaded
# captures, see tests/test_leakage.py). evtx-baseline's win2022-evtx capture
# uses a single auto-generated hostname (WIN-TKC15D7KHUR, confirmed directly
# by parsing the downloaded .evtx). Left as raw strings, a hostname/domain
# substring is a perfect source-identity proxy — trivially separable, zero
# behavioral signal. Mitigation: hash every hostname to a short, stable,
# domain-stripped token, using the SAME function for every record regardless
# of source_dataset, so the classifier sees an opaque categorical with no
# structural difference between the two corpora's naming conventions.


def pseudonymize_hostname(hostname: str) -> str:
    """Map any hostname/FQDN to a short, stable, source-blind token.

    Domain suffixes are stripped before hashing (not just hashed as-is)
    because otherwise the *domain part itself* (".theshire.local" appearing
    on every OTRF record, absent from every evtx-baseline record) would
    still leak through a hash's input distribution being source-correlated
    even though the output looks opaque — the fix has to remove the
    source-correlated substring before hashing, not just hash it.
    Deterministic (sha256, not random) so the same host always maps to the
    same token across records and across re-runs, which is what lets an
    eval harness still group/count events per-host without ever seeing the
    real name.
    """
    bare_host = hostname.split(".", 1)[0]
    digest = hashlib.sha256(bare_host.lower().encode("utf-8")).hexdigest()[:12]
    return f"host-{digest}"


def pseudonymize_record_hostname(record: AlertRecord) -> AlertRecord:
    """Return a copy of `record` with `source_host` and `raw_event["Hostname"]`
    pseudonymized, leaving every other field (including ATT&CK ground truth)
    untouched.

    Applied uniformly over the whole assembled corpus in corpus.py — see
    module docstring for why this can't live inside either per-source
    normalizer without breaking their existing "preserves raw host verbatim"
    tests.
    """
    new_host = pseudonymize_hostname(record.source_host)
    new_raw = dict(record.raw_event)
    if "Hostname" in new_raw:
        new_raw["Hostname"] = new_host
    return record.model_copy(update={"source_host": new_host, "raw_event": new_raw})


# --- Vector 2: absolute timestamp -----------------------------------------
# OTRF's atomic captures were recorded in 2020; evtx-baseline's win2022-evtx
# capture in 2022 (measured directly, see test_shortcut_audit.py). Absolute
# calendar time is purely an artifact of WHEN each dataset's authors happened
# to run their collection VM — it carries no security meaning across sources
# and is a perfect (accuracy 1.0000) classifier on its own.
#
# `timestamp` is NOT deleted from AlertRecord: it is a required schema field
# (schema.py) and downstream correlation logic (e.g. "did event B follow
# event A within N seconds on the same host") legitimately needs RELATIVE
# time within one capture. Deleting it would also make `_labels_consistent`-
# adjacent, ordering-dependent future logic impossible to build at all, which
# is a worse outcome than a documented, mitigated timestamp field.
#
# Mitigation: rebase every record's timestamp to an OFFSET from its OWN
# capture's first event, then re-anchor that offset at one FIXED, shared
# epoch (2000-01-01T00:00:00Z) common to every capture regardless of source.
# This keeps relative ordering and inter-event deltas fully intact (anything
# that only cares about "how long after the capture started" or "which of
# these two events happened first" is unaffected) while making the absolute
# calendar date uninformative: every record's rebased year is 2000 (or spills
# into 2001 only for a capture that legitimately runs past a year boundary,
# which none in this corpus do), regardless of which source it came from.
_TIMESTAMP_EPOCH = datetime(2000, 1, 1, tzinfo=timezone.utc)


def neutralize_timestamps(records: list[AlertRecord]) -> list[AlertRecord]:
    """Return copies of `records` with `timestamp` rebased to a shared,
    source-blind epoch, grouped by `source_capture_id`.

    For each capture, the earliest observed timestamp becomes that capture's
    zero point; every record in the capture is then re-expressed as
    `_TIMESTAMP_EPOCH + (original_timestamp - capture_start)`. Two captures
    from different sources and different real-world years land on the SAME
    rebased calendar date range, which is exactly what removes the
    collection-year shortcut, while the offset between any two records that
    were originally in the same capture is preserved exactly (ordering and
    inter-event deltas are unaffected).

    Applied over the whole corpus at once (not per-source) for the same
    reason `pseudonymize_record_hostname` is: computing "this capture's own
    first event" only needs one capture's records, but running it uniformly
    over every record regardless of source is what keeps the treatment
    symmetric.
    """
    capture_start: dict[str, datetime] = {}
    for record in records:
        current = capture_start.get(record.source_capture_id)
        if current is None or record.timestamp < current:
            capture_start[record.source_capture_id] = record.timestamp

    rebased = []
    for record in records:
        offset = record.timestamp - capture_start[record.source_capture_id]
        new_timestamp = _TIMESTAMP_EPOCH + offset
        rebased.append(record.model_copy(update={"timestamp": new_timestamp}))
    return rebased


# --- Vector 3: raw_event field count + exclusive EventIDs -----------------
# Two related but distinct shortcuts, both downstream of the same root cause
# (NXLog enrichment on the OTRF side, none on evtx-baseline): OTRF's raw_event
# dicts simply carry more keys per event (NXLog/Logstash/ECS bookkeeping
# fields like '@version', 'AccountDomain', 'AccessMask',
# 'AuthenticationPackageName'), and three Windows Security EventIDs
# (4658/4656/5447, measured) appear only on the malicious side because
# evtx-baseline's captured VM never triggered the underlying Windows audit
# policy for them.
#
# The field-count gap is NOT explained away by restricting to shared
# EventIDs alone (measured: EID 13 alone still splits 39 vs 24 fields) —
# restricting to shared EventIDs removes the exclusive-EventID shortcut but
# leaves the field-count shortcut fully intact, because a shipper can enrich
# an event without changing its EventID. Both fixes are required together,
# which is why `restrict_to_shared_support` below applies them as one step
# rather than as two independently-optional ones.


def shared_raw_event_keys(records_a: list[AlertRecord], records_b: list[AlertRecord]) -> set[str]:
    """Every raw_event key observed on BOTH `records_a` and `records_b`.

    Computed dynamically over whatever two record lists are actually in hand
    (never hardcoded), because the honest shared-key set depends on what was
    actually ingested — a static allowlist would silently go stale the first
    time either source's parser changes, or the moment this project ingests
    a new capture. This is schema-level intersection (every raw_event key
    across the whole list), not the coarser `_EVENT_TYPE_MAP`-level filtering
    `normalize_benign.py` already does (which only restricts which (Channel,
    EventID) pairs are ingested, saying nothing about the per-event field
    count within a shared pair).
    """
    keys_a: set[str] = set()
    for record in records_a:
        keys_a.update(record.raw_event.keys())
    keys_b: set[str] = set()
    for record in records_b:
        keys_b.update(record.raw_event.keys())
    return keys_a & keys_b


def shared_event_ids(records_a: list[AlertRecord], records_b: list[AlertRecord]) -> set[object]:
    """Every `raw_event["EventID"]` value observed on BOTH record lists.

    Also computed dynamically, for the same reason as `shared_raw_event_keys`
    — which EventIDs the two sources actually share is an empirical fact
    about the currently-ingested data, not a value this project should ever
    hand-maintain and risk drifting from reality.
    """
    ids_a = {record.raw_event.get("EventID") for record in records_a}
    ids_b = {record.raw_event.get("EventID") for record in records_b}
    return ids_a & ids_b


# Within each surviving shared EventID, one class can still vastly outnumber
# the other (measured on the real corpus: EID 13 is malicious:benign roughly
# 1:2, EID 4104 roughly 37:1, EID 3 roughly 24:1) purely because attacks and
# ordinary use legitimately trigger different EventIDs at different rates —
# real signal, not a collection-stack artifact (see the EventID test's own
# docstring: "attacks really do skew toward certain event types"). Left
# uncorrected, that per-EventID imbalance reintroduces (EventID, field count)
# and even a fully-neutralized-timestamp's constant-value majority-baseline
# as passable "shortcuts" simply because one class dominates a bucket's
# count, not because it dominates a bucket's field shape. This is why support
# restriction alone (dropping exclusive EventIDs) is necessary but not
# sufficient — it must be paired with capping how far any single shared
# EventID's class ratio can drift, which is the applied-ML remedy for exactly
# this ("avoid merging incompatible sources without correction" -- Arp et
# al.'s sampling-bias pitfall) rather than a Phase-1b-specific invention.
DEFAULT_MAX_CLASS_RATIO = 1.5


# Keys dropped outright because the two sources do not carry the SAME DATA in
# them, only data that happens to share a name — so no normalization can make
# them comparable without inventing a mapping.
#
# `Opcode`: OTRF/NXLog stores a RENDERED DESCRIPTION ('Info', 'On create
# calls', 'To be used when operation is just executing a method'); the raw
# .evtx side stores the NUMERIC opcode (0, 15). Windows defines no public
# total mapping between those two spaces, and the long descriptive strings
# have no numeric counterpart at all. Coercing one into the other would mean
# fabricating a correspondence, which is worse than dropping a field that
# carries almost no triage signal (measured: 99.995% of benign records are
# opcode 0, i.e. it is nearly constant on one side).
#
# Prefer normalization (see _canonicalize_value) over dropping wherever the
# two sources genuinely hold the same value; drop only when they do not.
UNMAPPABLE_KEYS = frozenset({"Opcode"})


def _canonicalize_value(value: object) -> object:
    """Normalize a raw_event VALUE to a source-independent representation.

    Found 2026-08-18 by an adversarial audit, AFTER key-level canonicalization
    was already in place and passing: the two sources serialize the SAME value
    differently, and value TYPE alone predicted the label at accuracy 1.0000 —
    holding even within a single shared EventID.

        Keywords:  OTRF/NXLog -> -9223372036854775808  (signed int64)
                   evtx-baseline -> '0x8000000000000000'  (hex string)
        Opcode:    OTRF/NXLog -> 'Info'  (rendered string)
                   evtx-baseline -> 0     (numeric code)

    Identical underlying data, different serialization — the same NXLog-vs-raw
    root cause as the field-count shortcut, one layer down. Canonicalizing
    which KEYS exist (the previous step) does nothing about this, because the
    leak is carried by the values' representation rather than their presence.

    Normalization strategy: coerce to a single canonical string form, and
    reduce integers-expressed-as-hex-strings to their decimal value so the two
    spellings of one number collapse together. Two's-complement is applied to
    64-bit values because NXLog emits Keywords as SIGNED int64 while the raw
    .evtx side emits the same bit pattern unsigned — without this the two
    spellings normalize to different numbers and the leak survives.

    Deliberately NOT dropping these fields: Keywords and Opcode carry real
    Windows event semantics. The goal is to remove the source tell while
    keeping the signal, which is why this normalizes rather than ablates.
    """
    if value is None or isinstance(value, bool):
        # bool before int: bool IS an int subclass in Python, and 'True'
        # is already source-independent.
        return value

    if isinstance(value, int):
        return _to_unsigned64(value)

    if isinstance(value, str):
        text = value.strip()
        try:
            if text.lower().startswith(("0x", "-0x")):
                return _to_unsigned64(int(text, 16))
            # Plain decimal strings normalize to int so '0' and 0 agree.
            return _to_unsigned64(int(text, 10))
        except ValueError:
            # A genuinely non-numeric string (e.g. an Image path) — leave it
            # alone. Casing/whitespace are NOT normalized away here: they can
            # be real signal (e.g. lookalike binary names) and this function
            # must not quietly destroy security-relevant differences.
            return text

    return value


def _to_unsigned64(number: int) -> int:
    """Fold a signed 64-bit value onto its unsigned twos-complement equal.

    NXLog renders Keywords as a SIGNED int64 (-9223372036854775808) while the
    raw .evtx path renders the identical bit pattern as an unsigned hex string
    ('0x8000000000000000' = 9223372036854775808). Both must land on one value
    or the type/format tell simply becomes a value tell.
    """
    if -(2**63) <= number < 0:
        return number + 2**64
    return number


def restrict_to_shared_support(
    malicious_records: list[AlertRecord],
    benign_records: list[AlertRecord],
    max_class_ratio: float = DEFAULT_MAX_CLASS_RATIO,
    seed: int = 20260818,
) -> tuple[list[AlertRecord], list[AlertRecord]]:
    """Apply feature ablation (a) + support restriction (b) together.

    Three steps, in order, matching research/phase-1b-shortcut-mitigation.md's
    verdict to implement (a)+(b) as one combined change rather than two
    independently-optional ones (restricting EventIDs alone does not close
    the field-count shortcut; ablating fields alone does not close the
    exclusive-EventID shortcut):

    1. Restrict both lists to `shared_event_ids(malicious, benign)` — drops
       EventIDs that structurally exist on only one side (e.g. 4658/4656/
       5447), which is real lost coverage, not merely unsampled coverage, so
       it must be measured and disclosed (see README), not silently applied.
    2. Canonicalize every surviving record's `raw_event` to exactly
       `shared_raw_event_keys(...)` of the SURVIVING records, always
       including every shared key (filling with `None` when a given event
       happens not to populate it) rather than merely dropping unshared keys.
       Filling missing shared keys with `None` is required, not cosmetic:
       dropping-only still lets `len(raw_event)` vary with which OPTIONAL
       shared fields a given event happened to populate, and that residual
       variance is itself still source-correlated (measured: even after
       restricting to a shared key set, malicious records vary 15-37 keys
       per event on EID 1 because Windows/Sysmon fields are frequently
       absent/null rather than always present, while evtx-baseline's flatten
       step always emits the full key set) — always emitting every shared key
       collapses `len(raw_event)` to a constant, EventID-determined value,
       which is legitimate signal (different EventIDs really do have
       different shapes), not a source tell.
    3. Cap each surviving shared EventID's class ratio at `max_class_ratio`
       by subsampling (never upsampling/duplicating) the majority class
       within that EventID bucket — see `DEFAULT_MAX_CLASS_RATIO`'s comment
       for why this is required in addition to steps 1-2, not an extra
       precaution.

    Returns `(malicious, benign)` in the same shape as the inputs. Never
    mutates the input lists or their records (AlertRecord is treated as
    immutable throughout, via `model_copy`).
    """
    shared_ids = shared_event_ids(malicious_records, benign_records)
    restricted_malicious = [r for r in malicious_records if r.raw_event.get("EventID") in shared_ids]
    restricted_benign = [r for r in benign_records if r.raw_event.get("EventID") in shared_ids]

    shared_keys = shared_raw_event_keys(restricted_malicious, restricted_benign) - UNMAPPABLE_KEYS

    def canonicalize(record: AlertRecord) -> AlertRecord:
        new_raw = {key: _canonicalize_value(record.raw_event.get(key)) for key in shared_keys}
        return record.model_copy(update={"raw_event": new_raw})

    canonical_malicious = [canonicalize(r) for r in restricted_malicious]
    canonical_benign = [canonicalize(r) for r in restricted_benign]

    rng = random.Random(seed)
    malicious_by_eid: dict[object, list[AlertRecord]] = defaultdict(list)
    benign_by_eid: dict[object, list[AlertRecord]] = defaultdict(list)
    for record in canonical_malicious:
        malicious_by_eid[record.raw_event.get("EventID")].append(record)
    for record in canonical_benign:
        benign_by_eid[record.raw_event.get("EventID")].append(record)

    balanced_malicious: list[AlertRecord] = []
    balanced_benign: list[AlertRecord] = []
    for event_id in shared_ids:
        mal_bucket = malicious_by_eid.get(event_id, [])
        ben_bucket = benign_by_eid.get(event_id, [])
        if not mal_bucket or not ben_bucket:
            # Can only happen if one side's bucket emptied out entirely
            # between the two record lists passed in (e.g. a caller already
            # pre-filtered one side) -- drop the now-one-sided bucket rather
            # than let it silently become an exclusive-EventID shortcut again.
            continue
        if len(mal_bucket) > len(ben_bucket) * max_class_ratio:
            mal_bucket = rng.sample(mal_bucket, int(len(ben_bucket) * max_class_ratio))
        elif len(ben_bucket) > len(mal_bucket) * max_class_ratio:
            ben_bucket = rng.sample(ben_bucket, int(len(mal_bucket) * max_class_ratio))
        balanced_malicious.extend(mal_bucket)
        balanced_benign.extend(ben_bucket)

    return balanced_malicious, balanced_benign
