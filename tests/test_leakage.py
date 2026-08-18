"""Offline tests for corpus-wide leakage mitigations — no network.

Covers leakage vector #1 (hostname/domain) from the Phase 1 research brief:
proves pseudonymization is deterministic, strips domain suffixes before
hashing (not after), and — the actual leakage check — that it is applied
identically regardless of which source_dataset a record came from.
"""

from datetime import datetime, timedelta, timezone

from src.ingest.leakage import (
    neutralize_timestamps,
    pseudonymize_hostname,
    pseudonymize_record_hostname,
    restrict_to_shared_support,
    shared_event_ids,
    shared_raw_event_keys,
)
from src.schema import AlertRecord, EventType


def _record(
    source_host: str,
    source_dataset: str,
    is_malicious: bool,
    *,
    event_id: int = 1,
    raw_event: dict | None = None,
    timestamp: datetime = datetime(2020, 1, 1, tzinfo=timezone.utc),
    capture_id: str = "TEST",
    record_id: str | None = None,
) -> AlertRecord:
    kwargs = dict(
        id=record_id or f"test:{source_host}:{id(raw_event) if raw_event else event_id}",
        timestamp=timestamp,
        source_host=source_host,
        event_type=EventType.PROCESS,
        source_dataset=source_dataset,
        source_capture_id=capture_id,
        raw_event=raw_event if raw_event is not None else {"Hostname": source_host, "EventID": event_id},
        is_malicious=is_malicious,
    )
    if is_malicious:
        kwargs["attack_technique"] = "T1059"
        kwargs["attack_tactics"] = ["TA0002"]
    return AlertRecord(**kwargs)


def test_pseudonymize_hostname_is_deterministic():
    a = pseudonymize_hostname("WORKSTATION5.theshire.local")
    b = pseudonymize_hostname("WORKSTATION5.theshire.local")
    assert a == b


def test_pseudonymize_hostname_strips_domain_before_hashing():
    # Same bare host, different domain suffix (or none) -> same token. This
    # is the actual leakage fix: if the domain suffix survived into the hash
    # input, OTRF's ".theshire.local" vs evtx-baseline's bare hostname would
    # still make the two corpora's pseudonymized-token *distributions*
    # trivially distinguishable even though individual tokens look opaque.
    theshire = pseudonymize_hostname("WORKSTATION5.theshire.local")
    mordor = pseudonymize_hostname("WORKSTATION5.mordor.local")
    bare = pseudonymize_hostname("WORKSTATION5")
    assert theshire == mordor == bare


def test_pseudonymize_hostname_is_case_insensitive():
    assert pseudonymize_hostname("WIN-TKC15D7KHUR") == pseudonymize_hostname("win-tkc15d7khur")


def test_pseudonymize_hostname_different_hosts_get_different_tokens():
    assert pseudonymize_hostname("WORKSTATION5") != pseudonymize_hostname("WORKSTATION6")


def test_pseudonymize_record_hostname_updates_both_fields_together():
    record = _record("WORKSTATION5.theshire.local", source_dataset="otrf_security_datasets", is_malicious=True)
    pseudo = pseudonymize_record_hostname(record)
    assert pseudo.source_host == pseudo.raw_event["Hostname"]
    assert pseudo.source_host != record.source_host
    # Every other field (crucially, ground truth) must be untouched.
    assert pseudo.is_malicious == record.is_malicious
    assert pseudo.attack_technique == record.attack_technique
    assert pseudo.raw_event["EventID"] == record.raw_event["EventID"]


def test_pseudonymization_applied_uniformly_is_not_separable_by_source():
    """The actual leakage check: apply the SAME function to a malicious-side
    and a benign-side host that happen to share a bare hostname convention
    difference, and confirm the resulting token carries no source-identity
    signal an attacker (or a classifier) could key on — i.e. two structurally
    different-looking raw hostnames from the two different corpora, once
    pseudonymized, are indistinguishable in shape (same prefix, same length,
    same hex alphabet) from each other."""
    otrf_record = _record("WORKSTATION5.theshire.local", source_dataset="otrf_security_datasets", is_malicious=True)
    benign_record = _record("WIN-TKC15D7KHUR", source_dataset="evtx_baseline", is_malicious=False)

    pseudo_otrf = pseudonymize_record_hostname(otrf_record)
    pseudo_benign = pseudonymize_record_hostname(benign_record)

    assert pseudo_otrf.source_host.startswith("host-")
    assert pseudo_benign.source_host.startswith("host-")
    assert len(pseudo_otrf.source_host) == len(pseudo_benign.source_host)
    # Neither original hostname/domain substring survives.
    assert "theshire" not in pseudo_otrf.source_host
    assert "WORKSTATION" not in pseudo_otrf.source_host
    assert "WIN-TKC" not in pseudo_benign.source_host


# --- shared_raw_event_keys / shared_event_ids ------------------------------


def test_shared_raw_event_keys_is_the_intersection_not_the_union():
    a = [_record("H1", "otrf_security_datasets", True, raw_event={"EventID": 1, "CommandLine": "x", "OnlyA": 1})]
    b = [_record("H2", "evtx_baseline", False, raw_event={"EventID": 1, "CommandLine": "y", "OnlyB": 2})]
    assert shared_raw_event_keys(a, b) == {"EventID", "CommandLine"}


def test_shared_raw_event_keys_unions_across_records_before_intersecting():
    # Record 1 of side A has 'Foo', record 2 of side A has 'Bar'; side B's
    # single record has both. The shared set must still include both, because
    # "observed anywhere on this side" is the right notion of "this side has
    # this field" -- a per-record-only intersection would wrongly drop fields
    # that are simply optional/sparse on one side.
    a = [
        _record("H1", "otrf_security_datasets", True, raw_event={"EventID": 1, "Foo": 1}),
        _record("H1", "otrf_security_datasets", True, raw_event={"EventID": 1, "Bar": 2}, record_id="a2"),
    ]
    b = [_record("H2", "evtx_baseline", False, raw_event={"EventID": 1, "Foo": 1, "Bar": 2})]
    assert shared_raw_event_keys(a, b) == {"EventID", "Foo", "Bar"}


def test_shared_event_ids_is_the_intersection():
    a = [
        _record("H1", "otrf_security_datasets", True, event_id=1, record_id="a1"),
        _record("H1", "otrf_security_datasets", True, event_id=4658, record_id="a2"),
    ]
    b = [_record("H2", "evtx_baseline", False, event_id=1)]
    assert shared_event_ids(a, b) == {1}


def test_shared_event_ids_empty_when_no_overlap():
    a = [_record("H1", "otrf_security_datasets", True, event_id=1)]
    b = [_record("H2", "evtx_baseline", False, event_id=2)]
    assert shared_event_ids(a, b) == set()


# --- restrict_to_shared_support ---------------------------------------------


def _many(n: int, is_malicious: bool, event_id: int, source_dataset: str, extra_key: str | None = None) -> list[AlertRecord]:
    raw = {"EventID": event_id, "Hostname": "H"}
    if extra_key:
        raw[extra_key] = "v"
    return [
        _record(
            "H",
            source_dataset,
            is_malicious,
            event_id=event_id,
            raw_event=dict(raw),
            record_id=f"{source_dataset}:{event_id}:{i}",
        )
        for i in range(n)
    ]


def test_restrict_to_shared_support_drops_exclusive_event_ids():
    malicious = _many(10, True, event_id=1, source_dataset="otrf_security_datasets") + _many(
        10, True, event_id=4658, source_dataset="otrf_security_datasets"
    )
    benign = _many(10, False, event_id=1, source_dataset="evtx_baseline")

    kept_malicious, kept_benign = restrict_to_shared_support(malicious, benign)

    assert all(r.raw_event.get("EventID") == 1 for r in kept_malicious)
    assert all(r.raw_event.get("EventID") == 1 for r in kept_benign)
    assert not any(r.raw_event.get("EventID") == 4658 for r in kept_malicious)


def test_restrict_to_shared_support_ablates_fields_not_shared():
    malicious = _many(5, True, event_id=1, source_dataset="otrf_security_datasets", extra_key="AccountDomain")
    benign = _many(5, False, event_id=1, source_dataset="evtx_baseline")

    kept_malicious, kept_benign = restrict_to_shared_support(malicious, benign)

    assert all("AccountDomain" not in r.raw_event for r in kept_malicious)
    assert all(set(r.raw_event.keys()) == set(kept_benign[0].raw_event.keys()) for r in kept_malicious)


def test_restrict_to_shared_support_canonicalizes_missing_shared_keys_to_none():
    # Malicious side sometimes has 'CommandLine' populated, sometimes not --
    # after restriction every surviving record must carry the key (as None
    # when absent), not just the ones that happened to have it, or field
    # count would still vary with which optional field was populated.
    malicious = [
        _record("H", "otrf_security_datasets", True, event_id=1, raw_event={"EventID": 1, "CommandLine": "x"}, record_id="m1"),
        _record("H", "otrf_security_datasets", True, event_id=1, raw_event={"EventID": 1}, record_id="m2"),
    ]
    benign = _many(2, False, event_id=1, source_dataset="evtx_baseline", extra_key="CommandLine")

    kept_malicious, _ = restrict_to_shared_support(malicious, benign)
    without_commandline = next(r for r in kept_malicious if r.id == "m2")
    assert "CommandLine" in without_commandline.raw_event
    assert without_commandline.raw_event["CommandLine"] is None


def test_restrict_to_shared_support_caps_per_event_id_class_ratio():
    # 100 malicious vs 10 benign on the same EventID -- far past any
    # reasonable ratio -- must be capped, not passed through untouched.
    malicious = _many(100, True, event_id=1, source_dataset="otrf_security_datasets")
    benign = _many(10, False, event_id=1, source_dataset="evtx_baseline")

    kept_malicious, kept_benign = restrict_to_shared_support(malicious, benign, max_class_ratio=1.5)

    assert len(kept_benign) == 10
    assert len(kept_malicious) == 15  # int(10 * 1.5)


def test_restrict_to_shared_support_leaves_balanced_buckets_untouched():
    malicious = _many(10, True, event_id=1, source_dataset="otrf_security_datasets")
    benign = _many(10, False, event_id=1, source_dataset="evtx_baseline")

    kept_malicious, kept_benign = restrict_to_shared_support(malicious, benign, max_class_ratio=1.5)

    assert len(kept_malicious) == 10
    assert len(kept_benign) == 10


def test_restrict_to_shared_support_never_mutates_inputs():
    malicious = _many(5, True, event_id=1, source_dataset="otrf_security_datasets", extra_key="AccountDomain")
    benign = _many(5, False, event_id=1, source_dataset="evtx_baseline")
    malicious_before = [dict(r.raw_event) for r in malicious]

    restrict_to_shared_support(malicious, benign)

    assert [dict(r.raw_event) for r in malicious] == malicious_before


def test_restrict_to_shared_support_is_deterministic_given_a_seed():
    malicious = _many(100, True, event_id=1, source_dataset="otrf_security_datasets")
    benign = _many(10, False, event_id=1, source_dataset="evtx_baseline")

    kept_a, _ = restrict_to_shared_support(malicious, benign, seed=7)
    kept_b, _ = restrict_to_shared_support(malicious, benign, seed=7)
    assert [r.id for r in kept_a] == [r.id for r in kept_b]


# --- neutralize_timestamps ---------------------------------------------


def test_neutralize_timestamps_collapses_absolute_year_across_sources():
    malicious = [_record("H1", "otrf_security_datasets", True, timestamp=datetime(2020, 9, 4, tzinfo=timezone.utc), capture_id="CAP-M")]
    benign = [_record("H2", "evtx_baseline", False, timestamp=datetime(2022, 4, 4, tzinfo=timezone.utc), capture_id="CAP-B")]

    rebased = neutralize_timestamps(malicious + benign)

    years = {r.timestamp.year for r in rebased}
    assert years == {2000}, f"expected a single shared rebased year, got {years}"


def test_neutralize_timestamps_preserves_relative_order_and_deltas_within_a_capture():
    start = datetime(2020, 9, 4, 12, 0, 0, tzinfo=timezone.utc)
    records = [
        _record("H1", "otrf_security_datasets", True, timestamp=start, capture_id="CAP-M", record_id="first"),
        _record(
            "H1",
            "otrf_security_datasets",
            True,
            timestamp=start + timedelta(seconds=30),
            capture_id="CAP-M",
            record_id="second",
        ),
    ]

    rebased = neutralize_timestamps(records)
    by_id = {r.id: r for r in rebased}
    assert by_id["second"].timestamp > by_id["first"].timestamp
    assert (by_id["second"].timestamp - by_id["first"].timestamp) == timedelta(seconds=30)


def test_neutralize_timestamps_zero_points_each_capture_independently():
    # Two captures whose absolute start times differ must each be zeroed to
    # their OWN first event, not to the corpus-wide earliest event -- capture
    # B's events must not carry a large offset just because capture A started
    # earlier in absolute time.
    records = [
        _record("H1", "otrf_security_datasets", True, timestamp=datetime(2020, 1, 1, tzinfo=timezone.utc), capture_id="CAP-A", record_id="a"),
        _record("H2", "evtx_baseline", False, timestamp=datetime(2022, 6, 1, tzinfo=timezone.utc), capture_id="CAP-B", record_id="b"),
    ]
    rebased = neutralize_timestamps(records)
    by_id = {r.id: r for r in rebased}
    assert by_id["a"].timestamp == by_id["b"].timestamp  # both are their own capture's t=0
