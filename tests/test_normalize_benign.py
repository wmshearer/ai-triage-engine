"""Offline tests for evtx-baseline -> AlertRecord normalization — no network."""

from pathlib import Path

from src.ingest.normalize_benign import (
    filter_to_mapped_channels,
    normalize_evtx_capture,
    normalize_evtx_file,
)
from src.schema import AlertRecord, EventType

FIXTURES = Path(__file__).parent / "fixtures" / "evtx"


def test_normalize_evtx_file_produces_labeled_benign_records():
    records = normalize_evtx_file(FIXTURES / "sysmon_sample.evtx", capture_id="TEST-SYSMON")

    assert len(records) > 0
    assert all(isinstance(r, AlertRecord) for r in records)
    assert all(r.is_malicious is False for r in records)
    assert all(r.attack_technique is None for r in records)
    assert all(r.attack_subtechnique is None for r in records)
    assert all(r.attack_tactics == [] for r in records)
    assert all(r.source_dataset == "evtx_baseline" for r in records)
    assert all(r.source_capture_id == "TEST-SYSMON" for r in records)


def test_normalize_evtx_file_classifies_known_event_types():
    records = normalize_evtx_file(FIXTURES / "sysmon_sample.evtx", capture_id="TEST-SYSMON")
    by_event_id: dict[int, list] = {}
    for r in records:
        by_event_id.setdefault(r.raw_event["EventID"], []).append(r)

    assert by_event_id[1][0].event_type == EventType.PROCESS  # Sysmon process create
    assert by_event_id[13][0].event_type == EventType.REGISTRY  # Sysmon registry value set


def test_normalize_evtx_file_default_filter_drops_unmapped_event_ids():
    # The sysmon fixture contains EventID 7 (image load) and 18 (pipe
    # connect) among others — 7 is NOT in _EVENT_TYPE_MAP, so the default
    # channel_filter must drop it (leakage vector #4 mitigation).
    unfiltered = normalize_evtx_file(FIXTURES / "sysmon_sample.evtx", capture_id="TEST", channel_filter=None)
    filtered = normalize_evtx_file(FIXTURES / "sysmon_sample.evtx", capture_id="TEST")
    assert len(filtered) < len(unfiltered)
    assert all(r.raw_event["EventID"] != 7 for r in filtered)
    assert any(r.raw_event["EventID"] == 7 for r in unfiltered)


def test_normalize_evtx_capture_concatenates_multiple_files_with_stable_ids():
    records = normalize_evtx_capture(
        [FIXTURES / "sysmon_sample.evtx", FIXTURES / "security_sample.evtx"],
        capture_id="TEST-CAPTURE",
    )
    ids = [r.id for r in records]
    assert len(ids) == len(set(ids)), "record ids must be unique across concatenated files"

    records_again = normalize_evtx_capture(
        [FIXTURES / "sysmon_sample.evtx", FIXTURES / "security_sample.evtx"],
        capture_id="TEST-CAPTURE",
    )
    assert [r.id for r in records] == [r.id for r in records_again]


def test_filter_to_mapped_channels_keeps_only_known_pairs():
    from src.ingest.parse_evtx import parse_evtx_file

    events = parse_evtx_file(FIXTURES / "sysmon_sample.evtx")
    keys = {("microsoft-windows-sysmon/operational", 1)}
    filtered = filter_to_mapped_channels(events, keys)
    assert filtered
    assert all(e["EventID"] == 1 for e in filtered)
