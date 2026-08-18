"""Offline tests for raw-capture -> AlertRecord normalization — no network."""

import json
from pathlib import Path

import pytest

from src.ingest.normalize import make_benign_record, normalize_capture
from src.schema import AlertRecord, EventType

FIXTURES = Path(__file__).parent / "fixtures"


def test_normalize_capture_produces_labeled_malicious_records():
    records = normalize_capture(
        FIXTURES / "sample_metadata.yaml",
        [FIXTURES / "sample_capture.zip"],
    )

    assert len(records) == 4
    assert all(isinstance(r, AlertRecord) for r in records)
    # Ground truth propagated from the metadata's attack_mappings to every event.
    assert all(r.is_malicious for r in records)
    assert all(r.attack_technique == "T1069" for r in records)
    assert all(r.attack_subtechnique == "001" for r in records)
    assert all(r.attack_tactics == ["TA0007"] for r in records)
    assert all(r.source_dataset == "otrf_security_datasets" for r in records)
    assert all(r.source_capture_id == "SDWIN-190319020147" for r in records)


def test_normalize_capture_classifies_known_event_types():
    records = normalize_capture(
        FIXTURES / "sample_metadata.yaml",
        [FIXTURES / "sample_capture.zip"],
    )
    by_event_id = {r.raw_event["EventID"]: r for r in records}

    assert by_event_id[4103].event_type == EventType.PROCESS  # PowerShell module log
    assert by_event_id[1].event_type == EventType.PROCESS      # Sysmon process create
    assert by_event_id[4688].event_type == EventType.PROCESS   # Security process creation
    assert by_event_id[9999].event_type == EventType.OTHER     # unmapped (Channel, EventID)


def test_normalize_capture_preserves_raw_event_and_host():
    records = normalize_capture(
        FIXTURES / "sample_metadata.yaml",
        [FIXTURES / "sample_capture.zip"],
    )
    r = records[0]
    assert r.source_host == "WORKSTATION5.theshire.local"
    assert r.raw_event["EventID"] == 4103
    assert r.timestamp.year == 2019
    assert r.timestamp.month == 3
    assert r.timestamp.day == 19


def test_normalize_capture_ids_are_stable_across_runs():
    r1 = normalize_capture(FIXTURES / "sample_metadata.yaml", [FIXTURES / "sample_capture.zip"])
    r2 = normalize_capture(FIXTURES / "sample_metadata.yaml", [FIXTURES / "sample_capture.zip"])
    assert [r.id for r in r1] == [r.id for r in r2]


def test_normalize_capture_raises_without_attack_mappings(tmp_path):
    bad_meta = tmp_path / "no_mappings.yaml"
    bad_meta.write_text("id: FAKE-001\nattack_mappings: []\nfiles: []\n")
    with pytest.raises(ValueError, match="no attack_mappings"):
        normalize_capture(bad_meta, [])


def test_make_benign_record_represents_a_negative():
    """A triage eval needs negatives, not only attacks — this is the mechanism for them."""
    event = json.loads((FIXTURES / "benign_event.json").read_text())
    record = make_benign_record(event, source_dataset="otrf_security_datasets", capture_id="SYNTH-BENIGN-001", index=0)

    assert record.is_malicious is False
    assert record.attack_technique is None
    assert record.attack_subtechnique is None
    assert record.attack_tactics == []
    assert record.event_type == EventType.AUTHENTICATION
    assert record.source_host == "WORKSTATION9.theshire.local"
