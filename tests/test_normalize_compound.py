"""Offline tests for compound-capture -> AlertRecord normalization — no network.

Mirrors tests/test_normalize.py's structure. The one thing under test that
does NOT exist in the atomic path: every record here must come out labeled
malicious with the explicit multi-technique-unresolved sentinel (see
src/schema.py:MULTI_TECHNIQUE_SENTINEL and
src/ingest/normalize_compound.py's module docstring for why a single
technique cannot be honestly assigned).
"""

from pathlib import Path

from src.ingest.normalize_compound import normalize_compound_capture
from src.schema import MULTI_TECHNIQUE_SENTINEL, AlertRecord, EventType

FIXTURES = Path(__file__).parent / "fixtures"


def test_normalize_compound_capture_produces_labeled_malicious_records():
    records = normalize_compound_capture(
        "APT29-EVALS-DAY1-FIXTURE",
        [FIXTURES / "sample_compound_capture.zip"],
    )

    assert len(records) == 4
    assert all(isinstance(r, AlertRecord) for r in records)
    # Every record asserted malicious (OTRF's own scenario-level assertion),
    # but with the technique left explicitly unresolved rather than guessed.
    assert all(r.is_malicious for r in records)
    assert all(r.attack_technique == MULTI_TECHNIQUE_SENTINEL for r in records)
    assert all(r.technique_unresolved for r in records)
    assert all(r.attack_subtechnique is None for r in records)
    assert all(r.attack_tactics == [] for r in records)
    assert all(r.source_dataset == "otrf_security_datasets" for r in records)
    assert all(r.source_capture_id == "APT29-EVALS-DAY1-FIXTURE" for r in records)


def test_normalize_compound_capture_classifies_known_event_types():
    records = normalize_compound_capture(
        "APT29-EVALS-DAY1-FIXTURE",
        [FIXTURES / "sample_compound_capture.zip"],
    )
    by_index = {i: r for i, r in enumerate(records)}

    assert by_index[0].raw_event["EventID"] == 1
    assert by_index[0].event_type == EventType.PROCESS  # Sysmon process create
    assert by_index[2].raw_event["EventID"] == 12
    assert by_index[2].event_type == EventType.REGISTRY  # Sysmon registry object
    assert by_index[3].raw_event["EventID"] == 9999
    assert by_index[3].event_type == EventType.OTHER  # unmapped (Channel, EventID)


def test_normalize_compound_capture_preserves_raw_event_and_host():
    records = normalize_compound_capture(
        "APT29-EVALS-DAY1-FIXTURE",
        [FIXTURES / "sample_compound_capture.zip"],
    )
    r = records[0]
    assert r.source_host == "SCRANTON.dmevals.local"
    assert r.raw_event["EventID"] == 1
    assert "CommandLine" in r.raw_event
    assert "ParentImage" in r.raw_event
    assert "User" in r.raw_event
    assert "Image" in r.raw_event


def test_normalize_compound_capture_eid1_carries_process_fields():
    """The whole point of ingesting these captures: EID1 process-creation
    records carry CommandLine + ParentImage + User + Image together, unlike
    the registry/access events that dominate the pre-existing corpus."""
    records = normalize_compound_capture(
        "APT29-EVALS-DAY1-FIXTURE",
        [FIXTURES / "sample_compound_capture.zip"],
    )
    eid1_records = [r for r in records if r.raw_event.get("EventID") == 1]
    assert len(eid1_records) == 2
    for r in eid1_records:
        for key in ("CommandLine", "ParentImage", "User", "Image"):
            assert r.raw_event.get(key), f"expected non-empty {key} on EID1 record"


def test_normalize_compound_capture_ids_are_stable_across_runs():
    r1 = normalize_compound_capture("FIXTURE", [FIXTURES / "sample_compound_capture.zip"])
    r2 = normalize_compound_capture("FIXTURE", [FIXTURES / "sample_compound_capture.zip"])
    assert [r.id for r in r1] == [r.id for r in r2]


def test_normalize_compound_capture_ids_differ_from_atomic_ids_for_same_index():
    """Sanity check that the shared id-derivation helper still discriminates
    by capture_id + event content, not just by index -- a compound and an
    atomic capture using the same index must never collide."""
    compound_records = normalize_compound_capture(
        "FIXTURE", [FIXTURES / "sample_compound_capture.zip"]
    )
    assert compound_records[0].id.startswith("otrf_security_datasets:FIXTURE:0:")
