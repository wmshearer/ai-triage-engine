"""Offline tests for OTRF format parsing — no network."""

from pathlib import Path

from src.ingest.parse_otrf import parse_capture_events, parse_metadata

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_metadata_reads_attack_mappings():
    meta = parse_metadata(FIXTURES / "sample_metadata.yaml")
    assert meta["id"] == "SDWIN-190319020147"
    assert meta["attack_mappings"] == [
        {"technique": "T1069", "sub-technique": "001", "tactics": ["TA0007"]}
    ]
    assert meta["files"][0]["type"] == "Host"
    assert meta["files"][0]["link"].endswith(".zip")


def test_parse_capture_events_reads_all_jsonlines():
    events = parse_capture_events(FIXTURES / "sample_capture.zip")
    assert len(events) == 4
    assert events[0]["EventID"] == 4103
    assert all("Hostname" in e for e in events)


def test_parse_capture_events_rejects_malformed_json(tmp_path):
    import zipfile

    bad_zip = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad_zip, "w") as zf:
        zf.writestr("bad.json", '{"ok": true}\nnot json at all\n')

    try:
        parse_capture_events(bad_zip)
        assert False, "expected ValueError on malformed JSON line"
    except ValueError as exc:
        assert "not valid JSON" in str(exc)
