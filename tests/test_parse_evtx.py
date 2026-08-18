"""Offline tests for `.evtx` -> OTRF-flat-shape parsing — no network.

Fixtures under tests/fixtures/evtx/ are single real 64KB EVTX chunks,
byte-truncated out of an actually-downloaded evtx-baseline win2022-evtx
capture (file header + one 65536-byte chunk — EVTX chunks are
self-contained, so a truncated file with a valid header and one full chunk
parses as a normal partial log). This is the same "small fixture trimmed
from real data" approach parse_otrf.py's tests already use
(tests/fixtures/sample_capture.zip), just via byte-truncation rather than a
JSON-lines subset, since `.evtx` is a binary chunked format with no
line-oriented equivalent to trim.
"""

from pathlib import Path

from src.ingest.parse_evtx import flatten_event, parse_evtx_file

FIXTURES = Path(__file__).parent / "fixtures" / "evtx"


def test_parse_evtx_file_returns_flat_otrf_shaped_dicts():
    events = parse_evtx_file(FIXTURES / "security_sample.evtx")
    assert len(events) > 0
    # No nested "Event"/"System"/"EventData" wrapper should survive — every
    # key is flat, matching OTRF's own JSON shape exactly (this is the
    # make-or-break requirement the whole task is built around).
    for event in events:
        assert "Event" not in event
        assert "System" not in event
        assert "EventData" not in event
        assert "Channel" in event
        assert "EventID" in event
        assert "Hostname" in event


def test_parse_evtx_file_process_creation_has_otrf_field_names():
    events = parse_evtx_file(FIXTURES / "sysmon_sample.evtx")
    process_events = [e for e in events if e.get("EventID") == 1]
    assert process_events, "fixture should contain at least one Sysmon EventID 1"
    proc = process_events[0]
    # These are the exact field names OTRF's own real captures carry for the
    # same (Channel, EventID) — see parse_evtx.py's module docstring for the
    # direct-inspection evidence. If these are missing/renamed, parity is
    # broken.
    for field in ("Image", "CommandLine", "ProcessGuid", "ParentImage", "User", "UtcTime"):
        assert field in proc, f"expected OTRF-equivalent field {field!r} on a Sysmon EventID 1 record"


def test_parse_evtx_file_registry_event_has_otrf_field_names():
    events = parse_evtx_file(FIXTURES / "sysmon_sample.evtx")
    registry_events = [e for e in events if e.get("EventID") == 13]
    assert registry_events, "fixture should contain at least one Sysmon EventID 13"
    reg = registry_events[0]
    for field in ("TargetObject", "Details", "Image", "ProcessGuid"):
        assert field in reg


def test_parse_evtx_file_security_process_creation_has_otrf_field_names():
    events = parse_evtx_file(FIXTURES / "security_sample.evtx")
    proc_events = [e for e in events if e.get("EventID") == 4688]
    assert proc_events, "fixture should contain at least one Security EventID 4688"
    proc = proc_events[0]
    for field in ("NewProcessName", "CommandLine", "SubjectUserSid", "TargetUserSid"):
        assert field in proc


def test_parse_evtx_file_timestamps_present_in_both_otrf_field_names():
    events = parse_evtx_file(FIXTURES / "security_sample.evtx")
    for event in events:
        # normalize.py's _parse_event_timestamp checks EventTime then
        # @timestamp then EventReceivedTime — both of the first two must be
        # populated here so a benign record's timestamp parses through the
        # identical code path as a malicious one.
        assert event.get("EventTime")
        assert event.get("@timestamp")


def test_flatten_event_drops_xml_namespace_noise():
    raw = {
        "Event": {
            "#attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"},
            "System": {
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Sysmon", "Guid": "GUID-HERE"}},
                "EventID": 1,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Computer": "TESTHOST",
                "TimeCreated": {"#attributes": {"SystemTime": "2022-01-01T00:00:00Z"}},
                "EventRecordID": 42,
                "Execution": {"#attributes": {"ProcessID": 100, "ThreadID": 200}},
            },
            "EventData": {"Image": "C:\\test.exe"},
        }
    }
    flat = flatten_event(raw)
    assert "#attributes" not in flat
    assert flat["Channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert flat["EventID"] == 1
    assert flat["Hostname"] == "TESTHOST"
    assert flat["EventTime"] == "2022-01-01T00:00:00Z"
    assert flat["@timestamp"] == "2022-01-01T00:00:00Z"
    assert flat["RecordNumber"] == 42
    assert flat["ExecutionProcessID"] == 100
    assert flat["ThreadID"] == 200
    assert flat["Image"] == "C:\\test.exe"
