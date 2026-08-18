"""Parse raw evtx-baseline `.evtx` files into OTRF-shaped plain Python dicts.

Library choice: **`evtx` (PyPI package `evtx`, aka `pyevtx-rs`, by
omerbenamram/evtx)** — dual MIT/Apache-2.0 licensed (confirmed via the wheel's
own METADATA: `License :: OSI Approved :: MIT License`), actively maintained
(0.12.x releases, Python 3.10-3.14 wheels published), Rust-backed for safety
and speed but with a plain Python API (`PyEvtxParser.records_json()`). Chosen
over `python-evtx` (williballenthin) because that library only exposes a
low-level Record/XML-node API with no built-in JSON projection, which would
require hand-rolling an XML-to-dict walk for every event schema variant this
project touches — `evtx` already does that walk and hands back parsed JSON,
so the only work left here is renaming fields, not building an XML parser.

THE CRITICAL PART — field-name parity with OTRF (see module docstring in
normalize_benign.py for the full rationale): `evtx`'s `records_json()` yields
each record as `{"Event": {"System": {...}, "EventData": {...}}}`, a nested
shape that does NOT match OTRF's flat JSON (`Channel`, `EventID`, `Hostname`,
... all top-level, `EventData` keys merged straight into the top level too).
Confirmed by direct inspection of a real evtx-baseline win2022-evtx.tgz
capture parsed with this library: `Event.EventData` keys for Sysmon EventID 1
(`Image`, `CommandLine`, `ProcessGuid`, `Hashes`, ...), EventID 13
(`TargetObject`, `Details`, `EventType`, ...), and Security EventID 4688
(`NewProcessName`, `CommandLine`, `SubjectUserSid`, `TargetUserSid`, ...) are
BYTE-IDENTICAL field names to what real OTRF captures already carry for the
same (Channel, EventID) pairs (verified against
data/raw/otrf/captures/*.zip content, not assumed from documentation). So
`flatten_event()` below does the *shape* transform (nested -> flat, matching
OTRF's own flattening of Windows Event Log XML) while relying on the
underlying field *names* already matching because both sources ultimately
originate from the same Windows Event Log EventData schema per event type.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from evtx import PyEvtxParser


def _unwrap_attributed(node: Any) -> Any:
    """Collapse evtx's `{"#attributes": {...}, "#text": ...}` wrapper shape.

    The `evtx` library represents an XML element that has both attributes and
    a text value (or just attributes) as a dict with special `#attributes`/
    `#text` keys (confirmed by inspecting real output, e.g.
    `System.TimeCreated == {"#attributes": {"SystemTime": "..."}}` and
    `System.EventID` sometimes appearing as a bare int and sometimes as
    `{"#attributes": {...}, "#text": 1}` depending on schema version). This
    project only ever wants the plain value, never the XML-attribute
    wrapper, so this collapses it uniformly rather than special-casing each
    call site.
    """
    if isinstance(node, dict) and "#text" in node:
        return node["#text"]
    return node


def flatten_event(raw: dict[str, Any]) -> dict[str, Any]:
    """Reshape one `evtx` nested JSON record into OTRF's flat field convention.

    Deliberately maps ONLY the fields OTRF's own real captures are confirmed
    (by direct inspection, see module docstring) to carry, rather than
    inventing new field names for `.evtx`-only metadata. Each decision below
    is explicit per the task's "map or drop, don't leave two schemas"
    requirement:

    Mapped (present in both sources under the same name, or a documented
    rename):
      - Channel, EventID, Keywords, Task, Opcode, Version    -> same name
      - System.Computer                  -> Hostname (OTRF's own field name
        for "which host emitted this event"; evtx-baseline's `.evtx` calls
        the equivalent field `Computer`, which is the raw Windows Event Log
        XML element name OTRF's own NXLog/Winlogbeat shipper renamed to
        `Hostname` at collection time — same underlying data, source-specific
        collector naming, so this is a rename not a fabrication)
      - System.TimeCreated.SystemTime    -> EventTime AND @timestamp (OTRF
        carries both; `_parse_event_timestamp` in normalize.py already
        prefers EventTime then falls back to @timestamp, so both must be
        present in the same format for a benign record to parse identically
        to a malicious one through the exact same code path)
      - System.EventRecordID             -> RecordNumber (OTRF's field name
        for the same per-channel monotonic sequence number Windows assigns)
      - Event.EventData.*                -> merged directly into the top
        level (OTRF's own JSON already does this flattening from the source
        Windows Event Log XML's <EventData><Data Name="X">value</Data>...>
        structure, e.g. Sysmon's `Image`/`CommandLine`/`ProcessGuid`,
        Security's `SubjectUserSid`/`NewProcessName`/`TargetUserSid` — see
        module docstring for the direct-inspection evidence these key names
        already match byte-for-byte across both sources for the event types
        this project's `_EVENT_TYPE_MAP` cares about)

    Deliberately DROPPED (present in evtx-baseline's raw XML, no OTRF
    equivalent, and not needed by any code downstream of raw_event today):
      - System.Provider (Name/Guid)      -> OTRF's captures don't carry a
        separate provider GUID as a top-level field in the trimmed JSON this
        project ingests (`ProviderGuid` DOES appear in some real OTRF
        records per direct inspection of data/raw/otrf captures, so this one
        IS mapped through, see below — listed here only to document that the
        two attribute sub-keys `Name`/`Guid` are collapsed to the single
        `ProviderGuid` value, matching OTRF's own single-field convention,
        rather than kept as a nested Provider object)
      - System.Execution (ProcessID/ThreadID attrs) -> OTRF has a flat
        `ExecutionProcessID`/`ThreadID` pair (confirmed in real captures);
        mapped through as such, not dropped
      - System.Correlation.ActivityID    -> mapped to `ActivityID` (present
        in some real OTRF records, e.g. PowerShell 4104's `ActivityID`)
      - System.Security.UserID           -> mapped to `UserID` (present in
        real OTRF Sysmon/PowerShell records)
      - The `#attributes` XML-namespace wrapper on the outer `Event` node
        itself (`xmlns=...`) -> dropped entirely; this is evtx's own
        serialization artifact of the raw XML namespace declaration, has no
        OTRF equivalent field at all, and carries zero behavioral signal
        (every single event, benign or malicious, has the identical
        Microsoft schema namespace URI — it is a constant, not a feature)
      - `System.Level` and EventData's `ProcessId`/`ParentUser` on Sysmon
        EventID 1 -> KEPT, not dropped, after direct verification across ALL
        5 downloaded OTRF captures (not just one): 2 of the 5
        (empire_shell_net_localgroup_administrators,
        empire_shell_net_local_users — both dated 2019/03) never populate
        these 3 fields on any of their 7 combined Sysmon EventID 1 records,
        while the other 3 captures DO (131 of 140 total OTRF Sysmon-EventID-1
        records across the full downloaded set carry `ProcessId`). This is
        real Sysmon-version variance WITHIN OTRF's own malicious corpus, not
        a benign-vs-malicious split — so dropping these fields would remove
        real signal for no leakage-reduction benefit, and keeping them is the
        honest choice. tests/test_field_parity.py's fixture happens to use
        one of the 2 older-Sysmon captures, so its own parity assertion
        documents this specific-fixture-pair variance explicitly rather than
        asserting a stricter global parity than the real multi-capture
        picture actually supports — see that test's comments for the full
        multi-capture verification.

    Anything not listed above that still shows up in `Event.EventData` is
    passed through verbatim at the top level (see loop below) rather than
    allow-listed field-by-field, because per-event-type EventData schemas
    number in the dozens across both sources and OTRF's own ingest already
    treats "whatever the source emitted" as authoritative for that layer —
    the parity claim this project makes is about the *shape* (flat, EventData
    merged to top level) and the *(Channel, EventID)-keyed field names* being
    real Windows Event Log schema names, not about a hand-maintained
    allowlist stanza matching every possible EventData key ahead of time.
    """
    event = raw.get("Event", {})
    system = event.get("System", {})
    event_data = event.get("EventData") or {}

    flat: dict[str, Any] = {}

    # --- EventData first, so the explicit System-derived fields below can
    # never be silently shadowed by a same-named EventData key (none observed
    # in practice, but System-derived ground truth should always win). ---
    if isinstance(event_data, dict):
        for key, value in event_data.items():
            flat[key] = value

    provider = system.get("Provider") or {}
    provider_attrs = provider.get("#attributes") or {}
    execution = system.get("Execution") or {}
    execution_attrs = execution.get("#attributes") or {}
    correlation = system.get("Correlation") or {}
    correlation_attrs = correlation.get("#attributes") if isinstance(correlation, dict) else {}
    security = system.get("Security") or {}
    security_attrs = security.get("#attributes") if isinstance(security, dict) else {}
    time_created = system.get("TimeCreated") or {}
    time_created_attrs = time_created.get("#attributes") or {}

    system_time = time_created_attrs.get("SystemTime")

    flat["Channel"] = system.get("Channel")
    flat["EventID"] = _unwrap_attributed(system.get("EventID"))
    flat["Hostname"] = system.get("Computer")
    if system_time:
        # OTRF carries the source clock under both names (see
        # _parse_event_timestamp in normalize.py, which prefers EventTime
        # then falls back to @timestamp) — both must be populated here so a
        # benign record parses through the identical timestamp-selection
        # code path as a malicious one, not a benign-only shortcut.
        flat["EventTime"] = system_time
        flat["@timestamp"] = system_time
    if "RecordNumber" not in flat:
        flat["RecordNumber"] = system.get("EventRecordID")
    for name in ("Keywords", "Task", "Opcode", "Version", "Level"):
        if name in system:
            flat[name] = system[name]
    if provider_attrs.get("Guid"):
        flat["ProviderGuid"] = provider_attrs["Guid"]
    if execution_attrs.get("ProcessID") is not None:
        flat["ExecutionProcessID"] = execution_attrs["ProcessID"]
    if execution_attrs.get("ThreadID") is not None:
        flat["ThreadID"] = execution_attrs["ThreadID"]
    if correlation_attrs and correlation_attrs.get("ActivityID"):
        flat["ActivityID"] = correlation_attrs["ActivityID"]
    if security_attrs and security_attrs.get("UserID"):
        flat["UserID"] = security_attrs["UserID"]

    return flat


def parse_evtx_file(evtx_path: Path | str) -> list[dict[str, Any]]:
    """Parse one `.evtx` file into a list of OTRF-flat-shaped event dicts.

    Malformed records raise rather than being silently skipped, mirroring
    parse_otrf.py's `parse_capture_events` policy — a silently-dropped event
    here would be a silently-wrong benign-corpus count, same failure mode the
    OTRF side already guards against.
    """
    parser = PyEvtxParser(str(evtx_path))
    events: list[dict[str, Any]] = []
    for record in parser.records_json():
        try:
            raw = json.loads(record["data"])
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ValueError(f"{evtx_path}: record {record.get('event_record_id')} is not valid JSON") from exc
        events.append(flatten_event(raw))
    return events
