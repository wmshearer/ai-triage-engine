"""Map raw OTRF captures into the project's normalized AlertRecord schema.

This is the one place source-format knowledge (parse_otrf.py) meets
schema knowledge (schema.py). Everything else in the pipeline should only
ever see AlertRecord instances, never raw OTRF JSON.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.ingest.parse_otrf import parse_capture_events, parse_metadata
from src.schema import AlertRecord, EventType

# (Channel, EventID) -> EventType. Built from an actual frequency count of a
# real downloaded capture (empire_powerview_ldap_ntsecuritydescriptor, 9002
# events) rather than assumed from Sysmon documentation alone — every key
# below was observed in real data during Phase 1 research. Channel names are
# matched case-insensitively because OTRF captures the same channel as both
# "Security" and "security" depending on collector (confirmed in the same
# capture). This is intentionally NOT an exhaustive Sysmon/Security event-id
# map — event types absent from the ingested subset fall through to OTHER,
# which is the honest answer for "we haven't seen this one yet."
_EVENT_TYPE_MAP: dict[tuple[str, int], EventType] = {
    ("microsoft-windows-sysmon/operational", 1): EventType.PROCESS,   # Sysmon: Process create
    ("microsoft-windows-sysmon/operational", 5): EventType.PROCESS,   # Sysmon: Process terminated
    ("microsoft-windows-sysmon/operational", 10): EventType.PROCESS,  # Sysmon: Process accessed
    ("microsoft-windows-sysmon/operational", 3): EventType.NETWORK,   # Sysmon: Network connection
    ("microsoft-windows-sysmon/operational", 11): EventType.FILE,     # Sysmon: File create
    ("microsoft-windows-sysmon/operational", 23): EventType.FILE,     # Sysmon: File delete
    ("microsoft-windows-sysmon/operational", 12): EventType.REGISTRY,  # Sysmon: Registry object added/deleted
    ("microsoft-windows-sysmon/operational", 13): EventType.REGISTRY,  # Sysmon: Registry value set
    ("microsoft-windows-sysmon/operational", 14): EventType.REGISTRY,  # Sysmon: Registry object renamed
    ("security", 4688): EventType.PROCESS,          # Windows Security: process creation
    ("security", 4689): EventType.PROCESS,          # Windows Security: process exit
    ("security", 4656): EventType.FILE,              # Windows Security: handle to object requested
    ("security", 4663): EventType.FILE,              # Windows Security: attempt to access object
    ("security", 4690): EventType.FILE,              # Windows Security: handle to object duplicated
    ("security", 5156): EventType.NETWORK,           # Windows Security: WFP permitted connection
    ("security", 5158): EventType.NETWORK,           # Windows Security: WFP permitted bind
    ("security", 4624): EventType.AUTHENTICATION,     # Windows Security: successful logon
    ("security", 4625): EventType.AUTHENTICATION,     # Windows Security: failed logon
    ("security", 4672): EventType.AUTHENTICATION,     # Windows Security: special privileges assigned at logon
    ("microsoft-windows-taskscheduler/operational", 129): EventType.SCHEDULED_TASK,  # Task Scheduler: task launched
    ("microsoft-windows-taskscheduler/operational", 106): EventType.SCHEDULED_TASK,  # Task Scheduler: task registered
    ("windows powershell", 800): EventType.PROCESS,   # PowerShell pipeline execution details
    ("microsoft-windows-powershell/operational", 4103): EventType.PROCESS,  # PowerShell module logging
    ("microsoft-windows-powershell/operational", 4104): EventType.PROCESS,  # PowerShell script block logging
}


def _classify_event_type(event: dict[str, Any]) -> EventType:
    channel = str(event.get("Channel", "")).lower()
    try:
        event_id = int(event.get("EventID"))
    except (TypeError, ValueError):
        return EventType.OTHER
    return _EVENT_TYPE_MAP.get((channel, event_id), EventType.OTHER)


def _parse_event_timestamp(event: dict[str, Any]) -> datetime:
    """Extract event time, preferring OTRF's own EventTime over the ELK '@timestamp'.

    EventTime is the source-system clock (when Windows recorded the event);
    '@timestamp' is when OTRF's Logstash/Elastic pipeline ingested it, which
    can lag EventTime by seconds. For ATT&CK-technique attribution and
    ordering, the source-system clock is the more meaningful "when it
    happened," so it's preferred when both are present. Falls back to
    '@timestamp' or EventReceivedTime if EventTime is absent, and raises
    rather than silently defaulting to "now" if no timestamp exists at all —
    a fabricated timestamp is worse than a loud failure for a ground-truth
    corpus.
    """
    for field in ("EventTime", "@timestamp", "EventReceivedTime"):
        raw = event.get(field)
        if raw:
            # OTRF timestamps observed in two formats: ISO8601 with 'Z'
            # ('@timestamp') and 'YYYY-MM-DD HH:MM:SS' local ('EventTime').
            try:
                return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            except ValueError:
                return datetime.strptime(str(raw), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    raise ValueError(f"event has no recognizable timestamp field: keys={list(event.keys())}")


def _record_id(source_dataset: str, capture_id: str, index: int, event: dict[str, Any]) -> str:
    """Deterministic id: hash of (capture, index, a stable slice of the event).

    Using the event's own content (not just capture+index) means the id
    changes if the underlying event content ever changes, which is the
    correct behavior for detecting a stale cache — but capture_id+index alone
    would collide across captures downloaded at different times if OTRF ever
    edits a file, so the content hash is included as a integrity check, not
    just for uniqueness.
    """
    digest_input = f"{capture_id}:{index}:{event}".encode("utf-8", errors="replace")
    digest = hashlib.sha256(digest_input).hexdigest()[:16]
    return f"{source_dataset}:{capture_id}:{index}:{digest}"


SOURCE_DATASET_NAME = "otrf_security_datasets"


def normalize_capture(metadata_path: Path | str, event_zip_paths: list[Path | str]) -> list[AlertRecord]:
    """Normalize one OTRF capture (its metadata + one or more event zips) into AlertRecords.

    Ground truth comes entirely from the metadata YAML's `attack_mappings`
    list, applied uniformly to every event in the capture. This is a direct
    consequence of how OTRF "atomic" captures are constructed (confirmed via
    metadata inspection): the capture already IS a single technique's
    execution, no per-event labeling exists or is needed within it. A capture
    with multiple attack_mappings entries (observed as possible in the
    schema, though not in this project's chosen subset) is applied as: every
    event gets the FIRST mapping's technique/tactics — multi-technique
    captures needing per-event disambiguation are out of scope for Phase 1
    and flagged in the README rather than silently guessed at.
    """
    meta = parse_metadata(metadata_path)
    capture_id = meta["id"]
    mappings = meta.get("attack_mappings") or []
    if not mappings:
        raise ValueError(f"{capture_id}: no attack_mappings in metadata — cannot establish ground truth")
    primary = mappings[0]
    technique = primary.get("technique")
    subtechnique = primary.get("sub-technique")
    tactics = list(primary.get("tactics") or [])

    records: list[AlertRecord] = []
    index = 0
    for zip_path in event_zip_paths:
        for event in parse_capture_events(zip_path):
            records.append(
                AlertRecord(
                    id=_record_id(SOURCE_DATASET_NAME, capture_id, index, event),
                    timestamp=_parse_event_timestamp(event),
                    source_host=str(event.get("Hostname", "unknown")),
                    event_type=_classify_event_type(event),
                    source_dataset=SOURCE_DATASET_NAME,
                    source_capture_id=capture_id,
                    raw_event=event,
                    is_malicious=True,
                    attack_technique=technique,
                    attack_subtechnique=subtechnique,
                    attack_tactics=tactics,
                )
            )
            index += 1
    return records


def make_benign_record(event: dict[str, Any], source_dataset: str, capture_id: str, index: int) -> AlertRecord:
    """Wrap an arbitrary event as a labeled-benign AlertRecord.

    Exists because OTRF atomic captures contain zero benign noise by
    construction (Phase 0 research flagged this explicitly: "atomic captures
    ARE the attack"). A triage evaluation needs negatives to measure false
    positives against, so this function lets normalize.py (or a future
    "benign background" ingest source) label any ordinary event as a
    negative example using the same schema and id scheme as attack records —
    see tests/test_normalize.py for the concrete usage.
    """
    return AlertRecord(
        id=_record_id(source_dataset, capture_id, index, event),
        timestamp=_parse_event_timestamp(event),
        source_host=str(event.get("Hostname", "unknown")),
        event_type=_classify_event_type(event),
        source_dataset=source_dataset,
        source_capture_id=capture_id,
        raw_event=event,
        is_malicious=False,
        attack_technique=None,
        attack_subtechnique=None,
        attack_tactics=[],
    )
