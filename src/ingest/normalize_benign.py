"""Map evtx-baseline `.evtx` captures into the project's AlertRecord schema.

This is the benign-corpus mirror of normalize.py, and exists to close the
gap the Phase 1 research brief identified: OTRF's atomic captures are 100%
malicious by construction (the capture IS the attack), so a false-positive
rate is mathematically undefined without an independent source of labeled
negatives. See wshearer-site/research/phase-1-benign-corpus.md for the full
sourcing rationale.

THE CRITICAL REQUIREMENT this module exists to satisfy: benign records must
carry the SAME field-name convention as OTRF's malicious records, or the
resulting "evaluation" measures which parser produced a record instead of
whether the underlying behavior is malicious. This is achieved by leaning on
parse_evtx.py's `flatten_event()` — by the time an event dict reaches this
module, it is already OTRF-flat-shaped (top-level `Channel`/`EventID`/
`Hostname`/`EventTime`, EventData keys merged to the top level), so this
module's job is identical in shape to normalize.py: take a flat event dict,
classify it, wrap it as an AlertRecord. See tests/test_field_parity.py for
the concrete proof (real benign vs. real malicious raw_event key-set
comparison for a shared (Channel, EventID) pair).

Every event from evtx-baseline is labeled is_malicious=False with no ATT&CK
fields, because evtx-baseline's own stated purpose (per its README, cited in
the Phase 1 research brief) is "sample software installation and basic user
interaction" — i.e. asserted-benign by construction, the same evidentiary
standing OTRF's atomic captures have for asserted-malicious (both are
ground truth claimed by the respective dataset's own authors, not inferred
by this project).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.ingest.normalize import _EVENT_TYPE_MAP, make_benign_record
from src.ingest.parse_evtx import parse_evtx_file
from src.schema import AlertRecord

SOURCE_DATASET_NAME = "evtx_baseline"

# Every (Channel, EventID) normalize.py's _EVENT_TYPE_MAP can classify. Reused
# (not duplicated) as the default channel filter below — see
# filter_to_mapped_channels()'s docstring for why an unfiltered dump of
# evtx-baseline's ~330 channels would itself be a leakage vector.
_MAPPED_CHANNEL_KEYS: set[tuple[str, int]] = set(_EVENT_TYPE_MAP.keys())


def filter_to_mapped_channels(events: list[dict[str, Any]], event_type_map_keys: set[tuple[str, int]]) -> list[dict[str, Any]]:
    """Keep only events whose (Channel, EventID) appears in normalize.py's
    `_EVENT_TYPE_MAP`.

    This is the concrete mitigation for leakage vector #4 (event-ID/channel
    distribution skew, Phase 1 research Section 5): evtx-baseline's raw
    capture spans ~330 `.evtx` files covering hundreds of channels most of
    which OTRF's malicious captures never touch at all (e.g. AppV, Bluetooth,
    Diagnostics-Scripted — desktop-software-specific channels with no
    attack-relevant analog). Ingesting all of them unfiltered would make
    "channel is one only OTRF-side or only benign-side ever uses" a
    near-perfect classifier shortcut, the opposite of what a curated overlap
    is supposed to prevent. Filtering to exactly the same (Channel, EventID)
    keys normalize.py already classifies (Sysmon process/file/registry/
    network, Security auth/process, PowerShell, Task Scheduler) means every
    (Channel, EventID) pair a classifier could key on is, by construction,
    observed on BOTH sides at least once — the corpus documents the overlap
    it curates rather than dumping the raw imbalance in different-EventType
    coverage and hoping a downstream model ignores it.
    """
    kept = []
    for event in events:
        channel = str(event.get("Channel", "")).lower()
        try:
            event_id = int(event.get("EventID"))
        except (TypeError, ValueError):
            continue
        if (channel, event_id) in event_type_map_keys:
            kept.append(event)
    return kept


def normalize_evtx_file(
    evtx_path: Path | str,
    capture_id: str,
    start_index: int = 0,
    channel_filter: set[tuple[str, int]] | None = _MAPPED_CHANNEL_KEYS,
) -> list[AlertRecord]:
    """Normalize events in one `.evtx` file into labeled-benign AlertRecords.

    `capture_id` identifies which evtx-baseline VM capture (e.g.
    "win2022-evtx") this file came from, and `start_index` lets a caller
    (normalize_evtx_capture below) assign globally-unique, stable indices
    across multiple `.evtx` files from the same capture without them
    colliding — mirrors normalize.py's normalize_capture() indexing scheme
    for the same reason (stable, content-derived ids).

    `channel_filter` defaults to exactly the (Channel, EventID) pairs
    normalize.py already classifies, for the leakage reasons documented on
    filter_to_mapped_channels(); pass `None` to keep every event (e.g. for
    ad hoc inspection of what a channel actually contains).
    """
    events = parse_evtx_file(evtx_path)
    if channel_filter is not None:
        events = filter_to_mapped_channels(events, channel_filter)
    return [
        make_benign_record(event, source_dataset=SOURCE_DATASET_NAME, capture_id=capture_id, index=start_index + i)
        for i, event in enumerate(events)
    ]


def normalize_evtx_capture(evtx_paths: list[Path | str], capture_id: str) -> list[AlertRecord]:
    """Normalize every event across all `.evtx` files in one capture directory.

    A capture (e.g. evtx-baseline's win2022-evtx release asset) ships one
    `.evtx` file per Windows Event Log channel rather than one combined
    stream — this simply concatenates them under one capture_id, the same
    way normalize.py's normalize_capture() concatenates multiple OTRF data
    zips under one capture_id.
    """
    records: list[AlertRecord] = []
    index = 0
    for path in evtx_paths:
        file_records = normalize_evtx_file(path, capture_id=capture_id, start_index=index)
        records.extend(file_records)
        index += len(file_records)
    return records
