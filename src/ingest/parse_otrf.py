"""Parse raw OTRF Security-Datasets files into plain Python structures.

Deliberately separate from normalize.py: this module knows OTRF's on-disk
format (YAML metadata, zipped JSON-lines events) and nothing about the
project's AlertRecord schema. normalize.py knows the reverse. That split lets
tests exercise "did we read OTRF's format correctly" independently from "did
we map it into our schema correctly."
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

import yaml


def parse_metadata(yaml_path: Path | str) -> dict[str, Any]:
    """Load one capture's metadata YAML as-is.

    No reshaping here — attack_mappings, files[], etc. are returned exactly as
    OTRF authored them, so a change in their schema is visible immediately
    rather than masked by an early transformation.
    """
    text = Path(yaml_path).read_text()
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError(f"expected a YAML mapping at top level: {yaml_path}")
    return data


def parse_capture_events(zip_path: Path | str) -> list[dict[str, Any]]:
    """Read every JSON-lines event out of one capture zip.

    OTRF's Windows atomic captures ship as a zip containing a single .json
    file where each line is one standalone JSON object (confirmed by
    downloading and inspecting a real capture zip: one member file, 9002
    lines, each independently `json.loads`-able Windows Event Log JSON).
    Blank lines are skipped defensively; malformed lines raise rather than
    being silently dropped, since a silently-dropped event is a silently
    wrong ground-truth count.
    """
    events: list[dict[str, Any]] = []
    with zipfile.ZipFile(zip_path) as zf:
        json_members = [n for n in zf.namelist() if n.endswith(".json")]
        for member in json_members:
            with zf.open(member) as fh:
                for line_no, raw_line in enumerate(fh, start=1):
                    line = raw_line.decode("utf-8").strip()
                    if not line:
                        continue
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError as exc:
                        raise ValueError(f"{zip_path}:{member}:{line_no} is not valid JSON") from exc
    return events
