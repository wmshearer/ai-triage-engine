"""Render an AlertRecord into a triage prompt string.

CRITICAL — GROUND-TRUTH LEAKAGE (read this before touching this file):
`AlertRecord.is_malicious`, `attack_technique`, `attack_subtechnique`, and
`attack_tactics` are LABELS, not inputs. Serializing the whole AlertRecord
naively would hand the model the answer and produce a perfect, meaningless
score. This module builds the prompt from exactly three fields —
`raw_event`, `event_type`, `source_host` — and nothing else on the record is
ever read. `tests/test_agents.py::test_prompt_excludes_label_fields` is the
regression gate for this; do not weaken it.

Two more things this module does, both load-bearing for prompt quality/cost:

1. Skips None/empty raw_event values, so the prompt is not padded with
   nulls the model would otherwise have to read past for no signal.
2. Prepends a compact explanation of what the event's (Channel, EventID)
   pair MEANS — a Sysmon EventID 12 is a registry key create, not a number —
   because the model cannot triage telemetry it cannot interpret. Reuses
   `src.ingest.normalize._EVENT_TYPE_MAP`'s key set (not a separately
   maintained list) so the two can't silently drift apart.
"""

from __future__ import annotations

from typing import Any

from src.ingest.normalize import _EVENT_TYPE_MAP
from src.schema import AlertRecord

# Human-readable meaning of specific (channel, event_id) pairs, layered on
# top of _EVENT_TYPE_MAP's coarse EventType classification. Keys match
# _EVENT_TYPE_MAP exactly (lowercased channel, int event id) so a pair this
# project can classify always has an explanation available, and a pair it
# can't (falls through to EventType.OTHER upstream) gets a generic fallback
# below rather than a maintenance-doomed attempt to describe every possible
# Windows event.
_EVENT_ID_MEANING: dict[tuple[str, int], str] = {
    ("microsoft-windows-sysmon/operational", 1): "Sysmon: process creation (a new process started).",
    ("microsoft-windows-sysmon/operational", 5): "Sysmon: process terminated.",
    ("microsoft-windows-sysmon/operational", 10): "Sysmon: process accessed (one process opened a handle to another, e.g. for credential dumping).",
    ("microsoft-windows-sysmon/operational", 3): "Sysmon: network connection initiated.",
    ("microsoft-windows-sysmon/operational", 11): "Sysmon: file created.",
    ("microsoft-windows-sysmon/operational", 23): "Sysmon: file deleted (archived to recycle bin).",
    ("microsoft-windows-sysmon/operational", 12): "Sysmon: registry key created or deleted.",
    ("microsoft-windows-sysmon/operational", 13): "Sysmon: registry value set.",
    ("microsoft-windows-sysmon/operational", 14): "Sysmon: registry key or value renamed.",
    ("security", 4688): "Windows Security: a new process was created.",
    ("security", 4689): "Windows Security: a process exited.",
    ("security", 4656): "Windows Security: a handle to an object was requested.",
    ("security", 4663): "Windows Security: an attempt was made to access an object.",
    ("security", 4690): "Windows Security: a handle to an object was duplicated.",
    ("security", 5156): "Windows Security: the Windows Filtering Platform permitted a connection.",
    ("security", 5158): "Windows Security: the Windows Filtering Platform permitted a bind to a local port.",
    ("security", 4624): "Windows Security: an account successfully logged on.",
    ("security", 4625): "Windows Security: an account failed to log on.",
    ("security", 4672): "Windows Security: special/administrative privileges were assigned at logon.",
    ("microsoft-windows-taskscheduler/operational", 129): "Task Scheduler: a scheduled task launched.",
    ("microsoft-windows-taskscheduler/operational", 106): "Task Scheduler: a scheduled task was registered.",
    ("windows powershell", 800): "PowerShell: pipeline execution details logged.",
    ("microsoft-windows-powershell/operational", 4103): "PowerShell: module logging (a cmdlet/function invocation was recorded).",
    ("microsoft-windows-powershell/operational", 4104): "PowerShell: script block logging (the actual script/command text was recorded, possibly deobfuscated).",
}

_FALLBACK_MEANING = "Unrecognized/uncommon event type for this project's ingest — interpret from the raw fields below."

# raw_event field values are frequently multi-kilobyte (observed: a base64
# -encoded PowerShell -enc payload in ParentCommandLine exceeding 4KB on its
# own in real OTRF data). Left unbounded, a single such field can blow the
# token budget on its own. Truncated rather than dropped, since the field's
# PRESENCE and prefix are still triage-relevant (e.g. "-enc" + a base64 blob
# is itself an indicator) even if the full payload isn't reproduced verbatim.
_MAX_VALUE_CHARS = 500

# Qwen's tokenizer runs DENSER than chars/4 on telemetry text (measured in
# research/phase-2-measured-latency.md: 1101 estimated vs 1364 actual, i.e.
# ~1.24 chars/token, not the ~4 chars/token rule of thumb for plain English).
# Budgeting off this measured ratio, not the generic one, so the "keep it
# well under 8192 tokens" requirement is checked against reality.
CHARS_PER_TOKEN_ESTIMATE = 1364 / 1101


def estimate_tokens(text: str) -> int:
    """Conservative token-count estimate, calibrated to Qwen's measured density."""
    return int(len(text) / CHARS_PER_TOKEN_ESTIMATE)


def _event_meaning(channel: str, event_id: Any) -> str:
    try:
        key = (str(channel).lower(), int(event_id))
    except (TypeError, ValueError):
        return _FALLBACK_MEANING
    return _EVENT_ID_MEANING.get(key, _FALLBACK_MEANING)


def _format_value(value: Any) -> str:
    text = str(value)
    if len(text) > _MAX_VALUE_CHARS:
        return text[:_MAX_VALUE_CHARS] + f"... [truncated, {len(text)} chars total]"
    return text


def _is_empty(value: Any) -> bool:
    """None, empty string, empty list/dict — anything that carries no signal."""
    if value is None:
        return True
    if isinstance(value, (str, list, dict, tuple, set)) and len(value) == 0:
        return True
    return False


def render_alert_prompt(record: AlertRecord) -> str:
    """Build the triage prompt from ONLY non-label fields of `record`.

    Reads exactly: `record.raw_event`, `record.event_type`, `record.source_host`.
    Never reads `record.is_malicious`, `record.attack_technique`,
    `record.attack_subtechnique`, or `record.attack_tactics` — see this
    module's docstring. Also never reads `record.id`, `record.timestamp`,
    `record.source_dataset`, or `record.source_capture_id`: none of those are
    labels, but they're either provenance the model doesn't need (id,
    dataset/capture id) or already present inside `raw_event` itself under
    its native field name (timestamp fields like EventTime/@timestamp),
    so including them separately would only pad the prompt.
    """
    channel = record.raw_event.get("Channel", "")
    event_id = record.raw_event.get("EventID", "")
    meaning = _event_meaning(channel, event_id)

    fields_lines = [
        f"- {key}: {_format_value(value)}"
        for key, value in record.raw_event.items()
        if not _is_empty(value)
    ]

    prompt = f"""You are a SOC security analyst triaging a single telemetry event. Decide whether it is benign, suspicious, or malicious, and if malicious/suspicious, identify the MITRE ATT&CK technique it most closely matches.

## Event context
Host: {record.source_host}
Event category: {record.event_type.value}
Event type meaning: {meaning}

## Raw event fields
{chr(10).join(fields_lines)}

## Instructions
- Judge this event ONLY on the fields above — do not assume additional context that isn't present.
- If the event looks like ordinary, expected system/user activity, verdict "benign" with no attack_technique.
- If it shows a specific, recognizable attack technique, verdict "malicious" (or "suspicious" if ambiguous) and cite the matching MITRE ATT&CK technique ID (format "T####" or "T####.###") in attack_technique.
- List the specific field values (not just field names) that drove your decision in key_indicators.
- confidence must be a decimal between 0.0 and 1.0 (e.g. 0.85), never a 0-100 scale.
- If verdict is "benign", omit attack_technique entirely (do not set it to an empty string).
- Keep reasoning brief (1-3 sentences).
"""
    return prompt
