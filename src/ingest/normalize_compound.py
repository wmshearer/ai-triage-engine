"""Map OTRF `compound/` captures into the project's AlertRecord schema.

Sibling to `normalize.py`, kept separate rather than folded in, because the
ground-truth story is genuinely different, not just the fetch mechanics:

`normalize.py:normalize_capture()` gets its ATT&CK ground truth from an
atomic capture's own metadata YAML (`attack_mappings[0]`), applied uniformly
to every event, which is honest ONLY because an atomic capture IS one
technique's execution by construction. Compound captures are not that — the
APT29 ATT&CK Evals scenarios each span 15+ distinct techniques across
multiple attacker stages, and OTRF publishes no per-event or single-primary
technique for them anywhere (verified: `datasets/compound/apt29/README.md`
and `day{1,2}/README.md` give per-Channel/per-EventID counts only; the
`emulationplans/apt29.xlsx` spreadsheet is a narrative operator runbook keyed
by attacker "step" like "3.B", with no join key back to individual telemetry
records). Calling `normalize_capture()` on one of these and taking
`attack_mappings[0]` would silently invent a false "this whole capture is
technique X" claim OTRF never made — exactly the kind of guessed ground truth
`src/schema.py`'s ground-truth block forbids.

What OTRF DOES assert, directly and unambiguously, for these captures:
  - every event in the capture comes from a real, executed APT29 ATT&CK
    Evals Round 2 red-team scenario, i.e. every event's source SESSION is
    malicious activity or its logging byproduct (confirmed:
    `datasets/compound/apt29/README.md`'s own "ATT&CK Evaluation" section
    and the two scenario READMEs)
  - this is a multi-technique campaign, not resolvable to one technique
    per event without inventing a mapping OTRF never published

So every record here is labeled `is_malicious=True` (an assertion OTRF makes,
not a guess this code makes) with `attack_technique` set to the explicit
`MULTI_TECHNIQUE_SENTINEL` and `technique_unresolved=True` (see
src/schema.py) — visible in every downstream metric as its own bucket,
never silently blended into a real technique ID or a null.
"""

from __future__ import annotations

from pathlib import Path

from src.ingest.normalize import (
    _classify_event_type,
    _parse_event_timestamp,
    _record_id,
)
from src.ingest.parse_otrf import parse_capture_events
from src.schema import MULTI_TECHNIQUE_SENTINEL, AlertRecord

SOURCE_DATASET_NAME = "otrf_security_datasets"


def normalize_compound_capture(capture_id: str, event_zip_paths: list[Path | str]) -> list[AlertRecord]:
    """Normalize one OTRF compound capture's event zip(s) into AlertRecords.

    Every record is labeled malicious with the multi-technique-unresolved
    sentinel (see module docstring for why) — there is no per-event
    disambiguation available from anything OTRF publishes for compound
    datasets, unlike `normalize.py:normalize_capture()`'s atomic-capture path
    which has a real metadata YAML to read a single, OTRF-asserted technique
    from.

    Reuses `normalize.py`'s own event classification, timestamp parsing, and
    id-derivation helpers rather than re-implementing them, so a compound and
    an atomic capture that both contain (say) a Sysmon EventID 1 record are
    classified/identified identically — the only thing that differs here is
    the ground-truth assignment, not the parsing.
    """
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
                    attack_technique=MULTI_TECHNIQUE_SENTINEL,
                    attack_subtechnique=None,
                    attack_tactics=[],
                    technique_unresolved=True,
                )
            )
            index += 1
    return records
