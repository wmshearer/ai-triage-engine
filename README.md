# AI Triage Engine — Phase 1: Ingest & Normalized Schema

An AI-assisted security-alert triage engine, built against a static, offline,
labeled dataset so its evaluation is honest and reproducible. This phase
covers **data ingest and a normalized schema with machine-readable ground
truth** only — no agents, no LLM pipeline, no dashboard yet.

## What this is (and isn't)

This project evaluates a triage pipeline against a **labeled corpus**, not a
live SOC. That distinction matters for what can honestly be claimed later:
metrics that require live-SOC analyst timestamps — **MTTD, MTTR, "analyst
hours saved"** — cannot be computed from a static dataset and will never
appear in this project's reporting. See
`../wshearer-site/research/phase-0-metrics.md` for the full reasoning.

## Dataset & licensing

**Primary source: [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets)
(Mordor), MIT licensed.** License verified directly via the GitHub API
(`license.spdx_id: "MIT"`) during this project's setup. It is the only
candidate dataset surveyed (see `../wshearer-site/research/phase-0-datasets.md`)
with structured, machine-parseable MITRE ATT&CK ground truth: each capture
ships a metadata YAML with an `attack_mappings: [{technique, sub-technique,
tactics}]` field, asserted by the OTRF researchers themselves, not inferred.

MIT permits redistribution, modification, and commercial use; the only
obligation is retaining the copyright notice, which is why this README
credits the project explicitly: **Copyright (c) 2021 Open Threat Research
Forge (OTRF), Security-Datasets project.**

No dataset files are committed to git — raw downloads are cached to
`data/raw/` (gitignored) and re-fetched via `src/ingest/fetch_otrf.py`. This
keeps the repo small and avoids any question of redistributing someone else's
(even permissively licensed) data files inside this repo's git history.

### Known deviation from the Phase 0 research brief — reported, not papered over

The brief described OTRF captures generically as "JSON-lines event captures."
Inspecting the actual repo (GitHub API tree listing + downloading real
captures) shows this is true for **Windows** atomic captures (155 of 159
atomic zips, confirmed via the API tree) but **false for the 2 Linux atomic
captures inspected**, which are raw `auditd` text log lines
(`type=SYSCALL msg=audit(...)...`), not JSON. The 2 AWS atomic captures were
not inspected this phase.

**Scope decision:** Phase 1 ingests Windows JSON captures only — the
dominant format and the one that matches a JSON-lines parser. Linux
`auditd`-format ingest is a real, distinct parsing problem (different schema,
different event semantics) and is explicitly out of scope here rather than
silently mis-parsed or silently dropped from the dataset description.

## Schema

`src/schema.py` defines `AlertRecord` (Pydantic v2), the one shape every
downstream phase consumes regardless of source dataset. Final field list:

| Field | Type | Purpose |
|---|---|---|
| `id` | `str` | Stable, content-derived identifier (reproducible across re-ingests). |
| `timestamp` | `datetime` | Event time, parsed from the source telemetry's own clock. |
| `source_host` | `str` | Host/asset the event was observed on. |
| `event_type` | `EventType` enum | Source-agnostic telemetry category (process/network/authentication/file/registry/scheduled_task/other). |
| `source_dataset` | `str` | Which dataset/project this record came from (provenance). |
| `source_capture_id` | `str` | The source dataset's own capture id (e.g. OTRF's `SDWIN-...`). |
| `raw_event` | `dict` | The unmodified source event, kept alongside the normalized fields so normalization is never lossy. |
| `is_malicious` | `bool` | Ground-truth label — required on every record. |
| `attack_technique` | `str \| None` | MITRE ATT&CK technique ID, from the source's own metadata; `None` iff benign. |
| `attack_subtechnique` | `str \| None` | ATT&CK sub-technique ID suffix, kept separate from the technique so technique-level rollups don't need string parsing. |
| `attack_tactics` | `list[str]` | ATT&CK tactic IDs (a technique can map to more than one); empty list for benign records. |

A model validator enforces the one hard invariant the rest of the project
depends on: `is_malicious=True` requires `attack_technique` to be set, and
`is_malicious=False` records must not carry one. This makes a labeling bug a
loud validation error at ingest time instead of a silent scoring error in a
later evaluation phase.

## Layout

```
src/schema.py                 # AlertRecord — the normalized schema
src/ingest/fetch_otrf.py      # downloads a small OTRF working subset (network)
src/ingest/parse_otrf.py      # parses OTRF's own format (YAML metadata, zipped JSON-lines)
src/ingest/normalize.py       # maps parsed OTRF captures -> AlertRecord, preserving ATT&CK ground truth
tests/                        # offline tests against small committed fixtures — no network required
tests/fixtures/               # trimmed real-shaped metadata YAML + capture zip + a benign event
data/raw/otrf/                # gitignored cache for downloaded captures (created by fetch_otrf.py)
```

## Running it

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Offline tests — no network, runs against tests/fixtures/ only
python -m pytest tests/ -q

# Real ingest — downloads a small (~4.5 MB), hand-picked subset of OTRF
# Windows atomic captures spanning distinct ATT&CK techniques
python -m src.ingest.fetch_otrf
```

To normalize what was downloaded into `AlertRecord`s, see
`src/ingest/normalize.py:normalize_capture()` — it takes a capture's metadata
YAML path and its data zip path(s) and returns a list of `AlertRecord`.

## What Phase 1 does not do

- No agents, no LLM calls, no correlation/triage logic — that's a later phase.
- No benign/noise records are ingested from a public source yet; OTRF atomic
  captures contain none by construction (the capture IS the attack). Negative
  examples are representable in the schema (`is_malicious=False`) and
  `src/ingest/normalize.py:make_benign_record()` exists to label an arbitrary
  event as one, but populating a real benign corpus (e.g. background traffic
  from a "compound" capture, or a synthetic source) is future work.
- Linux `auditd`-format captures and AWS captures are not parsed (see
  "Known deviation" above).
- Multi-technique captures (a metadata YAML with more than one
  `attack_mappings` entry) are not disambiguated per-event; `normalize_capture`
  applies the first mapping to every event in the capture and this is
  documented in code, not silently assumed. None of the 5 captures in the
  default working subset hit this case.
