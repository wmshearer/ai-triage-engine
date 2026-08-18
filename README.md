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
src/schema.py                       # AlertRecord — the normalized schema
src/corpus.py                       # assembles combined malicious+benign corpus at a stated ratio
src/ingest/fetch_otrf.py            # downloads a small OTRF working subset (network)
src/ingest/parse_otrf.py            # parses OTRF's own format (YAML metadata, zipped JSON-lines)
src/ingest/normalize.py             # maps parsed OTRF captures -> AlertRecord, preserving ATT&CK ground truth
src/ingest/fetch_evtx_baseline.py   # downloads a small evtx-baseline release asset (network)
src/ingest/parse_evtx.py            # parses raw .evtx into OTRF's own flat field convention
src/ingest/normalize_benign.py      # maps parsed evtx-baseline events -> AlertRecord (is_malicious=False)
src/ingest/leakage.py               # corpus-wide leakage mitigations (hostname pseudonymization)
tests/                              # offline tests against small committed fixtures — no network required
tests/fixtures/                     # trimmed real-shaped OTRF metadata YAML + capture zip
tests/fixtures/evtx/                # trimmed real evtx-baseline .evtx chunks (see test_parse_evtx.py)
data/raw/otrf/                      # gitignored cache for downloaded OTRF captures
data/raw/evtx_baseline/             # gitignored cache for downloaded evtx-baseline archives
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

# Real benign ingest — downloads one small (~27 MB) evtx-baseline release
# asset (win2022-evtx.tgz)
python -m src.ingest.fetch_evtx_baseline
```

To normalize what was downloaded into `AlertRecord`s, see
`src/ingest/normalize.py:normalize_capture()` (malicious) and
`src/ingest/normalize_benign.py:normalize_evtx_capture()` (benign). To
assemble both into one corpus at a stated ratio, see
`src/corpus.py:assemble_corpus()`.

## Benign corpus — making false-positive rate computable

OTRF's atomic captures are 100% malicious by construction (each capture IS
one ATT&CK technique's execution) — there is no way to compute a
false-positive rate without an independent source of labeled negatives. That
source is **[NextronSystems/evtx-baseline](https://github.com/NextronSystems/evtx-baseline)**
(Apache-2.0, verified via the GitHub API `license` endpoint and the raw
LICENSE file): real Sysmon + native Windows Event Log `.evtx` output from
genuine software installs across several VM builds — not synthetic data.
Full sourcing rationale: `../wshearer-site/research/phase-1-benign-corpus.md`.

**Field-name parity is the load-bearing requirement.** evtx-baseline ships
raw `.evtx` (binary Windows Event Log), while OTRF's own captures are
pre-flattened JSON from an NXLog/Winlogbeat/ELK pipeline. If the two sources
reached `AlertRecord.raw_event` with different field-naming conventions, an
evaluation could report excellent metrics while actually just learning
"which parser produced this record" — not "is this behavior malicious."
`src/ingest/parse_evtx.py:flatten_event()` reshapes the `.evtx` library's
nested JSON into OTRF's own flat convention (top-level `Channel`/`EventID`/
`Hostname`/`EventTime`, `EventData` keys merged to the top level), and
`tests/test_field_parity.py` proves it directly: it diffs the real,
downloaded-and-parsed key sets of a benign and a malicious `raw_event` for
the same (Channel, EventID) pair and fails if an unexplained field-name
mismatch appears.

**Leakage vectors** (hostname/domain, timestamp era, event-ID/channel
distribution, Windows build fingerprint — see the research brief's Section 5
for the full enumeration) are handled explicitly, not silently ignored:
- *Hostname/domain*: `src/ingest/leakage.py:pseudonymize_hostname()` strips
  the domain suffix and hashes what remains, applied identically to BOTH
  corpora in `src/corpus.py:assemble_corpus()` — asymmetric treatment (fixing
  one side only) would itself be a leak.
- *Timestamp era*: not neutralized in the schema (both sources' native
  timestamps are kept, since `raw_event` is explicitly lossless) — instead
  documented here as a constraint on future feature engineering: any model
  built on this corpus must not use absolute timestamp/date as a feature.
- *Event-ID/channel distribution skew*: `src/ingest/normalize_benign.py`
  filters evtx-baseline's ~330 available channels down to exactly the
  (Channel, EventID) pairs `normalize.py`'s own `_EVENT_TYPE_MAP` already
  classifies, so every classifiable event type is, by construction, observed
  on both sides.
- *Windows build/Sysmon-version fingerprint*: verified directly (not
  assumed) against all 5 downloaded OTRF captures — some Sysmon-version-
  specific fields (`Level`, `ProcessId`, `ParentUser` on Sysmon EventID 1)
  vary WITHIN OTRF's own malicious corpus depending on capture date, so they
  were kept rather than dropped (dropping real fields would lose signal
  without reducing actual class leakage); see
  `src/ingest/parse_evtx.py:flatten_event()`'s docstring for the full
  multi-capture verification.

**Class ratio**: `src/corpus.py` defaults to 4 benign : 1 malicious — a
stated design choice, not the ~99:1 real-SOC base rate (Alahmadi et al.,
USENIX Security 2022), because building at that extreme ratio against
OTRF's ~200K malicious events would need ~20M benign events, and Saito &
Rehmsmeier (PLOS ONE, 2015) note extreme imbalance makes precision/recall
estimates noisy at small absolute counts. See `src/corpus.py`'s module
docstring for the full reasoning; `assemble_corpus(benign_ratio=...)` is a
parameter specifically so this can be varied and the sensitivity reported,
not treated as a fixed truth.

## What Phase 1 does not do

- No agents, no LLM calls, no correlation/triage logic — that's a later phase.
- Linux `auditd`-format captures and AWS captures are not parsed (see
  "Known deviation" above).
- Multi-technique captures (a metadata YAML with more than one
  `attack_mappings` entry) are not disambiguated per-event; `normalize_capture`
  applies the first mapping to every event in the capture and this is
  documented in code, not silently assumed. None of the 5 captures in the
  default working subset hit this case.
- No actual model is trained/evaluated against the assembled corpus yet —
  that's the next phase this benign-ingest work unblocks (the corpus is now
  computable-FPR-ready, not yet scored).
