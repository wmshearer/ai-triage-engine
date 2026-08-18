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
| `attack_technique` | `str \| None` | MITRE ATT&CK technique ID, from the source's own metadata; `None` iff benign; or the `MULTI_TECHNIQUE_UNRESOLVED` sentinel (see below) for a multi-technique compound-capture record. |
| `attack_subtechnique` | `str \| None` | ATT&CK sub-technique ID suffix, kept separate from the technique so technique-level rollups don't need string parsing. |
| `attack_tactics` | `list[str]` | ATT&CK tactic IDs (a technique can map to more than one); empty list for benign records. |
| `technique_unresolved` | `bool` | `True` iff `attack_technique == MULTI_TECHNIQUE_UNRESOLVED` — see "Process-creation (EventID 1) coverage" below. `False` for every atomic-capture and benign record. |

A model validator enforces the one hard invariant the rest of the project
depends on: `is_malicious=True` requires `attack_technique` to be set, and
`is_malicious=False` records must not carry one. This makes a labeling bug a
loud validation error at ingest time instead of a silent scoring error in a
later evaluation phase. One explicit sentinel value,
`MULTI_TECHNIQUE_UNRESOLVED`, is allowed to satisfy "malicious requires
attack_technique" without asserting a real technique ID — see the next
section for why it exists and why it does not weaken this invariant.

## Layout

```
src/schema.py                       # AlertRecord — the normalized schema
src/corpus.py                       # assembles combined malicious+benign corpus at a stated ratio
src/ingest/fetch_otrf.py            # downloads a small OTRF working subset of atomic captures (network)
src/ingest/parse_otrf.py            # parses OTRF's own format (YAML metadata, zipped JSON-lines)
src/ingest/normalize.py             # maps parsed OTRF atomic captures -> AlertRecord, preserving ATT&CK ground truth
src/ingest/fetch_otrf_compound.py   # downloads OTRF compound captures, e.g. APT29 ATT&CK Evals (network)
src/ingest/normalize_compound.py    # maps parsed OTRF compound captures -> AlertRecord (multi-technique-unresolved)
src/ingest/fetch_evtx_baseline.py   # downloads a small evtx-baseline release asset (network)
src/ingest/parse_evtx.py            # parses raw .evtx into OTRF's own flat field convention
src/ingest/normalize_benign.py      # maps parsed evtx-baseline events -> AlertRecord (is_malicious=False)
src/ingest/leakage.py               # corpus-wide leakage mitigations (hostname, timestamp, shared-support/field ablation)
tests/                              # offline tests against small committed fixtures — no network required
tests/fixtures/                     # trimmed real-shaped OTRF metadata YAML + capture zip
tests/fixtures/sample_compound_capture.zip  # trimmed real-shaped OTRF compound capture (see test_normalize_compound.py)
tests/fixtures/evtx/                # trimmed real evtx-baseline .evtx chunks (see test_parse_evtx.py)
data/raw/otrf/                      # gitignored cache for downloaded OTRF atomic captures + metadata
data/raw/otrf/compound_captures/    # gitignored cache for downloaded OTRF compound captures
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

# Real ingest — downloads the two APT29 ATT&CK Evals compound captures
# (~57 MB total: day1 13.9 MB + day2 43.0 MB), the corpus's main source of
# Sysmon EventID 1 (process creation) volume — see "Process-creation
# (EventID 1) coverage" below.
python -m src.ingest.fetch_otrf_compound

# Real benign ingest — downloads one small (~27 MB) evtx-baseline release
# asset (win2022-evtx.tgz)
python -m src.ingest.fetch_evtx_baseline
```

To normalize what was downloaded into `AlertRecord`s, see
`src/ingest/normalize.py:normalize_capture()` (atomic captures, one ATT&CK
technique each), `src/ingest/normalize_compound.py:normalize_compound_capture()`
(compound captures, multi-technique-unresolved — see below), and
`src/ingest/normalize_benign.py:normalize_evtx_capture()` (benign). To
assemble all of them into one corpus at a stated ratio, see
`src/corpus.py:assemble_corpus()`.

## Process-creation (EventID 1) coverage — the APT29 compound captures

**Why this exists:** Sysmon EventID 1 (process creation) is the only event
type that carries `CommandLine` + `ParentImage` + `User` + `Image` together —
the fields an analyst (or an LLM) actually needs to judge "is this process
launch suspicious," as opposed to a registry write or a process-access event
that carries none of them. Measured on the original 5-atomic-capture corpus:
EventID 1 was a thin sliver of the mitigated corpus (low hundreds of records
out of tens of thousands), which makes any accuracy metric over that corpus
mostly a measurement of registry-write triage, not process-creation triage —
the task this project actually cares about.
`research/phase-1c-process-creation-captures.md` measured (by downloading
and directly counting, not estimating from technique names) that OTRF's
`compound/apt29/day1` and `day2` captures — real, multi-stage APT29 ATT&CK
Evals Round 2 red-team scenarios (Pupy/Meterpreter and PoshC2, respectively)
— are the highest-yield source of additional EventID 1 records available in
OTRF's repo without chasing dozens of atomic captures for a handful of
records each (measured yield ~7 EID1/atomic capture; 450 + 584 = 1,034 from
just these two compound zips).

**The ground-truth problem these captures create, and how it's resolved:**
unlike `atomic/` captures — each of which IS a single ATT&CK technique's
execution, asserted via a per-capture `_metadata/{id}.yaml` — OTRF's
`compound/` captures have **no per-capture metadata YAML and no per-event
technique mapping of any kind**. This was verified directly, not assumed:
`datasets/compound/apt29/` contains only a prose `README.md` (per-Channel and
per-Sysmon-EventID counts, no technique breakdown), per-scenario `day{1,2}/`
directories with the same kind of prose summary, and an emulation-plan
spreadsheet (`emulationplans/apt29.xlsx`) that — confirmed by downloading and
inspecting it — is a **narrative operator runbook** (columns: Stage,
Technique, Step, Description, commands-to-run), keyed by an attacker "step"
like `3.B`, with no join key back to individual telemetry records. Each day's
scenario genuinely spans 15+ distinct ATT&CK techniques (T1053, T1055,
T1059.001/.003, T1070, T1078, T1082, T1087, T1105, T1106, T1136, T1218,
T1543, T1547, T1569.002, T1570, and more for day 2 alone).

Per `src/schema.py`'s ground-truth rule ("every field here must be traceable
to something a human curator actually asserted, never inferred/guessed by
this codebase"), picking one technique to represent an entire 15+-technique
scenario would be a fabrication this project's own documented standard
forbids — there is no OTRF-declared "primary" technique to defer to, unlike
some atomic captures. The resolution: `src/schema.py` adds one explicit
sentinel, `MULTI_TECHNIQUE_SENTINEL = "MULTI_TECHNIQUE_UNRESOLVED"`, plus a
new boolean field `technique_unresolved`. A compound-capture record is
labeled `is_malicious=True` (an assertion OTRF's own README genuinely makes:
this data comes from an executed APT29 red-team scenario) with
`attack_technique=MULTI_TECHNIQUE_UNRESOLVED` and `technique_unresolved=True`
— visible in any per-technique breakdown or eval-harness accuracy table as
its own explicit bucket, never silently blended into a real technique ID or
a null. The original hard invariant (`is_malicious=True` requires
`attack_technique` to be set; benign records must not carry one) is
UNCHANGED for atomic and benign records — the sentinel is still a non-None
string, so it satisfies that rule exactly as written rather than loosening
it; `technique_unresolved` adds a second, additional consistency check
(sentinel value <-> `technique_unresolved=True`, both directions) on top,
not instead of, the original one. See `src/ingest/normalize_compound.py`'s
module docstring for the full reasoning and `tests/test_schema.py` /
`tests/test_normalize_compound.py` for the regression tests.

**What this means for a per-technique breakdown of the corpus:** most
malicious records are now `MULTI_TECHNIQUE_UNRESOLVED` (the compound
captures are large), with the original 5 atomic techniques (T1053, T1069,
T1087, T1123, T1547) still present and separately countable. This is an
honest trade — real process-creation volume and real multi-stage-campaign
diversity, at the cost of most new records not carrying a resolvable
per-event technique. Anyone building a per-technique accuracy score must
either filter out `technique_unresolved=True` records or score them only on
the malicious/benign axis, not the technique axis — the field exists
precisely so that choice is visible and deliberate, not accidental.

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
- *Timestamp era*: `raw_event`'s native, un-rebased timestamps are kept
  (lossless by design), but the normalized `AlertRecord.timestamp` field IS
  neutralized by default as of Phase 1b — see "Known limitations and
  residual bias" below for the measured leak (a year-only classifier hit
  accuracy 1.0000) and `src/ingest/leakage.py:neutralize_timestamps()` for
  the fix. This superseded the earlier Phase 1 guidance of "just don't build
  a feature on absolute timestamp" once it became clear the corpus should not
  rely on every future caller remembering that rule by hand.
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

## Known limitations and residual bias

**The corpus is built by pairing two datasets that were never designed to be
paired: OTRF Security-Datasets (malicious) and NextronSystems/evtx-baseline
(benign).** They differ by more than the behavior this project wants a model
to learn — they differ by **collection stack**: OTRF's Windows atomics ship
through Windows Event Forwarding -> NXLog CE -> Logstash -> Kafkacat -> JSON
(an enrichment pipeline that adds fields), while evtx-baseline is a raw
`Copy-Item C:\Windows\System32\winevt\Logs\*.evtx` export with no shipper at
all. Both root causes are confirmed directly from each project's own
documentation, not assumed (see `research/phase-1b-shortcut-mitigation.md`
for the full citation trail — Arp et al., USENIX Security 2022, Pitfalls #1
"Sampling Bias" and #4 "Spurious Correlations").

That difference produced three measured **shortcut features** — features a
trivial classifier can key on to predict the label with no security
reasoning at all, which is exactly what `tests/test_shortcut_audit.py`
exists to catch and re-catch on every future data source:

| Shortcut | Measured before mitigation | Mitigation | Where |
|---|---|---|---|
| Absolute timestamp (year) | malicious 100% 2020, benign 100% 2022 -> a year-only classifier hits accuracy **1.0000** | Rebase every record's timestamp to an offset from its own capture's first event, then re-anchor at one fixed, shared epoch — the field is kept (schema validity + relative-time correlation logic both require it), only its absolute-calendar-date content is removed | `src/ingest/leakage.py:neutralize_timestamps` |
| `raw_event` field count | malicious 35-46 fields, benign 21-28 — and the gap **persists inside every shared Sysmon EventID** (EID 13: 39 vs 24; EID 10: 43 vs 28; EID 1: 53 vs 38), so restricting to shared EventIDs alone does not fix it | Ablate `raw_event` to exactly the schema-level intersection of keys observed on both sides, always including every shared key (`None` when a given event doesn't populate it) so field *count* can't still vary with which optional field happened to be present | `src/ingest/leakage.py:shared_raw_event_keys`, `restrict_to_shared_support` |
| Exclusive EventIDs | EventIDs 4658/4656/5447 (Windows Security handle/audit-policy events) appear **only** on the malicious side | Restrict both classes to the EventIDs observed on both sides; additionally cap each surviving shared EventID's class ratio at 1.5:1 by subsampling the majority side (dropping exclusive EventIDs alone still leaves shared-but-skewed EventIDs as a residual shortcut) | `src/ingest/leakage.py:shared_event_ids`, `restrict_to_shared_support` |

All three mitigations are applied together in `src/corpus.py:assemble_corpus`
(default `mitigate_shortcuts=True`) — support restriction and field ablation
run first, then timestamp neutralization, then the existing ratio/host
mitigations. **`mitigate_shortcuts=False` reproduces the original leaking
corpus on purpose**: the ability to demonstrate the before/after is itself
evidence this project takes the failure mode seriously, so the leaking path
is disabled by default, not deleted.

**Cost of support restriction, measured on the full corpus (202,845
malicious / 110,095 benign events, before ratio control):** restricting to
shared EventIDs keeps 84,880 of 202,845 malicious events (**41.8%**,
**58.2% dropped**); after the additional per-EventID 1.5:1 class-ratio cap,
90,356 malicious / 88,197 benign events survive (**35.5%** of the original
malicious pool). **All 5 ATT&CK techniques in this project's working subset
survive** (T1053, T1069, T1087, T1123, T1547), each retained at
approximately the same rate (~35.5%) — support restriction does not silently
wipe out any single technique's coverage. (An earlier hand-measurement in the
research brief reported a narrower shared-EventID set of `{1, 3, 5, 10, 11,
12, 13, 4104}` and 38.8% retention; the code above computes the intersection
dynamically rather than from a fixed list, and on this project's currently
downloaded captures also finds Security-channel EventIDs 4624/4672/4688/4689
shared between both sides, which widens the overlap slightly — see this
task's own before/after numbers for the reproducible figure.)

**Adding the APT29 compound captures (this task) re-ran the audit rather than
assuming it still held.** A new capture recorded on a different host, Sysmon
version, or shipper config is exactly the kind of change that has
reintroduced a shortcut before (this project has hit three separate leaks:
timestamp year, `raw_event` field count, value serialization type — see the
table above). Measured directly on the corpus INCLUDING the two new APT29
compound captures (`otrf_security_datasets` malicious: 50,859 atomic +
783,367 compound = 834,226 pre-mitigation events; `evtx_baseline` benign:
110,095 pre-mitigation events; both loaded by correctly pairing each atomic
metadata YAML with its OWN capture zip via `files[0].link`'s basename, not
`capture_zips[:1]` for every metadata file), all 6 shortcut checks still
pass at the same 0.65 threshold on a 1:1-ratio audit corpus (974 malicious /
974 benign, `n=1948`): `timestamp.year` 0.5000, `len(raw_event)` 0.5241,
`(EventID, field count)` on the shared subset 0.5241, no `raw_event`
timestamp-value-prefix offender, no `raw_event` value-type offender,
`EventID` 0.5241 — no new shortcut was introduced by the different lab
environment (APT29 evals uses `*.dmevals.local` hostnames vs. the existing
captures' `*.theshire.local`/`*.mordor.local`, which pseudonymization treats
identically) or by the different Sysmon build. At the production settings
(`assemble_corpus` defaults: `mitigate_shortcuts=True`, `benign_ratio=4.0`),
the combined corpus is 137,619 records (27,524 malicious / 110,095 benign);
EventID 1 rose from 268 records (0.65% of a 40,941-record corpus built from
the original 5 atomic captures alone) to **1,480 records (1.08% of the
137,619-record corpus)** — real gain, though smaller than the raw capture
yield (1,178 EID1 malicious records survive `restrict_to_shared_support`
cleanly, close to the 1,274-benign-EID1 ceiling) because `assemble_corpus`'s
ratio control subsamples the malicious pool UNIFORMLY AT RANDOM across ALL
EventIDs to hit the requested 4:1 ratio, not per-EventID — so EID1's ~0.72%
share of the full mitigated malicious pool (162,914 records) is what
survives into the final ratio-controlled corpus (~199 expected, 206
measured), not its much healthier post-support-restriction count. This is a
real, disclosed dilution effect of the existing ratio-control design, not a
new bug this task introduced; a caller who specifically wants more EID1
volume in the final corpus should pass a lower `benign_ratio` or a
stratified sampling scheme, neither of which exists yet.

**What this does NOT fix, and why:** the textbook-correct remedy for a
sampling-bias problem like this is a same-stack benign source — background,
non-attack events captured through OTRF's own NXLog pipeline instead of a
differently-shipped benign dataset. **No such source currently exists**:
OTRF's own repo tree (`datasets/atomic`, `datasets/compound`) contains only
attack-technique and named-campaign captures, no standalone benign/background
category, verified directly via the GitHub API. Mordor's captures do
reportedly include incidental non-attack background traffic *within* an
attack capture, but this project's schema and `normalize_capture()` label an
entire capture malicious/benign at the capture level, not per-event, so
extracting those as true negatives would require new per-event labeling
logic that does not exist yet. This is real future work, not a Phase 1b
blocker being deferred out of convenience.

**Be honest about what "mitigated" means here:** feature ablation and
support restriction remove the *specific, measured* shortcuts this project
found — they do not prove no other collection-stack artifact remains
undetected. `tests/test_shortcut_audit.py` is a permanent regression gate
for exactly this reason: it must be re-run (and extended) every time a new
data source is added, not treated as a one-time fix.

## What Phase 1 does not do

- No agents, no LLM calls, no correlation/triage logic — that's a later phase.
- Linux `auditd`-format captures and AWS captures are not parsed (see
  "Known deviation" above).
- Multi-technique ATOMIC captures (a metadata YAML with more than one
  `attack_mappings` entry) are not disambiguated per-event; `normalize_capture`
  applies the first mapping to every event in the capture and this is
  documented in code, not silently assumed. None of the 5 atomic captures in
  the default working subset hit this case.
- Multi-technique COMPOUND captures (the two APT29 ATT&CK Evals captures) are
  NOT disambiguated per-event either, but for a different, stronger reason:
  there is no OTRF-published mapping to disambiguate FROM at all (see
  "Process-creation (EventID 1) coverage" above). These records carry the
  explicit `MULTI_TECHNIQUE_UNRESOLVED` sentinel / `technique_unresolved=True`
  rather than a guessed technique — any future work that wants finer-grained
  technique labels for this data would need a new, separate labeling effort
  (e.g. hand-correlating the emulation plan's timestamps against the
  capture's own event timestamps), which is out of scope here and not
  attempted.
- No actual model is trained/evaluated against the assembled corpus yet —
  that's the next phase this benign-ingest work unblocks (the corpus is now
  computable-FPR-ready, not yet scored).
