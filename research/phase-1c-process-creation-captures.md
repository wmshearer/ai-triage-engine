# Phase 1c — Which OTRF captures to download for Sysmon EventID 1 (process creation) volume

Context: current 5-capture corpus yields 47,094 mitigated records, of which EventID 1
(process creation — the only event type carrying `CommandLine`+`ParentImage`+`User`+`Image`
together) is only 315 records (0.67%). Benign side (evtx-baseline) has 1,274 EID1 records
total, and the shortcut-mitigation layer caps each EventID's class ratio at 1.5:1, so
**no more than ~1,911 malicious EID1 records could ever be used**, and realistic balanced
pairing means ~1,274 malicious : ~1,274 benign is the practical target. This brief
identifies which OTRF captures to add to close that gap without chasing data the ratio
cap would discard.

## Verdict

Ranked download list. All URLs are `raw.githubusercontent.com/OTRF/Security-Datasets/master/...`.
Sizes and EID1 counts are **measured** by downloading and counting, not inferred from
technique names, except where marked "unverified."

| Rank | Capture | Technique(s) | Measured EID1 | Size | Capture URL | Metadata URL |
|---|---|---|---|---|---|---|
| 1 | `apt29_evals_day2_manual.zip` | Full APT29 ATT&CK Evals Round 2, Scenario 2 (PoshC2 + custom tooling; dozens of sub-techniques: T1053, T1055, T1059.001/.003, T1070, T1078, T1082, T1087, T1105, T1106, T1136, T1218, T1543, T1547, T1569.002, T1570, and more — see emulation plan) | **584** | 43.0 MB (zip) | `datasets/compound/apt29/day2/apt29_evals_day2_manual.zip` | *(no atomic-style per-capture metadata YAML exists — this is a `compound/` dataset; provenance is `datasets/compound/apt29/README.md` + `datasets/compound/apt29/day2` MITRE ATT&CK Evals Round 2, Scenario 2 emulation plan, not a `_metadata/{id}.yaml` file)* |
| 2 | `apt29_evals_day1_manual.zip` | Full APT29 ATT&CK Evals Round 2, Scenario 1 (Pupy + Meterpreter + custom tooling; comparable technique breadth to Day 2, different scenario) | **450** (OTRF's own published README stat: 433 — both counts self-consistent, small delta explained below) | 13.9 MB (zip) | `datasets/compound/apt29/day1/apt29_evals_day1_manual.zip` | same as above — see `datasets/compound/apt29/day1/README.md` for the OTRF-published per-EventID breakdown table |
| 3 (optional, marginal) | `empire_wmic_add_user_backdoor.zip` | T1047 (WMI) — new technique vs. current 5 | 25 | 1.17 MB | `datasets/atomic/windows/lateral_movement/host/empire_wmic_add_user_backdoor.zip` | `datasets/atomic/_metadata/SDWIN-200914080546.yaml` |
| 4 (optional, marginal) | `covenant_wmi_wbemcomn_dll_hijack.zip` | T1047 (WMI) — same new technique as #3 | 13 | 620 KB | `datasets/atomic/windows/lateral_movement/host/covenant_wmi_wbemcomn_dll_hijack.zip` | `datasets/atomic/_metadata/SDWIN-201009173318.yaml` |
| — do not download | `empire_apt3.tar.gz` | Full APT3 emulation (would add real volume) | unverified count, but **structurally disqualified** — see Risks | 28.9 MB | `datasets/compound/windows/apt3/empire_apt3.tar.gz` | none (compound) |
| — not worth it | 14 other small atomic T1059/T1218/T1055/T1047 captures individually tested | T1059, T1218, T1055, T1047 | 3–13 each (107 combined across all 14) | 10 KB–1.2 MB each | see full list in "How I verified" | `datasets/atomic/_metadata/*.yaml` |

**Recommended action: download rank 1 and 2 only (apt29 day1 + day2, 57 MB total).**
Combined measured yield = 450 + 584 = **1,034 new malicious EID1 records**, against a
ceiling of ~1,274–1,911. That alone gets the corpus to ~85–95% of what the ratio cap will
ever allow, from 2 files, with far higher technique diversity than the existing 5 captures
(a real multi-stage adversary emulation vs. 5 single-technique atomics), and confirmed
matching schema/Sysmon-config-version to the existing corpus (see Risks).

Ranks 3–4 (or any 2–3 of the 14 small atomics) are optional top-ups purely for adding the
T1047 (WMI) label as a distinct technique if per-technique breakdowns need it — their EID1
volume contribution is immaterial (13–25 records each) and not needed to hit the ceiling.

Confirmed via GitHub API + WebFetch: **`empire_apt3.tar.gz` and the standalone small atomic
captures already tested carry MIT license** (OTRF/Security-Datasets root `LICENSE` file,
Copyright 2021 Open Threat Research Forge) — same license already documented for the
current 5 captures, unchanged, permissive for this use.

## How I verified

Downloaded and directly counted `EventID == 1` records by streaming-parsing the extracted
JSON-lines files (matching the project's own documented ingest convention: `Channel`/
`EventID` flat top-level fields) with a small Python script — no estimation from
technique names or capture titles.

**Sanity check on the counting method itself:** re-ran the identical counting script
against the 5 *already-downloaded* captures in
`/home/kali/director/projects/ai-triage-engine/data/raw/otrf/captures/` and got
124 + 1 + 5 + 2 + 12 = **144**, exactly matching the number given in this task's own
context ("Across all 5, only 144 EventID-1 records exist"), and the registry-modification
capture's total record count (40,569) also matched exactly. This confirms the counting
method is correct before trusting any new numbers.

**Full enumeration:** pulled the complete repo tree via
`https://api.github.com/repos/OTRF/Security-Datasets/git/trees/master?recursive=1`
(828 tree entries; 186 Windows-atomic paths, 162 zip/tar capture files across 9 tactic
folders: collection 1, credential_access 30, defense_evasion 43, discovery 14,
execution 4, lateral_movement 55, other 3, persistence 9, privilege_escalation 3).
Downloaded all 104 atomic-metadata YAMLs from `datasets/atomic/_metadata/` and parsed
`attack_mappings[].technique` to filter for techniques that inherently spawn processes:
T1059, T1218, T1055, T1047, T1053, T1569, T1204, T1106, T1202. This produced 30 matching
Windows-atomic captures; 16 were new techniques not already in the corpus.

**Actually downloaded and counted (verified, not guessed):**

Small atomic captures (all `datasets/atomic/windows/{defense_evasion,execution,lateral_movement}/host/*.zip`):

| Capture | Technique | Size | Measured EID1 |
|---|---|---|---|
| `empire_wmic_add_user_backdoor.zip` | T1047 | 1.17 MB | 25 |
| `covenant_wmi_wbemcomn_dll_hijack.zip` | T1047 | 620 KB | 13 |
| `empire_msbuild_dcerpc_wmi_smb.zip` | T1047 | 654 KB | 11 |
| `empire_launcher_sct_regsvr32.zip` | T1218 | 310 KB | 7 |
| `psh_mshta_html_application_execution.zip` | T1218 | 155 KB | 7 |
| `psh_register_cimprovider_execute_dll.zip` | T1218 | 130 KB | 6 |
| `cmd_mshta_javascript_getobject_sct.zip` | T1218 | 126 KB | 5 |
| `covenant_sharpwmi_create_dcerpc_wmi.zip` | T1047 | 195 KB | 5 |
| `covenant_wmi_remote_event_subscription_ActiveScriptEventConsumers.zip` | T1047 | 351 KB | 5 |
| `empire_launcher_vbs.zip` | T1059 | 313 KB | 5 |
| `empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip` | T1047 | 675 KB | 5 |
| `covenant_lolbin_wuauclt_createremotethread.zip` | T1218/T1055 | 137 KB | 4 |
| `cmd_mshta_vbscript_execute_psh.zip` | T1218 | 89 KB | 3 |
| `covenant_installutil.zip` | T1218 | 111 KB | 3 |
| `psh_python_webserver.zip` | T1059 | 113 KB | 3 |
| `psh_powershell_httplistener.zip` | T1059 | 10 KB | 0 |

Total across all 16: **107 EID1 records**. Root cause (measured, not assumed): these are
single-technique "atomic" captures with short simulation windows (one command execution
each), so the process tree per capture is shallow regardless of technique choice — a
technique name being "process-spawning" does not by itself predict volume, confirming the
task's premise that technique name is not evidence.

Compound (multi-stage campaign) datasets, found by widening enumeration beyond
`datasets/atomic/` to `datasets/compound/` (the OTRF repo tree has exactly two top-level
dataset categories: `atomic` and `compound`):

| Capture | Size | Measured EID1 | Note |
|---|---|---|---|
| `apt29_evals_day1_manual.zip` | 13.9 MB (196,081 total events) | **450** | OTRF's own published README table (`datasets/compound/apt29/day1/README.md`) reports 433 for a nearly-identical file of the same name/timestamp; my count is on the file currently served at that URL — both numbers are self-consistent and in the same range, small delta most likely due to a minor content update since the README table was written. Either number clears the bar. |
| `apt29_evals_day2_manual.zip` | 43.0 MB (587,286 total events) | **584** | No per-EventID table published in OTRF's own README for Day 2 (only per-Channel), so this number is my own direct count, cross-checked against the file's own total-event and per-channel counts, which match the OTRF README's stated 407,265 Sysmon-channel events for Day 2 within the same file. |
| `empire_apt3.tar.gz` | 28.9 MB (121,659 total events) | not counted — disqualified before counting, see Risks | Uses a completely different event schema (`event_id`, `event_data`, `computer_name`, `host.name`, Winlogbeat/ELK convention) instead of the flat `EventID`/`Channel`/`Hostname` convention every other capture (including apt29) uses. Ingesting it would require new parser code, which is out of this research task's scope, and more importantly would reintroduce exactly the kind of collection-pipeline-correlated schema difference Phase 1b's shortcut-mitigation work was written to eliminate. |

**Verified schema compatibility, not just event counts:** for both apt29_day1 and
apt29_day2 EID1 records, confirmed field-for-field that `CommandLine`, `ParentImage`,
`User`, and `Image` are all present, and that the full field set matches the existing
5-capture corpus's EID1 field set almost exactly (same 40-ish fields, same
`@timestamp`/`@version`/NXLog-style enrichment fields, same `Version: 5` Sysmon schema
marker, same absence of `Level`/`ParentUser` fields — the two version-sensitive fields the
project's own README already flags as varying across OTRF captures). This was a direct
diff against a live-extracted sample from
`data/raw/otrf/captures/empire_persistence_registry_modification_run_keys_standard_user.zip`,
not an assumption.

**Not independently downloaded/counted (inferred from OTRF's own published README tables,
cited above, not verified further):** the per-Channel-only breakdowns for Day 2 in
`datasets/compound/apt29/README.md` (I did verify the total-event-count and per-Channel
numbers against my own direct count of the downloaded file, so this is corroborated, not
a blind citation).

## Technique diversity

Current corpus techniques: T1069 (net localgroup), T1087 (net users), T1547 (registry Run
key persistence), T1053 (scheduled task creation), T1123 (audio capture). All five are
single, narrow, atomic actions.

Adding `apt29_evals_day1_manual.zip` + `apt29_evals_day2_manual.zip` contributes an entire
**MITRE ATT&CK Evaluations Round 2 emulation plan** (publicly documented at
`https://attackevals.mitre.org/evaluations.html?round=APT29` and
`github.com/mitre-attack/attack-arsenal`), which — confirmed by directly inspecting the
`Image` field distribution of the 450 Day-1 EID1 records — includes real, distinct
processes/techniques not represented at all today:

- `PsExec64.exe` / `PSEXESVC.exe` — T1021.002 (SMB/Windows Admin Shares) lateral movement
- `WmiPrvSE.exe` — T1047 (WMI) execution, the technique this task called out by name
- `powershell.exe`, `cmd.exe`, `python.exe` — T1059 (Command and Scripting Interpreter),
  the other technique this task called out by name
- `rundll32.exe` — T1218.011 (Rundll32, LOLBin/system-binary-proxy-execution)
- `sc.exe` — T1543.003 (service creation, a persistence technique distinct from the
  existing registry-Run-key T1547 already in the corpus)
- `sdelete64.exe` — T1070.004 (file/indicator deletion, defense evasion — a tactic with
  zero representation in the current 5 captures)
- `logman.exe`, `dsregcmd.exe`, `WerFault.exe`, `conhost.exe`, `svchost.exe`,
  `backgroundTaskHost.exe`, `RuntimeBroker.exe`, `taskhostw.exe` — a realistic mix of
  attacker-spawned and ambient/legitimate-but-triggered process activity, which is
  exactly the kind of "is this actually malicious" ambiguity a triage model needs to be
  evaluated against (the current 5-capture corpus, being 100% deliberately malicious
  atomics, has none of this ambiguity).

Net effect: goes from 5 single-technique labels to 5 existing + a full multi-stage
campaign spanning at minimum 6–8 additional distinct ATT&CK (sub-)techniques with
directly observed evidence in the `Image`/`CommandLine` fields (T1021.002, T1047, T1059,
T1218.011, T1543.003, T1070.004, plus whatever the remaining ~370 unexamined EID1 records
in Day 1 and all 584 in Day 2 add — not individually enumerated here, time-boxed).
The two optional T1047 top-ups (rank 3–4) would be redundant with what apt29 already
contributes and are not needed for diversity, only marginally useful if a project
decision specifically wants a *second*, independent, narrow T1047 atomic alongside the
campaign data for controlled per-technique comparison.

## Ceiling analysis

Hard constraint (given, not re-derived): benign side has 1,274 EID1 records total; the
mitigation's `DEFAULT_MAX_CLASS_RATIO = 1.5` (confirmed at
`/home/kali/director/projects/ai-triage-engine/src/ingest/leakage.py:314`) caps each
EventID's class ratio at 1.5:1 by subsampling the majority side. So the absolute ceiling
on usable malicious EID1 records is 1,274 × 1.5 ≈ **1,911**, and because the mitigation
subsamples the *majority* side down, the realistic balanced-pairing target the corpus
will actually converge to is close to **1,274 malicious : 1,274 benign** (1:1), not the
full 1.5:1 skew, once the malicious side has enough records to not be the constrained
side itself.

Measured contribution against that ceiling:

- apt29_day1 alone: 450 (35% of the 1,274 target, 24% of the 1,911 hard ceiling)
- apt29_day1 + apt29_day2: **1,034** (81% of the 1,274 target, 54% of the 1,911 hard
  ceiling)
- Adding all 4 optional small atomics on top: 1,034 + 25 + 13 + 11 + 7 = 1,090 (86% / 57%)
- Adding literally every one of the 16 small atomics tested: 1,034 + 107 = 1,141 (90% / 60%)

**Point of diminishing returns: after apt29_day1 + apt29_day2 (2 files, 57 MB total),
stop.** Getting from 1,034 to the full 1,274 target would require roughly another 240
EID1 records, which — going by the measured yield rate of the 16 small atomics tested
(3–25 each, averaging ~7) — would mean downloading on the order of **30+ additional small
atomic captures** for a return that's already inside the noise band of what the 1.5:1
cap will discard anyway (the cap subsamples the *larger* side down to 1.5× the smaller,
so once malicious EID1 count exceeds roughly benign×1.5, extra malicious EID1 records are
literally discarded by `restrict_to_shared_support`, not used). Concretely: at 1,034
malicious vs. 1,274 benign, malicious is still the *smaller* side, so nothing is
discarded yet and every one of those 1,034 records is usable — but the marginal value of
chasing the remaining ~240 by downloading dozens more tiny atomics is not worth the
schema-review and provenance-tracking overhead per new capture (each new file is another
thing to verify for the compound-vs-atomic-metadata mismatch, schema consistency, and
technique-label correctness noted above). **Two files gets to ~81% of target at effectively
zero marginal risk; do not download the 28+ remaining candidates chasing the last ~19%.**

If, after ingesting apt29 day1+day2, the actual mitigated/intersected EID1 count comes in
measurably short of the ~1,034 raw count (because `restrict_to_shared_support` also
intersects `raw_event` keys, which could drop records whose field set doesn't match the
benign side's field set), that is the trigger to revisit rank-3/4 top-ups — not before.

## Risks

1. **`empire_apt3.tar.gz` — do not use.** Confirmed by direct inspection: this capture
   uses a structurally different event schema (`event_id` lowercase, nested `event_data`,
   `computer_name`/`host.name`/`beat.name` Winlogbeat/Elastic-Beats convention) instead of
   the flat `EventID`/`Channel`/`Hostname` convention every other OTRF capture in this
   project (both the existing 5 and the recommended apt29 day1/day2) uses. This is exactly
   the kind of collection-pipeline-correlated field-schema difference Phase 1b's
   shortcut-mitigation research (`research/phase-1b-shortcut-mitigation.md`) was written
   to eliminate — ingesting it as-is (or writing bespoke parsing to normalize it) would
   reintroduce a schema-level shortcut axis the project already spent effort closing.
   Technical note for whoever eventually handles this file: it downloads to the exact
   `Content-Length` GitHub reports (28,948,319 bytes) but both `tar` and `gzip -t` report
   "unexpected end of file" / non-fatal errors after successfully extracting a complete,
   valid 630 MB JSON file (confirmed: last line is well-formed JSON, not truncated
   mid-record) — this is a benign gzip-trailer quirk in how this specific file was
   produced, not a corrupted download, but it's still a strong signal this file was
   produced by a different pipeline/tool version than the rest of the repo.

2. **Compound datasets have no per-capture `_metadata/{id}.yaml`.** The existing
   `src/ingest/fetch_otrf.py` selects captures by metadata YAML id and reads the
   authoritative download link out of `files[].link` in that YAML
   (`datasets/atomic/_metadata/{CAPTURE_ID}.yaml`). `datasets/compound/apt29/` has no
   equivalent per-file YAML — provenance/ATT&CK-technique ground truth lives in
   `datasets/compound/apt29/README.md` and `datasets/compound/apt29/day{1,2}/README.md`
   (prose tables, not structured YAML) plus an external emulation-plan spreadsheet
   (`datasets/compound/apt29/emulationplans/apt29.xlsx`). Whoever implements ingestion of
   these two files will need either a small compound-dataset-specific fetch path or a
   hand-written metadata stub — this is a real, if modest, code change, not a drop-in
   using the existing `CAPTURE_IDS` list mechanism. Flagging for the implementer, not
   fixing here (out of scope per task boundaries).

3. **Hostname/domain naming scheme differs from the existing 5 captures but is
   internally consistent and plausibly not a shortcut.** Existing captures use
   `*.theshire.local` / `*.mordor.local` hostnames (e.g. `WORKSTATION5.theshire.local`,
   confirmed while testing the 16 small atomics above). apt29 day1/day2 use
   `*.dmevals.local` hostnames (`NASHUA`, `SCRANTON`, `NEWYORK`, `UTICA` —
   confirmed directly from the EID1 `Hostname` field). This is a different lab
   environment (MITRE ATT&CK Evals infrastructure vs. OTRF's own Mordor-labs shire/mordor
   lab), which is expected and fine as long as the project's existing hostname
   pseudonymization (per README, already applied) treats it as just another string to
   pseudonymize — it does not by itself carry class-correlated information the way
   e.g. a systematically different Sysmon version or field set would. Confirmed
   Sysmon-schema-version marker (`Version: 5` on EID1, absence of `Level`/`ParentUser`)
   matches the existing corpus exactly (see "How I verified"), so this is very unlikely
   to be a live shortcut, but it is a second, independent naming domain now present in
   the corpus and worth a one-line note in whatever data card/documentation accompanies
   the corpus.

4. **Small delta between my apt29_day1 count (450) and OTRF's published README count
   (433) is unresolved** (see table above) — both numbers clear the bar by a wide margin
   so it doesn't change the recommendation, but if exact reproducibility matters later,
   pin the download to a specific commit SHA rather than `master`, since OTRF's repo does
   receive occasional content updates to existing files.

## Open questions

- Exact ATT&CK sub-technique list for the remaining ~370 (Day 1) and ~584 (Day 2) EID1
  records beyond the ~15 processes sampled above — not enumerated here (time-boxed); a
  follow-up pass could extract full `Image`+`CommandLine` distributions for a complete
  technique-coverage table if the director wants it before ingestion.
- Whether the project's `normalize.py` / `leakage.py` schema-intersection logic
  (mentioned in README: "restricting to shared EventIDs alone does not fix" the raw
  field-count gap) will pass apt29's EID1 records through cleanly given the field-set
  match confirmed above, or whether some other EventID in apt29 (e.g. its Security-channel
  events) reintroduces the previously-identified exclusive-EventID problem at a different
  ratio — not tested here since it requires running the actual ingest pipeline, which is
  out of this research task's scope (research/report only, no repo changes).
- Whether to pin to a specific OTRF commit SHA instead of `master` for reproducibility,
  given point 4 above.
