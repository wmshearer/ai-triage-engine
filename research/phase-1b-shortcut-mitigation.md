# Phase 1b — Shortcut-Feature / Spurious-Correlation Mitigation

Context: two-source Windows event corpus (malicious = OTRF/Security-Datasets
"Mordor" captures, ~40,569 events; benign = NextronSystems/evtx-baseline,
~107,459 events). Three measured, source-correlated shortcuts (timestamp year,
raw field count, exclusive EventIDs) make the label predictable without any
security reasoning. This brief answers: what is this failure mode called, what
does the literature establish as correct mitigation, is there prior art in
security-ML specifically, does a same-stack benign source exist, and what
should be disclosed.

## Verdict

Ranked, for this specific corpus:

1. **(c) Same-stack benign source — NOT AVAILABLE for this corpus; treat as
   the theoretically correct fix but currently blocked.** Confidence: high
   that this is the textbook-correct answer; high that it is not achievable
   with these two named repos as-is. OTRF's Windows atomic captures are
   attack-only by construction (`docs`, capture metadata) — Mordor's own docs
   describe capturing "benign events happening at the time of the attack" as
   background noise *within* an attack capture, but this project's schema
   labels an entire capture's events as malicious/benign at the capture
   level, not per-event, so that background traffic is not usable as clean
   negatives without new per-event relabeling work (a real, larger effort,
   out of scope here). No standalone OTRF "background-only"/"benign" dataset
   category exists in the repo (`datasets/` = `atomic`, `compound`, only
   attack techniques and named APT/campaign scenarios — verified via GitHub
   API tree). Cost if pursued properly: substantial re-engineering (per-event
   labeling of "boring" events inside attack captures) for likely a small
   yield of true negatives, since captures are short-duration/lab-controlled.
   **Not a near-term fix; log as a future-work direction, not a Phase 1b task.**

2. **(a) Feature ablation (drop timestamp + non-intersecting fields) —
   RECOMMENDED, do first.** Confidence: high, directly supported by Arp et
   al.'s "Spurious Correlations" remediation (define the intended learning
   signal, strip features unrelated to it) and by the CICIDS2017/NIDS
   literature's remedy of removing generator/collection artifacts (e.g.
   flow-meter bugs, IDs) rather than relabeling. Tradeoff: loses the 3
   identified shortcut axes (absolute timestamp, all NXLog-enrichment-only
   fields such as `@version`, `AccountDomain`, `AccessMask`,
   `AuthenticationPackageName`, and any raw field not present on both sides)
   but is cheap, reversible, and auditable. Does not reduce event *count*,
   only field/column count — this repo's own `leakage.py` and README already
   implement the timestamp half of this (documented as "must not use
   absolute timestamp/date as a feature") but the raw field-count and
   exclusive-EventID axes are NOT yet closed; extending the existing
   `leakage.py` intersection logic to enforce a schema-level (not just
   `_EVENT_TYPE_MAP`-level) intersection is the concrete next step.

3. **(b) Restrict to shared EventIDs + intersected field set — RECOMMENDED,
   do together with (a), as the stronger version of it.** Confidence:
   high — this is the standard "restrict to the overlap support" fix used
   when two sources differ in coverage (same logic as trimming CICIDS2017 to
   only correctly-labeled, non-artifact flows per Engelen et al. 2021 and Liu
   et al. 2022). Tradeoff: **loses real data** — specifically the entire
   Windows Security-channel EventIDs 4658/4656/5447 (measured: malicious-only,
   currently ~exclusive to OTRF) must be dropped from both the malicious
   corpus's coverage claims and any per-EventID metric, since benign coverage
   for them is structurally absent, not just currently unsampled. Quantify
   before implementing: how many of the 40,569 malicious events carry those
   3 EventIDs (expect this to be a minority, but it must be measured, not
   assumed) — that percentage is the real cost of this option and belongs in
   the disclosure text either way.

4. **(d) Adversarial validation / shortcut audit as a permanent regression
   gate — RECOMMENDED, ongoing, layer on top of (a)+(b).** Confidence: high
   that this is standard practice (Kaggle/applied-ML lineage, e.g. FastML's
   original write-up and subsequent applied papers on dataset-shift
   detection); no dedicated security-ML paper found specifically coining
   this for intrusion datasets, but it operationalizes exactly what Arp et
   al. prescribe ("use explanation techniques to reveal correlations... to
   validate that learned patterns align with intended goals") and is the
   direct mechanical test for the exact failure this project already found
   by hand (year-only classifier at 1.0000 accuracy IS an adversarial-
   validation result, just computed manually). Tradeoff: near-zero — it is a
   test, not a corpus transformation. Concretely: add a CI/pytest check that
   trains a trivial classifier (or even a single-feature check per known
   shortcut) on `source_dataset` as target and asserts accuracy stays near
   the random/base-rate floor after (a)+(b) are applied; re-run after every
   corpus change.
5. **Residual-bias disclosure (Arp et al.'s explicit "openly discuss
   limitations" prescription; Gebru et al. "Datasheets for Datasets") —
   MANDATORY regardless of which of the above are implemented.** Confidence:
   high this is necessary; not sufficient alone — Arp et al. list disclosure
   as the fallback specifically for residual bias that cannot be fully
   engineered away, not a substitute for (a)/(b)/(d). See exact text below.

Net recommendation order: **(a)+(b) now (schema/EventID intersection,
quantify the loss first) → (d) as a permanent gate → (5) disclosure always →
(c) as future work, not blocked-on for Phase 1b.**

## Findings

### 1. Terminology and primary papers

The measured phenomenon (label perfectly predictable from a feature
uncorrelated with the underlying task, here: which collection pipeline
produced the record) has three overlapping names in the literature, not
one canonical term — use whichever fits the audience, but the security-ML
venue term is **"spurious correlation"** per Arp et al.:

- **"Shortcut learning"** — Geirhos et al., "Shortcut Learning in Deep
  Neural Networks," *Nature Machine Intelligence* 2, 665–673 (2020),
  arXiv:2004.07780, DOI 10.1038/s42256-020-00257-z. Defines shortcuts as
  "decision rules that perform well on standard benchmarks but fail to
  transfer to more challenging testing conditions." This is the general
  ML/vision-originated term. [arXiv:2004.07780](https://arxiv.org/abs/2004.07780)
- **"Spurious correlations"** — the specific term used by the
  security-ML-specific primary source (Arp et al., see below); this is the
  term to use when writing for a security-ML audience.
- **"Sampling bias"** — the companion term, also from Arp et al., for the
  root cause here specifically (two classes drawn from non-comparable
  collection processes/populations), distinct from but co-occurring with
  spurious correlations in this corpus.
- ("Clever Hans" effect and "dataset bias" are informal/older synonyms in
  circulation but neither has a single canonical citation as clean as the
  above two; not needed given Arp et al. and Geirhos et al. cover the
  ground precisely.)

### 2. Established mitigation practice, ranked with citations

Primary source for the ranking logic: **Arp, D., Quiring, E., Pendlebury,
F., Warnecke, A., Pierazzi, F., Wressnegger, C., Cavallaro, L., Rieck, K.
"Dos and Don'ts of Machine Learning in Computer Security." USENIX Security
2022.** [Paper page](https://www.usenix.org/conference/usenixsecurity22/presentation/arp) ·
[Project site with pitfall list](https://dodo-mlsec.org/) ·
[PDF](https://www.usenix.org/system/files/sec22-arp.pdf) (blocked from direct
fetch by USENIX's server in this session — content below sourced via the
project's own summary page, which lists all 10 pitfalls verbatim).

Arp et al. name exactly two of the ten pitfalls as directly applicable:
- **Pitfall #1, Sampling Bias**: "the collected data does not sufficiently
  represent the true data distribution." Their prescribed remedies: construct
  a reasonable estimate of the true distribution, avoid merging data from
  incompatible/non-comparable sources without correction, and — where the
  bias can't be fully removed — **"limitations of the used dataset should be
  openly discussed."**
- **Pitfall #4, Spurious Correlations**: models "exploit artifacts unrelated
  to the security problem" (their own example: learning IP ranges instead of
  attack behavior — directly analogous to this corpus learning
  parser/pipeline instead of maliciousness). Prescribed remedies: use
  explanation techniques (feature attribution) to surface what the model
  actually keyed on, define the intended learning objective explicitly up
  front, and validate that learned decision rules match that objective
  before trusting reported metrics.

Evaluating this project's five candidate strategies against that guidance:

- **(a) Feature ablation (strip timestamp + non-shared fields):** Directly
  implements Arp et al.'s spurious-correlation remedy ("define the objective,
  remove artifacts unrelated to it"). Standard, low-cost, reversible. This is
  also exactly what the NIDS-dataset-repair literature does (see Q3) —
  Engelen et al. and Liu et al.'s CICIDS2017 fixes are, at their core,
  "remove/regenerate the artifact-contaminated features/flows," not
  "relabel" or "collect new data."
- **(b) Restrict to shared EventIDs + intersected fields:** Same family as
  (a), more aggressive (also drops rows, not just columns). Matches the
  "avoid merging incompatible sources without correction" clause of Arp et
  al.'s sampling-bias remedy — restricting to the overlap is a correction.
  Cost is real data loss (the 3 exclusive EventIDs) and must be quantified
  and disclosed, not silently applied.
- **(c) Same-stack benign source:** This is the *strongest* fix in
  principle — it removes the sampling-bias root cause instead of papering
  over its symptoms — but Arp et al. do not treat "recollect from a matched
  source" as always available; their own fallback for exactly this case is
  disclosure. See Q4 below: verified not straightforwardly available for
  this corpus pair.
- **(d) Adversarial validation as a permanent regression test:** Not named
  in Arp et al. by that term, but it is the direct operationalization of
  their instruction to use "explanation techniques" and validate learned
  correlations before trusting metrics — adversarial validation (train a
  classifier to predict `source_dataset`/train-vs-test membership; near-
  chance accuracy = no detectable shift) is the standard applied-ML
  technique for this, documented earliest/most clearly in practitioner
  literature: [FastML, "Adversarial validation, part one"](https://fastml.com/adversarial-validation-part-one/),
  [Kaggle: Adversarial Validation notebooks](https://www.kaggle.com/code/zakopur0/adversarial-validation-train-vs-test),
  and applied papers e.g. [Guo et al., "Managing dataset shift by adversarial
  validation for credit scoring," arXiv:2112.10078](https://arxiv.org/pdf/2112.10078).
  No dedicated intrusion-detection-specific paper coining this found in this
  search, but the technique is domain-agnostic and directly fits: this
  project's own manual finding ("year-only classifier hits 1.0000 accuracy")
  is literally a one-feature adversarial-validation result already.
- **(e) Not listed, but recommended by the literature:** *Disclosure* itself
  is explicitly prescribed by Arp et al. as a required practice, not an
  optional extra — see Q5. Also relevant: **Gebru et al., "Datasheets for
  Datasets," Communications of the ACM 64(12), 2021 (orig. arXiv:1803.09010,
  2018)** — proposes standardized dataset documentation covering motivation,
  composition, *collection process*, and known limitations; directly
  applicable template for what to ship alongside this corpus.
  [arXiv:1803.09010](https://arxiv.org/abs/1803.09010)

### 3. Prior art in security-ML on cross-dataset/collection bias

Two lines of prior art, both confirming this is a recognized, recurring
failure mode in security datasets specifically, not just a general-ML
concern:

- **Arp et al. 2022 (above)** is the direct, canonical, general statement
  for the security-ML field — "Sampling Bias" and "Spurious Correlations"
  are two of their ten named pitfalls, both squarely matching this corpus's
  situation (mixing incompatible sources; an artifact — parser/pipeline
  identity — correlating with the label).
- **NIDS-dataset-specific critiques**, confirming the same class of problem
  has been found and fixed before in adjacent security-ML datasets:
  - **CICIDS2017**: [Engelen, G., Rimmer, V., Joosen, W., "Troubleshooting
    an Intrusion Detection Dataset: the CICIDS2017 Case Study," WTMC 2021](https://intrusion-detection.distrinet-research.be/WTMC2021/extended_doc.html)
    — found errors in traffic generation, flow construction, feature
    extraction, and labeling; proposed corrected reprocessing rather than
    recollection.
  - Liu, L. et al. (2022) document further errors across CIC-IDS-2017/
    CIC-CSE-IDS-2018's full creation lifecycle (attack orchestration,
    feature generation, documentation, labeling) and release a refined
    version — same remedy pattern (fix the pipeline artifact, don't just
    retrain around it).
  - A concretely analogous *feature-level* artifact: CICFlowMeter's
    duplicated `Fwd Header Length` feature (a tool bug, not a real signal),
    cited as a specific instance of tool-introduced spurious features in
    NIDS data — structurally the same failure category as this corpus's
    NXLog-enrichment fields.
  - **KDD99/NSL-KDD**: widely cited as obsolete/unrepresentative; search
    results describe consistent recommendations against continued use for
    NIDS benchmarking due to synthetic-generation artifacts not matching
    real traffic — same underlying "collection-process artifact ≠ true
    signal" critique, at dataset-obsolescence scale rather than
    fixable-preprocessing scale.
  - **Sommer, R., Paxson, V., "Outside the Closed World: On Using Machine
    Learning for Network Intrusion Detection," IEEE S&P 2010.**
    [PDF via ICSI](http://www.icsi.berkeley.edu/pubs/networking/outsidethe10.pdf)
    — foundational, pre-dates Arp et al. by 12 years, argues intrusion
    detection is a poor match for naive ML evaluation because "attacks" and
    "normal" are drawn from populations that differ for reasons unrelated to
    the attack itself unless great care is taken in constructing evaluation
    data — the conceptual ancestor of Arp et al.'s sampling-bias pitfall,
    specific to this field. (Not independently re-fetched in full this
    session; cited via search-result description + long-standing field
    consensus on its content — flag as secondary-sourced, see Open
    Questions.)

No paper found in this search that names this *exact* two-repo pairing
(OTRF + evtx-baseline) or the identical shortcut set — this appears to be
either a novel-in-print combination or one not indexed under the terms
searched. Confidence on "no one has written this up before" is
therefore low; it is an absence-of-evidence result within budget, not a
proven absence.

### 4. Same-stack benign source — does one exist?

**Direct answer: no clean, ready-to-use same-stack benign source exists in
either named repo.**

- **evtx-baseline confirmed root cause (verified by reading the repo's own
  README, `NextronSystems/evtx-baseline`):** collection method is: install a
  trial-licensed Windows VM, install Sysmon with
  [`sysmonconfig-trace.xml`](https://github.com/Neo23x0/sysmon-config/blob/master/sysmonconfig-trace.xml)
  (itself forked from "Cyb3rWard0g's config" — Cyb3rWard0g is Roberto
  Rodriguez, OTRF's own founder, so the Sysmon *field/event coverage
  intent* is actually related lineage, even though the shipping mechanism
  differs sharply), enable native Windows audit policies/log channels via
  `wevtutil`/GPO, install ~40 applications via Ninite and simulate use, then
  export logs via **`Copy-Item "C:\Windows\System32\winevt\Logs\*.evtx"`
  directly** — i.e., raw native `.evtx` files, no shipper, no NXLog, no
  enrichment layer. This directly confirms half of the stated root-cause
  diagnosis: evtx-baseline really is raw-parsed `.evtx`, not
  pipeline-enriched.
- **OTRF confirmed pipeline (verified via OTRF's own documentation/issues,
  e.g. `Security-Datasets/scripts/data-shippers/Mordor-Elastic.py` and repo
  issues #44/#46):** Mordor's documented capture pipeline is **Windows Event
  Forwarding → NXLog CE → Logstash → Kafkacat → JSON**, exactly matching the
  stated diagnosis (NXLog enrichment: `@version`, `AccountDomain`,
  `AccessMask`, `AuthenticationPackageName`, etc., are shipper/ECS-mapping
  artifacts, not attacker behavior).
- **Root-cause diagnosis: CONFIRMED**, not merely plausible — both sides
  independently verified from each project's own documentation. The two
  classes differ by collection stack (NXLog-shipped-and-enriched JSON vs.
  raw exported `.evtx`), not by behavior.
- **Does OTRF ship a standalone benign/background dataset?** No. Verified
  directly via the GitHub API tree: `datasets/` contains only `atomic`
  (subdivided by ATT&CK tactic: collection, credential_access,
  defense_evasion, discovery, execution, lateral_movement, other,
  persistence, privilege_escalation — all attack-technique categories, no
  "benign"/"normal"/"baseline" folder) and `compound` (named APT/campaign
  scenarios: GoldenSAMLADFSMailAccess, LSASS_campaign_01-07, Log4Shell,
  apt29 — again, all attack scenarios). There is no dataset category in the
  repo tree that is benign-only.
- **Does a capture contain incidental non-attack background events that
  could be relabeled as benign?** Plausibly yes in principle — search
  results describe Mordor's broader design philosophy as capturing "not
  just the events directly related to the attack but also the set of
  benign events happening at the time of the attack" for realism — but this
  is not independently verified against actual downloaded capture content
  in this session (budget did not extend to parsing a raw OTRF JSON capture
  for non-attack-technique events), and critically: **even if present, this
  project's schema and normalize.py apply one `attack_technique` label to
  every event in a capture** (per README: "`normalize_capture` applies the
  first mapping to every event in the capture" for multi-technique
  captures) — so extracting true per-event benign negatives from inside an
  attack capture would require new per-event classification logic that does
  not exist yet. This is a real, larger engineering task, not a
  configuration change.
- **Conclusion for Q4:** The theoretically-correct fix (c) is blocked in
  practice for this specific project without new engineering work
  (per-event relabeling of intra-capture background traffic, which itself
  would need its own leakage audit). It is not a source that can be
  "swapped in" the way (a)/(b)/(d) can be applied today.

### 5. What good practice discloses (disclosure content itself, see next section)

Grounded in Arp et al.'s explicit instruction that residual sampling bias
"should be openly discussed" and Gebru et al.'s "Datasheets for Datasets"
structure (motivation / composition / collection process / known
limitations / recommended use). No single security-ML paper was found in
this search that publishes a canonical disclosure *template* text
specifically for a case like this (two-source label/pipeline confound);
the disclosure text below is synthesized from Arp et al.'s and Gebru et
al.'s stated *requirements* (say what was measured, say what remains
unaddressed, say what a downstream user must not do), not copied from a
primary source verbatim — flagged as synthesis, not quotation.

## What to disclose

Suggested text to ship with the corpus (e.g. in the README's dataset
section, adjacent to the existing "Leakage vectors" writeup in
`/home/kali/director/projects/ai-triage-engine/README.md`):

> **Known residual bias — read before reporting any metric from this
> corpus.** The malicious and benign classes in this corpus are drawn from
> two different collection pipelines, not just two different datasets:
> malicious events (OTRF/Security-Datasets) are shipped through Windows
> Event Forwarding → NXLog → Logstash, which enriches every record with
> shipper/ECS-mapping fields (e.g. `@version`, `AccountDomain`,
> `AccessMask`, `AuthenticationPackageName`); benign events
> (NextronSystems/evtx-baseline) are raw native `.evtx` exports with no
> shipper. This produces three measured, source-correlated shortcuts that a
> model can exploit without learning any security-relevant signal:
> (1) timestamp year is a perfect class proxy (malicious=2020,
> benign=2022) — **never use absolute timestamp as a feature**; (2) raw
> field count differs by pipeline within every shared Sysmon EventID
> (e.g. EventID 1: malicious 53 fields vs. benign 38) — **field-count and
> field-presence must not be used as features, and any model operating on
> raw_event verbatim risks keying on this**; (3) Windows Security-channel
> EventIDs 4658, 4656, 5447 appear only in the malicious set and have no
> benign counterpart in this corpus — **any reported per-EventID metric for
> these three IDs reflects pipeline coverage, not detectability, and should
> be reported separately or excluded, not blended into an aggregate
> precision/recall/F1.** Mitigations applied: [list whichever of
> feature-ablation / EventID-intersection / adversarial-validation-gate
> were actually implemented, and the exact field/EventID lists dropped].
> Mitigation NOT applied: a same-collection-stack benign source was
> investigated and is not available without new per-event relabeling
> engineering (see phase-1b-shortcut-mitigation.md, Q4) — this is the
> single largest unresolved external-validity threat to this corpus and any
> metric reported from it should be read as an upper bound conditioned on
> pipeline artifacts being successfully removed, not as ground truth for
> real-world detector performance.

## Open questions

- Sommer & Paxson 2010 was characterized via search-result summaries and
  general field knowledge, not a full primary-source re-read in this
  session — if it will be cited directly (e.g. with a specific quote), fetch
  and read the PDF directly first (`http://www.icsi.berkeley.edu/pubs/networking/outsidethe10.pdf`
  returned in search but not fetched here).
- Arp et al.'s full PDF was blocked by USENIX's server (403) in this
  session; the pitfall list and remedies above were reconstructed from the
  paper's own companion site (dodo-mlsec.org) rather than the primary PDF
  text directly. Recommend re-fetching `https://www.usenix.org/system/files/sec22-arp.pdf`
  via a different method (e.g. `gh` is not applicable; try a cached mirror
  or Google Scholar cache) if verbatim quotes are needed for a citation
  that requires exact wording.
- Whether OTRF capture JSON actually contains usable non-attack-technique
  background events (Q4's second sub-question) was not verified against
  real downloaded capture content — only against documentation/design-intent
  claims from search results. This is the highest-value follow-up if
  strategy (c) is to be seriously pursued: download 2-3 compound/apt29
  captures (multi-day, most likely to contain incidental background
  traffic) and check whether events exist that fall outside the capture's
  declared `attack_mappings` window/technique.
- Exact percentage of the 40,569 malicious events carrying EventIDs
  4658/4656/5447 was not computed in this research pass (out of scope —
  methodology only) but is required before implementing option (b), since
  it is the stated cost of that option.
- No security-ML-specific paper naming "adversarial validation" by that
  term was found; if a more authoritative/older citation exists it wasn't
  surfaced in this budget — current best citations are practitioner
  (FastML/Kaggle) plus one applied arXiv paper (credit scoring domain, not
  security).
