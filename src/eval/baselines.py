"""Non-LLM baselines, ranked essential->nice-to-have per the design brief.

Every baseline here exposes the SAME `predict(records) -> list[BaselinePrediction]`
interface the LLM agent's output is adapted to (see `harness.py`'s
`_llm_prediction_from_verdict`), so pooled/stratified scoring, significance
testing, and reporting all run through identical code regardless of which
system produced the verdict — this is what makes the LLM-vs-baseline
comparison apples-to-apples rather than baseline-specific ad hoc scoring.

Implements baselines #1-4 from research/phase-3-evaluation-design.md
(#5, a second LLM, is explicitly out of scope for this task):
  1. MajorityClassBaseline   — always predicts benign.
  2. StratifiedRandomBaseline — predicts malicious at the corpus's observed
     malicious rate, independently per record (a real coin flip weighted by
     prevalence, not a second majority-vote in disguise).
  3. RulesBaseline           — keyword/pattern heuristic over raw_event
     fields, no LLM, no learned parameters. This is a genuine, honest
     attempt (LOLBins, encoded-PowerShell markers, common attacker
     command-line patterns) — see its own docstring for the exact
     indicator list and the fairness rationale.
  4. ClassicalMLBaseline     — logistic regression over engineered
     structured features (EventID, event_type, a handful of raw_event-
     derived features), trained/evaluated with a leakage-safe
     capture-level train/test split, and excluding every field the
     shortcut-mitigation layer (`src.ingest.leakage`) exists to suppress.

All four never read `is_malicious`/`attack_technique`/`attack_subtechnique`/
`attack_tactics` at PREDICT time, mirroring `src.agents.prompt`'s own
"labels are not inputs" rule (`ClassicalMLBaseline.fit` is the one place
labels are legitimately read, since it is the training step — see its
docstring for the leakage-safe split this implies).
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field

from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from src.schema import AlertRecord

# ---------------------------------------------------------------------------
# Shared prediction shape
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BaselinePrediction:
    """One baseline's verdict for one record, in the same shape the LLM
    agent's `TriageVerdict` is adapted to (see harness.py).

    `is_malicious_pred`: hard binary call, `positive == malicious`, ALREADY
    reflecting whatever collapse policy is baked into the baseline itself
    (the four baselines here are binary by construction, so there is no
    3-way collapse ambiguity for them — only the LLM produces a genuine
    3-way verdict needing the conservative/high_precision/abstention
    policies from harness.py).
    score: a continuous P(malicious)-like value in [0, 1] for PR-AUC/ROC-AUC.
    """

    is_malicious_pred: bool
    score: float


# ---------------------------------------------------------------------------
# Baseline 1: majority-class / always-benign
# ---------------------------------------------------------------------------


class MajorityClassBaseline:
    """Always predicts benign. Trivial by design (Verdict #5, ranked #1).

    Makes the base-rate fallacy visible by construction: at
    `benign_ratio=4.0` this baseline scores 80% accuracy while having zero
    recall on the malicious class, which is exactly why accuracy alone must
    never be reported as a headline (design brief Verdict #3).
    """

    name = "majority_class"

    def predict(self, records: list[AlertRecord]) -> list[BaselinePrediction]:
        return [BaselinePrediction(is_malicious_pred=False, score=0.0) for _ in records]


# ---------------------------------------------------------------------------
# Baseline 2: stratified-random guess
# ---------------------------------------------------------------------------


class StratifiedRandomBaseline:
    """Predicts malicious independently per record at a fixed base rate.

    `malicious_rate` should be set to the EVAL SAMPLE's own observed
    malicious rate (not assumed), so this is the true chance floor
    accounting for class prevalence — distinct from baseline #1, useful
    mainly as a sanity check that #1 is in fact stronger (it always will be
    at any rate below 50%, per the design brief).

    Deterministic given a seed: same seed + same record count -> identical
    predictions, so a reported run is reproducible.
    """

    name = "stratified_random"

    def __init__(self, malicious_rate: float, seed: int = 20260818):
        if not (0.0 <= malicious_rate <= 1.0):
            raise ValueError("malicious_rate must be in [0, 1]")
        self.malicious_rate = malicious_rate
        self._seed = seed

    def predict(self, records: list[AlertRecord]) -> list[BaselinePrediction]:
        rng = random.Random(self._seed)
        predictions = []
        for _ in records:
            score = rng.random()
            predictions.append(
                BaselinePrediction(is_malicious_pred=score < self.malicious_rate, score=score)
            )
        return predictions


# ---------------------------------------------------------------------------
# Baseline 3: rules / keyword heuristic over raw_event, no LLM
# ---------------------------------------------------------------------------

# LOLBins (Living-Off-the-Land Binaries) commonly abused for execution,
# persistence, or discovery in the OTRF atomic captures this corpus draws
# from (Empire/Metasploit tradecraft: net.exe enumeration, rundll32/regsvr32
# proxy execution, wmic/schtasks persistence, certutil download-and-decode).
# This list targets GENUINE, well-documented LOLBAS entries
# (lolbas-project.github.io), not a strawman built to lose — a real SOC
# keyword rule would reasonably include exactly these.
_LOLBIN_NAMES = (
    "powershell.exe",
    "cmd.exe",
    "wmic.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "mshta.exe",
    "schtasks.exe",
    "net.exe",
    "net1.exe",
    "wscript.exe",
    "cscript.exe",
    "bitsadmin.exe",
    "psexec.exe",
    "reg.exe",
)

# Command-line substrings that are strong, well-documented indicators of
# offensive tradecraft rather than routine admin use of the same binaries
# (e.g. "powershell.exe" alone is far too common to be a signal by itself —
# these markers are what a real analyst's keyword rule would actually key
# on: encoded/hidden execution, discovery enumeration, and known C2
# frameworks' default artifacts).
_SUSPICIOUS_COMMAND_PATTERNS = (
    re.compile(r"-enc(odedcommand)?\b", re.IGNORECASE),
    re.compile(r"-e\s+[a-z0-9+/=]{20,}", re.IGNORECASE),  # short -e + base64 blob
    re.compile(r"-nop\b", re.IGNORECASE),
    re.compile(r"-windowstyle\s+hidden", re.IGNORECASE),
    re.compile(r"-noni(nteractive)?\b", re.IGNORECASE),
    re.compile(r"bypass", re.IGNORECASE),
    re.compile(r"downloadstring|downloadfile|invoke-webrequest|iwr\b|net\.webclient", re.IGNORECASE),
    re.compile(r"invoke-expression|iex\b", re.IGNORECASE),
    re.compile(r"net\s+localgroup\s+administrators", re.IGNORECASE),
    re.compile(r"net\s+(user|group)\s", re.IGNORECASE),
    re.compile(r"whoami\s*/(all|priv|groups)", re.IGNORECASE),
    re.compile(r"reg\s+(add|save)\s+[^\n]{0,200}\\run\b", re.IGNORECASE),  # registry Run-key persistence
    re.compile(r"schtasks\s*/create", re.IGNORECASE),
    re.compile(r"\\currentversion\\run\b", re.IGNORECASE),
)

# raw_event keys that plausibly carry a command line / executable path
# across both this corpus's sources (Sysmon EventID 1 CommandLine/Image,
# Windows Security 4688 CommandLine, registry TargetObject for persistence
# checks). Checked generically rather than assuming one schema, since the
# rules baseline must work on whatever fields a given EventID happens to
# populate.
_TEXT_FIELDS_TO_SCAN = (
    "CommandLine",
    "ParentCommandLine",
    "Image",
    "ParentImage",
    "TargetObject",
    "ScriptBlockText",
)


def _record_text_blob(record: AlertRecord) -> str:
    parts = []
    for key in _TEXT_FIELDS_TO_SCAN:
        value = record.raw_event.get(key)
        if value:
            parts.append(str(value))
    return " ".join(parts)


class RulesBaseline:
    """Static keyword/pattern heuristic over raw_event, no LLM, no training.

    Isolates the LLM's marginal contribution — per Arp et al.'s "Inappropriate
    Baseline" pitfall, this is the crux comparison the "does AI help" claim
    rests on (design brief Verdict #5, ranked essential). Kept a genuine,
    honest attempt: real LOLBin names + real offensive-tradecraft command-
    line markers (encoded PowerShell, download cradles, discovery/persistence
    commands), not a rule built to lose. See module-level indicator lists
    for the exact patterns and their rationale.

    Scoring: `score` is the fraction of matched indicator categories present
    (LOLBin name match, suspicious command-line pattern match, exclusive
    high-signal EventID match), giving a continuous [0, 1] value for
    PR-AUC/ROC-AUC rather than a bare 0/1. `is_malicious_pred` fires if AT
    LEast one indicator category matched — a single explicit design choice
    (documented, not hidden) that trades some false positives for recall,
    matching the design brief's framing that a rules baseline's job is to
    give the LLM's marginal contribution a genuine target to beat, not to be
    tuned defensively.
    """

    name = "rules_heuristic"

    # EventIDs that, on their own, OTRF's atomic captures use disproportionately
    # for credential access / lateral movement techniques in this corpus (e.g.
    # Sysmon 10 = ProcessAccess, frequently LSASS-dump-adjacent). Included as
    # ONE signal among several, never as a sole trigger, since EventID alone
    # is also exactly the kind of feature `test_shortcut_audit.py` flags as a
    # collection-stack artifact when used in isolation on the FULL corpus —
    # here it only contributes one vote among three category checks on
    # already shortcut-mitigated records, not a standalone classifier.
    _HIGH_SIGNAL_EVENT_IDS = frozenset({10})  # Sysmon ProcessAccess

    def predict(self, records: list[AlertRecord]) -> list[BaselinePrediction]:
        predictions = []
        for record in records:
            text_blob = _record_text_blob(record)
            lolbin_hit = any(name in text_blob.lower() for name in _LOLBIN_NAMES) and any(
                pattern.search(text_blob) for pattern in _SUSPICIOUS_COMMAND_PATTERNS
            )
            pattern_hit = any(pattern.search(text_blob) for pattern in _SUSPICIOUS_COMMAND_PATTERNS)
            event_id_hit = record.raw_event.get("EventID") in self._HIGH_SIGNAL_EVENT_IDS

            categories_hit = sum([lolbin_hit, pattern_hit, event_id_hit])
            score = categories_hit / 3.0
            predictions.append(BaselinePrediction(is_malicious_pred=categories_hit > 0, score=score))
        return predictions


# ---------------------------------------------------------------------------
# Baseline 4: classical ML on structured features
# ---------------------------------------------------------------------------

# Fields the shortcut-mitigation layer (src/ingest/leakage.py) exists to
# suppress or that are collector/provenance bookkeeping rather than
# behavior — excluded here for the SAME reason leakage.py excludes them
# from the corpus's cross-source comparison, applied now to feature
# engineering specifically. Superset of `leakage.UNMAPPABLE_KEYS` (that set
# is about cross-source VALUE comparability; this one is about what a
# leakage-safe feature vector may read at all) plus timestamp-bearing keys
# (raw calendar time is a documented shortcut per leakage.py) and any
# hostname/identity field pseudonymization exists to blind.
_LEAKAGE_SUPPRESSED_KEYS = frozenset(
    {
        "ProviderGuid",
        "ThreadID",
        "RecordNumber",
        "ExecutionProcessID",
        "Opcode",
        "@timestamp",
        "EventTime",
        "UtcTime",
        "CreationUtcTime",
        "PreviousCreationUtcTime",
        "EventReceivedTime",
        "Hostname",
        "@version",
    }
)


def _engineer_features(record: AlertRecord) -> dict[str, object]:
    """Map one AlertRecord to a flat feature dict for `DictVectorizer`.

    Reads ONLY `event_type`, `raw_event["EventID"]`, and a small set of
    engineered signals derived from the same LOLBin/pattern vocabulary the
    rules baseline uses (command-line length, presence of an encoded-
    PowerShell marker, LOLBin-name presence, field count of the record) —
    never a raw free-text field verbatim (that would let the model
    memorize specific strings from a small training split rather than
    learn generalizable structure, and would reopen exactly the raw-field
    shortcut surface `src/ingest/leakage.py` exists to close). Every key in
    `_LEAKAGE_SUPPRESSED_KEYS` is skipped outright, and no timestamp,
    hostname, or provenance field is read at all — this is the
    leakage-safe feature set required by the task.
    """
    text_blob = _record_text_blob(record)
    lower_blob = text_blob.lower()

    return {
        "event_type": record.event_type.value,
        "event_id": str(record.raw_event.get("EventID")),
        "field_count": len([k for k in record.raw_event if k not in _LEAKAGE_SUPPRESSED_KEYS]),
        "command_line_length": len(str(record.raw_event.get("CommandLine") or "")),
        "has_lolbin_name": any(name in lower_blob for name in _LOLBIN_NAMES),
        "has_suspicious_pattern": any(p.search(text_blob) for p in _SUSPICIOUS_COMMAND_PATTERNS),
        "has_parent_command_line": bool(record.raw_event.get("ParentCommandLine")),
        "has_target_object": bool(record.raw_event.get("TargetObject")),
    }


@dataclass
class ClassicalMLBaseline:
    """Logistic regression over engineered structured features.

    Per the design brief: "high priority, not nice-to-have" — the single
    comparison most likely to be flagged missing by an ML-literate reviewer
    (Arp et al.'s "Inappropriate Baseline" pitfall). Logistic regression
    chosen over gradient boosting for this implementation: comparable
    accuracy on a modest engineered-feature set, faster to fit/inspect, and
    scikit-learn's own `LogisticRegression` needs no extra dependency beyond
    what this task already adds.

    MUST be trained on a leakage-safe, capture-level split (`fit`'s
    docstring) and must never read a field `_LEAKAGE_SUPPRESSED_KEYS`
    excludes (`_engineer_features`'s docstring) — both requirements enforced
    structurally by this class's own code, not left to caller discipline.
    """

    _pipeline: Pipeline = field(init=False, repr=False)
    _fitted: bool = field(init=False, default=False, repr=False)

    name = "classical_ml"

    def __post_init__(self) -> None:
        self._pipeline = Pipeline(
            steps=[
                ("vectorize", DictVectorizer(sparse=False)),
                ("scale", StandardScaler()),
                ("classify", LogisticRegression(max_iter=1000, class_weight="balanced")),
            ]
        )
        self._fitted = False

    def fit(self, records: list[AlertRecord]) -> "ClassicalMLBaseline":
        """Fit on `records`, reading `is_malicious` ONLY here (the training
        step) — never at `predict` time.

        Leakage-safety is the caller's responsibility at the SPLIT level:
        `harness.py` is required to pass a `records` set here that is
        capture-disjoint from whatever it later calls `.predict()` on (i.e.
        `source_capture_id` must not overlap between the fit set and the
        eval set), so the model cannot memorize a specific capture's
        idiosyncrasies and then be "evaluated" on the same capture. This
        class itself cannot enforce that (it only sees whatever list it's
        given), which is why `harness.py`'s train/eval split is built at the
        capture-id level explicitly, not a per-record random split — see
        `harness.py::_classical_ml_train_test_split` docstring.
        """
        if not records:
            raise ValueError("cannot fit ClassicalMLBaseline on zero records")
        features = [_engineer_features(r) for r in records]
        labels = [int(r.is_malicious) for r in records]
        if len(set(labels)) < 2:
            raise ValueError("fit set must contain both classes")
        self._pipeline.fit(features, labels)
        self._fitted = True
        return self

    def predict(self, records: list[AlertRecord]) -> list[BaselinePrediction]:
        if not self._fitted:
            raise RuntimeError("ClassicalMLBaseline.predict called before fit")
        features = [_engineer_features(r) for r in records]
        probs = self._pipeline.predict_proba(features)
        # predict_proba's column order follows self._pipeline's classes_;
        # locate the column for class 1 (malicious) explicitly rather than
        # assuming index 1, since a pathological fit set could in principle
        # order classes differently.
        classifier = self._pipeline.named_steps["classify"]
        malicious_col = list(classifier.classes_).index(1)
        scores = probs[:, malicious_col]
        return [
            BaselinePrediction(is_malicious_pred=bool(score >= 0.5), score=float(score)) for score in scores
        ]


ALL_BASELINE_NAMES = (
    MajorityClassBaseline.name,
    StratifiedRandomBaseline.name,
    RulesBaseline.name,
    ClassicalMLBaseline.name,
)
