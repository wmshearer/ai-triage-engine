"""Field-presence predicate: "context-rich" vs "context-poor" records.

Built to test the observation from `reports/evaluation-run1.md`'s per-EventID/
per-event_type breakdown: the LLM scored strongly positive MCC on EventID 1
(process creation, MCC 0.695) and EventID 4624 (successful logon, MCC 0.705),
and negative-to-harmful MCC on registry (EventID 12/13, MCC -0.369/-0.693) and
file (EventID 11 folds into event_type=file, MCC -0.419). The candidate
explanation: the model does well when a record names a semantic ACTOR (who/
what did this — a command line, a parent process, an account name) and/or a
semantic OBJECT it can reason about in context (a destination host, a target
account) — and does at-or-below-chance when the record is bare machine state
(a registry key path, a file path, a call-trace of DLL offsets) with no named
actor at all.

THIS PREDICATE MUST NOT BE DERIVED FROM THE EventID LIST ABOVE, or the test
that uses it would just re-find what run 1 already showed (circular). It is
derived instead from which FIELDS are present on a record's `raw_event` —
schema-level structure, decided before looking at which EventIDs fall where.
The EventID membership below is reported as a CONSEQUENCE of running the
predicate over the real corpus (see `scripts/run_context_experiment.py`'s
pre-registration section), not as an input to defining it.

--------------------------------------------------------------------------
Field taxonomy (the actual definition)
--------------------------------------------------------------------------

ACTOR fields — name WHO or WHAT specifically did something, in a form an
analyst (or an LLM) can reason about semantically rather than just pattern-
match a hash-like string:
  - `CommandLine` / `ParentCommandLine` — the literal invocation, arguments
    and all; the single richest actor signal in this corpus.
  - `ParentImage` — names the parent process by path, establishing a
    process-lineage relationship (not just "a process", but "process X
    launched by process Y").
  - `User` / `SubjectUserName` / `TargetUserName` — a named account the
    event is attributed to or acts upon.
  - `ScriptBlockText` — the literal PowerShell source being executed; the
    same "the actor's own words" signal `CommandLine` provides, for the one
    EventID (4104) that carries script content instead of a command line.

OBJECT fields — name a specific, externally-meaningful destination or
target the actor interacted with, beyond the local machine's own state:
  - `DestinationIp` / `DestinationHostname` — a network peer, a real
    "where did this go" fact.

Deliberately EXCLUDED from both lists — present on records in BOTH strata,
so their presence carries no discriminating signal, and treating them as
"context" would blur the predicate rather than sharpen it:
  - `Image` alone (no CommandLine/ParentImage alongside it) — every EventID
    in this corpus carries some form of executable path (EID 1, 3, 5, 10,
    11, 12, 13 all have `Image` or `SourceImage`/`TargetImage`); a bare path
    string is exactly the "opaque identifier" this predicate's rationale
    calls out, not a semantic actor. It only becomes actor-bearing once
    paired with a command line or a named parent, which is why `Image` is
    not itself a context field but `CommandLine`/`ParentImage` are.
  - `TargetObject` (registry key path), `TargetFilename` (file path),
    `CallTrace` (raw DLL+offset stack), `ProcessGuid`/`LogonGuid`/GUIDs in
    general, `ProcessId`/PIDs — all opaque identifiers/state, the exact
    "bare machine state" half of the hypothesis, and are the OBJECT-poor
    side by construction, not by exclusion after the fact.

A record is CONTEXT-RICH iff its (post shortcut-mitigation) `raw_event`
carries at least one non-empty ACTOR field OR at least one non-empty OBJECT
field from the lists above. Everything else is CONTEXT-POOR.

Checked against the real corpus (`scripts/run_eval.py::load_full_corpus`,
`benign_ratio=4.0`, `mitigate_shortcuts=True`, `seed=20260818` — the same
assembly run1 scored), per-EventID field-presence rates are always 0% or
~100% within an EventID (Sysmon/Windows-Security events are structurally
homogeneous per EventID), so this predicate is effectively — but only AS A
CONSEQUENCE, never as an input — an EventID-level split. See
`scripts/run_context_experiment.py`'s "Bucket definition" section for the
after-the-fact EventID membership table this predicate produces.
"""

from __future__ import annotations

from src.schema import AlertRecord

# Fields that name a semantic ACTOR: who/what specifically did this, in a
# form that carries meaning beyond an opaque identifier (a literal command
# invocation, a named parent process, a named account, literal script
# source). See module docstring for the full per-field rationale.
ACTOR_FIELDS: tuple[str, ...] = (
    "CommandLine",
    "ParentCommandLine",
    "ParentImage",
    "User",
    "SubjectUserName",
    "TargetUserName",
    "ScriptBlockText",
)

# Fields that name a semantic OBJECT: an externally-meaningful destination/
# target beyond the local machine's own opaque state. See module docstring.
OBJECT_FIELDS: tuple[str, ...] = (
    "DestinationIp",
    "DestinationHostname",
)

CONTEXT_FIELDS: tuple[str, ...] = ACTOR_FIELDS + OBJECT_FIELDS

# Sentinel strings this corpus's sources use for "field present but no real
# value" (measured on the real corpus: EventID 4624's TargetOutboundUserName
# and several Security-log subject fields populate a literal "-" rather than
# being absent/null when the value genuinely does not apply). Treated as
# "not present" for this predicate — a literal placeholder dash carries no
# more semantic content than an absent key, and counting it as "context"
# would credit records that in fact have none.
_EMPTY_SENTINELS = frozenset({"", "-", "-\\-"})


def _field_present(value: object) -> bool:
    """True iff `value` is a real, non-placeholder, non-empty value."""
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip() not in _EMPTY_SENTINELS
    return True


def is_context_rich(record: AlertRecord) -> bool:
    """True iff `record.raw_event` carries at least one real actor or object
    field (see module docstring for the exact field lists and rationale).

    Reads ONLY `raw_event` field presence — never `EventID`, `event_type`,
    or any ground-truth field — so this predicate cannot be, even
    accidentally, a relabeling of the EventID list the hypothesis it tests
    was originally observed on.
    """
    return any(_field_present(record.raw_event.get(field)) for field in CONTEXT_FIELDS)


def context_bucket(record: AlertRecord) -> str:
    """`"context_rich"` or `"context_poor"` for `record` — the two bucket
    names used throughout `scripts/run_context_experiment.py` and
    `reports/context-experiment.md`."""
    return "context_rich" if is_context_rich(record) else "context_poor"


def split_by_context(records: list[AlertRecord]) -> tuple[list[AlertRecord], list[AlertRecord]]:
    """Partition `records` into `(context_rich, context_poor)`."""
    rich, poor = [], []
    for record in records:
        (rich if is_context_rich(record) else poor).append(record)
    return rich, poor
