"""Test the "context-rich vs. context-poor" observation from run 1
(`reports/evaluation-run1.md`) as a genuine, pre-registered hypothesis on a
FRESH sample — not a re-description of the subgroup finding it was observed
in.

Run 1's per-EventID/per-event_type breakdown showed the LLM scoring strongly
positive MCC on EventID 1 (process creation, 0.695) and EventID 4624
(successful logon, 0.705), and negative-to-harmful MCC on registry (EventID
12/13: -0.369/-0.693) and file (event_type=file: -0.419). The candidate
explanation: the model does well when a record names a semantic ACTOR/OBJECT
it can reason about (a command line, a parent process, an account name, a
destination host) and does at-or-below-chance on bare machine state (a
registry path, a file path, a call-trace) with no such field.

This script:
  1. Buckets the corpus by `src.eval.context_bucket.is_context_rich` — a
     predicate defined from FIELD PRESENCE, never from the EventID list
     above (see that module's docstring for the full rationale and why
     deriving it from EventIDs would make this test circular).
  2. Draws a FRESH, independently-seeded (20260819, not run 1's 20260818),
     EventID-stratified sample from EACH bucket via the existing
     `src.eval.sampling.stratified_eval_sample` (reused unmodified, called
     once per bucket's own record pool).
  3. Runs the LLM + all four existing baselines (`src.eval.baselines`) on
     both buckets' samples, using the existing harness (`src.eval.harness`)
     for every metric — nothing here reimplements MCC, PR-AUC, Wilson CIs,
     or McNemar.
  4. Tests the significance of the MCC difference between buckets with an
     UNPAIRED bootstrap CI (McNemar does not apply: the two buckets are
     disjoint records, not the same items scored by two systems — see
     `_unpaired_bootstrap_diff_ci` below).
  5. Writes `reports/context-experiment.md`.

Durability, mirroring `scripts/run_eval.py::run_llm` exactly (same pattern,
same rationale — a 1,925-record run is ~1.5-2h of sequential inference and
run 1 already lost 2.5h once to a late failure): LLM verdicts are appended to
a `.progress.jsonl` file as they are produced and resumed from it if present.
Every supplementary/diagnostic step (bucket EventID summary, corpus-load
sanity print) is wrapped so it cannot fail the core measurement.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.agents.triage import DEFAULT_MODEL, TriageError, triage_alert  # noqa: E402
from src.agents.schema import TriageVerdict  # noqa: E402
from src.corpus import DEFAULT_BENIGN_RATIO  # noqa: E402
from src.eval import harness  # noqa: E402
from src.eval import metrics as m  # noqa: E402
from src.eval.baselines import (  # noqa: E402
    ClassicalMLBaseline,
    MajorityClassBaseline,
    RulesBaseline,
    StratifiedRandomBaseline,
)
from src.eval.context_bucket import is_context_rich, split_by_context  # noqa: E402
from src.eval.sampling import DEFAULT_SAMPLE_SIZE, MALICIOUS_FLOOR_FOR_5PP_CI, stratified_eval_sample  # noqa: E402
from src.schema import AlertRecord  # noqa: E402

# Deliberately DIFFERENT from run 1's eval_seed (20260818) -- reusing that
# seed on a corpus assembled the same way would draw an OVERLAPPING sample
# with run 1's, which is exactly the "tested on the data it was found in"
# failure this whole experiment exists to avoid.
EXPERIMENT_SEED = 20260819

PROMPT_TEMPLATE_VERSION = "phase-2-single-agent-v1"

BUCKET_NAMES = ("context_rich", "context_poor")


# ---------------------------------------------------------------------------
# Corpus loading -- delegates to scripts/run_eval.py's own loader so the
# malicious/benign record construction is IDENTICAL to run 1's (same source
# files, same normalization, same assemble_corpus call), and only the
# DOWNSTREAM sampling seed differs. run_eval.py is explicitly out of scope to
# MODIFY, but importing its loader is reuse, not modification.
# ---------------------------------------------------------------------------


def load_corpus(benign_ratio: float, seed: int, mitigate_shortcuts: bool) -> list[AlertRecord]:
    # Local import: scripts/ is not normally a package, added to sys.path
    # above the same way run_eval.py adds the repo root.
    import run_eval

    return run_eval.load_full_corpus(benign_ratio=benign_ratio, seed=seed, mitigate_shortcuts=mitigate_shortcuts)


# ---------------------------------------------------------------------------
# LLM runner -- same checkpoint/resume pattern as run_eval.py::run_llm,
# parameterized by a bucket-specific progress path so the two buckets never
# collide or partially overwrite each other's checkpoints.
# ---------------------------------------------------------------------------


def run_llm(eval_records: list[AlertRecord], model: str, progress_path: str) -> list[TriageVerdict | None]:
    """Sequential Ollama triage over `eval_records`, checkpointed to
    `progress_path` as JSON-lines AS EACH VERDICT IS PRODUCED and resumed
    from it if the file already exists -- identical rationale and mechanics
    to `scripts/run_eval.py::run_llm`'s own docstring (duplicated here
    rather than imported, since importing would require modifying
    run_eval.py to export it as reusable, which is out of scope)."""
    verdicts: list[TriageVerdict | None] = []
    done_ids: dict[str, dict] = {}

    if os.path.exists(progress_path):
        with open(progress_path) as handle:
            for line in handle:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue  # truncated final line from a hard kill -- skip it
                done_ids[row["record_id"]] = row
        if done_ids:
            print(f"    Resuming: {len(done_ids)} records already done in {progress_path}")

    total = len(eval_records)
    t_start = time.monotonic()
    n_called = 0

    for i, record in enumerate(eval_records, start=1):
        if record.id in done_ids:
            row = done_ids[record.id]
            verdicts.append(_verdict_from_row(row))
            continue

        try:
            verdict = triage_alert(record, model=model)
        except TriageError as exc:
            print(f"    [{i}/{total}] PARSE/TRANSPORT FAILURE for {record.id}: {exc}")
            verdict = None
        verdicts.append(verdict)
        n_called += 1

        with open(progress_path, "a") as handle:
            handle.write(
                json.dumps(
                    {
                        "record_id": record.id,
                        "verdict": None if verdict is None else verdict.verdict.value,
                        "confidence": None if verdict is None else verdict.confidence,
                        "attack_technique": None if verdict is None else verdict.attack_technique,
                        "reasoning": None if verdict is None else verdict.reasoning,
                        "key_indicators": None if verdict is None else list(verdict.key_indicators),
                    }
                )
                + "\n"
            )

        if i % 10 == 0 or i == total:
            elapsed = time.monotonic() - t_start
            per_call = elapsed / max(n_called, 1)
            print(f"    [{i}/{total}] {elapsed:.1f}s elapsed, {per_call:.2f}s/call avg")

    return verdicts


def _verdict_from_row(row: dict) -> TriageVerdict | None:
    if row.get("verdict") is None:
        return None
    return TriageVerdict(
        verdict=row["verdict"],
        confidence=row["confidence"],
        attack_technique=row.get("attack_technique"),
        reasoning=row.get("reasoning") or "",
        key_indicators=row.get("key_indicators") or [],
    )


# ---------------------------------------------------------------------------
# Baselines -- run the SAME four baselines on each bucket's sample. Each
# bucket gets its OWN leakage-safe classical-ML fit split, drawn from that
# bucket's own corpus-wide pool (not the other bucket's), via
# harness.classical_ml_train_test_split reused unmodified.
# ---------------------------------------------------------------------------


def run_baselines(
    bucket_corpus_pool: list[AlertRecord], eval_records: list[AlertRecord], seed: int
) -> tuple[dict[str, list[harness.ItemPrediction]], harness.SplitDisclosure]:
    results: dict[str, list[harness.ItemPrediction]] = {}

    majority = MajorityClassBaseline()
    results[majority.name] = harness._predictions_for_baseline(eval_records, majority.predict(eval_records))

    malicious_rate = sum(1 for r in eval_records if r.is_malicious) / len(eval_records)
    stratified_random = StratifiedRandomBaseline(malicious_rate=malicious_rate, seed=seed)
    results[stratified_random.name] = harness._predictions_for_baseline(
        eval_records, stratified_random.predict(eval_records)
    )

    rules = RulesBaseline()
    results[rules.name] = harness._predictions_for_baseline(eval_records, rules.predict(eval_records))

    fit_pool, split_disclosure = harness.classical_ml_train_test_split(bucket_corpus_pool, eval_records, seed=seed)
    clf = ClassicalMLBaseline()
    clf.fit(fit_pool)
    results[clf.name] = harness._predictions_for_baseline(eval_records, clf.predict(eval_records))

    return results, split_disclosure


# ---------------------------------------------------------------------------
# Unpaired significance test for the MCC difference between the two buckets.
#
# McNemar (and significance.py's existing paired_bootstrap_ci) both require
# the SAME items scored by two systems, paired by index. That does not apply
# here: context_rich and context_poor are DISJOINT record sets of possibly
# different sizes, scored by the SAME system (the LLM). The appropriate tool
# for "is the difference in a metric between two independent samples bigger
# than sampling noise" is an UNPAIRED (two-sample) bootstrap: resample each
# group's items independently (with replacement, at its own size), recompute
# the metric on each resample, and take the percentile CI of the resampled
# difference. This is the standard two-sample bootstrap (Efron & Tibshirani
# 1993, ch. 16) -- distinct from the paired/matched-pairs bootstrap
# significance.py already implements for LLM-vs-baseline-on-the-same-items.
# ---------------------------------------------------------------------------


def unpaired_bootstrap_mcc_diff_ci(
    rich_items: list[harness.ItemPrediction],
    poor_items: list[harness.ItemPrediction],
    policy: str,
    n_resamples: int = 10_000,
    confidence: float = 0.95,
    seed: int = EXPERIMENT_SEED,
) -> dict[str, float]:
    """Two-sample bootstrap CI on MCC(context_rich) - MCC(context_poor).

    Resamples each bucket's committed items independently, so the pairing
    assumption `significance.paired_bootstrap_ci` relies on is never invoked.
    Returns a dict with `point_estimate`, `low`, `high`, `n_resamples` --
    same shape as `significance.BootstrapCIResult` but not that dataclass,
    since this is a genuinely different (unpaired) procedure and forcing it
    into the paired result type would misrepresent what was computed.
    """
    rich_true, rich_pred = harness._committed_items(rich_items, policy)
    poor_true, poor_pred = harness._committed_items(poor_items, policy)
    if not rich_true or not poor_true:
        raise ValueError("both buckets need at least one committed item under this policy")

    def _mcc_of(y_true: list[bool], y_pred: list[bool]) -> float:
        val = m.mcc(m.confusion_counts(y_true, y_pred))
        return val if val is not None else 0.0  # degenerate resample (single predicted class); treat as no-signal, not undefined-poisons-the-CI

    point_estimate = _mcc_of(rich_true, rich_pred) - _mcc_of(poor_true, poor_pred)

    rng = random.Random(seed)
    n_rich, n_poor = len(rich_true), len(poor_true)
    diffs: list[float] = []
    for _ in range(n_resamples):
        r_idx = [rng.randrange(n_rich) for _ in range(n_rich)]
        p_idx = [rng.randrange(n_poor) for _ in range(n_poor)]
        r_mcc = _mcc_of([rich_true[i] for i in r_idx], [rich_pred[i] for i in r_idx])
        p_mcc = _mcc_of([poor_true[i] for i in p_idx], [poor_pred[i] for i in p_idx])
        diffs.append(r_mcc - p_mcc)

    diffs.sort()
    alpha = 1 - confidence
    low_idx = max(0, int((alpha / 2) * n_resamples))
    high_idx = min(n_resamples - 1, int((1 - alpha / 2) * n_resamples) - 1)

    return {
        "point_estimate": point_estimate,
        "low": diffs[low_idx],
        "high": diffs[high_idx],
        "n_resamples": n_resamples,
        "confidence": confidence,
    }


# ---------------------------------------------------------------------------
# Report rendering -- reuses report.py's per-system rendering helpers for
# each bucket's full breakdown, adds a bucket-comparison section on top.
# ---------------------------------------------------------------------------


def _bucket_eventid_summary(records: list[AlertRecord]) -> dict[str, int]:
    """Non-fatal diagnostic: EventID counts within a bucket, for the report's
    'Bucket definition' section ('which EventIDs fell where as a
    consequence'). Wrapped by the caller in try/except -- this is disclosure,
    not the core measurement."""
    counts = Counter(str(r.raw_event.get("EventID")) for r in records)
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def render_bucket_definition_section() -> str:
    from src.eval import context_bucket as cb

    lines = ["## Bucket definition\n"]
    lines.append(
        "`src/eval/context_bucket.py::is_context_rich(record)` — a record is "
        "**context-rich** iff its (post shortcut-mitigation) `raw_event` carries "
        "at least one non-empty, non-placeholder value for one of the fields below; "
        "otherwise it is **context-poor**. Defined from FIELD PRESENCE only — "
        "never from `EventID` or `event_type` — see that module's docstring for "
        "the full per-field rationale.\n"
    )
    lines.append(f"- ACTOR fields (who/what specifically acted): `{', '.join(cb.ACTOR_FIELDS)}`")
    lines.append(f"- OBJECT fields (a specific external destination/target): `{', '.join(cb.OBJECT_FIELDS)}`")
    lines.append(
        "- Excluded on purpose: a bare `Image`/`SourceImage`/`TargetImage` path alone "
        "(present on nearly every EventID in this corpus, so it carries no "
        "discriminating signal by itself), and opaque identifiers "
        "(`TargetObject`, `TargetFilename`, `CallTrace`, `ProcessGuid`, `ProcessId`, "
        "`LogonGuid`).\n"
    )
    return "\n".join(lines)


def render_eventid_consequence_table(rich_summary: dict, poor_summary: dict) -> str:
    lines = ["### EventID membership, AS A CONSEQUENCE of the predicate (not an input to it)\n"]
    lines.append("| EventID | n in context_rich sample | n in context_poor sample |")
    lines.append("|---|---|---|")
    all_eids = sorted(set(rich_summary) | set(poor_summary), key=lambda x: (len(x), x))
    for eid in all_eids:
        lines.append(f"| {eid} | {rich_summary.get(eid, 0)} | {poor_summary.get(eid, 0)} |")
    lines.append("")
    return "\n".join(lines)


PRE_REGISTRATION = """## Pre-registered prediction

Committed BEFORE running the LLM on either bucket's sample.

**Hypothesis under test:** the LLM performs well when a record names a
semantic actor/object it can reason about, and performs at-or-below chance
when the record is bare machine state with no such field (see module
docstring / this report's introduction for the full statement, carried over
verbatim from the run-1 observation this experiment tests).

**CONFIRMS the hypothesis** if, on the headline (`conservative`) policy:
  - MCC(context_rich) is positive AND meaningfully above chance (its 95% CI
    excludes 0), AND
  - MCC(context_poor) is at-or-below chance (point estimate <= 0, or a 95%
    CI that includes 0), AND
  - the unpaired bootstrap 95% CI on MCC(context_rich) - MCC(context_poor)
    excludes 0 (the gap itself is not explainable by sampling noise), AND
  - on context_rich, the LLM beats the best-performing baseline's MCC by a
    margin larger than that baseline's own year-over-run noise would explain
    (reported qualitatively against each baseline's MCC + CI, since a single
    run has no repeated-baseline variance estimate) -- this is the "does it
    beat the baselines THERE, when it lost everywhere pooled" claim the task
    brief calls the actually-interesting question, not merely "LLM MCC > 0
    on context_rich".

**REFUTES the hypothesis** if:
  - MCC(context_rich) is NOT meaningfully above chance (its CI includes 0 or
    is negative), regardless of what context_poor does -- the "it does well
    with context" half fails on its own account, independent of the
    poor-bucket comparison, OR
  - the unpaired bootstrap CI on the MCC difference includes 0 -- the
    pooled-run gap observed in run 1 does not survive being tested on a
    disjoint, freshly-drawn sample, OR
  - context_rich's LLM MCC is statistically indistinguishable from (or worse
    than) its own best baseline's MCC on the SAME context_rich sample -- i.e.
    even if the LLM is "less bad" on context-rich data, it is not
    demonstrating genuine semantic reasoning if a baseline gets there too.

**INCONCLUSIVE** if the achieved malicious floor in either bucket falls
meaningfully short of 385 (wide CIs prevent either CONFIRM or REFUTE from
being asserted honestly), or if context_poor's own CI is too wide to
distinguish "at chance" from "meaningfully negative" -- reported as
inconclusive rather than forced into a verdict the data cannot support.
"""


def render_report(
    rich_result: harness.SystemResult,
    rich_baselines: dict[str, harness.SystemResult],
    rich_sample_report,
    poor_result: harness.SystemResult,
    poor_baselines: dict[str, harness.SystemResult],
    poor_sample_report,
    diff_ci: dict,
    eventid_rich: dict,
    eventid_poor: dict,
    run_metadata: dict,
) -> str:
    from src.eval import report as report_mod

    parts = ["# AI Triage Engine — Context-Richness Hypothesis Experiment\n"]
    parts.append(
        "Tests the run-1 subgroup observation (`reports/evaluation-run1.md`) that the LLM's "
        "performance splits sharply between EventIDs carrying a semantic actor/object and "
        "EventIDs carrying only bare machine state, on a FRESH, independently-seeded sample "
        "not reused from run 1.\n"
    )

    parts.append(PRE_REGISTRATION)
    parts.append(render_bucket_definition_section())
    parts.append(render_eventid_consequence_table(eventid_rich, eventid_poor))

    parts.append("## Run metadata\n")
    for key, value in run_metadata.items():
        parts.append(f"- **{key}**: {value}")
    parts.append("")

    parts.append("## Results\n")
    for label, result_bundle, sample_report in (
        ("context_rich", (rich_result, rich_baselines), rich_sample_report),
        ("context_poor", (poor_result, poor_baselines), poor_sample_report),
    ):
        llm_res, baseline_results = result_bundle
        parts.append(f"### Bucket: `{label}`\n")
        parts.append(
            f"Sample: target {sample_report.target_total} total ({sample_report.target_malicious} malicious "
            f"floor-targeted), achieved {sample_report.achieved_total} total "
            f"({sample_report.achieved_malicious} malicious / {sample_report.achieved_benign} benign), "
            f"385-floor met: {sample_report.floor_met}\n"
        )
        parts.append(f"#### `{label}` headline table (headline policy = `{harness.HEADLINE_POLICY}`)\n")
        parts.append(
            "| System | n | MCC | PR-AUC | ROC-AUC (secondary) | Balanced acc. | "
            "Recall [Wilson 95% CI] | Precision [Wilson 95% CI] |"
        )
        parts.append("|---|---|---|---|---|---|---|---|")
        all_systems = {"llm": llm_res, **baseline_results}
        for name, sys_result in all_systems.items():
            headline = sys_result.pooled.policies.get(harness.HEADLINE_POLICY)
            if headline is None:
                parts.append(f"| {name} | {sys_result.pooled.n} | n/a | n/a | n/a | n/a | n/a | n/a |")
                continue
            parts.append(
                f"| {name} | {headline.n} | {report_mod._fmt(headline.metrics['mcc'])} | "
                f"{report_mod._fmt(headline.pr_auc)} | {report_mod._fmt(headline.roc_auc)} | "
                f"{report_mod._fmt(headline.metrics['balanced_accuracy'])} | "
                f"{report_mod._fmt_pct_ci(headline.recall_wilson_ci)} | "
                f"{report_mod._fmt_pct_ci(headline.precision_wilson_ci)} |"
            )
        parts.append("")

        for name, sys_result in all_systems.items():
            parts.append(report_mod.render_system_section(f"{label} / {name}", sys_result))

    parts.append("## Significance\n")
    parts.append(
        "**Method: unpaired (two-sample) bootstrap CI on MCC(context_rich) - MCC(context_poor), "
        "headline `conservative` policy.** McNemar's test and the harness's existing "
        "`significance.paired_bootstrap_ci` both require the SAME items scored by two systems, "
        "paired by index — that assumption does not hold here (context_rich and context_poor are "
        "disjoint record sets scored by the same system). A two-sample bootstrap resamples each "
        "bucket's committed items independently (with replacement, at its own size) and takes the "
        "percentile CI of the resampled MCC difference — the standard nonparametric tool for "
        "comparing a statistic between two independent samples (Efron & Tibshirani 1993, ch. 16).\n"
    )
    parts.append(
        f"MCC(context_rich) - MCC(context_poor) = {diff_ci['point_estimate']:+.3f} "
        f"[{diff_ci['low']:+.3f}, {diff_ci['high']:+.3f}] (95% CI, {diff_ci['n_resamples']} resamples)\n"
    )
    ci_excludes_zero = diff_ci["low"] > 0 or diff_ci["high"] < 0
    parts.append(f"CI excludes 0: **{ci_excludes_zero}**\n")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample-size", type=int, default=DEFAULT_SAMPLE_SIZE, help="Per-bucket target sample size.")
    parser.add_argument("--seed", type=int, default=EXPERIMENT_SEED)
    parser.add_argument("--benign-ratio", type=float, default=DEFAULT_BENIGN_RATIO)
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL)
    parser.add_argument("--no-mitigate-shortcuts", action="store_true")
    parser.add_argument("--output", type=str, default="reports/context-experiment.md")
    parser.add_argument(
        "--baselines-only",
        action="store_true",
        help="Skip the LLM entirely (no Ollama, no network) -- for smoke-testing the sampling/baseline/report plumbing.",
    )
    args = parser.parse_args()

    mitigate_shortcuts = not args.no_mitigate_shortcuts

    print("Loading full corpus (same construction as run 1, fresh sampling seed)...")
    corpus = load_corpus(benign_ratio=args.benign_ratio, seed=args.seed, mitigate_shortcuts=mitigate_shortcuts)

    print("Splitting corpus by context_bucket.is_context_rich (field-presence predicate)...")
    rich_pool, poor_pool = split_by_context(corpus)
    print(f"  context_rich pool: {len(rich_pool)} (malicious={sum(r.is_malicious for r in rich_pool)})")
    print(f"  context_poor pool: {len(poor_pool)} (malicious={sum(r.is_malicious for r in poor_pool)})")

    print(f"\nDrawing FRESH stratified samples per bucket (seed={args.seed}, target={args.sample_size})...")
    rich_sample, rich_sample_report = stratified_eval_sample(rich_pool, sample_size=args.sample_size, seed=args.seed)
    poor_sample, poor_sample_report = stratified_eval_sample(poor_pool, sample_size=args.sample_size, seed=args.seed)
    print(
        f"  context_rich: {rich_sample_report.achieved_total} total "
        f"({rich_sample_report.achieved_malicious} malicious), floor met: {rich_sample_report.floor_met}"
    )
    print(
        f"  context_poor: {poor_sample_report.achieved_total} total "
        f"({poor_sample_report.achieved_malicious} malicious), floor met: {poor_sample_report.floor_met}"
    )

    eventid_rich: dict[str, int] = {}
    eventid_poor: dict[str, int] = {}
    try:
        eventid_rich = _bucket_eventid_summary(rich_sample)
        eventid_poor = _bucket_eventid_summary(poor_sample)
    except Exception as exc:  # non-fatal diagnostic only
        print(f"  WARNING: EventID summary diagnostic failed ({type(exc).__name__}: {exc}) -- continuing.")

    bucket_results: dict[str, tuple] = {}
    for label, sample, pool in (("context_rich", rich_sample, rich_pool), ("context_poor", poor_sample, poor_pool)):
        print(f"\n=== Bucket: {label} ===")
        print("Running baselines...")
        baseline_items, split_disclosure = run_baselines(pool, sample, seed=args.seed)
        baseline_results = {
            name: harness.build_system_result(name, items) for name, items in baseline_items.items()
        }

        if args.baselines_only:
            print("  --baselines-only: skipping the LLM entirely.")
            verdicts = [None] * len(sample)
        else:
            progress_path = f"{args.output}.{label}.progress.jsonl"
            print(
                f"Running LLM ({args.model}) sequentially on {len(sample)} records "
                f"(checkpointed to {progress_path})..."
            )
            verdicts = run_llm(sample, model=args.model, progress_path=progress_path)
        llm_items = harness._predictions_for_llm(sample, verdicts)

        checkpoint_path = f"{args.output}.{label}.verdicts.json"
        try:
            with open(checkpoint_path, "w") as handle:
                json.dump(
                    [
                        {
                            "record_id": record.id,
                            "is_malicious": record.is_malicious,
                            "event_id": record.raw_event.get("EventID"),
                            "context_rich": is_context_rich(record),
                            "verdict": None if verdict is None else verdict.verdict.value,
                            "confidence": None if verdict is None else verdict.confidence,
                        }
                        for record, verdict in zip(sample, verdicts)
                    ],
                    handle,
                    indent=2,
                )
            print(f"  Checkpointed {len(verdicts)} verdicts -> {checkpoint_path}")
        except OSError as exc:
            print(f"  WARNING: could not write verdict checkpoint: {exc}")

        llm_specific = harness.compute_llm_specific_report(llm_items)
        llm_result = harness.build_system_result("llm", llm_items, llm_specific)

        bucket_results[label] = (llm_result, baseline_results, llm_items, split_disclosure)

    rich_llm, rich_baselines, rich_llm_items, rich_split = bucket_results["context_rich"]
    poor_llm, poor_baselines, poor_llm_items, poor_split = bucket_results["context_poor"]

    print("\nComputing unpaired bootstrap CI on MCC(context_rich) - MCC(context_poor)...")
    diff_ci = unpaired_bootstrap_mcc_diff_ci(
        rich_llm_items, poor_llm_items, policy=harness.HEADLINE_POLICY, seed=args.seed
    )
    print(f"  MCC diff = {diff_ci['point_estimate']:+.3f} [{diff_ci['low']:+.3f}, {diff_ci['high']:+.3f}]")

    run_metadata = {
        "prompt_template_version": PROMPT_TEMPLATE_VERSION,
        "experiment_seed": args.seed,
        "run1_eval_seed_for_comparison": 20260818,
        "benign_ratio": args.benign_ratio,
        "mitigate_shortcuts": mitigate_shortcuts,
        "model": args.model,
        "temperature": 0.0,
        "per_bucket_sample_target": args.sample_size,
        "malicious_floor_per_bucket": MALICIOUS_FLOOR_FOR_5PP_CI,
        "context_rich_classical_ml_split": f"malicious={rich_split.malicious_split_strategy}, benign={rich_split.benign_split_strategy}",
        "context_poor_classical_ml_split": f"malicious={poor_split.malicious_split_strategy}, benign={poor_split.benign_split_strategy}",
    }

    md = render_report(
        rich_llm,
        rich_baselines,
        rich_sample_report,
        poor_llm,
        poor_baselines,
        poor_sample_report,
        diff_ci,
        eventid_rich,
        eventid_poor,
        run_metadata,
    )

    Path(args.output).write_text(md)
    print(f"\nReport written to {args.output}")


if __name__ == "__main__":
    main()
