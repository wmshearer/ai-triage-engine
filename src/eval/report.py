"""Render an `EvalResult` (harness.py) to markdown.

Layout follows the design brief's disclosure requirements directly
("What must be disclosed" section): headline table (MCC/PR-AUC first, never
accuracy alone), per-policy confusion matrices (all three, never just the
headline), per-EventID stratified table, baseline comparison with p-values,
LLM-specific metrics as first-class sections, and an explicit
honest-limitations section pulled from the research brief.
"""

from __future__ import annotations

from src.eval import harness as h
from src.eval import metrics as m


def _fmt(value: float | None, digits: int = 3) -> str:
    return "undefined" if value is None else f"{value:.{digits}f}"


def _fmt_ci(ci: m.WilsonInterval | None, digits: int = 3) -> str:
    if ci is None:
        return "n/a"
    return f"{ci.point:.{digits}f} [{ci.low:.{digits}f}, {ci.high:.{digits}f}] (n={ci.n})"


def _fmt_pct_ci(ci: m.WilsonInterval | None) -> str:
    if ci is None:
        return "n/a"
    return f"{ci.point:.1%} [{ci.low:.1%}, {ci.high:.1%}] (n={ci.n})"


def render_policy_confusion_table(policy_report: h.PolicyReport) -> str:
    metrics = policy_report.metrics
    lines = [
        "| TP | FP | FN | TN | n |",
        "|---|---|---|---|---|",
        f"| {metrics['tp']} | {metrics['fp']} | {metrics['fn']} | {metrics['tn']} | {metrics['n']} |",
    ]
    return "\n".join(lines)


def render_policy_metrics_table(policy_report: h.PolicyReport) -> str:
    metrics = policy_report.metrics
    lines = [
        "| Metric | Value |",
        "|---|---|",
        f"| MCC | {_fmt(metrics['mcc'])} |",
        f"| PR-AUC | {_fmt(policy_report.pr_auc)} |",
        f"| ROC-AUC (secondary) | {_fmt(policy_report.roc_auc)} |",
        f"| Balanced accuracy | {_fmt(metrics['balanced_accuracy'])} |",
        f"| Precision | {_fmt_ci(policy_report.precision_wilson_ci)} |",
        f"| Recall | {_fmt_ci(policy_report.recall_wilson_ci)} |",
        f"| F1 | {_fmt(metrics['f1'])} |",
        f"| FPR = FP/(FP+TN) | {_fmt_ci(policy_report.fpr_wilson_ci)} |",
        f"| FNR = FN/(FN+TP) | {_fmt(metrics['fnr'])} |",
        f"| Accuracy (context only, NOT a headline) | {_fmt(metrics['accuracy'])} |",
    ]
    return "\n".join(lines)


def render_system_section(system_name: str, result: h.SystemResult) -> str:
    parts = [f"### {system_name}\n"]
    parts.append(f"Pooled n={result.pooled.n} (malicious={result.pooled.n_malicious}, benign={result.pooled.n_benign})\n")

    for policy in h.COLLAPSE_POLICIES:
        report = result.pooled.policies.get(policy)
        parts.append(f"#### Policy: `{policy}`" + ("  (HEADLINE)" if policy == h.HEADLINE_POLICY else ""))
        if report is None:
            parts.append("_No committed predictions under this policy in the pooled slice._\n")
            continue
        parts.append(render_policy_confusion_table(report))
        parts.append("")
        parts.append(render_policy_metrics_table(report))
        parts.append("")

    sp = result.pooled.selective_prediction
    if sp is not None:
        parts.append("#### Abstention / selective-prediction detail")
        parts.append(
            f"- Coverage: {sp.coverage:.1%} ({sp.n_committed}/{sp.n_total} committed, {sp.n_abstained} abstained)"
        )
        parts.append(f"- Selective accuracy (on committed subset): {_fmt(sp.selective_accuracy)}")
        if sp.aurc is not None:
            parts.append(f"- AURC (area under risk-coverage curve, lower=better): {sp.aurc:.4f}")
        else:
            parts.append("- AURC: not computed (no confidence scores available for this system)")
        parts.append("")

    if result.llm_specific is not None:
        parts.append(render_llm_specific_section(result.llm_specific))

    parts.append(render_stratified_table("Per-EventID", result.per_event_id))
    parts.append(render_stratified_table("Per-event_type", result.per_event_type))
    parts.append(render_stratified_table("Per-technique (sentinel EXCLUDED, see below)", result.per_technique))

    if result.sentinel_bucket is not None:
        parts.append("#### MULTI_TECHNIQUE_UNRESOLVED sentinel bucket (reported separately, never scored per-technique)")
        parts.append(
            f"n={result.sentinel_bucket.n} malicious records whose source capture (OTRF APT29 compound scenarios) "
            "has no OTRF-published per-event technique mapping. No per-technique claim is made for these records."
        )
        headline_report = result.sentinel_bucket.policies.get(h.HEADLINE_POLICY)
        if headline_report is not None:
            parts.append(f"Aggregate recall under `{h.HEADLINE_POLICY}` policy: {_fmt_ci(headline_report.recall_wilson_ci)}")
        parts.append("")

    return "\n".join(parts)


def render_stratified_table(title: str, slices: dict) -> str:
    if not slices:
        return f"#### {title}\n\n_no strata present_\n"
    lines = [f"#### {title}\n"]
    lines.append("| Stratum | n (mal/ben) | MCC (conservative) | Recall [95% Wilson CI] | Precision [95% Wilson CI] |")
    lines.append("|---|---|---|---|---|")
    for key in sorted(slices.keys(), key=str):
        s = slices[key]
        headline = s.policies.get(h.HEADLINE_POLICY)
        mcc_val = _fmt(headline.metrics["mcc"]) if headline else "n/a"
        recall_str = _fmt_pct_ci(headline.recall_wilson_ci) if headline else "n/a"
        precision_str = _fmt_pct_ci(headline.precision_wilson_ci) if headline else "n/a"
        lines.append(f"| {key} | {s.n} ({s.n_malicious}/{s.n_benign}) | {mcc_val} | {recall_str} | {precision_str} |")
    lines.append("")
    return "\n".join(lines)


def render_llm_specific_section(report: h.LLMSpecificReport) -> str:
    lines = ["#### LLM-specific metrics\n"]
    lines.append(f"- Parse-failure rate: {_fmt_pct_ci(report.parse_failure_rate_ci)} ({report.n_parse_failed}/{report.n_attempted} attempted)")
    if report.ece is not None:
        lines.append(f"- Expected Calibration Error (ECE) on self-reported `confidence`: {report.ece.ece:.4f}")
        lines.append("  - Reliability bins (low-high: n, avg_confidence, empirical accuracy):")
        for b in report.ece.bins:
            if b.n == 0:
                continue
            lines.append(f"    - [{b.low:.1f}-{b.high:.1f}): n={b.n}, avg_conf={b.avg_confidence:.3f}, acc={b.accuracy:.3f}")
    else:
        lines.append("- ECE: not computed (no scored records with confidence available)")
    if report.determinism is not None:
        d = report.determinism
        lines.append(
            f"- Run-to-run determinism ({d.n_repeats_per_item} repeats x {d.n_items_tested} items): "
            f"{_fmt_pct_ci(d.agreement_rate_ci)}"
        )
    else:
        lines.append("- Run-to-run determinism: NOT MEASURED in this run (see limitations section)")
    lines.append("")
    return "\n".join(lines)


def render_significance_section(significance: list[h.SignificanceResult]) -> str:
    if not significance:
        return "## Significance vs. baselines\n\n_No significance results computed (baselines-only run, or paired items unavailable)._\n"
    lines = ["## Significance: LLM vs. each baseline (headline policy)\n"]
    lines.append("| Baseline | McNemar method | b (LLM right, base wrong) | c (base right, LLM wrong) | p-value | Bootstrap accuracy diff [95% CI] |")
    lines.append("|---|---|---|---|---|---|")
    for result in significance:
        mc = result.mcnemar
        bs = result.bootstrap_ci
        lines.append(
            f"| {result.baseline_name} | {mc.method} | {mc.b} | {mc.c} | {mc.p_value:.4g} | "
            f"{bs.point_estimate:+.3f} [{bs.low:+.3f}, {bs.high:+.3f}] |"
        )
    lines.append("")
    return "\n".join(lines)


LIMITATIONS_SECTION = """## What must be disclosed (honest-limitations section)

1. **This is a static, offline, labeled-corpus evaluation**, not a live-SOC
   measurement. MTTD/MTTR/dwell-time/analyst-touch-time remain uncomputable
   and unclaimed here — Phase 0's finding, not re-derived, only inherited.
2. **The `suspicious`-collapse policy used for the headline number** is
   `conservative` (`suspicious` -> `malicious`), chosen because a triage
   system's cost asymmetry favors extra human review over a missed
   intrusion. The other two policies' (`high_precision`, `abstention`) full
   tables are published alongside it above — never read the headline number
   as the only honest collapse of `suspicious`.
3. **Exact temperature, seed, model name+version, and prompt template
   version**: see the corpus/run metadata block emitted alongside this
   report by `scripts/run_eval.py` — an unversioned, undisclosed prompt
   makes every downstream number irreproducible by definition.
4. **Parse-failure rate** is reported above as an ACTUAL measured number for
   this run, not an assumed near-zero; the design brief's requested
   grammar-vs-semantic-validation split is not separately measurable from
   outside `triage_alert` in its current form (`TriageError` does not
   currently distinguish HTTP/transport failure, JSON-grammar failure, and
   `TriageVerdict` semantic-validation failure from each other) — this run's
   parse-failure rate is the union of all three failure surfaces, not solely
   surface (b). Splitting them further would require a change to
   `src/agents/triage.py`, which is out of scope for this task (see "What I
   could not do").
5. **ECE / calibration on the `confidence` field** is reported above,
   including if it turns out poorly calibrated — if ECE is high, the
   abstention/selective-prediction thresholding in the pooled section above
   is correspondingly less trustworthy at whatever confidence threshold a
   downstream consumer might pick, because it inherits the same field.
6. **Sample size (n) is reported next to every metric above**, at every
   stratification level, including per-technique breakdowns with small n
   and their (necessarily wide) Wilson CIs — never omitted for being thin.
7. **Corpus construction choices**: `benign_ratio=4.0` is a stated design
   choice (`src/corpus.py`'s own docstring), not a claim of matching real
   ~99:1 SOC prevalence. `mitigate_shortcuts=True` was used to assemble the
   corpus this run scored — see `src/ingest/leakage.py` for exactly what
   that mitigation changes (hostname pseudonymization, timestamp
   neutralization, raw_event field-set ablation to the cross-source
   intersection, and a capped per-EventID class ratio). The
   `MULTI_TECHNIQUE_UNRESOLVED` sentinel bucket's own aggregate metrics are
   reported separately above; no per-technique claim is made for those
   records.
8. **What this does not measure**: MTTD, MTTR, dwell-time, and
   analyst-touch-time are NOT computed anywhere in this report, and cannot
   be honestly computed from a static labeled corpus (no real analyst, no
   real alert arrival-time distribution) — named explicitly here so the
   omission reads as a stated limitation, not an oversight.
9. **No claim of comparability to any external published SOC-LLM benchmark's
   numbers** (e.g. Simbian's "AI SOC LLM Benchmark", n=100, no visible CIs
   or significance testing found in that prior art). Different corpus,
   different ground-truth construction, different task framing — this
   report's numbers stand on their own terms.
"""


def render_report(
    result: h.EvalResult,
    run_metadata: dict[str, object] | None = None,
    title: str = "AI Triage Engine — Evaluation Report",
) -> str:
    parts = [f"# {title}\n"]

    ssr = result.sample_size_report
    parts.append("## Sample\n")
    parts.append(
        f"- Target: {ssr.target_total} total ({ssr.target_malicious} malicious floor-targeted)\n"
        f"- Achieved: {ssr.achieved_total} total ({ssr.achieved_malicious} malicious / {ssr.achieved_benign} benign)\n"
        f"- 385-malicious floor (+/-5pp 95% CI on malicious-class recall) met: {ssr.floor_met}\n"
    )

    if run_metadata:
        parts.append("## Run metadata\n")
        for key, value in run_metadata.items():
            parts.append(f"- **{key}**: {value}")
        parts.append("")

    parts.append("## Corpus metadata\n")
    for key, value in result.corpus_metadata.items():
        parts.append(f"- **{key}**: {value}")
    parts.append("")

    parts.append("## Headline table (pooled, all systems, headline policy = `%s`)\n" % h.HEADLINE_POLICY)
    parts.append("| System | n | MCC | PR-AUC | ROC-AUC (secondary) | Balanced acc. | Recall [Wilson 95% CI] | Accuracy (context only) |")
    parts.append("|---|---|---|---|---|---|---|---|")
    for name, sys_result in result.systems.items():
        headline = sys_result.pooled.policies.get(h.HEADLINE_POLICY)
        if headline is None:
            parts.append(f"| {name} | {sys_result.pooled.n} | n/a | n/a | n/a | n/a | n/a | n/a |")
            continue
        parts.append(
            f"| {name} | {headline.n} | {_fmt(headline.metrics['mcc'])} | {_fmt(headline.pr_auc)} | "
            f"{_fmt(headline.roc_auc)} | {_fmt(headline.metrics['balanced_accuracy'])} | "
            f"{_fmt_pct_ci(headline.recall_wilson_ci)} | {_fmt(headline.metrics['accuracy'])} |"
        )
    parts.append("")

    parts.append("## Per-system detail\n")
    for name, sys_result in result.systems.items():
        parts.append(render_system_section(name, sys_result))

    parts.append(render_significance_section(result.significance))
    parts.append(LIMITATIONS_SECTION)

    return "\n".join(parts)
