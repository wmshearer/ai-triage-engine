"""CLI entry point for the evaluation harness.

Loads the real corpus (OTRF atomic captures + OTRF compound/APT29 captures +
evtx-baseline benign events), assembles it via `src.corpus.assemble_corpus`
(shortcut-mitigated by default), draws a stratified evaluation sample, runs
all four baselines plus (optionally) the live LLM agent on the SAME items,
computes pooled/stratified metrics + significance, and writes a markdown
report.

`--baselines-only` skips the LLM entirely (no Ollama, no network) so the
harness is testable/runnable without a multi-hour sequential run — this is
the mode used to produce this task's "Baselines-only results" section.

Correct metadata<->zip pairing (mirrors scripts/smoke_triage.py, NOT
tests/test_shortcut_audit.py's known-buggy `capture_zips[:1]` shortcut):
each metadata YAML's `files[0].link` basename is matched against the actual
capture zip filenames.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import time
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.agents.triage import DEFAULT_MODEL, TriageError, triage_alert  # noqa: E402
from src.corpus import DEFAULT_BENIGN_RATIO, assemble_corpus  # noqa: E402
from src.eval import harness  # noqa: E402
from src.eval import report as report_mod  # noqa: E402
from src.eval.baselines import (  # noqa: E402
    ClassicalMLBaseline,
    MajorityClassBaseline,
    RulesBaseline,
    StratifiedRandomBaseline,
)
from src.eval.sampling import DEFAULT_SAMPLE_SIZE, stratified_eval_sample  # noqa: E402
from src.ingest.normalize import normalize_capture  # noqa: E402
from src.ingest.normalize_benign import normalize_evtx_file  # noqa: E402
from src.ingest.normalize_compound import normalize_compound_capture  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent

# Fixed, versioned prompt/config identity for this run — disclosed in the
# report per the design brief's "exact temperature, seed, model name+version,
# and prompt template version" requirement. `render_alert_prompt` (see
# src/agents/prompt.py) has no independent version string of its own yet;
# this is the version identifier for THIS project's triage prompt as it
# exists at the time this harness was built.
PROMPT_TEMPLATE_VERSION = "phase-2-single-agent-v1"


def _atomic_metadata_zip_pairs() -> list[tuple[Path, Path]]:
    """Pair each OTRF atomic metadata YAML with its capture zip via the
    YAML's `files[0].link` basename — see module docstring."""
    metadata_paths = sorted(glob.glob(str(REPO_ROOT / "data/raw/otrf/metadata/*.yaml")))
    capture_zips = sorted(glob.glob(str(REPO_ROOT / "data/raw/otrf/captures/*.zip")))
    zip_by_name = {os.path.basename(z): Path(z) for z in capture_zips}

    pairs: list[tuple[Path, Path]] = []
    for metadata_path in metadata_paths:
        with open(metadata_path) as fh:
            meta = yaml.safe_load(fh)
        files = meta.get("files") or []
        if not files:
            continue
        basename = os.path.basename(files[0]["link"])
        zip_path = zip_by_name.get(basename)
        if zip_path is not None:
            pairs.append((Path(metadata_path), zip_path))
    return pairs


def load_full_corpus(benign_ratio: float, seed: int, mitigate_shortcuts: bool) -> list:
    print("Loading OTRF atomic captures (malicious, per-capture technique)...")
    malicious: list = []
    for metadata_path, zip_path in _atomic_metadata_zip_pairs():
        malicious.extend(normalize_capture(metadata_path, [zip_path]))
    print(f"  {len(malicious)} atomic-capture records loaded.")

    print("Loading OTRF compound/APT29 captures (malicious, MULTI_TECHNIQUE_UNRESOLVED)...")
    compound_zips = sorted(glob.glob(str(REPO_ROOT / "data/raw/otrf/compound_captures/*.zip")))
    n_compound_before = len(malicious)
    for zip_path in compound_zips:
        capture_id = Path(zip_path).stem
        malicious.extend(normalize_compound_capture(capture_id, [zip_path]))
    print(f"  {len(malicious) - n_compound_before} compound-capture records loaded.")

    print("Loading evtx-baseline benign events...")
    evtx_paths = sorted(glob.glob(str(REPO_ROOT / "data/raw/evtx_baseline/**/*.evtx"), recursive=True))
    benign: list = []
    index = 0
    for evtx_path in evtx_paths:
        file_records = normalize_evtx_file(evtx_path, capture_id="win2022-evtx", start_index=index)
        benign.extend(file_records)
        index += len(file_records)
    print(f"  {len(benign)} benign records loaded.")

    print(f"Assembling corpus (benign_ratio={benign_ratio}, mitigate_shortcuts={mitigate_shortcuts})...")
    corpus = assemble_corpus(
        malicious, benign, benign_ratio=benign_ratio, seed=seed, mitigate_shortcuts=mitigate_shortcuts
    )
    print(f"  {len(corpus)} total records in assembled corpus.")
    return corpus


def run_baselines(
    corpus: list, eval_records: list, seed: int
) -> tuple[dict[str, list], "harness.SplitDisclosure"]:
    """Run all four baselines on `eval_records`, returning per-baseline
    ItemPrediction lists plus the classical-ML baseline's leakage-safe-split
    disclosure. `corpus` (the full assembled corpus) is needed only by the
    classical-ML baseline, for its fit split."""
    results: dict[str, list] = {}

    majority = MajorityClassBaseline()
    results[majority.name] = harness._predictions_for_baseline(eval_records, majority.predict(eval_records))

    malicious_rate = sum(1 for r in eval_records if r.is_malicious) / len(eval_records)
    stratified_random = StratifiedRandomBaseline(malicious_rate=malicious_rate, seed=seed)
    results[stratified_random.name] = harness._predictions_for_baseline(
        eval_records, stratified_random.predict(eval_records)
    )

    rules = RulesBaseline()
    results[rules.name] = harness._predictions_for_baseline(eval_records, rules.predict(eval_records))

    print("Fitting classical-ML baseline on a leakage-safe split...")
    fit_pool, split_disclosure = harness.classical_ml_train_test_split(corpus, eval_records, seed=seed)
    print(
        f"  malicious split: {split_disclosure.malicious_split_strategy} "
        f"({split_disclosure.n_malicious_captures_excluded} captures excluded); "
        f"benign split: {split_disclosure.benign_split_strategy}"
    )
    clf = ClassicalMLBaseline()
    clf.fit(fit_pool)
    results[clf.name] = harness._predictions_for_baseline(eval_records, clf.predict(eval_records))

    return results, split_disclosure


def run_llm(eval_records: list, model: str) -> list:
    """Triage every record in `eval_records` sequentially against a live
    Ollama server, returning a list of `TriageVerdict | None` (None = the
    record's call raised TriageError, kept as an explicit parse failure)."""
    verdicts = []
    total = len(eval_records)
    t_start = time.monotonic()
    for i, record in enumerate(eval_records, start=1):
        try:
            verdict = triage_alert(record, model=model)
        except TriageError as exc:
            print(f"  [{i}/{total}] PARSE/TRANSPORT FAILURE for {record.id}: {exc}")
            verdicts.append(None)
            continue
        verdicts.append(verdict)
        if i % 10 == 0 or i == total:
            elapsed = time.monotonic() - t_start
            print(f"  [{i}/{total}] {elapsed:.1f}s elapsed, {elapsed / i:.2f}s/call avg")
    return verdicts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample-size", type=int, default=DEFAULT_SAMPLE_SIZE)
    parser.add_argument("--seed", type=int, default=20260818)
    parser.add_argument("--benign-ratio", type=float, default=DEFAULT_BENIGN_RATIO)
    parser.add_argument("--baselines-only", action="store_true", help="Skip the LLM entirely (no Ollama, no network).")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL)
    parser.add_argument("--no-mitigate-shortcuts", action="store_true", help="Reproduce the pre-Phase-1b leaking corpus (audit use only).")
    parser.add_argument("--determinism-repeats", type=int, default=0, help="If >0 and LLM is run, measure run-to-run agreement over this many repeats on a small subsample.")
    parser.add_argument("--determinism-n-items", type=int, default=10)
    parser.add_argument("--output", type=str, default=None, help="Path to write the markdown report. Defaults to stdout.")
    args = parser.parse_args()

    mitigate_shortcuts = not args.no_mitigate_shortcuts

    corpus = load_full_corpus(benign_ratio=args.benign_ratio, seed=args.seed, mitigate_shortcuts=mitigate_shortcuts)

    print(f"Drawing stratified evaluation sample (target size={args.sample_size})...")
    eval_records, sample_report = stratified_eval_sample(corpus, sample_size=args.sample_size, seed=args.seed)
    print(
        f"  Achieved {sample_report.achieved_total} records "
        f"({sample_report.achieved_malicious} malicious / {sample_report.achieved_benign} benign), "
        f"385-floor met: {sample_report.floor_met}"
    )

    print("\nRunning baselines...")
    baseline_items, split_disclosure = run_baselines(corpus, eval_records, seed=args.seed)

    systems: dict[str, harness.SystemResult] = {}
    for name, items in baseline_items.items():
        systems[name] = harness.build_system_result(name, items)

    significance: list[harness.SignificanceResult] = []
    run_metadata: dict[str, object] = {
        "prompt_template_version": PROMPT_TEMPLATE_VERSION,
        "eval_seed": args.seed,
        "benign_ratio": args.benign_ratio,
        "mitigate_shortcuts": mitigate_shortcuts,
        "baselines_only": args.baselines_only,
        "classical_ml_split_malicious_strategy": split_disclosure.malicious_split_strategy,
        "classical_ml_split_benign_strategy": split_disclosure.benign_split_strategy,
    }

    if not args.baselines_only:
        print(f"\nRunning LLM ({args.model}, temperature=0.0) sequentially on {len(eval_records)} records...")
        run_metadata["model"] = args.model
        run_metadata["temperature"] = 0.0
        verdicts = run_llm(eval_records, model=args.model)
        llm_items = harness._predictions_for_llm(eval_records, verdicts)

        # Checkpoint the LLM verdicts to disk the moment they exist.
        #
        # These cost hours -- the 1,925-record run took ~2.5h of sequential
        # inference. Run 1 of this harness produced all of them, then died in
        # the determinism check below on a single read timeout and lost every
        # one, because results were only written at the very end. Nothing
        # downstream of this point (metrics, significance, rendering) costs
        # more than seconds, so there is no reason for a late failure to
        # destroy the expensive part.
        checkpoint_path = (args.output or "eval") + ".verdicts.json"
        try:
            with open(checkpoint_path, "w") as handle:
                json.dump(
                    [
                        {
                            "record_id": record.id,
                            "is_malicious": record.is_malicious,
                            "event_id": record.raw_event.get("EventID"),
                            "attack_technique": record.attack_technique,
                            "verdict": None if verdict is None else verdict.verdict.value,
                            "confidence": None if verdict is None else verdict.confidence,
                            "predicted_technique": None if verdict is None else verdict.attack_technique,
                        }
                        for record, verdict in zip(eval_records, verdicts)
                    ],
                    handle,
                    indent=2,
                )
            print(f"  Checkpointed {len(verdicts)} verdicts -> {checkpoint_path}")
        except OSError as exc:  # a failed checkpoint must not kill a good run
            print(f"  WARNING: could not write verdict checkpoint: {exc}")

        determinism_report = None
        if args.determinism_repeats >= 2:
            print(f"\nMeasuring run-to-run determinism ({args.determinism_repeats} repeats x {args.determinism_n_items} items)...")
            subsample = eval_records[: args.determinism_n_items]
            try:
                determinism_report = harness.measure_determinism(
                    subsample, lambda r: triage_alert(r, model=args.model), n_repeats=args.determinism_repeats
                )
                print(f"  Agreement rate: {determinism_report.agreement_rate:.1%}")
            except Exception as exc:
                # Determinism is a supplementary diagnostic, not the result.
                # Letting it abort the run is what destroyed run 1: a single
                # 120s read timeout on one record threw away 2.5 hours of
                # completed inference. Report the gap and carry on.
                print(f"  WARNING: determinism measurement failed ({type(exc).__name__}: {exc})")
                print("  Continuing without it -- the evaluation itself is unaffected.")

        llm_specific = harness.compute_llm_specific_report(llm_items, determinism=determinism_report)
        systems = {"llm": harness.build_system_result("llm", llm_items, llm_specific), **systems}

        print("\nComputing significance (LLM vs. each baseline)...")
        significance = harness.compute_significance(llm_items, baseline_items, seed=args.seed)
    else:
        run_metadata["model"] = "N/A (baselines-only run)"
        run_metadata["temperature"] = "N/A"

    corpus_metadata = {
        "corpus_size": len(corpus),
        "benign_ratio": args.benign_ratio,
        "mitigate_shortcuts": mitigate_shortcuts,
        "eval_seed": args.seed,
    }

    result = harness.EvalResult(
        sample_size_report=sample_report,
        systems=systems,
        significance=significance,
        corpus_metadata=corpus_metadata,
    )

    md = report_mod.render_report(result, run_metadata=run_metadata)

    if args.output:
        Path(args.output).write_text(md)
        print(f"\nReport written to {args.output}")
    else:
        print("\n" + md)


if __name__ == "__main__":
    main()
