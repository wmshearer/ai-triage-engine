"""Live end-to-end smoke test for the single-agent triage baseline.

Loads a handful of REAL records (both malicious OTRF captures and benign
evtx-baseline events), triages each one against a live Ollama server, and
prints the model's verdict next to ground truth.

THIS SCRIPT HITS A REAL OLLAMA SERVER — it is not part of the offline test
suite (tests/test_agents.py) and must never be imported by it.

WHAT THIS SCRIPT PROVES, AND WHAT IT DOES NOT: it proves the mechanism works
end-to-end (real record -> prompt -> Ollama -> validated TriageVerdict). It
is NOT an accuracy measurement. The corpus available on this machine is
dominated by registry-write and ProcessAccess events that an independent
assessment judged not reliably triageable by a competent human analyst from
the fields alone (no CommandLine/ParentImage/User context) — see the task
brief this script was built against. Do not report this script's verdict/
ground-truth agreement rate as a result.

Pairing metadata to capture zips: matches each metadata YAML's
`files[0].link` basename to a capture zip filename, NOT `capture_zips[:1]`
for every file (a bug documented as present in
tests/test_shortcut_audit.py's own helper — deliberately not copied here).
"""

from __future__ import annotations

import glob
import os
import random
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.agents.triage import TriageError, triage_alert  # noqa: E402
from src.ingest.normalize import normalize_capture  # noqa: E402
from src.ingest.normalize_benign import normalize_evtx_file  # noqa: E402
from src.schema import AlertRecord  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
SEED = 20260818  # matches src/corpus.py's DEFAULT_RANDOM_SEED for reproducibility


def _metadata_zip_pairs() -> list[tuple[Path, Path]]:
    """Pair each metadata YAML with its capture zip via files[0].link's basename.

    This is the correct pairing logic — tests/test_shortcut_audit.py's own
    `_load_real_corpus` helper has a known bug (`capture_zips[:1]` reused for
    every metadata file); this function exists specifically so this script
    does not repeat that mistake.
    """
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


def load_malicious_sample(n: int) -> list[AlertRecord]:
    records: list[AlertRecord] = []
    for metadata_path, zip_path in _metadata_zip_pairs():
        records.extend(normalize_capture(metadata_path, [zip_path]))
    rng = random.Random(SEED)
    rng.shuffle(records)
    return records[:n]


def load_benign_sample(n: int) -> list[AlertRecord]:
    evtx_paths = sorted(glob.glob(str(REPO_ROOT / "data/raw/evtx_baseline/**/*.evtx"), recursive=True))
    records: list[AlertRecord] = []
    index = 0
    for evtx_path in evtx_paths:
        file_records = normalize_evtx_file(evtx_path, capture_id="win2022-evtx", start_index=index)
        records.extend(file_records)
        index += len(file_records)
        if len(records) >= n * 20:  # don't parse every .evtx file just to sample a handful
            break
    rng = random.Random(SEED)
    rng.shuffle(records)
    return records[:n]


def main() -> None:
    n_malicious = 5
    n_benign = 5

    print(f"Loading {n_malicious} malicious + {n_benign} benign real records...")
    malicious = load_malicious_sample(n_malicious)
    benign = load_benign_sample(n_benign)
    records = malicious + benign
    rng = random.Random(SEED)
    rng.shuffle(records)

    print(f"Loaded {len(records)} records. Triaging sequentially against Ollama...\n")
    print(
        "NOTE: this corpus is not a reliable accuracy benchmark (see this script's "
        "module docstring) -- this run proves the MECHANISM, not accuracy.\n"
    )

    correct = 0
    total_seconds = 0.0
    for i, record in enumerate(records, start=1):
        import time

        t0 = time.monotonic()
        try:
            verdict = triage_alert(record)
        except TriageError as exc:
            print(f"[{i}/{len(records)}] id={record.id} ERROR: {exc}")
            continue
        elapsed = time.monotonic() - t0
        total_seconds += elapsed

        ground_truth = "malicious" if record.is_malicious else "benign"
        predicted_malicious = verdict.verdict.value in ("malicious", "suspicious")
        agree = predicted_malicious == record.is_malicious
        correct += int(agree)

        print(f"[{i}/{len(records)}] id={record.id}")
        print(f"    event_type={record.event_type.value} EventID={record.raw_event.get('EventID')} host={record.source_host}")
        print(f"    ground_truth={ground_truth} (technique={record.attack_technique})")
        print(
            f"    predicted={verdict.verdict.value} confidence={verdict.confidence:.2f} "
            f"technique={verdict.attack_technique} agree_on_malicious_vs_benign={agree}"
        )
        print(f"    reasoning: {verdict.reasoning}")
        print(f"    key_indicators: {verdict.key_indicators}")
        print(f"    latency: {elapsed:.2f}s")
        print()

    n_scored = len(records)
    if n_scored:
        print(f"Mechanism check complete: {correct}/{n_scored} agreed on malicious-vs-benign direction.")
        print(f"Average latency: {total_seconds / n_scored:.2f}s/call over {n_scored} calls.")
    print(
        "\nREMINDER: do not report the agreement count above as an accuracy result -- "
        "see this script's module docstring for why this corpus isn't a valid benchmark yet."
    )


if __name__ == "__main__":
    main()
