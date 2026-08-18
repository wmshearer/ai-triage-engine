"""Download OTRF Security-Datasets `compound/` captures (multi-stage campaigns).

Sibling to `fetch_otrf.py`, kept as a separate module rather than folded in,
because `compound/` captures structurally differ from `atomic/` ones in the
one way that matters for fetch logic: **there is no per-capture metadata YAML
under `datasets/*/_metadata/{id}.yaml`** to read a `files[].link` from.
`fetch_otrf.py`'s whole selection mechanism (`fetch_metadata` ->
`fetch_capture_files` reading `meta["files"]`) has nothing to key off for
these datasets — confirmed directly via the GitHub API content-listing of
`datasets/compound/apt29/` (only `README.md`, `day1/`, `day2/`,
`emulationplans/`, no `_metadata/` sibling anywhere under `compound/`).

Ground-truth consequence (see src/schema.py's `MULTI_TECHNIQUE_SENTINEL` and
research/phase-1c-process-creation-captures.md): OTRF's own published
artifacts for these captures are a prose README (per-Channel and
per-Sysmon-EventID counts only, no per-event or single-primary technique) and
an emulation-plan spreadsheet that is a narrative operator runbook (Stage /
Technique / Step / Description columns keyed by attacker "step", e.g. "3.B"),
not a machine-joinable per-record label — confirmed by downloading and
inspecting `datasets/compound/apt29/emulationplans/apt29.xlsx` directly. So
this module (and `normalize_compound.py`) can assert "this capture is
malicious, from a named multi-technique APT29 emulation" but must NOT invent
a per-event technique OTRF never asserted.

Selection here is therefore by a small, explicit, hand-verified URL list
(`COMPOUND_CAPTURES` below) rather than a metadata-driven walk, because there
is no structured index to walk. Each entry's provenance
(`datasets/compound/apt29/README.md`) is recorded alongside the URL so a
reader does not have to re-derive where the ground truth assertion comes
from. See research/phase-1c-process-creation-captures.md for why exactly
these two captures (not the other compound datasets, not `empire_apt3.tar.gz`
which uses an incompatible event schema) were selected: measured, not
assumed, EventID-1 yield.

Politeness matches fetch_otrf.py: sequential requests, no concurrency. These
are two files (13.9 MB + 43.0 MB), not a bulk mirror.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import requests

RAW_BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master"


@dataclasses.dataclass(frozen=True)
class CompoundCapture:
    """One compound-dataset capture this project ingests.

    `capture_id` is a stable, project-chosen identifier (there is no OTRF-
    issued id for compound captures the way `SDWIN-...` exists for atomics),
    used as `AlertRecord.source_capture_id` and as the on-disk cache filename
    stem. `scenario_label` and `provenance_url` are carried through to
    normalize_compound.py purely for documentation/traceability — the actual
    ground-truth assertion (malicious, multi-technique, unresolved per-event)
    is the same for every entry in this list, not derived from these fields.
    """

    capture_id: str
    link: str
    scenario_label: str
    provenance_url: str


# Hand-verified working set: the two APT29 ATT&CK Evals Round 2 compound
# captures identified in research/phase-1c-process-creation-captures.md as
# the highest-yield source of Sysmon EventID 1 (process creation) records
# without chasing dozens of marginal atomic captures. `empire_apt3.tar.gz`
# (the third compound dataset in the repo) is deliberately excluded: verified
# to use a structurally different event schema (`event_id`/`event_data`
# Winlogbeat convention) that this project's flat `EventID`/`Channel`
# convention parser would silently mis-parse.
COMPOUND_CAPTURES: list[CompoundCapture] = [
    CompoundCapture(
        capture_id="APT29-EVALS-DAY1",
        link=f"{RAW_BASE}/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip",
        scenario_label="APT29 ATT&CK Evals Round 2, Scenario 1 (Pupy + Meterpreter + custom tooling)",
        provenance_url=f"{RAW_BASE}/datasets/compound/apt29/day1/README.md",
    ),
    CompoundCapture(
        capture_id="APT29-EVALS-DAY2",
        link=f"{RAW_BASE}/datasets/compound/apt29/day2/apt29_evals_day2_manual.zip",
        scenario_label="APT29 ATT&CK Evals Round 2, Scenario 2 (PoshC2 + custom tooling)",
        provenance_url=f"{RAW_BASE}/datasets/compound/apt29/README.md",
    ),
]

DEFAULT_CACHE_DIR = Path(__file__).resolve().parents[2] / "data" / "raw" / "otrf" / "compound_captures"


def fetch_compound_capture(capture: CompoundCapture, cache_dir: Path) -> Path:
    """Download one compound capture's zip, caching to disk.

    Filename is derived from `capture.capture_id`, not from the URL's own
    basename — unlike the atomic path (which has a metadata YAML's
    `files[].link` as an authoritative filename source), compound captures'
    only naming convention is "whatever the README happens to call it," and
    both apt29 day1/day2 zips are coincidentally named
    `apt29_evals_day{1,2}_manual.zip`, close enough to collide with a
    same-named file from an unrelated future compound capture if this ever
    grows beyond apt29. Keying the cache file on the project's own stable id
    avoids that.
    """
    dest = cache_dir / f"{capture.capture_id}.zip"
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    resp = requests.get(capture.link, timeout=180, stream=True)
    resp.raise_for_status()
    with dest.open("wb") as fh:
        for chunk in resp.iter_content(chunk_size=1024 * 1024):
            fh.write(chunk)
    return dest


def fetch_all(
    captures: list[CompoundCapture] | None = None, cache_dir: Path | None = None
) -> dict[str, Path]:
    """Fetch every (or the given) compound capture. Returns capture_id -> zip path."""
    captures = captures if captures is not None else COMPOUND_CAPTURES
    cache_dir = cache_dir if cache_dir is not None else DEFAULT_CACHE_DIR
    return {capture.capture_id: fetch_compound_capture(capture, cache_dir) for capture in captures}


if __name__ == "__main__":
    results = fetch_all()
    for cid, path in results.items():
        size_mb = path.stat().st_size / (1024 * 1024)
        print(f"{cid}: {path} ({size_mb:.1f} MB)")
