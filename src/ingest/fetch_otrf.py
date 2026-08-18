"""Download a small working subset of OTRF Security-Datasets.

Scope decision (see README "Known deviations from Phase 0 research"): this
project ingests the Windows "atomic" captures only. Repo-tree inspection
(GitHub API, recursive tree of OTRF/Security-Datasets@master) showed atomic
captures split 155 Windows / 2 Linux / 2 AWS zips, and — contradicting the
Phase 0 research brief's assumption that all captures are "JSON-lines" — the
Linux captures are actually raw auditd text logs, not JSON. Windows is both
the dominant format and the one that matches the expected JSON schema, so
Phase 1 scopes to it explicitly rather than silently mis-parsing auditd text
as JSON or quietly dropping the discovery.

Selection is by metadata YAML id (the ground-truth-bearing side), not by
guessing zip filenames, because the metadata's own `files[].link` field is
the authoritative pointer to its data file(s) — confirmed by fetching a real
metadata YAML and observing an explicit https raw.githubusercontent.com URL,
not a filename convention this code would otherwise have to reverse-engineer.

Politeness: sequential requests with a short delay, no concurrency — this is
a handful of small files (all well under 4 MB per the content-length checks
done during research), not a bulk mirror.
"""

from __future__ import annotations

import time
from pathlib import Path

import requests
import yaml

RAW_BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master"
METADATA_DIR = f"{RAW_BASE}/datasets/atomic/_metadata"

# Hand-picked working subset: small Windows atomic captures spanning distinct
# ATT&CK techniques/tactics (confirmed via content-length checks: each under
# ~3.5MB). Picking a spread of techniques, not five variants of one, gives the
# schema/tests something more representative to validate against.
CAPTURE_IDS = [
    "SDWIN-190319020147",  # T1069.001 - Net Local Administrators Group
    "SDWIN-190319020729",  # T1087.001 - Net Local Users
    "SDWIN-190319023812",  # T1547.001 - Userland Registry Run Keys
    "SDWIN-190319024742",  # T1053.005 - Userland Scheduled Tasks
    "SDWIN-200609225055",  # T1123     - MSF Record Mic
]

DEFAULT_CACHE_DIR = Path(__file__).resolve().parents[2] / "data" / "raw" / "otrf"
POLITE_DELAY_SECONDS = 0.5


def fetch_metadata(capture_id: str, cache_dir: Path) -> Path:
    """Download one capture's metadata YAML, caching to disk."""
    dest = cache_dir / "metadata" / f"{capture_id}.yaml"
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    resp = requests.get(f"{METADATA_DIR}/{capture_id}.yaml", timeout=30)
    resp.raise_for_status()
    dest.write_bytes(resp.content)
    return dest


def fetch_capture_files(capture_id: str, cache_dir: Path) -> list[Path]:
    """Download every data file (zip) a capture's metadata points to.

    Returns paths to the downloaded zips. Reads the link list out of the
    metadata YAML rather than reconstructing paths, since the YAML's `files`
    field is the source of truth for where a capture's data actually lives.
    """
    meta_path = fetch_metadata(capture_id, cache_dir)
    meta = yaml.safe_load(meta_path.read_text())
    downloaded = []
    for entry in meta.get("files", []):
        link = entry["link"]
        filename = link.rsplit("/", 1)[-1]
        dest = cache_dir / "captures" / filename
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            resp = requests.get(link, timeout=60)
            resp.raise_for_status()
            dest.write_bytes(resp.content)
            time.sleep(POLITE_DELAY_SECONDS)
        downloaded.append(dest)
    return downloaded


def fetch_all(capture_ids: list[str] | None = None, cache_dir: Path | None = None) -> dict[str, list[Path]]:
    """Fetch metadata + data files for the given (or default) capture ids."""
    capture_ids = capture_ids if capture_ids is not None else CAPTURE_IDS
    cache_dir = cache_dir if cache_dir is not None else DEFAULT_CACHE_DIR
    return {cid: fetch_capture_files(cid, cache_dir) for cid in capture_ids}


if __name__ == "__main__":
    results = fetch_all()
    for cid, paths in results.items():
        print(f"{cid}: {[str(p) for p in paths]}")
