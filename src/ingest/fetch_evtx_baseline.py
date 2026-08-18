"""Download a small working subset of NextronSystems/evtx-baseline.

Source: github.com/NextronSystems/evtx-baseline, Apache-2.0 (verified via the
GitHub API `license` endpoint returning `{"spdx_id": "Apache-2.0"}` and the
raw LICENSE file, per the Phase 1 research brief). It ships real Sysmon +
native Windows Event Log `.evtx` output from genuine software installs
across several VM builds, packaged as one `.tgz` per VM release asset
(confirmed via the GitHub Releases API: `win7-x86.tgz`, `win10-client.tgz`,
`win11-client.tgz`, `win11-client-2023.tgz`, `win2022-evtx.tgz`,
`win2022-ad.tgz`, `win2022-0-20348-azure.tgz`, plus a 621 MB `all-evtx.tgz`
combining everything).

Scope decision: this project downloads exactly ONE release asset by default
(`win2022-evtx.tgz`, ~27 MB) rather than the full 621 MB `all-evtx.tgz` or
several per-VM archives — "a SMALL subset, one or two VM captures, not
621MB" per the task. `win2022-evtx.tgz` was chosen (over the even-smaller
`win7-x86.tgz`) because it is a non-domain-joined single-VM capture (simpler
provenance than `win2022-ad.tgz`) whose `.evtx` files were directly confirmed
during Phase 1 implementation to carry every channel this project's
`_EVENT_TYPE_MAP` cares about (Sysmon Operational, Security, PowerShell
Operational, TaskScheduler Operational) — win7-x86 was not directly
inspected and Windows 7's much older Sysmon/PowerShell logging schema
support is a real, undesirable extra variable (see "Windows build
fingerprint" leakage vector in normalize_benign.py).

Politeness: a single sequential HTTP GET for one release asset — no
concurrency, no repeated polling, matching fetch_otrf.py's approach for the
same reason (this is a handful of requests against someone else's
infrastructure, not a bulk mirror).
"""

from __future__ import annotations

import tarfile
from pathlib import Path

import requests

RELEASE_BASE = "https://github.com/NextronSystems/evtx-baseline/releases/download"

# Pinned to the release tag confirmed present at Phase 1 implementation time
# (GitHub Releases API, 2026-08-18) rather than "latest", so a re-run of this
# script months from now can't silently start downloading a different
# archive with a different channel/event mix than what the normalize_benign
# tests and leakage analysis were built against.
DEFAULT_RELEASE_TAG = "v0.8.4"
DEFAULT_ASSET = "win2022-evtx.tgz"

DEFAULT_CACHE_DIR = Path(__file__).resolve().parents[2] / "data" / "raw" / "evtx_baseline"


def fetch_archive(asset: str = DEFAULT_ASSET, release_tag: str = DEFAULT_RELEASE_TAG, cache_dir: Path | None = None) -> Path:
    """Download one evtx-baseline release .tgz asset, caching to disk."""
    cache_dir = cache_dir if cache_dir is not None else DEFAULT_CACHE_DIR
    dest = cache_dir / asset
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    url = f"{RELEASE_BASE}/{release_tag}/{asset}"
    resp = requests.get(url, timeout=120)
    resp.raise_for_status()
    dest.write_bytes(resp.content)
    return dest


def extract_evtx_files(archive_path: Path, cache_dir: Path | None = None) -> list[Path]:
    """Extract an evtx-baseline .tgz and return paths to its `.evtx` members.

    Extracts once (skips if an extraction dir already exists) so repeat test
    runs / ingest calls don't re-untar 27 MB every time, matching
    fetch_otrf.py's "skip if already cached" behavior for the zip downloads.
    """
    cache_dir = cache_dir if cache_dir is not None else DEFAULT_CACHE_DIR
    extract_dir = cache_dir / archive_path.stem.replace(".tar", "")
    if not extract_dir.exists():
        extract_dir.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive_path) as tf:
            tf.extractall(extract_dir, filter="data")
    return sorted(extract_dir.rglob("*.evtx"))


def fetch_all(asset: str = DEFAULT_ASSET, release_tag: str = DEFAULT_RELEASE_TAG, cache_dir: Path | None = None) -> list[Path]:
    """Fetch and extract the default (or given) evtx-baseline asset."""
    archive_path = fetch_archive(asset=asset, release_tag=release_tag, cache_dir=cache_dir)
    return extract_evtx_files(archive_path, cache_dir=cache_dir)


if __name__ == "__main__":
    evtx_files = fetch_all()
    print(f"{len(evtx_files)} .evtx files extracted:")
    for p in evtx_files:
        print(f"  {p}")
