"""Corpus-wide leakage mitigations, applied identically to BOTH sources.

Phase 1 research (wshearer-site/research/phase-1-benign-corpus.md, Section 5)
enumerates six concrete leakage vectors from pairing OTRF (malicious) with
evtx-baseline (benign). This module holds the ones that need code, not just
documentation, and — critically — every function here is applied to the
FULL assembled corpus in corpus.py, never to one source only. Per the task's
own framing: "whatever you do to one corpus you must do to the other —
asymmetric treatment is itself a leak." A hostname-pseudonymization pass that
only touched the benign side (or vice versa) would still let a classifier
learn "pseudonymized-looking string = one class," which is just the same
leak wearing a disguise.

Deliberately NOT done in normalize.py / normalize_benign.py themselves: those
modules' existing tests assert the raw, un-pseudonymized `source_host` value
(e.g. `WORKSTATION5.theshire.local`) is preserved verbatim from the source
event — changing that would both violate "existing 13 tests must still pass,
unmodified" and would defeat the raw_event field's own documented purpose
("kept as the raw, unmodified source event", schema.py). Mitigation therefore
happens one layer up, in corpus.py's assembly step, over the combined set of
records from both sources at once.
"""

from __future__ import annotations

import hashlib

from src.schema import AlertRecord

# --- Vector 1: hostname/domain ------------------------------------------
# OTRF's Windows atomics are a fixed lab ("theshire.local"/"mordor.local",
# hosts WORKSTATION5/6, MORDORDC — confirmed directly from downloaded
# captures, see tests/test_leakage.py). evtx-baseline's win2022-evtx capture
# uses a single auto-generated hostname (WIN-TKC15D7KHUR, confirmed directly
# by parsing the downloaded .evtx). Left as raw strings, a hostname/domain
# substring is a perfect source-identity proxy — trivially separable, zero
# behavioral signal. Mitigation: hash every hostname to a short, stable,
# domain-stripped token, using the SAME function for every record regardless
# of source_dataset, so the classifier sees an opaque categorical with no
# structural difference between the two corpora's naming conventions.


def pseudonymize_hostname(hostname: str) -> str:
    """Map any hostname/FQDN to a short, stable, source-blind token.

    Domain suffixes are stripped before hashing (not just hashed as-is)
    because otherwise the *domain part itself* (".theshire.local" appearing
    on every OTRF record, absent from every evtx-baseline record) would
    still leak through a hash's input distribution being source-correlated
    even though the output looks opaque — the fix has to remove the
    source-correlated substring before hashing, not just hash it.
    Deterministic (sha256, not random) so the same host always maps to the
    same token across records and across re-runs, which is what lets an
    eval harness still group/count events per-host without ever seeing the
    real name.
    """
    bare_host = hostname.split(".", 1)[0]
    digest = hashlib.sha256(bare_host.lower().encode("utf-8")).hexdigest()[:12]
    return f"host-{digest}"


def pseudonymize_record_hostname(record: AlertRecord) -> AlertRecord:
    """Return a copy of `record` with `source_host` and `raw_event["Hostname"]`
    pseudonymized, leaving every other field (including ATT&CK ground truth)
    untouched.

    Applied uniformly over the whole assembled corpus in corpus.py — see
    module docstring for why this can't live inside either per-source
    normalizer without breaking their existing "preserves raw host verbatim"
    tests.
    """
    new_host = pseudonymize_hostname(record.source_host)
    new_raw = dict(record.raw_event)
    if "Hostname" in new_raw:
        new_raw["Hostname"] = new_host
    return record.model_copy(update={"source_host": new_host, "raw_event": new_raw})
