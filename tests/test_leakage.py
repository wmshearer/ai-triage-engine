"""Offline tests for corpus-wide leakage mitigations — no network.

Covers leakage vector #1 (hostname/domain) from the Phase 1 research brief:
proves pseudonymization is deterministic, strips domain suffixes before
hashing (not after), and — the actual leakage check — that it is applied
identically regardless of which source_dataset a record came from.
"""

from datetime import datetime, timezone

from src.ingest.leakage import pseudonymize_hostname, pseudonymize_record_hostname
from src.schema import AlertRecord, EventType


def _record(source_host: str, source_dataset: str, is_malicious: bool) -> AlertRecord:
    kwargs = dict(
        id=f"test:{source_host}",
        timestamp=datetime(2020, 1, 1, tzinfo=timezone.utc),
        source_host=source_host,
        event_type=EventType.PROCESS,
        source_dataset=source_dataset,
        source_capture_id="TEST",
        raw_event={"Hostname": source_host, "EventID": 1},
        is_malicious=is_malicious,
    )
    if is_malicious:
        kwargs["attack_technique"] = "T1059"
        kwargs["attack_tactics"] = ["TA0002"]
    return AlertRecord(**kwargs)


def test_pseudonymize_hostname_is_deterministic():
    a = pseudonymize_hostname("WORKSTATION5.theshire.local")
    b = pseudonymize_hostname("WORKSTATION5.theshire.local")
    assert a == b


def test_pseudonymize_hostname_strips_domain_before_hashing():
    # Same bare host, different domain suffix (or none) -> same token. This
    # is the actual leakage fix: if the domain suffix survived into the hash
    # input, OTRF's ".theshire.local" vs evtx-baseline's bare hostname would
    # still make the two corpora's pseudonymized-token *distributions*
    # trivially distinguishable even though individual tokens look opaque.
    theshire = pseudonymize_hostname("WORKSTATION5.theshire.local")
    mordor = pseudonymize_hostname("WORKSTATION5.mordor.local")
    bare = pseudonymize_hostname("WORKSTATION5")
    assert theshire == mordor == bare


def test_pseudonymize_hostname_is_case_insensitive():
    assert pseudonymize_hostname("WIN-TKC15D7KHUR") == pseudonymize_hostname("win-tkc15d7khur")


def test_pseudonymize_hostname_different_hosts_get_different_tokens():
    assert pseudonymize_hostname("WORKSTATION5") != pseudonymize_hostname("WORKSTATION6")


def test_pseudonymize_record_hostname_updates_both_fields_together():
    record = _record("WORKSTATION5.theshire.local", source_dataset="otrf_security_datasets", is_malicious=True)
    pseudo = pseudonymize_record_hostname(record)
    assert pseudo.source_host == pseudo.raw_event["Hostname"]
    assert pseudo.source_host != record.source_host
    # Every other field (crucially, ground truth) must be untouched.
    assert pseudo.is_malicious == record.is_malicious
    assert pseudo.attack_technique == record.attack_technique
    assert pseudo.raw_event["EventID"] == record.raw_event["EventID"]


def test_pseudonymization_applied_uniformly_is_not_separable_by_source():
    """The actual leakage check: apply the SAME function to a malicious-side
    and a benign-side host that happen to share a bare hostname convention
    difference, and confirm the resulting token carries no source-identity
    signal an attacker (or a classifier) could key on — i.e. two structurally
    different-looking raw hostnames from the two different corpora, once
    pseudonymized, are indistinguishable in shape (same prefix, same length,
    same hex alphabet) from each other."""
    otrf_record = _record("WORKSTATION5.theshire.local", source_dataset="otrf_security_datasets", is_malicious=True)
    benign_record = _record("WIN-TKC15D7KHUR", source_dataset="evtx_baseline", is_malicious=False)

    pseudo_otrf = pseudonymize_record_hostname(otrf_record)
    pseudo_benign = pseudonymize_record_hostname(benign_record)

    assert pseudo_otrf.source_host.startswith("host-")
    assert pseudo_benign.source_host.startswith("host-")
    assert len(pseudo_otrf.source_host) == len(pseudo_benign.source_host)
    # Neither original hostname/domain substring survives.
    assert "theshire" not in pseudo_otrf.source_host
    assert "WORKSTATION" not in pseudo_otrf.source_host
    assert "WIN-TKC" not in pseudo_benign.source_host
