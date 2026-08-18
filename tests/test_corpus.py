"""Offline tests for corpus assembly (ratio control + leakage mitigation)."""

from datetime import datetime, timezone

import pytest

from src.corpus import assemble_corpus, corpus_composition
from src.schema import AlertRecord, EventType


def _malicious(n: int, host: str = "WORKSTATION5.theshire.local") -> list[AlertRecord]:
    return [
        AlertRecord(
            id=f"mal:{i}",
            timestamp=datetime(2019, 3, 19, tzinfo=timezone.utc),
            source_host=host,
            event_type=EventType.PROCESS,
            source_dataset="otrf_security_datasets",
            source_capture_id="SDWIN-TEST",
            raw_event={"EventID": 1, "Hostname": host},
            is_malicious=True,
            attack_technique="T1059",
            attack_tactics=["TA0002"],
        )
        for i in range(n)
    ]


def _benign(n: int, host: str = "WIN-TKC15D7KHUR") -> list[AlertRecord]:
    return [
        AlertRecord(
            id=f"ben:{i}",
            timestamp=datetime(2022, 4, 4, tzinfo=timezone.utc),
            source_host=host,
            event_type=EventType.PROCESS,
            source_dataset="evtx_baseline",
            source_capture_id="win2022-evtx",
            raw_event={"EventID": 1, "Hostname": host},
            is_malicious=False,
        )
        for i in range(n)
    ]


def test_assemble_corpus_hits_the_requested_ratio_by_subsampling_benign():
    records = assemble_corpus(_malicious(100), _benign(1000), benign_ratio=4.0, pseudonymize_hosts=False)
    composition = corpus_composition(records)
    assert composition["otrf_security_datasets:malicious"] == 100
    assert composition["evtx_baseline:benign"] == 400


def test_assemble_corpus_shrinks_malicious_when_benign_pool_is_too_small():
    records = assemble_corpus(_malicious(1000), _benign(40), benign_ratio=4.0, pseudonymize_hosts=False)
    composition = corpus_composition(records)
    assert composition["evtx_baseline:benign"] == 40
    assert composition["otrf_security_datasets:malicious"] == 10


def test_assemble_corpus_is_deterministic_given_a_seed():
    r1 = assemble_corpus(_malicious(50), _benign(500), seed=42, pseudonymize_hosts=False)
    r2 = assemble_corpus(_malicious(50), _benign(500), seed=42, pseudonymize_hosts=False)
    assert [r.id for r in r1] == [r.id for r in r2]


def test_assemble_corpus_rejects_empty_inputs():
    with pytest.raises(ValueError, match="malicious"):
        assemble_corpus([], _benign(10))
    with pytest.raises(ValueError, match="benign"):
        assemble_corpus(_malicious(10), [])


def test_assemble_corpus_pseudonymizes_hosts_by_default():
    records = assemble_corpus(_malicious(10), _benign(10))
    hosts = {r.source_host for r in records}
    assert "WORKSTATION5.theshire.local" not in hosts
    assert "WIN-TKC15D7KHUR" not in hosts
    assert all(h.startswith("host-") for h in hosts)


def test_corpus_composition_reports_per_source_per_label_counts():
    records = assemble_corpus(_malicious(20), _benign(80), benign_ratio=4.0, pseudonymize_hosts=False)
    composition = corpus_composition(records)
    assert composition == {
        "otrf_security_datasets:malicious": 20,
        "evtx_baseline:benign": 80,
    }
