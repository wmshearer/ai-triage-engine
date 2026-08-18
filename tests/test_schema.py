"""Offline tests for the AlertRecord schema's own invariants."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from src.schema import AlertRecord, EventType


def _base_kwargs(**overrides):
    kwargs = dict(
        id="test:1",
        timestamp=datetime(2019, 3, 19, tzinfo=timezone.utc),
        source_host="HOST1",
        event_type=EventType.PROCESS,
        source_dataset="otrf_security_datasets",
        source_capture_id="SDWIN-TEST",
        raw_event={"EventID": 1},
        is_malicious=True,
        attack_technique="T1059",
        attack_subtechnique=None,
        attack_tactics=["TA0002"],
    )
    kwargs.update(overrides)
    return kwargs


def test_malicious_record_with_technique_is_valid():
    record = AlertRecord(**_base_kwargs())
    assert record.is_malicious is True
    assert record.attack_technique == "T1059"


def test_benign_record_without_technique_is_valid():
    record = AlertRecord(
        **_base_kwargs(is_malicious=False, attack_technique=None, attack_tactics=[])
    )
    assert record.is_malicious is False
    assert record.attack_technique is None
    assert record.attack_tactics == []


def test_malicious_record_without_technique_is_rejected():
    with pytest.raises(ValidationError, match="is_malicious=True requires attack_technique"):
        AlertRecord(**_base_kwargs(attack_technique=None))


def test_benign_record_with_technique_is_rejected():
    with pytest.raises(ValidationError, match="is_malicious=False records must not carry"):
        AlertRecord(**_base_kwargs(is_malicious=False))
