"""Offline tests for the AlertRecord schema's own invariants."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from src.schema import MULTI_TECHNIQUE_SENTINEL, AlertRecord, EventType


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


def test_multi_technique_sentinel_record_is_valid():
    """A compound-capture record with an honestly-unresolved technique.

    Still satisfies the original 'malicious requires attack_technique'
    invariant unmodified — the sentinel IS a non-None string — while
    `technique_unresolved=True` makes the gap explicit and queryable rather
    than a technique ID this codebase would otherwise have to guess at.
    """
    record = AlertRecord(
        **_base_kwargs(
            attack_technique=MULTI_TECHNIQUE_SENTINEL,
            attack_subtechnique=None,
            attack_tactics=[],
            technique_unresolved=True,
        )
    )
    assert record.is_malicious is True
    assert record.attack_technique == MULTI_TECHNIQUE_SENTINEL
    assert record.technique_unresolved is True


def test_technique_unresolved_true_requires_sentinel_technique():
    with pytest.raises(ValidationError, match="technique_unresolved=True requires attack_technique"):
        AlertRecord(**_base_kwargs(technique_unresolved=True))  # attack_technique="T1059" here


def test_sentinel_technique_requires_technique_unresolved_true():
    with pytest.raises(ValidationError, match="requires technique_unresolved=True"):
        AlertRecord(**_base_kwargs(attack_technique=MULTI_TECHNIQUE_SENTINEL))


def test_technique_unresolved_defaults_to_false():
    record = AlertRecord(**_base_kwargs())
    assert record.technique_unresolved is False
