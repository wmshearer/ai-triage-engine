"""Offline tests for the single-agent triage baseline — no network, no Ollama.

Every test in this file must run without hitting a real Ollama server; the
HTTP call in `triage_alert`/`triage_batch` is monkeypatched wherever it would
otherwise fire. The live end-to-end path is exercised separately by
`scripts/smoke_triage.py`, which is NOT part of the offline test suite.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from src.agents.prompt import render_alert_prompt
from src.agents.schema import TRIAGE_VERDICT_JSON_SCHEMA, TriageVerdict, Verdict
from src.agents.triage import TriageError, triage_alert, triage_batch
from src.schema import AlertRecord, EventType

MALICIOUS_RAW_EVENT = {
    "EventID": 12,
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "EventTime": "2020-09-21 19:18:41",
    "EmptyField": None,
    "EmptyList": [],
    "EmptyString": "",
}


def _malicious_record(**overrides) -> AlertRecord:
    fields = dict(
        id="test:1",
        timestamp="2020-09-21T19:18:41",
        source_host="WORKSTATION5.theshire.local",
        event_type=EventType.REGISTRY,
        source_dataset="otrf_security_datasets",
        source_capture_id="SDWIN-TEST",
        raw_event=dict(MALICIOUS_RAW_EVENT),
        is_malicious=True,
        attack_technique="T1547",
        attack_subtechnique="001",
        attack_tactics=["TA0003"],
    )
    fields.update(overrides)
    return AlertRecord(**fields)


def _benign_record(**overrides) -> AlertRecord:
    fields = dict(
        id="test:2",
        timestamp="2022-01-01T00:00:00",
        source_host="WIN2022-01",
        event_type=EventType.AUTHENTICATION,
        source_dataset="evtx_baseline",
        source_capture_id="win2022-evtx",
        raw_event={"EventID": 4624, "Channel": "Security", "LogonType": "3", "TargetUserName": "svc_backup"},
        is_malicious=False,
    )
    fields.update(overrides)
    return AlertRecord(**fields)


# --- Label-leakage test (the single most important test in this file) -----


def test_prompt_excludes_all_label_fields():
    """No ground-truth label may ever appear in the rendered prompt string.

    Deliberately checks every label field/value AlertRecord carries, not
    just is_malicious, per the task's explicit warning: a naive
    "serialize the whole record" implementation would leak
    attack_technique/attack_subtechnique/attack_tactics too, and each is
    checked independently so a partial fix (e.g. dropping is_malicious but
    not attack_technique) would still fail this test.
    """
    record = _malicious_record(
        attack_technique="T1547",
        attack_subtechnique="001",
        attack_tactics=["TA0003", "TA0004"],
    )
    prompt = render_alert_prompt(record)

    # The label VALUES must not appear anywhere in the prompt text. Note:
    # the prompt legitimately mentions the FIELD NAME "attack_technique" as
    # part of instructing the model what output key to fill in (that's the
    # output schema's field name, not a leaked ground-truth value) — so this
    # test checks values, not field names, for attack_technique specifically.
    # is_malicious/attack_subtechnique/attack_tactics have no legitimate
    # reason to appear at all (the prompt never discusses sub-techniques or
    # tactics as a separate concept), so those are checked as full-name
    # absences.
    assert "T1547" not in prompt
    assert "TA0003" not in prompt
    assert "TA0004" not in prompt
    assert "is_malicious" not in prompt
    assert "attack_subtechnique" not in prompt
    assert "attack_tactics" not in prompt


def test_prompt_excludes_label_fields_across_many_technique_values():
    """Sweep several technique/tactic values, not just one hardcoded pair.

    A single-value test could pass by accident (e.g. if the leaked label
    happened to share text with something legitimately in the prompt). This
    sweeps a handful of distinct, realistic ATT&CK values to reduce that
    risk.
    """
    cases = [
        ("T1059", "001", ["TA0002"]),
        ("T1003", "002", ["TA0006", "TA0004"]),
        ("T1069", None, ["TA0007"]),
    ]
    for technique, subtechnique, tactics in cases:
        record = _malicious_record(
            attack_technique=technique, attack_subtechnique=subtechnique, attack_tactics=tactics
        )
        prompt = render_alert_prompt(record)
        assert technique not in prompt
        for tactic in tactics:
            assert tactic not in prompt


def test_prompt_for_benign_record_has_no_label_leakage_either():
    """Benign records carry no technique, but is_malicious=False must still not leak."""
    record = _benign_record()
    prompt = render_alert_prompt(record)
    assert "is_malicious" not in prompt
    assert "False" not in prompt  # would only appear if is_malicious's value leaked in


# --- Prompt rendering -------------------------------------------------


def test_prompt_includes_raw_event_content():
    record = _malicious_record()
    prompt = render_alert_prompt(record)
    assert "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater" in prompt
    assert "powershell.exe" in prompt
    assert record.source_host in prompt


def test_prompt_excludes_none_and_empty_raw_event_values():
    record = _malicious_record()
    prompt = render_alert_prompt(record)
    assert "EmptyField" not in prompt
    assert "EmptyList" not in prompt
    assert "EmptyString" not in prompt


def test_prompt_includes_event_type_explanation():
    record = _malicious_record()  # EventID 12, Sysmon -> registry create/delete
    prompt = render_alert_prompt(record)
    assert "registry" in prompt.lower()


def test_prompt_falls_back_gracefully_for_unmapped_event_id():
    record = _malicious_record(
        raw_event={"EventID": 99999, "Channel": "Some-Unknown-Channel", "Foo": "bar"},
        event_type=EventType.OTHER,
    )
    prompt = render_alert_prompt(record)
    assert "bar" in prompt
    # Should not raise, and should still produce a usable prompt.
    assert len(prompt) > 0


def test_prompt_stays_well_under_context_budget():
    """A single alert's prompt should be far below the 8192-token num_ctx."""
    record = _malicious_record()
    prompt = render_alert_prompt(record)
    from src.agents.prompt import estimate_tokens

    assert estimate_tokens(prompt) < 4000


def test_prompt_truncates_very_long_field_values():
    huge_value = "A" * 10_000
    record = _malicious_record(raw_event={"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "ParentCommandLine": huge_value})
    prompt = render_alert_prompt(record)
    assert "truncated" in prompt
    assert len(prompt) < len(huge_value)


# --- TriageVerdict schema / response parsing ---------------------------


def test_valid_json_parses_to_triage_verdict():
    raw = json.dumps(
        {
            "verdict": "malicious",
            "confidence": 0.9,
            "attack_technique": "T1547.001",
            "reasoning": "Registry Run key persistence.",
            "key_indicators": ["TargetObject=...Run\\Updater"],
        }
    )
    verdict = TriageVerdict.model_validate_json(raw)
    assert verdict.verdict == Verdict.MALICIOUS
    assert verdict.attack_technique == "T1547.001"
    assert verdict.confidence == 0.9


def test_benign_verdict_allows_no_technique():
    raw = json.dumps({"verdict": "benign", "confidence": 0.95, "reasoning": "Normal logon."})
    verdict = TriageVerdict.model_validate_json(raw)
    assert verdict.attack_technique is None


def test_malformed_json_raises_validation_error():
    with pytest.raises(ValidationError):
        TriageVerdict.model_validate_json("{not valid json")


def test_schema_valid_but_fake_technique_id_is_rejected():
    """Structured output guarantees shape, not truth — this is the residual check."""
    raw = json.dumps(
        {
            "verdict": "malicious",
            "confidence": 0.8,
            "attack_technique": "NOT_A_TECHNIQUE",
            "reasoning": "x",
        }
    )
    with pytest.raises(ValidationError, match="not a valid MITRE ATT&CK technique ID"):
        TriageVerdict.model_validate_json(raw)


def test_benign_verdict_with_technique_attached_is_rejected():
    raw = json.dumps({"verdict": "benign", "confidence": 0.5, "attack_technique": "T1547", "reasoning": "x"})
    with pytest.raises(ValidationError, match="must not carry an attack_technique"):
        TriageVerdict.model_validate_json(raw)


def test_confidence_out_of_range_is_rejected():
    raw = json.dumps({"verdict": "benign", "confidence": 1.5, "reasoning": "x"})
    with pytest.raises(ValidationError):
        TriageVerdict.model_validate_json(raw)


def test_invalid_verdict_enum_is_rejected():
    raw = json.dumps({"verdict": "extremely_bad", "confidence": 0.5, "reasoning": "x"})
    with pytest.raises(ValidationError):
        TriageVerdict.model_validate_json(raw)


def test_json_schema_has_expected_shape_for_ollama_format_param():
    """Sanity check on the dict handed to Ollama's `format` parameter."""
    assert TRIAGE_VERDICT_JSON_SCHEMA["type"] == "object"
    assert "verdict" in TRIAGE_VERDICT_JSON_SCHEMA["required"]
    assert "confidence" in TRIAGE_VERDICT_JSON_SCHEMA["required"]


# --- triage_alert / triage_batch (HTTP call mocked) ---------------------


class _FakeResponse:
    def __init__(self, json_body: dict, status_code: int = 200):
        self._json_body = json_body
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests

            raise requests.HTTPError(f"status {self.status_code}")

    def json(self):
        return self._json_body


def _ok_ollama_response(verdict_dict: dict) -> _FakeResponse:
    return _FakeResponse({"response": json.dumps(verdict_dict)})


def test_triage_alert_success_parses_verdict(monkeypatch):
    record = _malicious_record()
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        return _ok_ollama_response(
            {"verdict": "malicious", "confidence": 0.9, "attack_technique": "T1547.001", "reasoning": "run key"}
        )

    monkeypatch.setattr("src.agents.triage.requests.post", fake_post)

    verdict = triage_alert(record, base_url="http://fake-ollama:11434")

    assert verdict.verdict == Verdict.MALICIOUS
    assert captured["url"] == "http://fake-ollama:11434/api/generate"
    assert captured["json"]["options"]["num_ctx"] == 8192
    assert captured["json"]["format"] == TRIAGE_VERDICT_JSON_SCHEMA
    # The label must never have reached the outgoing prompt either.
    assert "T1547" not in captured["json"]["prompt"]


def test_triage_alert_configurable_model_base_url_timeout(monkeypatch):
    seen = {}

    def fake_post(url, json=None, timeout=None):
        seen["url"] = url
        seen["model"] = json["model"]
        seen["timeout"] = timeout
        seen["num_ctx"] = json["options"]["num_ctx"]
        return _ok_ollama_response({"verdict": "benign", "confidence": 0.7, "reasoning": "x"})

    monkeypatch.setattr("src.agents.triage.requests.post", fake_post)

    triage_alert(
        _benign_record(),
        model="some-other-model:latest",
        base_url="http://example-host:9999",
        timeout=5.0,
        num_ctx=16384,
    )

    assert seen["url"] == "http://example-host:9999/api/generate"
    assert seen["model"] == "some-other-model:latest"
    assert seen["timeout"] == 5.0
    assert seen["num_ctx"] == 16384


def test_triage_alert_raises_typed_error_on_malformed_response(monkeypatch):
    def fake_post(url, json=None, timeout=None):
        return _ok_ollama_response({"verdict": "malicious", "confidence": 0.9})  # missing 'reasoning'

    monkeypatch.setattr("src.agents.triage.requests.post", fake_post)

    with pytest.raises(TriageError):
        triage_alert(_malicious_record())


def test_triage_alert_raises_typed_error_on_non_json_response(monkeypatch):
    def fake_post(url, json=None, timeout=None):
        return _FakeResponse({"response": "not json at all"})

    monkeypatch.setattr("src.agents.triage.requests.post", fake_post)

    with pytest.raises(TriageError):
        triage_alert(_malicious_record())


def test_triage_alert_raises_typed_error_on_transport_failure(monkeypatch):
    import requests

    def fake_post(url, json=None, timeout=None):
        raise requests.ConnectionError("connection refused")

    monkeypatch.setattr("src.agents.triage.requests.post", fake_post)

    with pytest.raises(TriageError):
        triage_alert(_malicious_record())


def test_triage_batch_runs_sequentially_and_reports_progress(monkeypatch):
    records = [_malicious_record(id=f"test:{i}") for i in range(3)]
    call_order = []

    def fake_post(url, json=None, timeout=None):
        call_order.append(json["prompt"][:20])
        return _ok_ollama_response({"verdict": "benign", "confidence": 0.6, "reasoning": "x"})

    monkeypatch.setattr("src.agents.triage.requests.post", fake_post)

    progress_calls = []
    results = triage_batch(records, on_progress=lambda i, total, r: progress_calls.append((i, total, r.id)))

    assert len(results) == 3
    assert len(call_order) == 3  # no concurrency shortcuts, one call per record
    assert progress_calls == [(1, 3, "test:0"), (2, 3, "test:1"), (3, 3, "test:2")]


def test_triage_batch_skips_failed_records_by_default(monkeypatch):
    records = [_malicious_record(id="good"), _malicious_record(id="bad")]

    def fake_post(url, json=None, timeout=None):
        if "bad" in str(json.get("prompt", "")):
            pass  # can't key on id (not in prompt by design) -- key on call order instead
        return _ok_ollama_response({"verdict": "benign", "confidence": 0.6, "reasoning": "x"})

    call_count = {"n": 0}

    def flaky_post(url, json=None, timeout=None):
        call_count["n"] += 1
        if call_count["n"] == 2:
            return _FakeResponse({"response": "{broken"})
        return _ok_ollama_response({"verdict": "benign", "confidence": 0.6, "reasoning": "x"})

    monkeypatch.setattr("src.agents.triage.requests.post", flaky_post)

    results = triage_batch(records, stop_on_error=False)
    assert len(results) == 1
    assert results[0].record.id == "good"


def test_triage_batch_stop_on_error_propagates(monkeypatch):
    records = [_malicious_record(id="only")]

    def fake_post(url, json=None, timeout=None):
        return _FakeResponse({"response": "{broken"})

    monkeypatch.setattr("src.agents.triage.requests.post", fake_post)

    with pytest.raises(TriageError):
        triage_batch(records, stop_on_error=True)
