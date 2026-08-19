"""Offline tests for `src/eval/context_bucket.py` — the field-presence
predicate the context-experiment hypothesis test (`scripts/run_context_
experiment.py`) is built on. This is the load-bearing new code for that
experiment (a wrong predicate would silently invalidate the whole test), so
it is verified directly here against constructed records, not only indirectly
via the corpus.
"""

from __future__ import annotations

from datetime import datetime, timezone

from src.eval.context_bucket import (
    ACTOR_FIELDS,
    CONTEXT_FIELDS,
    OBJECT_FIELDS,
    context_bucket,
    is_context_rich,
    split_by_context,
)
from src.schema import AlertRecord, EventType


def make_record(idx: int, is_malicious: bool, event_id: int, raw_event: dict) -> AlertRecord:
    payload = {"EventID": event_id, **raw_event}
    return AlertRecord(
        id=f"rec:{idx}",
        timestamp=datetime(2020, 1, 1, tzinfo=timezone.utc),
        source_host="host-0",
        event_type=EventType.OTHER,
        source_dataset="otrf_security_datasets" if is_malicious else "evtx_baseline",
        source_capture_id=f"cap-{idx}",
        raw_event=payload,
        is_malicious=is_malicious,
        attack_technique="T1059" if is_malicious else None,
        attack_tactics=["TA0002"] if is_malicious else [],
    )


# ---------------------------------------------------------------------------
# Field-list sanity
# ---------------------------------------------------------------------------


class TestFieldLists:
    def test_actor_and_object_fields_disjoint(self):
        assert set(ACTOR_FIELDS).isdisjoint(set(OBJECT_FIELDS))

    def test_context_fields_is_union(self):
        assert set(CONTEXT_FIELDS) == set(ACTOR_FIELDS) | set(OBJECT_FIELDS)

    def test_image_alone_is_not_a_context_field(self):
        # Per the module docstring: a bare executable path is an opaque
        # identifier every EventID in the corpus carries in some form, so it
        # must NOT be treated as an actor/object signal on its own.
        assert "Image" not in CONTEXT_FIELDS
        assert "SourceImage" not in CONTEXT_FIELDS
        assert "TargetImage" not in CONTEXT_FIELDS

    def test_opaque_identifiers_are_not_context_fields(self):
        for field in ("TargetObject", "TargetFilename", "CallTrace", "ProcessGuid", "ProcessId", "LogonGuid"):
            assert field not in CONTEXT_FIELDS


# ---------------------------------------------------------------------------
# is_context_rich — the predicate itself
# ---------------------------------------------------------------------------


class TestIsContextRich:
    def test_command_line_alone_is_rich(self):
        r = make_record(1, True, 1, {"CommandLine": "cmd.exe /c whoami", "Image": "C:\\cmd.exe"})
        assert is_context_rich(r) is True

    def test_parent_image_alone_is_rich(self):
        r = make_record(2, True, 1, {"ParentImage": "C:\\svchost.exe", "Image": "C:\\evil.exe"})
        assert is_context_rich(r) is True

    def test_user_field_alone_is_rich(self):
        r = make_record(3, False, 3, {"User": "NT AUTHORITY\\SYSTEM"})
        assert is_context_rich(r) is True

    def test_subject_user_name_alone_is_rich(self):
        r = make_record(4, False, 4689, {"SubjectUserName": "SCRANTON$"})
        assert is_context_rich(r) is True

    def test_target_user_name_alone_is_rich(self):
        r = make_record(5, False, 4624, {"TargetUserName": "WORKSTATION5$"})
        assert is_context_rich(r) is True

    def test_script_block_text_alone_is_rich(self):
        r = make_record(6, True, 4104, {"ScriptBlockText": "Invoke-Expression $x"})
        assert is_context_rich(r) is True

    def test_destination_ip_alone_is_rich(self):
        r = make_record(7, False, 3, {"DestinationIp": "10.0.0.4"})
        assert is_context_rich(r) is True

    def test_destination_hostname_alone_is_rich(self):
        r = make_record(8, False, 3, {"DestinationHostname": "dc01.corp.local"})
        assert is_context_rich(r) is True

    def test_bare_image_and_target_object_is_poor(self):
        # Mirrors a real EventID 12/13 (registry) record: Image + TargetObject
        # only, no actor/object field — this is the "bare machine state" side
        # the hypothesis predicts is harmful.
        r = make_record(
            9, True, 13, {"Image": "C:\\poqexec.exe", "TargetObject": "HKLM\\SOFTWARE\\Run", "ProcessGuid": "{...}"}
        )
        assert is_context_rich(r) is False

    def test_call_trace_and_images_is_poor(self):
        # Mirrors a real EventID 10 (ProcessAccess) record: SourceImage +
        # TargetImage + CallTrace only — image paths without CommandLine or a
        # named user are still context-poor per this predicate's definition.
        r = make_record(
            10,
            True,
            10,
            {"SourceImage": "C:\\svchost.exe", "TargetImage": "C:\\lsass.exe", "CallTrace": "ntdll.dll+9c584"},
        )
        assert is_context_rich(r) is False

    def test_target_filename_and_image_is_poor(self):
        r = make_record(11, False, 11, {"Image": "C:\\ProvTool.exe", "TargetFilename": "C:\\Windows\\tmp.tw"})
        assert is_context_rich(r) is False

    def test_empty_dict_is_poor(self):
        r = make_record(12, False, 999, {})
        assert is_context_rich(r) is False

    def test_none_value_does_not_count_as_present(self):
        r = make_record(13, False, 1, {"CommandLine": None, "Image": "C:\\a.exe"})
        assert is_context_rich(r) is False

    def test_empty_string_does_not_count_as_present(self):
        r = make_record(14, False, 4688, {"CommandLine": "", "Image": "C:\\a.exe"})
        assert is_context_rich(r) is False

    def test_dash_sentinel_does_not_count_as_present(self):
        # Measured on the real corpus: Security-log subject/user fields
        # populate a literal "-" placeholder rather than being absent when
        # genuinely not applicable (e.g. EventID 4624's
        # TargetOutboundUserName). A dash carries no more semantic content
        # than a missing key.
        r = make_record(15, False, 4624, {"TargetUserName": "-", "SubjectUserName": "-"})
        assert is_context_rich(r) is False

    def test_dash_sentinel_does_not_mask_a_real_field(self):
        r = make_record(16, False, 4624, {"TargetUserName": "-", "SubjectUserName": "real.user"})
        assert is_context_rich(r) is True

    def test_whitespace_only_value_does_not_count_as_present(self):
        r = make_record(17, False, 1, {"CommandLine": "   ", "Image": "C:\\a.exe"})
        assert is_context_rich(r) is False

    def test_reads_only_raw_event_never_event_id_directly(self):
        # Same raw_event content, different EventID label -- must classify
        # identically, proving the predicate does not special-case EventID.
        rich_event = {"CommandLine": "whoami"}
        r_a = make_record(18, True, 1, rich_event)
        r_b = make_record(19, True, 99999, rich_event)
        assert is_context_rich(r_a) == is_context_rich(r_b) is True


# ---------------------------------------------------------------------------
# context_bucket / split_by_context
# ---------------------------------------------------------------------------


class TestContextBucketLabel:
    def test_rich_label(self):
        r = make_record(20, True, 1, {"CommandLine": "whoami"})
        assert context_bucket(r) == "context_rich"

    def test_poor_label(self):
        r = make_record(21, True, 13, {"TargetObject": "HKLM\\SOFTWARE\\Run"})
        assert context_bucket(r) == "context_poor"


class TestSplitByContext:
    def test_partitions_all_records_exactly_once(self):
        records = [
            make_record(30, True, 1, {"CommandLine": "whoami"}),
            make_record(31, True, 13, {"TargetObject": "HKLM\\SOFTWARE\\Run"}),
            make_record(32, False, 3, {"DestinationIp": "10.0.0.4"}),
            make_record(33, False, 11, {"TargetFilename": "C:\\tmp.dat"}),
        ]
        rich, poor = split_by_context(records)
        assert len(rich) + len(poor) == len(records)
        assert set(r.id for r in rich) | set(r.id for r in poor) == {r.id for r in records}
        assert {r.id for r in rich} == {"rec:30", "rec:32"}
        assert {r.id for r in poor} == {"rec:31", "rec:33"}

    def test_empty_input(self):
        rich, poor = split_by_context([])
        assert rich == []
        assert poor == []
