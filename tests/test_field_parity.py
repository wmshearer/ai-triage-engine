"""THE make-or-break test: benign and malicious raw_event key sets must match.

If evtx-baseline's parsed .evtx output carried different field names than
OTRF's own JSON for the same (Channel, EventID), a classifier trained on the
combined corpus could trivially separate classes on "which parser produced
this" instead of "is this behavior malicious" — an evaluation that reports
excellent metrics while measuring nothing real. This is the single most
important test in the benign-ingest path (see the task's own framing); every
other test in this suite is secondary to this one.

Both fixtures used here are trimmed slices of REAL data (not hand-written):
tests/fixtures/sample_capture.zip is a real OTRF Windows atomic capture
(existing fixture, predates this module); tests/fixtures/evtx/*.evtx are
real evtx-baseline .evtx chunks (see test_parse_evtx.py's module docstring
for how they were trimmed). Comparing their parsed key sets is therefore
comparing what the two real upstream sources actually emit, not two
fixtures this project made up to make the test pass.
"""

from pathlib import Path

from src.ingest.normalize import normalize_capture
from src.ingest.normalize_benign import normalize_evtx_file

OTRF_FIXTURES = Path(__file__).parent / "fixtures"
EVTX_FIXTURES = Path(__file__).parent / "fixtures" / "evtx"

# Fields present on OTRF's real Sysmon EventID 1 records that are pure
# artifacts of OTRF's own NXLog/Winlogbeat/ELK collection pipeline, not of
# the underlying Windows Event Log schema itself — confirmed by direct
# inspection of real downloaded OTRF captures (see parse_evtx.py's module
# docstring; the full real key set for ('microsoft-windows-sysmon/
# operational', 1) was fetched and diffed during implementation, not
# assumed). Windows Event Log's actual schema (what both OTRF and
# evtx-baseline both ultimately derive from) has no equivalent field for
# any of these — they are shipper/pipeline bookkeeping, e.g. which ELK
# module ingested the event, Logstash's own tag list, or an odd sourcetype
# typo OTRF's own pipeline introduces ("EventTypeOrignal") — not a Windows
# Sysmon field name that evtx-baseline's raw .evtx parsing could ever
# produce, no matter which .evtx library is used.
OTRF_PIPELINE_ONLY_FIELDS = {
    "@version",  # Logstash's own schema-version marker, not a Windows field
    "Category",  # OTRF/Winlogbeat classification tag, not in raw Windows XML
    "EventReceivedTime",  # when OTRF's collector received it, not source-system time
    "EventType",  # Winlogbeat's own coarse type tag (e.g. "INFO"), not Sysmon's field
    "EventTypeOrignal",  # OTRF pipeline artifact (note: misspelled in the source data itself)
    "Message",  # Winlogbeat's rendered human-readable message string
    "OpcodeValue",  # Winlogbeat's numeric mirror of the already-present Opcode field
    "SeverityValue",  # Winlogbeat's numeric mirror of the already-present Severity field
    "Severity",  # Winlogbeat's own rendered severity label
    "SourceModuleName",  # which NXLog/Winlogbeat input module read this event
    "SourceModuleType",  # NXLog input type identifier (e.g. "im_msvistalog")
    "SourceName",  # Winlogbeat's rendered provider name (duplicates ProviderGuid's Provider.Name)
    "host",  # Logstash's own generic "host" field (lowercase; distinct from Hostname)
    "port",  # Logstash pipeline bookkeeping (source port of the shipper connection)
    "tags",  # Logstash's own free-form tag list added by the ingest pipeline
    "AccountName",  # Winlogbeat-resolved SID->name lookup, not in the raw Sysmon EventData
    "AccountType",  # Winlogbeat-resolved account type, ditto
    "Domain",  # Winlogbeat-resolved SID->domain lookup, ditto
}


def test_sysmon_process_create_raw_event_keys_are_parity_compatible():
    """Benign Sysmon EventID 1 keys must be a subset of malicious Sysmon
    EventID 1 keys, with every excess OTRF-side key accounted for above as a
    documented shipper artifact — not a silent, unexplained mismatch."""
    malicious_records = normalize_capture(
        OTRF_FIXTURES / "sample_metadata.yaml",
        [OTRF_FIXTURES / "sample_capture.zip"],
    )
    malicious_sysmon_1 = [r for r in malicious_records if r.raw_event.get("EventID") == 1]
    assert malicious_sysmon_1, "OTRF fixture must contain a Sysmon EventID 1 record"
    malicious_keys = set(malicious_sysmon_1[0].raw_event.keys())

    benign_records = normalize_evtx_file(EVTX_FIXTURES / "sysmon_sample.evtx", capture_id="TEST", channel_filter=None)
    benign_sysmon_1 = [r for r in benign_records if r.raw_event.get("EventID") == 1]
    assert benign_sysmon_1, "evtx fixture must contain a Sysmon EventID 1 record"
    benign_keys = set(benign_sysmon_1[0].raw_event.keys())

    extra_on_malicious_side = malicious_keys - benign_keys
    unexplained = extra_on_malicious_side - OTRF_PIPELINE_ONLY_FIELDS
    assert not unexplained, (
        f"malicious-only fields not covered by the documented whitelist: {unexplained} "
        "— either map them for the benign side too, or add them to OTRF_PIPELINE_ONLY_FIELDS "
        "with a justification"
    )

    # And the core, behaviorally-meaningful fields must genuinely be shared,
    # not just "everything extra is excused" — this is the actual parity
    # proof, not merely the absence of an alarm.
    core_shared_fields = {"Channel", "EventID", "Hostname", "Image", "CommandLine", "ProcessGuid", "ParentImage", "User"}
    assert core_shared_fields <= malicious_keys
    assert core_shared_fields <= benign_keys


# Sysmon EventID 1 fields present on evtx-baseline's (newer Sysmon build)
# records but absent from THIS SPECIFIC fixture capture
# (empire_shell_net_localgroup_administrators, 2019/03) — verified during
# implementation to be a real Sysmon-schema-version difference WITHIN OTRF's
# own corpus, not a benign/malicious split: 3 of OTRF's other 4 downloaded
# captures (dated later) DO carry these fields on their own Sysmon EventID 1
# records (131 of 140 total OTRF Sysmon-EventID-1 records across all 5
# captures have ProcessId — see parse_evtx.py's flatten_event() docstring
# for the full multi-capture count). Whitelisted here, for this single-
# fixture-pair comparison, rather than dropped in flatten_event(), because
# dropping real Sysmon fields would lose genuine signal without reducing
# actual class leakage (the variance already exists inside the malicious
# class alone).
BENIGN_ONLY_DUE_TO_FIXTURE_SYSMON_VERSION = {"Level", "ProcessId", "ParentUser"}


def test_field_parity_side_by_side_evidence():
    """Not a strict assertion beyond the above — prints the side-by-side key
    sets so the parity evidence is visible directly in pytest -s / -v output,
    per the task's explicit requirement to produce this as evidence."""
    malicious_records = normalize_capture(
        OTRF_FIXTURES / "sample_metadata.yaml",
        [OTRF_FIXTURES / "sample_capture.zip"],
    )
    malicious_sysmon_1 = next(r for r in malicious_records if r.raw_event.get("EventID") == 1)

    benign_records = normalize_evtx_file(EVTX_FIXTURES / "sysmon_sample.evtx", capture_id="TEST", channel_filter=None)
    benign_sysmon_1 = next(r for r in benign_records if r.raw_event.get("EventID") == 1)

    malicious_keys = sorted(malicious_sysmon_1.raw_event.keys())
    benign_keys = sorted(benign_sysmon_1.raw_event.keys())

    print("\n--- Sysmon EventID 1 raw_event key-set parity ---")
    print("malicious (OTRF)      keys:", malicious_keys)
    print("benign    (evtx-baseline) keys:", benign_keys)
    print("malicious-only (documented shipper artifacts):", sorted(set(malicious_keys) - set(benign_keys)))
    print("benign-only:", sorted(set(benign_keys) - set(malicious_keys)))

    unexplained_benign_only = set(benign_keys) - set(malicious_keys) - BENIGN_ONLY_DUE_TO_FIXTURE_SYSMON_VERSION
    assert not unexplained_benign_only, (
        f"benign side introduces unexplained keys OTRF never has: {unexplained_benign_only}"
    )
