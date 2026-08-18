"""Normalized alert record schema.

This is the single contract every downstream phase (agents, eval harness,
dashboard) is built against. Every source dataset (OTRF Security-Datasets now;
others later, per the Phase 0 research) gets mapped INTO this shape rather than
being consumed in its native form, so the rest of the pipeline never needs to
know where an alert came from.

Ground-truth fields are first-class, not bolted on, because the whole point of
this project (per Phase 0 metrics research) is a rigorous offline evaluation
against labeled data. A record without usable ground truth cannot be scored,
so `is_malicious` is required and the ATT&CK fields are optional-but-validated
(present together or not at all — see the model validator below).

Deliberately NOT present anywhere in this file: MTTD, MTTR, "time to respond",
or any other live-SOC timing metric. Phase 0 metrics research established
these cannot be honestly computed from a static labeled corpus (no real
analyst, no real arrival-time distribution) — see
wshearer-site/research/phase-0-metrics.md, Section 1B. Do not add them later
without re-reading that section.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class EventType(str, Enum):
    """Coarse category of the underlying telemetry.

    Kept intentionally small and source-agnostic (not "Sysmon EventID 1", which
    is OTRF/Windows-specific vocabulary) so a future non-Windows source (AWS
    CloudTrail, Linux auditd, etc.) normalizes into the same enum instead of
    forcing a schema migration. OTRF captures already span Windows, Linux, and
    AWS (confirmed via repo tree inspection), so this abstraction is needed
    even within Phase 1, not just "for later."
    """

    PROCESS = "process"
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    FILE = "file"
    REGISTRY = "registry"
    SCHEDULED_TASK = "scheduled_task"
    OTHER = "other"


class AlertRecord(BaseModel):
    """One normalized alert/event, source-agnostic, with ground truth attached.

    Field-by-field rationale (why it exists, where its value comes from):
    """

    # Stable identity -----------------------------------------------------
    # Deterministic, content-derived (not a random UUID) so re-running ingest
    # on the same source data yields the same id — required for reproducible
    # test fixtures and for de-duplicating if a capture is ingested twice.
    id: str = Field(..., description="Stable identifier, derived from source capture id + event index.")

    # When it happened -----------------------------------------------------
    # Every OTRF event carries a native timestamp field (commonly
    # '@timestamp' or 'EventTime'/'UtcTime' depending on log channel); this is
    # parsed out at normalization time so downstream code never has to know
    # the source's field-naming conventions.
    timestamp: datetime = Field(..., description="Event time, parsed from the source telemetry.")

    # Where it happened -----------------------------------------------------
    # OTRF events carry a 'Hostname' (Windows) or equivalent host field; this
    # is the SOC-relevant asset identifier an analyst would triage against.
    source_host: str = Field(..., description="Host or asset the event was observed on.")

    # What kind of telemetry this is ----------------------------------------
    event_type: EventType = Field(..., description="Coarse category of the telemetry, source-agnostic.")

    # Provenance --------------------------------------------------------
    # Records which dataset/project this came from (e.g. 'otrf_security_datasets').
    # Needed because Phase 0 research is explicit that different sources carry
    # different licensing and ground-truth quality (Mordor: structured ATT&CK
    # labels; BOTS: CTF trivia, not machine-readable) — a mixed corpus later
    # must be able to report per-source provenance, not blend it invisibly.
    source_dataset: str = Field(..., description="Name of the originating dataset/project.")
    source_capture_id: str = Field(..., description="Source dataset's own capture/metadata id (e.g. OTRF 'SDWIN-...').")

    # The actual telemetry --------------------------------------------------
    # Kept as the raw, unmodified source event (parsed JSON) alongside the
    # normalized fields above, rather than only the normalized subset. Every
    # normalization step is lossy by construction (we pick a handful of
    # canonical fields out of dozens of source-specific ones); keeping the raw
    # payload means no information is silently discarded, and it gives later
    # phases (e.g. an LLM triage agent) something richer to reason over than
    # the seven fields this schema chose to elevate.
    raw_event: dict[str, Any] = Field(..., description="Unmodified source event payload, for lossless downstream use.")

    # --- Ground truth -------------------------------------------------
    # This block is the entire point of the project (Phase 0: an eval harness
    # needs machine-readable labels, which is why OTRF was chosen as the
    # primary source over BOTS/CICIDS2017). Every field here must be
    # traceable to something a human curator (OTRF researchers) actually
    # asserted, never inferred/guessed by this codebase.

    # True for every event in an OTRF "atomic" capture (the capture IS the
    # attack, by construction — see OTRF metadata YAML: each capture maps to
    # exactly one technique). False for synthetic/injected benign records
    # this project adds itself (see normalize.py) to give the eval harness
    # negatives, since OTRF atomics alone contain no benign noise.
    is_malicious: bool = Field(..., description="Ground-truth malicious/benign label for this event.")

    # ATT&CK technique id, e.g. 'T1087'. Sourced verbatim from the capture's
    # metadata YAML 'attack_mappings[].technique' field. None for benign
    # records — there is no technique to report.
    attack_technique: str | None = Field(default=None, description="MITRE ATT&CK technique ID, or None if benign.")

    # ATT&CK sub-technique id, e.g. '001'. OTRF YAML represents this as either
    # a string or an explicit null (confirmed by inspecting real metadata:
    # some captures have no sub-technique, e.g. T1018 with sub-technique:
    # None). Kept separate from attack_technique rather than pre-concatenated
    # (e.g. 'T1087.001') so a technique-level-only rollup is a trivial filter,
    # not a string-parsing exercise, for the eval harness in a later phase.
    attack_subtechnique: str | None = Field(default=None, description="MITRE ATT&CK sub-technique ID suffix, or None.")

    # List because OTRF's own schema allows attack_mappings[].tactics to be a
    # list (a technique can map to multiple tactics), confirmed by inspecting
    # real metadata. Empty list, not None, for benign records — "no tactics"
    # is a valid empty collection, not a missing value.
    attack_tactics: list[str] = Field(default_factory=list, description="MITRE ATT&CK tactic IDs, e.g. ['TA0007'].")

    @model_validator(mode="after")
    def _labels_consistent(self) -> "AlertRecord":
        """Enforce that malicious records carry a technique and benign ones don't.

        This is the load-bearing invariant for the whole eval phase: a
        malicious record with no technique, or a benign record with a
        technique attached, is a labeling bug, not a valid edge case, and
        should fail loudly at ingest time rather than surface as a silent
        scoring error three phases from now.
        """
        if self.is_malicious and self.attack_technique is None:
            raise ValueError("is_malicious=True requires attack_technique to be set")
        if not self.is_malicious and self.attack_technique is not None:
            raise ValueError("is_malicious=False records must not carry an attack_technique")
        return self
