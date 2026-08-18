"""Structured-output contract for the single-agent triage baseline.

`TriageVerdict` is what the model is constrained to produce (its JSON Schema
is handed to Ollama's `format` parameter, which compiles it into a grammar
and constrains DECODING — see `research/phase-2-agent-design.md` Finding 1).
That constraint is STRUCTURAL only: it guarantees shape (every required key
present, `verdict` is one of the three enum values, types match), never
semantic correctness — a schema-valid ATT&CK technique ID can still be
hallucinated. `attack_technique` is therefore re-validated after parsing
(see `_TECHNIQUE_ID_RE` below) rather than trusted just because it passed the
grammar, per the task's explicit "validate enum values and technique-ID
format after parsing" requirement.

This model is intentionally separate from `src.schema.AlertRecord` — it is
the OUTPUT contract (what the model asserts), not the INPUT/ground-truth
contract (what the corpus asserts). Conflating the two would make it easy to
accidentally leak a ground-truth field into a place that looks like model
output.
"""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, Field, field_validator

# MITRE ATT&CK technique IDs look like 'T' + 3-4 digits, optionally a
# '.NNN' sub-technique suffix (e.g. 'T1547', 'T1547.001'). This is a format
# check only — it catches "the model made up a string that isn't shaped like
# a technique ID" (e.g. "NOT_A_TECHNIQUE" or "Registry Run Key"), not "the
# model picked the wrong real technique," which needs a human/eval-harness
# judgment call, not a regex.
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class Verdict(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class TriageVerdict(BaseModel):
    """One model-produced triage judgment for one AlertRecord."""

    verdict: Verdict = Field(..., description="Overall triage classification.")

    confidence: float = Field(..., ge=0.0, le=1.0, description="Model's confidence in `verdict`, 0.0-1.0.")

    # None for benign — there is no technique to report, mirroring
    # AlertRecord.attack_technique's own None-for-benign convention so a
    # verdict and its ground-truth counterpart compare like-for-like.
    attack_technique: str | None = Field(
        default=None, description="MITRE ATT&CK technique ID (e.g. 'T1547'), or None if benign."
    )

    reasoning: str = Field(..., description="Brief justification for the verdict.")

    key_indicators: list[str] = Field(
        default_factory=list,
        description="Specific field values from the event that drove the decision.",
    )

    @field_validator("attack_technique")
    @classmethod
    def _technique_id_shape(cls, value: str | None) -> str | None:
        """Reject schema-valid-but-not-technique-shaped strings.

        Structured output guarantees `attack_technique` is *a string*; it
        says nothing about whether that string looks like a real ATT&CK
        technique ID. A model that emits "NOT_A_TECHNIQUE" or a free-text
        description instead of an ID would pass the grammar and fail this.
        """
        if value is None:
            return value
        if not _TECHNIQUE_ID_RE.match(value):
            raise ValueError(
                f"attack_technique={value!r} is not a valid MITRE ATT&CK technique ID "
                "(expected shape 'T####' or 'T####.###')"
            )
        return value

    @field_validator("attack_technique")
    @classmethod
    def _benign_has_no_technique(cls, value: str | None, info) -> str | None:
        """Mirror AlertRecord's own invariant: benign verdicts carry no technique.

        Field-order-dependent (pydantic v2 runs field validators in
        declaration order, and `verdict` is declared before
        `attack_technique` above), so `info.data['verdict']` is already
        populated here when this runs.
        """
        verdict = info.data.get("verdict")
        if verdict == Verdict.BENIGN and value is not None:
            raise ValueError("verdict=benign must not carry an attack_technique")
        return value


# JSON Schema handed to Ollama's `format` parameter for grammar-constrained
# decoding. Built from the pydantic model rather than hand-written so the two
# can never drift apart. `mode="serialization"` (not the default
# "validation") so the enum renders as its string values (["benign",
# "suspicious", "malicious"]) rather than pydantic's validation-mode
# representation, which is what the grammar compiler needs to see.
TRIAGE_VERDICT_JSON_SCHEMA: dict = TriageVerdict.model_json_schema(mode="serialization")
