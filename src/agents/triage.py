"""The single-agent triage baseline itself — one Ollama call per AlertRecord.

Deliberately NOT a multi-agent pipeline. See `src/agents/__init__.py` and
`research/phase-2-agent-design.md` for why: classification-task literature
found single-prompt equal-or-better than decomposition at a fraction of the
cost, and this host measures ~4.2s/call vs ~16.9s for a 4-call chain (because
`OLLAMA_NUM_PARALLEL=1` forces strict serialization — see
`research/phase-2-measured-latency.md`). Batch triage below is therefore
SEQUENTIAL by design, not an oversight: concurrency buys nothing on this host.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

import requests
from pydantic import ValidationError

from src.agents.prompt import render_alert_prompt
from src.agents.schema import TRIAGE_VERDICT_JSON_SCHEMA, TriageVerdict
from src.schema import AlertRecord

DEFAULT_MODEL = "qwen2.5:7b-instruct-q4_K_M"
DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_TIMEOUT = 120.0

# Ollama's automatic num_ctx default is 4096 on <24GB-VRAM hosts (confirmed,
# research/phase-2-agent-design.md Finding 5) — silently truncating any
# prompt beyond that rather than erroring. This project's real prompts
# measured ~1364 tokens for a single alert (phase-2-measured-latency.md), so
# 8192 leaves generous headroom without paying for a context length this
# hardware can't use efficiently. MUST be passed explicitly on every request;
# relying on the server default is exactly the trap this comment warns about.
DEFAULT_NUM_CTX = 8192

# temperature=0.0 alone does NOT make output reproducible. Measured on this
# host, and the failure is subtle enough to be worth spelling out:
#
#   same prompt 10x back-to-back        -> 10/10 byte-identical
#   prompts A,B,A,B,A,B interleaved     -> B returns two DIFFERENT answers
#
# So the naive determinism check passes while a real evaluation -- which
# interleaves distinct records through one warm server -- silently does not
# reproduce. The cause is server-side KV-cache/batch state carried across
# requests, not sampling randomness, which is why temperature=0 cannot fix it.
# Passing an explicit seed REDUCES but does not eliminate it. Measured through
# this function over 4 records x 3 interleaved passes: 3 of 4 records became
# fully stable, while one differed on its FIRST call only and then settled --
# consistent with cold-cache state rather than sampling, and not something a
# seed can reach.
#
# So: seed it (it demonstrably helps, and costs nothing), but do NOT claim
# determinism. The honest position is that run-to-run agreement is high and
# must be MEASURED and REPORTED per evaluation, never assumed -- which is why
# the eval harness carries run-to-run agreement as a first-class metric
# instead of a footnote. An earlier check of this same property passed 5/5 by
# repeating one prompt back-to-back; that only ever tested the easy case.
DEFAULT_SEED = 20260818

SYSTEM_PROMPT = (
    "You are a precise, evidence-driven SOC security analyst. Respond only with the "
    "requested structured JSON verdict, grounded strictly in the event fields provided."
)


class TriageError(Exception):
    """Raised when Ollama's response cannot be turned into a valid TriageVerdict.

    Covers both HTTP/transport failures and post-parse validation failures
    (malformed JSON, or JSON that's schema-shaped but semantically invalid —
    e.g. `attack_technique: "NOT_A_TECHNIQUE"` — since TriageVerdict's own
    validators, not just Ollama's grammar constraint, are the last line of
    defense against that; see src/agents/schema.py's module docstring).
    """


@dataclass
class TriageResult:
    """One record's verdict, paired with the record it came from.

    Exists so callers (the smoke-test script, a future eval harness) can
    line a verdict back up against its AlertRecord — including its ground
    truth — without the two ever having been in the same prompt.
    """

    record: AlertRecord
    verdict: TriageVerdict


def triage_alert(
    record: AlertRecord,
    model: str = DEFAULT_MODEL,
    base_url: str = DEFAULT_BASE_URL,
    timeout: float = DEFAULT_TIMEOUT,
    num_ctx: int = DEFAULT_NUM_CTX,
    seed: int = DEFAULT_SEED,
) -> TriageVerdict:
    """Triage one AlertRecord with a single Ollama call.

    Posts to `{base_url}/api/generate` with `format` set to
    `TriageVerdict`'s JSON Schema (grammar-constrained decoding — see
    src/agents/schema.py) and `options.num_ctx` explicitly set (see
    DEFAULT_NUM_CTX above for why this must never be left to the server
    default). Raises `TriageError` on any transport failure, malformed JSON,
    or schema-shaped-but-semantically-invalid output (caught by
    TriageVerdict's own field validators).
    """
    prompt = render_alert_prompt(record)
    payload = {
        "model": model,
        "prompt": prompt,
        "system": SYSTEM_PROMPT,
        "format": TRIAGE_VERDICT_JSON_SCHEMA,
        "stream": False,
        "options": {"num_ctx": num_ctx, "temperature": 0.0, "seed": seed},
    }

    try:
        response = requests.post(f"{base_url}/api/generate", json=payload, timeout=timeout)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise TriageError(f"Ollama request failed for record {record.id!r}: {exc}") from exc

    try:
        body = response.json()
    except ValueError as exc:
        raise TriageError(f"Ollama returned non-JSON HTTP body for record {record.id!r}: {exc}") from exc

    raw_verdict = body.get("response")
    if not raw_verdict:
        raise TriageError(f"Ollama response for record {record.id!r} had no 'response' field: {body!r}")

    try:
        return TriageVerdict.model_validate_json(raw_verdict)
    except ValidationError as exc:
        raise TriageError(
            f"Model output for record {record.id!r} failed TriageVerdict validation "
            f"(schema-valid-but-semantically-wrong, or malformed): {exc}\nraw: {raw_verdict!r}"
        ) from exc


def triage_batch(
    records: Iterable[AlertRecord],
    model: str = DEFAULT_MODEL,
    base_url: str = DEFAULT_BASE_URL,
    timeout: float = DEFAULT_TIMEOUT,
    num_ctx: int = DEFAULT_NUM_CTX,
    on_progress: Callable[[int, int, AlertRecord], None] | None = None,
    stop_on_error: bool = False,
) -> list[TriageResult]:
    """Triage a list of records SEQUENTIALLY.

    Sequential, not a design placeholder for future concurrency:
    `OLLAMA_NUM_PARALLEL=1` (confirmed, research/phase-2-agent-design.md
    Finding 4) means this Ollama instance serves requests strictly serially
    regardless of how many are in flight, so concurrent requests would only
    add client-side complexity for zero throughput gain on this host.

    `on_progress(index, total, record)` is called after each record
    completes (success or handled failure) so a caller can report progress
    on what is, per the measured latency brief, a multi-second-per-call
    operation. `stop_on_error` defaults False: one record's TriageError does
    not abort the whole batch by default (a single bad record shouldn't kill
    a long-running batch), it is simply skipped and absent from the
    returned list; set True to propagate the first failure instead.
    """
    results: list[TriageResult] = []
    records = list(records)
    total = len(records)
    for index, record in enumerate(records):
        try:
            verdict = triage_alert(record, model=model, base_url=base_url, timeout=timeout, num_ctx=num_ctx)
        except TriageError:
            if stop_on_error:
                raise
            verdict = None
        if verdict is not None:
            results.append(TriageResult(record=record, verdict=verdict))
        if on_progress is not None:
            on_progress(index + 1, total, record)
    return results
