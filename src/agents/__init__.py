"""Single-agent triage baseline (Phase 2).

Deliberately NOT a multi-agent pipeline — see
`research/phase-2-agent-design.md` for the evidence (classification-task
literature favors single-prompt over decomposition at this task shape, and
`research/phase-2-measured-latency.md` measured ~4.2s/call vs ~16.9s for a
4-call chain under this host's `OLLAMA_NUM_PARALLEL=1`). A strong single-call
baseline must exist and be measured before any additional agent stage is
justified.
"""
