"""Evaluation harness for the LLM alert-triage classifier.

Implements the design specified in `research/phase-3-evaluation-design.md`
("the Verdict section is the specification" — see that file for the full
citation trail behind every choice made here). This package does not
relitigate that design; it implements it.

Modules:
    sampling.py     — stratified evaluation-set sampling with a malicious-
                       class floor, deterministic given a seed.
    baselines.py     — the four required non-LLM baselines, sharing the LLM
                       agent's predict interface so all are scored by
                       identical code.
    metrics.py       — MCC, PR-AUC/ROC-AUC, balanced accuracy, Wilson score
                       intervals, ECE, selective-prediction metrics.
    significance.py  — McNemar's test (exact/mid-p) and bootstrap CIs on
                       paired metric differences.
    harness.py       — orchestrates sample -> run LLM + baselines on the
                       SAME items -> pooled + stratified metrics ->
                       significance -> a structured EvalResult.
    report.py        — renders an EvalResult to markdown.
"""
