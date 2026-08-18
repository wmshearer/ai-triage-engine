"""Offline tests for the evaluation harness (src/eval/*) — no network, no Ollama.

Metrics are verified against KNOWN hand-computed values, not just "returns a
float" — a wrong MCC silently invalidates every downstream number, per this
task's own effort-budget instruction.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.agents.schema import TriageVerdict, Verdict
from src.eval import harness
from src.eval import metrics as m
from src.eval import significance as sig
from src.eval.baselines import (
    ClassicalMLBaseline,
    MajorityClassBaseline,
    RulesBaseline,
    StratifiedRandomBaseline,
)
from src.eval.sampling import MALICIOUS_FLOOR_FOR_5PP_CI, stratified_eval_sample
from src.schema import MULTI_TECHNIQUE_SENTINEL, AlertRecord, EventType

# ---------------------------------------------------------------------------
# Shared fixtures / builders
# ---------------------------------------------------------------------------


def make_record(
    idx: int,
    is_malicious: bool,
    event_id: int = 1,
    event_type: EventType = EventType.PROCESS,
    attack_technique: str | None = None,
    technique_unresolved: bool = False,
    capture_id: str | None = None,
    raw_event: dict | None = None,
) -> AlertRecord:
    if is_malicious and attack_technique is None:
        attack_technique = MULTI_TECHNIQUE_SENTINEL if technique_unresolved else "T1059"
    return AlertRecord(
        id=f"rec:{idx}",
        timestamp=datetime(2020, 1, 1, tzinfo=timezone.utc),
        source_host="host-0",
        event_type=event_type,
        source_dataset="otrf_security_datasets" if is_malicious else "evtx_baseline",
        source_capture_id=capture_id or f"cap-{idx}",
        raw_event=raw_event if raw_event is not None else {"EventID": event_id},
        is_malicious=is_malicious,
        attack_technique=attack_technique,
        attack_tactics=["TA0002"] if is_malicious else [],
        technique_unresolved=technique_unresolved,
    )


# ---------------------------------------------------------------------------
# metrics.py — confusion matrix + derived rates
# ---------------------------------------------------------------------------


class TestConfusionCounts:
    def test_basic_counts(self):
        # 2 TP, 1 FP, 1 FN, 2 TN, hand-verified
        y_true = [True, True, False, True, False, False]
        y_pred = [True, True, True, False, False, False]
        c = m.confusion_counts(y_true, y_pred)
        assert (c.tp, c.fp, c.fn, c.tn) == (2, 1, 1, 2)
        assert c.n == 6

    def test_length_mismatch_raises(self):
        with pytest.raises(ValueError):
            m.confusion_counts([True], [True, False])

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            m.confusion_counts([], [])


class TestMCC:
    def test_perfect_classifier(self):
        c = m.ConfusionCounts(tp=10, fp=0, fn=0, tn=10)
        assert m.mcc(c) == pytest.approx(1.0)

    def test_perfectly_wrong_classifier(self):
        c = m.ConfusionCounts(tp=0, fp=10, fn=10, tn=0)
        assert m.mcc(c) == pytest.approx(-1.0)

    def test_random_classifier_near_zero(self):
        # TP=TN=FP=FN=5: a classifier uncorrelated with truth
        c = m.ConfusionCounts(tp=5, fp=5, fn=5, tn=5)
        assert m.mcc(c) == pytest.approx(0.0)

    def test_hand_computed_imbalanced_example(self):
        # TP=90 FP=4 FN=1 TN=5 -- hand computation:
        # numerator = 90*5 - 4*1 = 450 - 4 = 446
        # denom = sqrt((94)(91)(9)(6)) = sqrt(94*91*9*6) = sqrt(461916)
        import math

        c = m.ConfusionCounts(tp=90, fp=4, fn=1, tn=5)
        expected = 446 / math.sqrt(94 * 91 * 9 * 6)
        assert m.mcc(c) == pytest.approx(expected)
        assert m.mcc(c) == pytest.approx(0.6562258828755642)

    def test_matches_sklearn_reference(self):
        y_true = [True] * 90 + [False] * 4 + [True] * 1 + [False] * 5
        y_pred = [True] * 90 + [True] * 4 + [False] * 1 + [False] * 5
        c = m.confusion_counts(y_true, y_pred)
        assert m.mcc(c) == pytest.approx(m.mcc_sklearn_cross_check(y_true, y_pred))

    def test_undefined_when_row_or_column_all_zero(self):
        # Classifier never predicts positive at all: TP=0, FP=0
        c = m.ConfusionCounts(tp=0, fp=0, fn=10, tn=10)
        assert m.mcc(c) is None

    def test_undefined_never_silently_zero_or_one(self):
        # All-positive-predicted degenerate case (TN=0, FN=0)
        c = m.ConfusionCounts(tp=10, fp=10, fn=0, tn=0)
        assert m.mcc(c) is None


class TestPrecisionRecallF1:
    def test_hand_computed(self):
        c = m.ConfusionCounts(tp=2, fp=1, fn=1, tn=2)
        assert m.precision(c) == pytest.approx(2 / 3)
        assert m.recall(c) == pytest.approx(2 / 3)
        p, r = 2 / 3, 2 / 3
        assert m.f1(c) == pytest.approx(2 * p * r / (p + r))

    def test_precision_undefined_when_never_predicts_positive(self):
        c = m.ConfusionCounts(tp=0, fp=0, fn=5, tn=5)
        assert m.precision(c) is None

    def test_recall_undefined_with_no_actual_positives(self):
        c = m.ConfusionCounts(tp=0, fp=5, fn=0, tn=5)
        assert m.recall(c) is None


class TestRatesAndBalancedAccuracy:
    def test_fpr_fnr_specificity_hand_computed(self):
        c = m.ConfusionCounts(tp=2, fp=1, fn=1, tn=2)
        assert m.false_positive_rate(c) == pytest.approx(1 / 3)
        assert m.false_negative_rate(c) == pytest.approx(1 / 3)
        assert m.specificity(c) == pytest.approx(2 / 3)

    def test_balanced_accuracy_majority_class_case(self):
        # 80/20 imbalance, always-benign predictor: recall=0, specificity=1
        c = m.ConfusionCounts(tp=0, fp=0, fn=20, tn=80)
        assert m.accuracy(c) == pytest.approx(0.8)
        assert m.balanced_accuracy(c) == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# metrics.py — Wilson score intervals, verified against published values
# ---------------------------------------------------------------------------


class TestWilsonInterval:
    def test_50_of_100_matches_published_value(self):
        # Newcombe 1998's worked example: 50/100 -> approx (0.4038, 0.5962)
        w = m.wilson_interval(50, 100)
        assert w.point == pytest.approx(0.5)
        assert w.low == pytest.approx(0.4038, abs=1e-3)
        assert w.high == pytest.approx(0.5962, abs=1e-3)

    def test_90_of_100_matches_published_value(self):
        w = m.wilson_interval(90, 100)
        assert w.low == pytest.approx(0.8256, abs=1e-3)
        assert w.high == pytest.approx(0.9448, abs=1e-3)

    def test_zero_successes_small_n_is_not_degenerate(self):
        # Wald would give (0, 0) here; Wilson must give a nonzero upper bound
        w = m.wilson_interval(0, 10)
        assert w.low == pytest.approx(0.0)
        assert w.high > 0.15

    def test_raises_on_zero_n(self):
        with pytest.raises(ValueError):
            m.wilson_interval(0, 0)

    def test_raises_on_successes_out_of_range(self):
        with pytest.raises(ValueError):
            m.wilson_interval(11, 10)


# ---------------------------------------------------------------------------
# metrics.py — PR-AUC / ROC-AUC sanity (not hand-derived, but checked against
# a known-separable and a known-random case)
# ---------------------------------------------------------------------------


class TestRankingMetrics:
    def test_perfect_separation_gives_auc_one(self):
        y_true = [False, False, False, True, True, True]
        y_score = [0.1, 0.2, 0.3, 0.7, 0.8, 0.9]
        assert m.roc_auc(y_true, y_score) == pytest.approx(1.0)
        assert m.pr_auc(y_true, y_score) == pytest.approx(1.0)

    def test_inverted_scores_give_auc_zero(self):
        y_true = [False, False, False, True, True, True]
        y_score = [0.9, 0.8, 0.7, 0.3, 0.2, 0.1]
        assert m.roc_auc(y_true, y_score) == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# metrics.py — ECE
# ---------------------------------------------------------------------------


class TestECE:
    def test_perfectly_calibrated_has_zero_ece(self):
        # All 10 items report confidence exactly 1.0 and are all correct ->
        # avg_confidence == accuracy == 1.0 in the top bin, ECE == 0.
        confidences = [1.0] * 10
        correct = [True] * 10
        result = m.expected_calibration_error(confidences, correct, n_bins=10)
        assert result.ece == pytest.approx(0.0)

    def test_hand_computed_two_bin_case(self):
        # Bin A: 5 items, confidence 0.9, 3 correct (acc=0.6) -> |0.6-0.9|=0.3, weight 5/10
        # Bin B: 5 items, confidence 0.2, 1 correct (acc=0.2) -> |0.2-0.2|=0.0, weight 5/10
        # ECE = 0.5*0.3 + 0.5*0.0 = 0.15
        confidences = [0.9] * 5 + [0.2] * 5
        correct = [True, True, True, False, False] + [True, False, False, False, False]
        result = m.expected_calibration_error(confidences, correct, n_bins=10)
        assert result.ece == pytest.approx(0.15)

    def test_mismatched_lengths_raise(self):
        with pytest.raises(ValueError):
            m.expected_calibration_error([0.5], [True, False])

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            m.expected_calibration_error([], [])


# ---------------------------------------------------------------------------
# metrics.py — selective prediction (abstention framing)
# ---------------------------------------------------------------------------


class TestSelectivePrediction:
    def test_hand_computed_coverage_and_selective_accuracy(self):
        # 10 items, 6 committed (4 correct), 4 abstained
        committed = [True] * 6 + [False] * 4
        correct = [True, True, True, True, False, False] + [False] * 4
        result = m.selective_prediction_metrics(committed, correct)
        assert result.coverage == pytest.approx(0.6)
        assert result.selective_accuracy == pytest.approx(4 / 6)
        assert result.n_committed == 6
        assert result.n_abstained == 4

    def test_full_abstention_gives_none_selective_accuracy(self):
        committed = [False] * 5
        correct = [False] * 5
        result = m.selective_prediction_metrics(committed, correct)
        assert result.coverage == pytest.approx(0.0)
        assert result.selective_accuracy is None

    def test_full_coverage_matches_plain_accuracy(self):
        committed = [True] * 10
        correct = [True] * 7 + [False] * 3
        result = m.selective_prediction_metrics(committed, correct)
        assert result.coverage == pytest.approx(1.0)
        assert result.selective_accuracy == pytest.approx(0.7)

    def test_aurc_lower_for_better_confidence_ranking(self):
        # Case A: confidence perfectly ranks correctness (high conf -> correct)
        committed = [True] * 10
        correct = [True] * 5 + [False] * 5
        confidences_good = [0.9, 0.8, 0.7, 0.6, 0.55, 0.5, 0.4, 0.3, 0.2, 0.1]
        result_good = m.selective_prediction_metrics(committed, correct, confidences=confidences_good)

        # Case B: confidence inversely ranks correctness (worst possible ranking)
        confidences_bad = [0.1, 0.2, 0.3, 0.4, 0.45, 0.5, 0.6, 0.7, 0.8, 0.9]
        result_bad = m.selective_prediction_metrics(committed, correct, confidences=confidences_bad)

        assert result_good.aurc < result_bad.aurc

    def test_mismatched_lengths_raise(self):
        with pytest.raises(ValueError):
            m.selective_prediction_metrics([True, False], [True])


# ---------------------------------------------------------------------------
# significance.py — McNemar's test, verified against a worked example
# ---------------------------------------------------------------------------


class TestMcNemar:
    def test_exact_form_matches_scipy_binomtest(self):
        from scipy.stats import binomtest

        a_correct = [True] * 3 + [False] * 15 + [True] * 10 + [False] * 5
        b_correct = [False] * 3 + [True] * 15 + [True] * 10 + [False] * 5
        result = sig.mcnemar_test(a_correct, b_correct)
        assert result.b == 3
        assert result.c == 15
        assert result.method == "exact_binomial"
        expected = binomtest(3, 18, p=0.5, alternative="two-sided").pvalue
        assert result.p_value == pytest.approx(expected)

    def test_chi_squared_form_hand_computed(self):
        # b=21, c=9, n_discordant=30 (>= threshold of 25 -> chi-squared form)
        # statistic = (|21-9|-1)^2 / 30 = 121/30
        a_correct = [True] * 21 + [False] * 9 + [True] * 20 + [False] * 20
        b_correct = [False] * 21 + [True] * 9 + [True] * 20 + [False] * 20
        result = sig.mcnemar_test(a_correct, b_correct)
        assert result.method == "chi_squared_continuity_corrected"
        assert result.statistic == pytest.approx(121 / 30)
        from scipy.stats import chi2

        assert result.p_value == pytest.approx(float(chi2.sf(121 / 30, df=1)))

    def test_no_discordant_pairs_gives_p_one(self):
        a_correct = [True, True, False, False]
        b_correct = [True, True, False, False]
        result = sig.mcnemar_test(a_correct, b_correct)
        assert result.n_discordant == 0
        assert result.p_value == pytest.approx(1.0)
        assert result.statistic is None

    def test_length_mismatch_raises(self):
        with pytest.raises(ValueError):
            sig.mcnemar_test([True], [True, False])

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            sig.mcnemar_test([], [])


class TestBootstrapCI:
    def test_point_estimate_is_exact_difference(self):
        values_a = [1.0] * 8 + [0.0] * 2  # accuracy 0.8
        values_b = [1.0] * 5 + [0.0] * 5  # accuracy 0.5
        result = sig.paired_bootstrap_ci(values_a, values_b, metric_fn=lambda xs: sum(xs) / len(xs), n_resamples=2000, seed=1)
        assert result.point_estimate == pytest.approx(0.3)

    def test_identical_systems_ci_straddles_zero(self):
        values_a = [1.0, 0.0] * 25
        values_b = [1.0, 0.0] * 25
        result = sig.paired_bootstrap_ci(values_a, values_b, metric_fn=lambda xs: sum(xs) / len(xs), n_resamples=2000, seed=1)
        assert result.low <= 0.0 <= result.high

    def test_deterministic_given_seed(self):
        values_a = [1.0, 0.0, 1.0, 1.0, 0.0]
        values_b = [0.0, 0.0, 1.0, 0.0, 1.0]
        r1 = sig.paired_bootstrap_ci(values_a, values_b, metric_fn=lambda xs: sum(xs) / len(xs), n_resamples=500, seed=42)
        r2 = sig.paired_bootstrap_ci(values_a, values_b, metric_fn=lambda xs: sum(xs) / len(xs), n_resamples=500, seed=42)
        assert r1 == r2

    def test_length_mismatch_raises(self):
        with pytest.raises(ValueError):
            sig.paired_bootstrap_ci([1.0], [1.0, 0.0], metric_fn=lambda xs: sum(xs))


# ---------------------------------------------------------------------------
# sampling.py
# ---------------------------------------------------------------------------


class TestStratifiedSampling:
    def _big_pool(self, n_malicious=2000, n_benign=8000):
        records = []
        for i in range(n_malicious):
            event_id = 1 if i % 20 == 0 else 12  # rare EventID 1, common EventID 12
            records.append(make_record(i, True, event_id=event_id))
        for i in range(n_benign):
            event_id = 1 if i % 20 == 0 else 12
            records.append(make_record(n_malicious + i, False, event_id=event_id))
        return records

    def test_deterministic_given_seed(self):
        pool = self._big_pool()
        sample1, report1 = stratified_eval_sample(pool, sample_size=500, seed=7)
        sample2, report2 = stratified_eval_sample(pool, sample_size=500, seed=7)
        assert [r.id for r in sample1] == [r.id for r in sample2]
        assert report1 == report2

    def test_different_seeds_give_different_samples(self):
        pool = self._big_pool()
        sample1, _ = stratified_eval_sample(pool, sample_size=500, seed=1)
        sample2, _ = stratified_eval_sample(pool, sample_size=500, seed=2)
        assert [r.id for r in sample1] != [r.id for r in sample2]

    def test_meets_malicious_floor_when_pool_is_large_enough(self):
        pool = self._big_pool(n_malicious=2000, n_benign=8000)
        _, report = stratified_eval_sample(pool, sample_size=1925, seed=1)
        assert report.achieved_malicious >= MALICIOUS_FLOOR_FOR_5PP_CI
        assert report.floor_met is True

    def test_reports_shortfall_honestly_when_pool_too_small(self):
        # Only 100 malicious records available -- far below the 385 floor
        pool = self._big_pool(n_malicious=100, n_benign=8000)
        _, report = stratified_eval_sample(pool, sample_size=1925, seed=1)
        assert report.achieved_malicious == 100
        assert report.floor_met is False  # must not silently claim the floor was met

    def test_preserves_rare_event_id_stratification(self):
        # EventID 1 is 5% of the malicious pool; a uniform sample at a small
        # target would likely draw zero if not stratified. Verify EventID 1
        # is represented in the achieved malicious sample.
        pool = self._big_pool(n_malicious=2000, n_benign=8000)
        sample, _ = stratified_eval_sample(pool, sample_size=200, seed=1)
        malicious_event_ids = {r.raw_event["EventID"] for r in sample if r.is_malicious}
        assert 1 in malicious_event_ids

    def test_invalid_sample_size_raises(self):
        with pytest.raises(ValueError):
            stratified_eval_sample(self._big_pool(), sample_size=0)

    def test_empty_records_raises(self):
        with pytest.raises(ValueError):
            stratified_eval_sample([], sample_size=10)


# ---------------------------------------------------------------------------
# baselines.py
# ---------------------------------------------------------------------------


class TestMajorityClassBaseline:
    def test_always_predicts_benign(self):
        records = [make_record(i, i % 2 == 0) for i in range(10)]
        preds = MajorityClassBaseline().predict(records)
        assert all(p.is_malicious_pred is False for p in preds)
        assert all(p.score == 0.0 for p in preds)


class TestStratifiedRandomBaseline:
    def test_deterministic_given_seed(self):
        records = [make_record(i, False) for i in range(50)]
        b1 = StratifiedRandomBaseline(malicious_rate=0.2, seed=7)
        b2 = StratifiedRandomBaseline(malicious_rate=0.2, seed=7)
        assert b1.predict(records) == b2.predict(records)

    def test_rate_zero_never_predicts_malicious(self):
        records = [make_record(i, False) for i in range(20)]
        preds = StratifiedRandomBaseline(malicious_rate=0.0, seed=1).predict(records)
        assert all(p.is_malicious_pred is False for p in preds)

    def test_invalid_rate_raises(self):
        with pytest.raises(ValueError):
            StratifiedRandomBaseline(malicious_rate=1.5)


class TestRulesBaseline:
    def test_flags_encoded_powershell(self):
        record = make_record(
            0,
            True,
            raw_event={
                "EventID": 1,
                "CommandLine": "powershell.exe -enc AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            },
        )
        pred = RulesBaseline().predict([record])[0]
        assert pred.is_malicious_pred is True
        assert pred.score > 0

    def test_does_not_flag_ordinary_notepad(self):
        record = make_record(0, False, raw_event={"EventID": 1, "CommandLine": "notepad.exe C:\\file.txt"})
        pred = RulesBaseline().predict([record])[0]
        assert pred.is_malicious_pred is False
        assert pred.score == pytest.approx(0.0)

    def test_produces_valid_output_on_synthetic_records(self):
        records = [make_record(i, i % 2 == 0, raw_event={"EventID": i % 5}) for i in range(20)]
        preds = RulesBaseline().predict(records)
        assert len(preds) == 20
        assert all(0.0 <= p.score <= 1.0 for p in preds)
        assert all(isinstance(p.is_malicious_pred, bool) for p in preds)


class TestClassicalMLBaseline:
    def _training_records(self, n=200):
        records = []
        for i in range(n):
            is_mal = i % 2 == 0
            cmd = "powershell.exe -enc XYZ -nop -windowstyle hidden" if is_mal else "explorer.exe"
            records.append(
                make_record(i, is_mal, event_id=1, capture_id=f"cap-{i}", raw_event={"EventID": 1, "CommandLine": cmd})
            )
        return records

    def test_predict_before_fit_raises(self):
        clf = ClassicalMLBaseline()
        with pytest.raises(RuntimeError):
            clf.predict([make_record(0, False)])

    def test_fit_requires_both_classes(self):
        clf = ClassicalMLBaseline()
        with pytest.raises(ValueError):
            clf.fit([make_record(i, True) for i in range(5)])

    def test_fit_on_empty_raises(self):
        clf = ClassicalMLBaseline()
        with pytest.raises(ValueError):
            clf.fit([])

    def test_learns_separable_synthetic_pattern(self):
        records = self._training_records(200)
        clf = ClassicalMLBaseline().fit(records)
        preds = clf.predict(records)
        # Not a leakage-safety test (train==eval here is fine for a pure
        # sanity check that predict() runs and produces valid output) -- the
        # actual leakage-safe SPLIT is tested separately below.
        assert len(preds) == len(records)
        assert all(0.0 <= p.score <= 1.0 for p in preds)
        accuracy = sum(
            1 for p, r in zip(preds, records) if p.is_malicious_pred == r.is_malicious
        ) / len(records)
        assert accuracy > 0.7  # a strongly separable synthetic pattern should be learnable

    def test_does_not_read_leakage_suppressed_fields(self):
        # A record where @timestamp/Hostname/etc. would trivially separate
        # the classes must NOT let the classifier use them -- verified
        # indirectly: two records identical except for a suppressed field
        # produce identical engineered feature vectors.
        from src.eval.baselines import _engineer_features

        r1 = make_record(0, True, raw_event={"EventID": 1, "CommandLine": "powershell.exe", "Hostname": "AAA", "@timestamp": "2020-01-01T00:00:00Z"})
        r2 = make_record(1, True, raw_event={"EventID": 1, "CommandLine": "powershell.exe", "Hostname": "ZZZ", "@timestamp": "2099-01-01T00:00:00Z"})
        assert _engineer_features(r1) == _engineer_features(r2)


# ---------------------------------------------------------------------------
# harness.py — 3-way collapse policies
# ---------------------------------------------------------------------------


class TestCollapsePolicies:
    def test_conservative_maps_suspicious_to_malicious(self):
        assert harness._collapse_verdict(Verdict.SUSPICIOUS, "conservative") is True

    def test_high_precision_maps_suspicious_to_benign(self):
        assert harness._collapse_verdict(Verdict.SUSPICIOUS, "high_precision") is False

    def test_abstention_leaves_suspicious_uncommitted(self):
        assert harness._collapse_verdict(Verdict.SUSPICIOUS, "abstention") is None

    def test_malicious_and_benign_identical_across_all_policies(self):
        for policy in harness.COLLAPSE_POLICIES:
            assert harness._collapse_verdict(Verdict.MALICIOUS, policy) is True
            assert harness._collapse_verdict(Verdict.BENIGN, policy) is False

    def test_unknown_policy_raises(self):
        with pytest.raises(ValueError):
            harness._collapse_verdict(Verdict.SUSPICIOUS, "not_a_policy")


# ---------------------------------------------------------------------------
# harness.py — per-technique scoring EXCLUDES sentinel records (the
# correctness property most likely to be silently wrong, per the task brief)
# ---------------------------------------------------------------------------


class TestSentinelExclusion:
    def _mixed_items(self):
        records = [
            make_record(0, True, attack_technique="T1059", technique_unresolved=False),
            make_record(1, True, attack_technique="T1059", technique_unresolved=False),
            make_record(2, True, technique_unresolved=True),  # sentinel
            make_record(3, True, technique_unresolved=True),  # sentinel
            make_record(4, False),
        ]
        verdicts = [
            TriageVerdict(verdict=Verdict.MALICIOUS, confidence=0.9, attack_technique="T1059", reasoning="x"),
            TriageVerdict(verdict=Verdict.BENIGN, confidence=0.9, reasoning="x"),  # wrong on purpose
            TriageVerdict(verdict=Verdict.MALICIOUS, confidence=0.9, reasoning="x"),
            TriageVerdict(verdict=Verdict.BENIGN, confidence=0.9, reasoning="x"),  # wrong on purpose
            TriageVerdict(verdict=Verdict.BENIGN, confidence=0.9, reasoning="x"),
        ]
        return harness._predictions_for_llm(records, verdicts)

    def test_split_sentinel_records_separates_correctly(self):
        items = self._mixed_items()
        resolvable, sentinel = harness.split_sentinel_records(items)
        assert len(sentinel) == 2
        assert all(item.record.technique_unresolved for item in sentinel)
        assert len(resolvable) == 3
        assert all(not item.record.technique_unresolved for item in resolvable)

    def test_per_technique_buckets_never_contain_sentinel_records(self):
        items = self._mixed_items()
        resolvable, _ = harness.split_sentinel_records(items)
        buckets = harness.stratify_by_technique(resolvable)
        for bucket_items in buckets.values():
            assert all(not item.record.technique_unresolved for item in bucket_items)
        # The sentinel string itself must never appear as a bucket key
        assert MULTI_TECHNIQUE_SENTINEL not in buckets

    def test_sentinel_records_not_scored_as_wrong_in_per_technique_table(self):
        # Sentinel record #3 above got a WRONG verdict (benign, but is
        # malicious) -- if it leaked into per-technique T1059 scoring, T1059
        # recall would be dragged down by a record that was never asked to
        # match T1059 in the first place. Verify T1059's bucket only contains
        # the two genuinely-T1059-labeled records.
        items = self._mixed_items()
        resolvable, _ = harness.split_sentinel_records(items)
        result = harness.build_system_result("llm", resolvable)
        assert "T1059" in result.per_technique
        assert result.per_technique["T1059"].n == 2

    def test_sentinel_bucket_reported_separately_not_dropped(self):
        items = self._mixed_items()
        result = harness.build_system_result("llm", items)
        assert result.sentinel_bucket is not None
        assert result.sentinel_bucket.n == 2


# ---------------------------------------------------------------------------
# harness.py — leakage-safe classical-ML split
# ---------------------------------------------------------------------------


class TestLeakageSafeSplit:
    def test_fit_pool_excludes_eval_captures_when_both_classes_have_many_captures(self):
        # 200 records across 100 DISTINCT captures (2 records/capture) so
        # excluding the first 20 records' 10 captures still leaves 90 intact.
        corpus = [make_record(i, i % 2 == 0, capture_id=f"cap-{i // 2}") for i in range(200)]
        eval_records = corpus[:20]
        fit_pool, disclosure = harness.classical_ml_train_test_split(corpus, eval_records, seed=1)
        eval_capture_ids = {r.source_capture_id for r in eval_records}
        fit_capture_ids = {r.source_capture_id for r in fit_pool}
        assert eval_capture_ids.isdisjoint(fit_capture_ids)
        assert disclosure.malicious_split_strategy == "capture_level_exclusion"
        assert disclosure.benign_split_strategy == "capture_level_exclusion"

    def test_single_shared_capture_class_falls_back_to_record_level_holdout(self):
        # Mirrors the REAL corpus's measured shape: malicious spans several
        # captures, but every benign record shares ONE capture id (evtx-
        # baseline ships as a single VM capture) -- capture-level exclusion
        # would empty the entire benign fit pool the moment any benign
        # record lands in eval. Verify the fallback kicks in and still
        # produces a usable, genuinely eval-disjoint (by id) fit pool.
        malicious = [make_record(i, True, capture_id=f"mal-cap-{i // 2}") for i in range(20)]
        benign = [make_record(100 + i, False, capture_id="shared-benign-cap") for i in range(100)]
        corpus = malicious + benign
        eval_records = malicious[:4] + benign[:20]

        fit_pool, disclosure = harness.classical_ml_train_test_split(corpus, eval_records, seed=1)

        assert disclosure.malicious_split_strategy == "capture_level_exclusion"
        assert disclosure.benign_split_strategy == "record_level_holdout_fallback"

        fit_ids = {r.id for r in fit_pool}
        eval_ids = {r.id for r in eval_records}
        assert fit_ids.isdisjoint(eval_ids)  # no exact record overlap either way

        fit_malicious_captures = {r.source_capture_id for r in fit_pool if r.is_malicious}
        eval_malicious_captures = {r.source_capture_id for r in eval_records if r.is_malicious}
        assert fit_malicious_captures.isdisjoint(eval_malicious_captures)  # malicious side still capture-safe

        assert any(not r.is_malicious for r in fit_pool)  # benign fit pool is NOT empty

    def test_raises_if_split_empties_a_class_even_after_fallback(self):
        # Every record (both classes) shares ONE capture id AND the eval set
        # covers every single record -- no fallback can rescue this.
        corpus = [make_record(i, i % 2 == 0, capture_id="only-cap") for i in range(20)]
        eval_records = corpus
        with pytest.raises(ValueError):
            harness.classical_ml_train_test_split(corpus, eval_records, seed=1)


# ---------------------------------------------------------------------------
# harness.py — end-to-end wiring smoke tests (LLM + baseline through the
# same scoring code, significance computed)
# ---------------------------------------------------------------------------


class TestHarnessEndToEnd:
    def _records_and_verdicts(self, n=40):
        records = [make_record(i, i % 2 == 0, event_id=(1 if i % 3 == 0 else 12)) for i in range(n)]
        verdicts = [
            TriageVerdict(
                verdict=(Verdict.MALICIOUS if r.is_malicious else Verdict.BENIGN),
                confidence=0.9,
                attack_technique=(r.attack_technique if r.is_malicious and not r.technique_unresolved else None),
                reasoning="x",
            )
            for r in records
        ]
        return records, verdicts

    def test_llm_and_baseline_scored_by_identical_code(self):
        records, verdicts = self._records_and_verdicts()
        llm_items = harness._predictions_for_llm(records, verdicts)
        llm_result = harness.build_system_result("llm", llm_items, harness.compute_llm_specific_report(llm_items))

        baseline_preds = MajorityClassBaseline().predict(records)
        baseline_items = harness._predictions_for_baseline(records, baseline_preds)
        baseline_result = harness.build_system_result("majority_class", baseline_items)

        # A perfect LLM on this synthetic set should score MCC=1.0 under the
        # headline policy; the majority-class baseline should score MCC
        # undefined (never predicts positive).
        assert llm_result.pooled.policies["conservative"].metrics["mcc"] == pytest.approx(1.0)
        assert baseline_result.pooled.policies["conservative"].metrics["mcc"] is None

    def test_significance_detects_llm_advantage(self):
        records, verdicts = self._records_and_verdicts()
        llm_items = harness._predictions_for_llm(records, verdicts)
        baseline_items = harness._predictions_for_baseline(records, MajorityClassBaseline().predict(records))

        results = harness.compute_significance(llm_items, {"majority_class": baseline_items})
        assert len(results) == 1
        result = results[0]
        # Perfect LLM vs. always-benign on a 50/50 set: every malicious item
        # is discordant in the LLM's favor -> p-value should be tiny.
        assert result.mcnemar.p_value < 0.05
        assert result.bootstrap_ci.point_estimate > 0

    def test_parse_failures_kept_in_sample_not_dropped(self):
        records, verdicts = self._records_and_verdicts(n=10)
        verdicts_with_failure = [None] + verdicts[1:]  # first record "failed to parse"
        items = harness._predictions_for_llm(records, verdicts_with_failure)
        assert len(items) == 10  # not silently dropped
        assert items[0].parse_failed is True
        report = harness.compute_llm_specific_report(items)
        assert report.n_attempted == 10
        assert report.n_parse_failed == 1
        assert report.parse_failure_rate == pytest.approx(0.1)

    def test_determinism_measurement_with_stub(self):
        records = [make_record(i, i % 2 == 0) for i in range(4)]

        def stable_triage(record: AlertRecord) -> TriageVerdict:
            return TriageVerdict(
                verdict=Verdict.MALICIOUS if record.is_malicious else Verdict.BENIGN,
                confidence=0.9,
                reasoning="x",
            )

        report = harness.measure_determinism(records, stable_triage, n_repeats=5)
        assert report.agreement_rate == pytest.approx(1.0)

    def test_determinism_detects_flip(self):
        records = [make_record(0, True)]
        call_count = {"n": 0}

        def flaky_triage(record: AlertRecord) -> TriageVerdict:
            call_count["n"] += 1
            # Flips verdict on every other call
            verdict = Verdict.MALICIOUS if call_count["n"] % 2 == 1 else Verdict.BENIGN
            return TriageVerdict(verdict=verdict, confidence=0.9, reasoning="x")

        report = harness.measure_determinism(records, flaky_triage, n_repeats=5)
        assert report.agreement_rate == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# report.py — smoke test that rendering doesn't crash and includes required sections
# ---------------------------------------------------------------------------


class TestReportRendering:
    def test_render_report_includes_required_sections(self):
        from src.eval import report as report_mod
        from src.eval.sampling import SampleSizeReport

        records = [make_record(i, i % 2 == 0, event_id=(1 if i % 3 == 0 else 12)) for i in range(20)]
        verdicts = [
            TriageVerdict(
                verdict=(Verdict.MALICIOUS if r.is_malicious else Verdict.BENIGN),
                confidence=0.9,
                reasoning="x",
            )
            for r in records
        ]
        llm_items = harness._predictions_for_llm(records, verdicts)
        llm_result = harness.build_system_result("llm", llm_items, harness.compute_llm_specific_report(llm_items))
        baseline_items = harness._predictions_for_baseline(records, MajorityClassBaseline().predict(records))
        baseline_result = harness.build_system_result("majority_class", baseline_items)

        significance = harness.compute_significance(llm_items, {"majority_class": baseline_items})

        result = harness.EvalResult(
            sample_size_report=SampleSizeReport(
                target_total=20, target_malicious=10, achieved_total=20, achieved_malicious=10, achieved_benign=10, floor_met=False
            ),
            systems={"llm": llm_result, "majority_class": baseline_result},
            significance=significance,
            corpus_metadata={"benign_ratio": 4.0, "mitigate_shortcuts": True},
        )

        md = report_mod.render_report(result, run_metadata={"model": "test", "temperature": 0.0})

        assert "MCC" in md
        assert "PR-AUC" in md
        assert "conservative" in md
        assert "high_precision" in md
        assert "abstention" in md
        assert "What must be disclosed" in md
        assert "MULTI_TECHNIQUE_UNRESOLVED" in md or "sentinel" in md.lower()
        assert "McNemar" in md or "McNemar" in md
