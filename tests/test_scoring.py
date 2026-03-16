from __future__ import annotations

import unittest

from cloakscan.models import RunSummary, Signal, TargetResult, TargetSpec
from cloakscan.score import build_summary, classify_risk, compute_exit_code


class ScoringTests(unittest.TestCase):
    def test_no_signals_is_clean(self) -> None:
        risk, score = classify_risk([])
        self.assertEqual(risk, "CLEAN")
        self.assertEqual(score, 0)

    def test_score_mapping(self) -> None:
        risk, score = classify_risk([Signal(code="x", message="x", points=1)])
        self.assertEqual((risk, score), ("LOW", 1))

        risk, score = classify_risk([Signal(code="x", message="x", points=4)])
        self.assertEqual((risk, score), ("MEDIUM", 4))

        risk, score = classify_risk([Signal(code="x", message="x", points=6)])
        self.assertEqual((risk, score), ("HIGH", 6))

    def test_escalation_rule_for_mismatch_plus_keywords(self) -> None:
        risk, score = classify_risk(
            [
                Signal(code="bot_human_mismatch", message="mismatch", points=1),
                Signal(code="casino_keywords", message="casino", points=1),
            ]
        )
        self.assertEqual(risk, "MEDIUM")
        self.assertGreaterEqual(score, 3)

    def test_rendered_mismatch_plus_link_growth_stays_low(self) -> None:
        risk, score = classify_risk(
            [
                Signal(code="headless_human_mismatch", message="rendered mismatch", points=2),
                Signal(code="outbound_link_injection", message="link growth", points=2),
            ]
        )
        self.assertEqual((risk, score), ("LOW", 2))

    def test_link_growth_with_keyword_signal_escalates(self) -> None:
        risk, score = classify_risk(
            [
                Signal(code="outbound_link_injection", message="link growth", points=2),
                Signal(code="adult_keywords", message="adult", points=2),
            ]
        )
        self.assertEqual((risk, score), ("MEDIUM", 4))

    def test_link_growth_with_bot_mismatch_stays_medium(self) -> None:
        risk, score = classify_risk(
            [
                Signal(code="bot_human_mismatch", message="bot mismatch", points=2),
                Signal(code="outbound_link_injection", message="link growth", points=2),
            ]
        )
        self.assertEqual((risk, score), ("MEDIUM", 4))

    def test_exit_code_matrix(self) -> None:
        self.assertEqual(
            compute_exit_code(
                RunSummary(
                    targets_total=2,
                    clean_count=1,
                    low_count=1,
                    medium_count=0,
                    high_count=0,
                    failures_count=0,
                    runtime_seconds=1.0,
                )
            ),
            0,
        )
        self.assertEqual(
            compute_exit_code(
                RunSummary(
                    targets_total=2,
                    clean_count=1,
                    low_count=0,
                    medium_count=1,
                    high_count=0,
                    failures_count=0,
                    runtime_seconds=1.0,
                )
            ),
            1,
        )
        self.assertEqual(
            compute_exit_code(
                RunSummary(
                    targets_total=2,
                    clean_count=1,
                    low_count=0,
                    medium_count=0,
                    high_count=0,
                    failures_count=1,
                    runtime_seconds=1.0,
                )
            ),
            3,
        )

        self.assertEqual(
            compute_exit_code(
                RunSummary(
                    targets_total=1,
                    clean_count=0,
                    low_count=0,
                    medium_count=0,
                    high_count=0,
                    failures_count=0,
                    runtime_seconds=1.0,
                    partial_count=1,
                )
            ),
            3,
        )


    def test_incomplete_results_count_as_failures_in_summary(self) -> None:
        summary = build_summary(
            results=[
                TargetResult(
                    target=TargetSpec(raw="example.com", normalized_url="https://example.com/"),
                    risk="CLEAN",
                    score=0,
                    reason="No major cloaking/spam indicators",
                    incomplete=True,
                    warnings=["bot view failed: cert error"],
                )
            ],
            runtime_seconds=1.0,
        )

        self.assertEqual(summary.clean_count, 0)
        self.assertEqual(summary.partial_count, 1)
        self.assertEqual(summary.failures_count, 0)


if __name__ == "__main__":
    unittest.main()
