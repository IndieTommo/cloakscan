from __future__ import annotations

import unittest

from rich.console import Console

from cloakscan.models import DebugEvent, RunSummary, Signal, TargetResult, TargetSpec, ViewSnapshot
from cloakscan.ui.output import print_banner, print_result, print_summary


class UiOutputTests(unittest.TestCase):
    def test_print_banner_includes_version_label(self) -> None:
        console = Console(record=True, width=140)

        print_banner(console)
        output = console.export_text()

        self.assertIn("v1.0.1 by Tommo", output)

    def test_debug_output_prints_phase_lines_without_raw_html(self) -> None:
        console = Console(record=True, width=140)
        result = TargetResult(
            target=TargetSpec(raw="https://example.com", normalized_url="https://example.com/"),
            risk="CLEAN",
            score=0,
            reason="No major cloaking/spam indicators",
            debug_events=[
                DebugEvent("browser_http", 1.25, {"status": 200, "final_url": "https://example.com/"}),
                DebugEvent("detect_score", 0.03, {"signal_count": 0, "risk": "CLEAN"}),
            ],
            views={
                "browser": ViewSnapshot(
                    profile="browser",
                    requested_url="https://example.com/",
                    final_url="https://example.com/",
                    status_code=200,
                    html="<html><body>secret html</body></html>",
                )
            },
            runtime_seconds=1.28,
        )

        print_result(console, result, explain=False, debug=True)
        output = console.export_text()

        self.assertIn("DEBUG browser_http 1.25s", output)
        self.assertIn("DEBUG detect_score 0.03s", output)
        self.assertNotIn("secret html", output)

    def test_explain_output_prints_signal_details(self) -> None:
        console = Console(record=True, width=140)
        result = TargetResult(
            target=TargetSpec(raw="https://example.com", normalized_url="https://example.com/"),
            risk="MEDIUM",
            score=3,
            reason="Rendered/Human content mismatch + Suspicious outbound link growth",
            signals=[],
            runtime_seconds=1.0,
        )
        result.signals.append(
            Signal(
                code="headless_human_mismatch",
                message="Rendered/Human content mismatch",
                points=2,
                metrics={"similarity": 0.455, "length_delta": 0.361},
                details=[
                    "title diff: browser='Home' vs rendered='Promo Landing'",
                    "rendered-only text sample: Casino offers and bonus links now live",
                ],
            )
        )

        print_result(console, result, explain=True, debug=False)
        output = console.export_text()

        self.assertIn("Rendered/Human content mismatch (similarity=0.455, length_delta=0.361)", output)
        self.assertIn("title diff: browser='Home' vs rendered='Promo Landing'", output)
        self.assertIn("rendered-only text sample:", output)

    def test_incomplete_clean_output_surfaces_specific_reason_and_warning(self) -> None:
        console = Console(record=True, width=140)
        result = TargetResult(
            target=TargetSpec(raw="https://example.com", normalized_url="https://example.com/"),
            risk="CLEAN",
            score=0,
            reason="Bot TLS verification failed; possible bot-only redirect or certificate issue. Rerun with --tls-debug",
            incomplete=True,
            warnings=[
                "bot view failed: certificate verify failed",
                "possible bot-only redirect or certificate issue; rerun with --tls-debug",
            ],
            runtime_seconds=1.0,
        )

        print_result(console, result, explain=False, debug=False)
        output = console.export_text()

        self.assertIn("PARTIAL https://example.com - Bot TLS verification failed", output)
        self.assertIn("WARNING bot view failed: certificate verify failed", output)
        self.assertIn("WARNING possible bot-only redirect or certificate issue; rerun with --tls-debug", output)

    def test_summary_output_includes_partial_count(self) -> None:
        console = Console(record=True, width=140)

        print_summary(
            console,
            RunSummary(
                targets_total=1,
                clean_count=0,
                low_count=0,
                medium_count=0,
                high_count=0,
                failures_count=0,
                runtime_seconds=1.0,
                partial_count=1,
            ),
        )
        output = console.export_text()

        self.assertIn("Partial scans: 1", output)
        self.assertIn("Failures: 0", output)

    def test_incomplete_risky_output_marks_partial_evidence(self) -> None:
        console = Console(record=True, width=140)
        result = TargetResult(
            target=TargetSpec(raw="https://example.com", normalized_url="https://example.com/"),
            risk="MEDIUM",
            score=3,
            reason="Possible sneaky redirect mismatch",
            incomplete=True,
            warnings=[
                "bot view failed: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed",
                "possible bot-only redirect or certificate issue; rerun with --tls-debug",
            ],
            runtime_seconds=1.0,
        )

        print_result(console, result, explain=False, debug=False)
        output = console.export_text()

        self.assertIn(
            "MEDIUM https://example.com - Possible sneaky redirect mismatch (partial evidence: bot TLS failed)",
            output,
        )


if __name__ == "__main__":
    unittest.main()

