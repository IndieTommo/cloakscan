from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import unittest

from typer.testing import CliRunner

from cloakscan.config import load_scan_config
from cloakscan.models import RunSummary, TargetSpec


class CliBehaviorTests(unittest.TestCase):

    @staticmethod
    def _sample_result():
        from cloakscan.models import Signal, TargetResult, ViewSnapshot

        return TargetResult(
            target=TargetSpec(raw="example.com", normalized_url="https://example.com/"),
            risk="MEDIUM",
            score=3,
            reason="Possible sneaky redirect mismatch",
            signals=[
                Signal(
                    code="sneaky_redirect",
                    message="Possible sneaky redirect mismatch",
                    points=3,
                    metrics={"browser_final": "https://example.com/", "bot_final": "https://spam.example/"},
                    details=["final URL diff: browser=https://example.com/ vs bot=https://spam.example/"],
                )
            ],
            views={
                "browser": ViewSnapshot(
                    profile="browser",
                    requested_url="https://example.com/",
                    final_url="https://example.com/",
                    status_code=200,
                    html="",
                )
            },
            runtime_seconds=0.5,
        )

    def test_cli_has_root_callback(self) -> None:
        from cloakscan.cli.app import app

        # With a root callback present, Click/Typer treats this as a real
        # command group and requires explicit subcommands like "scan".
        self.assertIsNotNone(app.registered_callback)

    def test_scan_accepts_json_option(self) -> None:
        from cloakscan.cli.app import app

        runner = CliRunner()
        config = load_scan_config("balanced", config_path=None)
        run_scan_mock = MagicMock(return_value="scan-coro")

        with patch("cloakscan.cli.app.load_scan_config", return_value=config):
            with patch(
                "cloakscan.cli.app.collect_targets",
                return_value=[TargetSpec(raw="example.com", normalized_url="https://example.com/")],
            ):
                with patch("cloakscan.cli.app.run_scan", run_scan_mock):
                    with patch("cloakscan.cli.app.asyncio.run", return_value=([], 0)):
                        with patch(
                            "cloakscan.cli.app.build_summary",
                            return_value=RunSummary(
                                targets_total=1,
                                clean_count=1,
                                low_count=0,
                                medium_count=0,
                                high_count=0,
                                failures_count=0,
                                runtime_seconds=0.5,
                            ),
                        ):
                            result = runner.invoke(
                                app,
                                ["scan", "https://example.com", "--json", "--no-headless", "--no-new-window"],
                            )

        self.assertEqual(result.exit_code, 0)
        self.assertTrue(run_scan_mock.called)
        self.assertFalse(run_scan_mock.call_args.kwargs["emit_output"])

    def test_scan_accepts_json_out_option(self) -> None:
        from cloakscan.cli.app import app

        runner = CliRunner()
        config = load_scan_config("balanced", config_path=None)
        run_scan_mock = MagicMock(return_value="scan-coro")

        with patch("cloakscan.cli.app.load_scan_config", return_value=config):
            with patch(
                "cloakscan.cli.app.collect_targets",
                return_value=[TargetSpec(raw="example.com", normalized_url="https://example.com/")],
            ):
                with patch("cloakscan.cli.app.run_scan", run_scan_mock):
                    with patch("cloakscan.cli.app.asyncio.run", return_value=([], 0)):
                        with patch(
                            "cloakscan.cli.app.build_summary",
                            return_value=RunSummary(
                                targets_total=1,
                                clean_count=1,
                                low_count=0,
                                medium_count=0,
                                high_count=0,
                                failures_count=0,
                                runtime_seconds=0.5,
                            ),
                        ):
                            result = runner.invoke(
                                app,
                                ["scan", "https://example.com", "--json-out", "report.json", "--no-headless", "--no-new-window"],
                            )

        self.assertEqual(result.exit_code, 0)
        self.assertTrue(run_scan_mock.called)
        self.assertTrue(run_scan_mock.call_args.kwargs["emit_output"])

    def test_json_out_rejects_option_like_value(self) -> None:
        from cloakscan.cli.app import app

        runner = CliRunner()

        with patch("cloakscan.cli.app._write_json_payload", side_effect=AssertionError("should not write")) as write_json:
            result = runner.invoke(
                app,
                ["scan", "https://example.com", "--json-out", "--no-new-window"],
            )

        self.assertEqual(result.exit_code, 2)
        self.assertIn("Path Missing", result.stdout)
        self.assertFalse(write_json.called)

    def test_scan_accepts_debug_option(self) -> None:
        from cloakscan.cli.app import app

        runner = CliRunner()
        config = load_scan_config("balanced", config_path=None)
        run_scan_mock = MagicMock(return_value="scan-coro")

        with patch("cloakscan.cli.app.load_scan_config", return_value=config):
            with patch(
                "cloakscan.cli.app.collect_targets",
                return_value=[TargetSpec(raw="example.com", normalized_url="https://example.com/")],
            ):
                with patch("cloakscan.cli.app.run_scan", run_scan_mock):
                    with patch("cloakscan.cli.app.asyncio.run", return_value=([], 0)):
                        with patch(
                            "cloakscan.cli.app.build_summary",
                            return_value=RunSummary(
                                targets_total=1,
                                clean_count=1,
                                low_count=0,
                                medium_count=0,
                                high_count=0,
                                failures_count=0,
                                runtime_seconds=0.5,
                            ),
                        ):
                            result = runner.invoke(
                                app,
                                ["scan", "https://example.com", "--debug", "--no-headless", "--no-new-window"],
                            )

        self.assertEqual(result.exit_code, 0)
        self.assertTrue(run_scan_mock.called)
        self.assertTrue(run_scan_mock.call_args.kwargs["debug"])
        self.assertTrue(run_scan_mock.call_args.kwargs["cache_bust"])


    def test_scan_accepts_tls_debug_option(self) -> None:
        from cloakscan.cli.app import app

        runner = CliRunner()
        config = load_scan_config("balanced", config_path=None)
        run_scan_mock = MagicMock(return_value="scan-coro")

        with patch("cloakscan.cli.app.load_scan_config", return_value=config):
            with patch(
                "cloakscan.cli.app.collect_targets",
                return_value=[TargetSpec(raw="example.com", normalized_url="https://example.com/")],
            ):
                with patch("cloakscan.cli.app.run_scan", run_scan_mock):
                    with patch("cloakscan.cli.app.asyncio.run", return_value=([], 0)):
                        with patch(
                            "cloakscan.cli.app.build_summary",
                            return_value=RunSummary(
                                targets_total=1,
                                clean_count=1,
                                low_count=0,
                                medium_count=0,
                                high_count=0,
                                failures_count=0,
                                runtime_seconds=0.5,
                            ),
                        ):
                            result = runner.invoke(
                                app,
                                ["scan", "https://example.com", "--tls-debug", "--no-headless", "--no-new-window"],
                            )

        self.assertEqual(result.exit_code, 0)
        self.assertTrue(run_scan_mock.called)
        self.assertTrue(run_scan_mock.call_args.kwargs["tls_debug"])

    def test_scan_cache_bust_is_enabled_by_default(self) -> None:
        from cloakscan.cli.app import app

        runner = CliRunner()
        config = load_scan_config("balanced", config_path=None)
        run_scan_mock = MagicMock(return_value="scan-coro")

        with patch("cloakscan.cli.app.load_scan_config", return_value=config):
            with patch(
                "cloakscan.cli.app.collect_targets",
                return_value=[TargetSpec(raw="example.com", normalized_url="https://example.com/")],
            ):
                with patch("cloakscan.cli.app.run_scan", run_scan_mock):
                    with patch("cloakscan.cli.app.asyncio.run", return_value=([], 0)):
                        with patch(
                            "cloakscan.cli.app.build_summary",
                            return_value=RunSummary(
                                targets_total=1,
                                clean_count=1,
                                low_count=0,
                                medium_count=0,
                                high_count=0,
                                failures_count=0,
                                runtime_seconds=0.5,
                            ),
                        ):
                            result = runner.invoke(
                                app,
                                ["scan", "https://example.com", "--no-headless", "--no-new-window"],
                            )

        self.assertEqual(result.exit_code, 0)
        self.assertTrue(run_scan_mock.called)
        self.assertTrue(run_scan_mock.call_args.kwargs["cache_bust"])

    def test_scan_accepts_no_cache_bust_option(self) -> None:
        from cloakscan.cli.app import app

        runner = CliRunner()
        config = load_scan_config("balanced", config_path=None)
        run_scan_mock = MagicMock(return_value="scan-coro")

        with patch("cloakscan.cli.app.load_scan_config", return_value=config):
            with patch(
                "cloakscan.cli.app.collect_targets",
                return_value=[TargetSpec(raw="example.com", normalized_url="https://example.com/")],
            ):
                with patch("cloakscan.cli.app.run_scan", run_scan_mock):
                    with patch("cloakscan.cli.app.asyncio.run", return_value=([], 0)):
                        with patch(
                            "cloakscan.cli.app.build_summary",
                            return_value=RunSummary(
                                targets_total=1,
                                clean_count=1,
                                low_count=0,
                                medium_count=0,
                                high_count=0,
                                failures_count=0,
                                runtime_seconds=0.5,
                            ),
                        ):
                            result = runner.invoke(
                                app,
                                ["scan", "https://example.com", "--no-cache-bust", "--no-headless", "--no-new-window"],
                            )

        self.assertEqual(result.exit_code, 0)
        self.assertTrue(run_scan_mock.called)
        self.assertFalse(run_scan_mock.call_args.kwargs["cache_bust"])

    def test_scan_safe_mode_disables_headless(self) -> None:
        from cloakscan.cli.app import app

        runner = CliRunner()
        config = load_scan_config("balanced", config_path=None)
        run_scan_mock = MagicMock(return_value="scan-coro")

        with patch("cloakscan.cli.app.load_scan_config", return_value=config):
            with patch(
                "cloakscan.cli.app.collect_targets",
                return_value=[TargetSpec(raw="example.com", normalized_url="https://example.com/")],
            ):
                with patch("cloakscan.cli.app.run_scan", run_scan_mock):
                    with patch("cloakscan.cli.app.asyncio.run", return_value=([], 0)):
                        with patch(
                            "cloakscan.cli.app.build_summary",
                            return_value=RunSummary(
                                targets_total=1,
                                clean_count=1,
                                low_count=0,
                                medium_count=0,
                                high_count=0,
                                failures_count=0,
                                runtime_seconds=0.5,
                            ),
                        ):
                            result = runner.invoke(
                                app,
                                ["scan", "https://example.com", "--safe", "--no-new-window"],
                            )

        self.assertEqual(result.exit_code, 0)
        self.assertFalse(config.headless_enabled)
        self.assertTrue(config.safe_mode)

    def test_json_output_prints_machine_report(self) -> None:
        from cloakscan.cli.app import app

        runner = CliRunner()
        config = load_scan_config("balanced", config_path=None)
        result_item = self._sample_result()

        with patch("cloakscan.cli.app.load_scan_config", return_value=config):
            with patch(
                "cloakscan.cli.app.collect_targets",
                return_value=[TargetSpec(raw="example.com", normalized_url="https://example.com/")],
            ):
                with patch("cloakscan.cli.app.run_scan", MagicMock(return_value="scan-coro")):
                    with patch("cloakscan.cli.app.asyncio.run", return_value=([result_item], 1)):
                        with patch(
                            "cloakscan.cli.app.build_summary",
                            return_value=RunSummary(
                                targets_total=1,
                                clean_count=0,
                                low_count=0,
                                medium_count=1,
                                high_count=0,
                                failures_count=0,
                                runtime_seconds=1.25,
                            ),
                        ):
                            cli_result = runner.invoke(
                                app,
                                ["scan", "https://example.com", "--json", "--no-headless", "--no-new-window"],
                            )

        self.assertEqual(cli_result.exit_code, 1)
        payload = json.loads(cli_result.stdout)
        self.assertEqual(payload["exit_code"], 1)
        self.assertEqual(payload["summary"]["medium_count"], 1)
        self.assertEqual(payload["results"][0]["target"]["raw"], "example.com")
        self.assertNotIn("Run Summary", cli_result.stdout)

    def test_json_out_writes_machine_report_file(self) -> None:
        from cloakscan.cli.app import app

        runner = CliRunner()
        config = load_scan_config("balanced", config_path=None)
        result_item = self._sample_result()
        base_dir = Path("tests") / "_tmp_cli_behavior_json"
        base_dir.mkdir(parents=True, exist_ok=True)
        output_path = base_dir / "report.json"

        with patch("cloakscan.cli.app.load_scan_config", return_value=config):
            with patch(
                "cloakscan.cli.app.collect_targets",
                return_value=[TargetSpec(raw="example.com", normalized_url="https://example.com/")],
            ):
                with patch("cloakscan.cli.app.run_scan", MagicMock(return_value="scan-coro")):
                    with patch("cloakscan.cli.app.asyncio.run", return_value=([result_item], 1)):
                        with patch(
                            "cloakscan.cli.app.build_summary",
                            return_value=RunSummary(
                                targets_total=1,
                                clean_count=0,
                                low_count=0,
                                medium_count=1,
                                high_count=0,
                                failures_count=0,
                                runtime_seconds=1.25,
                            ),
                        ):
                            cli_result = runner.invoke(
                                app,
                                [
                                    "scan",
                                    "https://example.com",
                                    "--json-out",
                                    str(output_path),
                                    "--no-headless",
                                    "--no-new-window",
                                ],
                            )

        self.assertEqual(cli_result.exit_code, 1)
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["exit_code"], 1)
        self.assertEqual(payload["summary"]["medium_count"], 1)
        self.assertEqual(payload["results"][0]["target"]["raw"], "example.com")
        self.assertIn("Run Summary", cli_result.stdout)

    def test_json_out_writes_error_payload_on_invalid_preset(self) -> None:
        from cloakscan.cli.app import app

        runner = CliRunner()
        base_dir = Path("tests") / "_tmp_cli_behavior_json"
        base_dir.mkdir(parents=True, exist_ok=True)
        output_path = base_dir / "error.json"
        cli_result = runner.invoke(
            app,
            ["scan", "https://example.com", "--preset", "invalid", "--json-out", str(output_path)],
        )

        self.assertEqual(cli_result.exit_code, 2)
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["exit_code"], 2)
        self.assertIn("Invalid preset", payload["error"])

    def test_single_file_target_is_treated_as_input_file(self) -> None:
        from cloakscan.cli.app import _coerce_single_file_target

        base_dir = Path("tests") / "_tmp_cli_behavior"
        base_dir.mkdir(parents=True, exist_ok=True)
        input_path = base_dir / "domains.txt"
        input_path.write_text("example.com\nexample.org\n", encoding="utf-8")

        targets, coerced_input = _coerce_single_file_target(["domains.txt"], None, base_dir=base_dir)

        self.assertEqual(targets, [])
        self.assertEqual(coerced_input, input_path)

    def test_single_non_file_target_stays_as_target(self) -> None:
        from cloakscan.cli.app import _coerce_single_file_target

        targets, coerced_input = _coerce_single_file_target(["orf.at"], None)

        self.assertEqual(targets, ["orf.at"])
        self.assertIsNone(coerced_input)


if __name__ == "__main__":
    unittest.main()
