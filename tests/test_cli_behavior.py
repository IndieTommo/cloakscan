from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch
import unittest

from typer.testing import CliRunner

from cloakscan.config import load_scan_config
from cloakscan.models import RunSummary, TargetSpec


class CliBehaviorTests(unittest.TestCase):
    def test_cli_has_root_callback(self) -> None:
        from cloakscan.cli.app import app

        # With a root callback present, Click/Typer treats this as a real
        # command group and requires explicit subcommands like "scan".
        self.assertIsNotNone(app.registered_callback)

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
