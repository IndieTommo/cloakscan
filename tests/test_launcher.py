from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest.mock import MagicMock, patch
import unittest

from cloakscan.runtime import SPAWNED_SHELL_EXIT_CODE


def _load_launcher_module():
    launcher_path = Path(__file__).resolve().parent.parent / "cloakscan.py"
    spec = importlib.util.spec_from_file_location("cloakscan_launcher", launcher_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load cloakscan.py module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LauncherTests(unittest.TestCase):
    def test_strip_internal_flags(self) -> None:
        launcher = _load_launcher_module()
        stripped = launcher._strip_internal_flags(
            ["--no-new-window", "scan", "https://example.com", "--no-new-window"]
        )
        self.assertEqual(stripped, ["scan", "https://example.com"])

    def test_interactive_loop_prints_banner_once_on_startup(self) -> None:
        launcher = _load_launcher_module()
        with patch.object(launcher, "print_banner") as print_banner:
            with patch("builtins.input", side_effect=["exit"]):
                exit_code = launcher._interactive_loop(console=MagicMock())

        self.assertEqual(exit_code, 0)
        self.assertEqual(print_banner.call_count, 1)

    def test_interactive_help_routes_to_scan_help(self) -> None:
        launcher = _load_launcher_module()
        console = MagicMock()
        with patch.object(launcher, "print_banner"):
            with patch.object(launcher, "_run_cli_args") as run_cli_args:
                with patch("builtins.input", side_effect=["help", "exit"]):
                    exit_code = launcher._interactive_loop(console=console)

        self.assertEqual(exit_code, 0)
        run_cli_args.assert_called_once_with(["scan", "--help"])

    def test_interactive_clear_redraws_banner(self) -> None:
        launcher = _load_launcher_module()
        console = MagicMock()
        with patch.object(launcher, "print_banner") as print_banner:
            with patch.object(launcher, "clear_terminal_screen") as clear_terminal_screen:
                with patch.object(launcher, "Console", return_value=MagicMock()):
                    with patch("builtins.input", side_effect=["clear", "exit"]):
                        exit_code = launcher._interactive_loop(console=console)

        self.assertEqual(exit_code, 0)
        clear_terminal_screen.assert_called_once_with()
        self.assertEqual(print_banner.call_count, 2)

    def test_interactive_exit_closes_spawned_shell(self) -> None:
        launcher = _load_launcher_module()
        with patch.dict("os.environ", {"CLOAKSCAN_CHILD": "1"}, clear=False):
            with patch.object(launcher, "print_banner"):
                with patch("builtins.input", side_effect=["exit"]):
                    exit_code = launcher._interactive_loop(console=MagicMock())

        self.assertEqual(exit_code, SPAWNED_SHELL_EXIT_CODE)

    def test_should_print_banner_only_for_scan(self) -> None:
        launcher = _load_launcher_module()
        self.assertTrue(launcher._should_print_banner(["scan", "https://example.com"]))
        self.assertFalse(launcher._should_print_banner(["--help"]))
        self.assertFalse(launcher._should_print_banner([]))


if __name__ == "__main__":
    unittest.main()

