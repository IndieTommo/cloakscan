from __future__ import annotations

from pathlib import Path
from unittest.mock import patch
import unittest

from cloakscan.runtime.terminal import SPAWNED_SHELL_EXIT_CODE, _spawn_windows


class TerminalRuntimeTests(unittest.TestCase):
    def test_spawn_windows_closes_shell_on_special_exit_code(self) -> None:
        with patch("cloakscan.runtime.terminal.subprocess.Popen") as popen_mock:
            with patch("cloakscan.runtime.terminal.sys.executable", "python"):
                spawned = _spawn_windows(Path("E:/cloakscan/cloakscan.py"), [])

        self.assertTrue(spawned)
        command = popen_mock.call_args.args[0]
        self.assertEqual(command[0], "powershell.exe")
        self.assertIn("-NoExit", command)
        script = command[-1]
        self.assertIn("$cloakscanExit = $LASTEXITCODE", script)
        self.assertIn(f"$cloakscanExit -eq {SPAWNED_SHELL_EXIT_CODE}", script)


if __name__ == "__main__":
    unittest.main()
