from __future__ import annotations

from pathlib import Path
import os
import shlex
import sys

from rich.console import Console
from cloakscan.cli.app import app
from cloakscan.runtime import (
    SPAWNED_SHELL_EXIT_CODE,
    clear_terminal_screen,
    maybe_spawn_new_window,
    set_terminal_title,
)
from cloakscan.ui import print_banner
from typer.main import get_command


def _strip_internal_flags(argv: list[str]) -> list[str]:
    return [arg for arg in argv if arg != "--no-new-window"]


def _run_cli_args(argv: list[str]) -> int:
    command = get_command(app)
    try:
        command.main(
            args=argv,
            prog_name="cloakscan.py",
            standalone_mode=False,
        )
        return 0
    except SystemExit as exc:
        code = exc.code
        if isinstance(code, int):
            return code
        return 1
    except Exception as exc:
        exit_code = getattr(exc, "exit_code", None)
        if isinstance(exit_code, int):
            return exit_code
        raise


def _clear_interactive_screen(console: Console) -> None:
    del console
    clear_terminal_screen()
    print_banner(Console())


def _interactive_exit_code() -> int:
    if os.environ.get("CLOAKSCAN_CHILD") == "1":
        return SPAWNED_SHELL_EXIT_CODE
    return 0


def _interactive_loop(console: Console) -> int:
    print_banner(console)
    while True:
        try:
            line = input("cloakscan> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("")
            return 0

        if not line:
            continue

        lowered = line.lower()
        if lowered in {"exit", "quit"}:
            return _interactive_exit_code()
        if lowered in {"clear", "cls"}:
            _clear_interactive_screen(console)
            continue
        if lowered in {"help", "?"}:
            _run_cli_args(["scan", "--help"])
            continue

        try:
            argv = shlex.split(line, posix=True)
        except ValueError as exc:
            print(f"Input parse error: {exc}")
            continue

        if not argv:
            continue

        if "--no-new-window" not in argv:
            argv.append("--no-new-window")
        try:
            _run_cli_args(argv)
        except Exception as exc:
            print(f"Command failed: {exc}")


def _should_print_banner(argv: list[str]) -> bool:
    return bool(argv) and argv[0] == "scan"


def main() -> int:
    argv = sys.argv[1:]
    script_path = Path(__file__).resolve()

    if maybe_spawn_new_window(script_path=script_path, argv=argv):
        return 0

    set_terminal_title("Cloakscan")
    business_args = _strip_internal_flags(argv)
    console = Console()
    if not business_args:
        return _interactive_loop(console)
    if _should_print_banner(business_args):
        print_banner(console)
    return _run_cli_args(business_args)


if __name__ == "__main__":
    raise SystemExit(main())
