from __future__ import annotations

from pathlib import Path
import ctypes
import os
import platform
import shlex
import shutil
import subprocess
import sys

SPAWNED_SHELL_EXIT_CODE = 91
_STDOUT_HANDLE = -11


class _Coord(ctypes.Structure):
    _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]


class _SmallRect(ctypes.Structure):
    _fields_ = [
        ("Left", ctypes.c_short),
        ("Top", ctypes.c_short),
        ("Right", ctypes.c_short),
        ("Bottom", ctypes.c_short),
    ]


class _ConsoleScreenBufferInfo(ctypes.Structure):
    _fields_ = [
        ("dwSize", _Coord),
        ("dwCursorPosition", _Coord),
        ("wAttributes", ctypes.c_ushort),
        ("srWindow", _SmallRect),
        ("dwMaximumWindowSize", _Coord),
    ]


def set_terminal_title(title: str) -> None:
    if not sys.stdout.isatty():
        return
    if os.name == "nt":
        try:
            ctypes.windll.kernel32.SetConsoleTitleW(str(title))
            return
        except Exception:
            pass
    # ANSI OSC sequence fallback for terminals that support title changes.
    sys.stdout.write(f"\033]0;{title}\007")
    sys.stdout.flush()


def clear_terminal_screen() -> None:
    if os.name == "nt":
        try:
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(_STDOUT_HANDLE)
            if handle:
                info = _ConsoleScreenBufferInfo()
                if kernel32.GetConsoleScreenBufferInfo(handle, ctypes.byref(info)):
                    cells = int(info.dwSize.X) * int(info.dwSize.Y)
                    origin = _Coord(0, 0)
                    written = ctypes.c_ulong()
                    kernel32.FillConsoleOutputCharacterW(
                        handle,
                        ctypes.c_wchar(" "),
                        cells,
                        origin,
                        ctypes.byref(written),
                    )
                    kernel32.FillConsoleOutputAttribute(
                        handle,
                        info.wAttributes,
                        cells,
                        origin,
                        ctypes.byref(written),
                    )
                    kernel32.SetConsoleCursorPosition(handle, origin)
                    return
        except Exception:
            pass

    if sys.stdout.isatty():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()
        return

    os.system("cls" if os.name == "nt" else "clear")


def _is_non_interactive() -> bool:
    if os.environ.get("CI"):
        return True
    if os.environ.get("GITHUB_ACTIONS"):
        return True
    return not sys.stdout.isatty()


def should_attempt_new_window(argv: list[str]) -> bool:
    if "--no-new-window" in argv:
        return False
    if os.environ.get("CLOAKSCAN_CHILD") == "1":
        return False
    if _is_non_interactive():
        return False
    return True


def _append_no_new_window(argv: list[str]) -> list[str]:
    if "--no-new-window" in argv:
        return list(argv)
    return [*argv, "--no-new-window"]


def _powershell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _spawn_windows(script_path: Path, argv: list[str]) -> bool:
    env = dict(os.environ)
    env["CLOAKSCAN_CHILD"] = "1"
    child_argv = [sys.executable, str(script_path), *_append_no_new_window(argv)]
    quoted_parts = " ".join(_powershell_single_quote(part) for part in child_argv)
    script = "; ".join(
        [
            "$host.UI.RawUI.WindowTitle = 'Cloakscan'",
            f"Set-Location -LiteralPath {_powershell_single_quote(str(Path.cwd()))}",
            f"& {quoted_parts}",
            "$cloakscanExit = $LASTEXITCODE",
            f"if ($cloakscanExit -eq {SPAWNED_SHELL_EXIT_CODE}) {{ exit }}",
        ]
    )
    creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0x00000010)
    subprocess.Popen(
        ["powershell.exe", "-NoExit", "-Command", script],
        env=env,
        creationflags=creationflags,
    )  # noqa: S603
    return True


def _escape_applescript_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _spawn_macos(script_path: Path, argv: list[str]) -> bool:
    env = dict(os.environ)
    env["CLOAKSCAN_CHILD"] = "1"
    quoted_cmd = " ".join(
        shlex.quote(part)
        for part in [sys.executable, str(script_path), *_append_no_new_window(argv)]
    )
    command = f"cd {shlex.quote(str(Path.cwd()))}; {quoted_cmd}"
    applescript = f'tell application "Terminal" to do script "{_escape_applescript_string(command)}"'
    subprocess.Popen(["osascript", "-e", applescript], env=env)  # noqa: S603
    return True


def _spawn_linux(script_path: Path, argv: list[str]) -> bool:
    env = dict(os.environ)
    env["CLOAKSCAN_CHILD"] = "1"
    cmd = " ".join(
        shlex.quote(part)
        for part in [sys.executable, str(script_path), *_append_no_new_window(argv)]
    )
    cwd = shlex.quote(str(Path.cwd()))
    full_cmd = f"cd {cwd}; {cmd}"

    candidates = [
        ("x-terminal-emulator", ["x-terminal-emulator", "-e", "bash", "-lc", full_cmd]),
        ("gnome-terminal", ["gnome-terminal", "--", "bash", "-lc", full_cmd]),
        ("konsole", ["konsole", "-e", "bash", "-lc", full_cmd]),
        ("xterm", ["xterm", "-e", "bash", "-lc", full_cmd]),
    ]
    for binary, command in candidates:
        if shutil.which(binary):
            subprocess.Popen(command, env=env)  # noqa: S603
            return True
    return False


def maybe_spawn_new_window(script_path: Path, argv: list[str]) -> bool:
    if not should_attempt_new_window(argv):
        set_terminal_title("Cloakscan")
        return False

    system_name = platform.system().lower()
    spawned = False

    try:
        if system_name.startswith("win"):
            spawned = _spawn_windows(script_path, argv)
        elif system_name == "darwin":
            spawned = _spawn_macos(script_path, argv)
        else:
            spawned = _spawn_linux(script_path, argv)
    except Exception:
        spawned = False

    if not spawned:
        set_terminal_title("Cloakscan")
        return False
    return True
