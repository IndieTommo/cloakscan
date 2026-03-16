from __future__ import annotations

import asyncio
from pathlib import Path
import time

from rich.console import Console
import typer

from cloakscan.config import ConfigError, available_presets, load_scan_config
from cloakscan.input import collect_targets
from cloakscan.scanner import run_scan
from cloakscan.score import build_summary
from cloakscan.ui import print_summary

_TEXT_INPUT_SUFFIXES = {".txt", ".list", ".lst", ".csv"}

app = typer.Typer(
    name="cloakscan",
    help="Terminal-first scanner for cloaked SEO spam and related compromises.",
    add_completion=False,
    no_args_is_help=True,
)


@app.callback()
def root_callback(
    no_new_window: bool = typer.Option(
        False,
        "--no-new-window",
        hidden=True,
        help="Internal launcher flag; scan command also accepts this option.",
    ),
) -> None:
    """Root CLI callback to enforce subcommand-style invocation."""
    del no_new_window
    return


def _coerce_single_file_target(
    targets: list[str],
    input_file: Path | None,
    base_dir: Path | None = None,
) -> tuple[list[str], Path | None]:
    if input_file is not None or len(targets) != 1:
        return targets, input_file

    candidate_text = targets[0].strip()
    if not candidate_text:
        return targets, input_file

    base_path = base_dir or Path.cwd()
    candidate = Path(candidate_text)
    if not candidate.is_absolute():
        candidate = base_path / candidate

    if not candidate.is_file():
        return targets, input_file

    suffix = candidate.suffix.lower()
    looks_like_path = any(sep in candidate_text for sep in ("/", "\\"))
    if suffix not in _TEXT_INPUT_SUFFIXES and not looks_like_path:
        return targets, input_file

    return [], candidate


@app.command("scan")
def scan_command(
    targets: list[str] = typer.Argument(
        default_factory=list,
        help="Targets to scan (full URLs or domains).",
    ),
    input_file: Path | None = typer.Option(
        None,
        "--input",
        help="Path to a text file with targets.",
    ),
    preset: str = typer.Option(
        "balanced",
        "--preset",
        help="Preset sensitivity profile.",
        case_sensitive=False,
    ),
    config_path: Path | None = typer.Option(
        None,
        "--config",
        help="Optional TOML config override file.",
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Print measured signal details.",
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        help="Print phase timings and key scan metadata.",
    ),
    tls_debug: bool = typer.Option(
        False,
        "--tls-debug",
        help="Retry TLS-failed bot fetches without certificate verification to reveal redirect/certificate paths for debugging.",
    ),
    cache_bust: bool = typer.Option(
        True,
        "--cache-bust/--no-cache-bust",
        help="Enable per-profile cache-busting tokens to reduce false negatives on cached sites.",
    ),
    safe_mode: bool = typer.Option(
        False,
        "--safe",
        help="Safer mode: disables headless rendering and keeps strict network safeguards.",
    ),
    no_headless: bool = typer.Option(
        False,
        "--no-headless",
        help="Disable headless-rendered view.",
    ),
    no_new_window: bool = typer.Option(
        False,
        "--no-new-window",
        help="Run in current terminal; do not spawn a new one.",
    ),
) -> None:
    del no_new_window  # Handled by outer script launcher; retained for CLI parity.

    console = Console()

    normalized_preset = preset.lower().strip()
    if normalized_preset not in available_presets():
        console.print(
            f"[bold red]Invalid preset[/bold red]: {preset}. "
            f"Valid presets: {', '.join(available_presets())}"
        )
        raise typer.Exit(code=2)

    try:
        config = load_scan_config(preset=normalized_preset, config_path=config_path)
    except ConfigError as exc:
        console.print(f"[bold red]Config error[/bold red]: {exc}")
        raise typer.Exit(code=2)

    config.safe_mode = safe_mode
    if no_headless:
        config.headless_enabled = False
    if safe_mode:
        config.headless_enabled = False

    targets, input_file = _coerce_single_file_target(targets, input_file)

    try:
        target_specs = collect_targets(targets, input_path=input_file)
    except RuntimeError as exc:
        console.print(f"[bold red]Input error[/bold red]: {exc}")
        raise typer.Exit(code=2)

    if not target_specs:
        console.print("[bold red]No valid targets provided.[/bold red]")
        raise typer.Exit(code=2)

    started_at = time.perf_counter()
    try:
        results, exit_code = asyncio.run(
            run_scan(
                targets=target_specs,
                config=config,
                explain=explain,
                debug=debug,
                tls_debug=tls_debug,
                console=console,
                cache_bust=cache_bust,
            )
        )
    except RuntimeError as exc:
        console.print(f"[bold red]Runtime error[/bold red]: {exc}")
        raise typer.Exit(code=2)
    except KeyboardInterrupt:
        console.print("[bold red]Interrupted[/bold red]")
        raise typer.Exit(code=2)

    runtime_seconds = time.perf_counter() - started_at
    summary = build_summary(results=results, runtime_seconds=runtime_seconds)
    print_summary(console, summary)
    raise typer.Exit(code=exit_code)

