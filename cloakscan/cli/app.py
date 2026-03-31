from __future__ import annotations

import asyncio
import json
from pathlib import Path
import time

from rich.console import Console
import typer

from cloakscan.config import ConfigError, available_presets, load_scan_config
from cloakscan.input import collect_targets
from cloakscan.scanner import run_scan
from cloakscan.score import build_summary
from cloakscan.ui import print_summary, render_json_report

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


def _render_json_payload(payload: dict[str, object]) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=True)


def _write_json_payload(output_path: Path, payload: dict[str, object]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_render_json_payload(payload), encoding="utf-8")


def _emit_json_payload(payload: dict[str, object]) -> None:
    typer.echo(_render_json_payload(payload))


def _deliver_json_payload(
    payload: dict[str, object],
    *,
    emit_stdout: bool,
    output_path: Path | None,
) -> None:
    if output_path is not None:
        _write_json_payload(output_path, payload)
    if emit_stdout:
        _emit_json_payload(payload)


def _json_error_payload(message: str, exit_code: int) -> dict[str, object]:
    return {
        "exit_code": exit_code,
        "error": message,
    }


def _is_option_like_output_path(path: Path | None) -> bool:
    if path is None:
        return False
    return str(path).lstrip().startswith("-")


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
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit a machine-readable JSON report instead of terminal output.",
    ),
    json_output_path: Path | None = typer.Option(
        None,
        "--json-out",
        help="Write a machine-readable JSON report to the given file path.",
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

    if _is_option_like_output_path(json_output_path):
        message = "Path Missing"
        if json_output:
            _emit_json_payload(_json_error_payload(message, exit_code=2))
        else:
            console.print(f"[bold red]Input error[/bold red]: {message}")
        raise typer.Exit(code=2)

    normalized_preset = preset.lower().strip()
    if normalized_preset not in available_presets():
        message = (
            f"Invalid preset: {preset}. "
            f"Valid presets: {', '.join(available_presets())}"
        )
        if json_output or json_output_path is not None:
            try:
                _deliver_json_payload(
                    _json_error_payload(message, exit_code=2),
                    emit_stdout=json_output,
                    output_path=json_output_path,
                )
            except OSError as exc:
                console.print(f"[bold red]JSON output error[/bold red]: {exc}")
        if not json_output:
            console.print(
                f"[bold red]Invalid preset[/bold red]: {preset}. "
                f"Valid presets: {', '.join(available_presets())}"
            )
        raise typer.Exit(code=2)

    try:
        config = load_scan_config(preset=normalized_preset, config_path=config_path)
    except ConfigError as exc:
        if json_output or json_output_path is not None:
            try:
                _deliver_json_payload(
                    _json_error_payload(f"Config error: {exc}", exit_code=2),
                    emit_stdout=json_output,
                    output_path=json_output_path,
                )
            except OSError as write_exc:
                console.print(f"[bold red]JSON output error[/bold red]: {write_exc}")
        if not json_output:
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
        if json_output or json_output_path is not None:
            try:
                _deliver_json_payload(
                    _json_error_payload(f"Input error: {exc}", exit_code=2),
                    emit_stdout=json_output,
                    output_path=json_output_path,
                )
            except OSError as write_exc:
                console.print(f"[bold red]JSON output error[/bold red]: {write_exc}")
        if not json_output:
            console.print(f"[bold red]Input error[/bold red]: {exc}")
        raise typer.Exit(code=2)

    if not target_specs:
        if json_output or json_output_path is not None:
            try:
                _deliver_json_payload(
                    _json_error_payload("No valid targets provided.", exit_code=2),
                    emit_stdout=json_output,
                    output_path=json_output_path,
                )
            except OSError as write_exc:
                console.print(f"[bold red]JSON output error[/bold red]: {write_exc}")
        if not json_output:
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
                emit_output=not json_output,
            )
        )
    except RuntimeError as exc:
        if json_output or json_output_path is not None:
            try:
                _deliver_json_payload(
                    _json_error_payload(f"Runtime error: {exc}", exit_code=2),
                    emit_stdout=json_output,
                    output_path=json_output_path,
                )
            except OSError as write_exc:
                console.print(f"[bold red]JSON output error[/bold red]: {write_exc}")
        if not json_output:
            console.print(f"[bold red]Runtime error[/bold red]: {exc}")
        raise typer.Exit(code=2)
    except KeyboardInterrupt:
        if json_output or json_output_path is not None:
            try:
                _deliver_json_payload(
                    _json_error_payload("Interrupted", exit_code=2),
                    emit_stdout=json_output,
                    output_path=json_output_path,
                )
            except OSError as write_exc:
                console.print(f"[bold red]JSON output error[/bold red]: {write_exc}")
        if not json_output:
            console.print("[bold red]Interrupted[/bold red]")
        raise typer.Exit(code=2)

    runtime_seconds = time.perf_counter() - started_at
    summary = build_summary(results=results, runtime_seconds=runtime_seconds)
    if json_output or json_output_path is not None:
        json_payload = json.loads(render_json_report(results, summary, exit_code))
        try:
            _deliver_json_payload(
                json_payload,
                emit_stdout=json_output,
                output_path=json_output_path,
            )
        except OSError as exc:
            console.print(f"[bold red]JSON output error[/bold red]: {exc}")
            raise typer.Exit(code=2)
    if not json_output:
        print_summary(console, summary)
    raise typer.Exit(code=exit_code)
