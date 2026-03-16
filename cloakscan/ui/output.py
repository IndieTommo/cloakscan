from __future__ import annotations

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from cloakscan.models import DebugEvent, DebugValue, RunSummary, TargetResult

BANNER_VERSION = "v1.0.1 by Tommo"

BANNER = r"""
          $$\                     $$\                                                    
          $$ |                    $$ |                                                   
 $$$$$$$\ $$ | $$$$$$\   $$$$$$\  $$ |  $$\  $$$$$$$\  $$$$$$$\ $$$$$$\  $$$$$$$\       
$$  _____|$$ |$$  __$$\  \____$$\ $$ | $$  |$$  _____|$$  _____|\____$$\ $$  __$$\      
$$ /      $$ |$$ /  $$ | $$$$$$$ |$$$$$$  / \$$$$$$\  $$ /      $$$$$$$ |$$ |  $$ |     
$$ |      $$ |$$ |  $$ |$$  __$$ |$$  _$$<   \____$$\ $$ |     $$  __$$ |$$ |  $$ |     
\$$$$$$$\ $$ |\$$$$$$  |\$$$$$$$ |$$ | \$$\ $$$$$$$  |\$$$$$$$\$$$$$$$ |$$ |  $$ |     
 \_______|\__| \______/  \_______|\__|  \__|\_______/  \_______|\_______|\__|  \__|      
                                                                                         
                                                                                         
                                                                                         
"""

_RISK_STYLE = {
    "CLEAN": "bold green",
    "LOW": "bold yellow",
    "MEDIUM": "bold yellow",
    "HIGH": "bold red",
}


def print_banner(console: Console) -> None:
    console.print(BANNER.rstrip(), style="cyan")
    console.print(BANNER_VERSION, style="cyan", justify="right")


def create_progress(console: Console) -> Progress:
    return Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    )


def _format_debug_value(value: DebugValue) -> str:
    if value is None:
        return "none"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:.2f}"
    return str(value)


def print_debug_event(console: Console, event: DebugEvent) -> None:
    details = " ".join(
        f"{key}={_format_debug_value(value)}"
        for key, value in event.details.items()
        if value is not None
    )
    prefix = f"[cyan]DEBUG[/cyan] {event.phase} {event.elapsed_seconds:.2f}s"
    if details:
        console.print(f"  {prefix} {details}")
    else:
        console.print(f"  {prefix}")


def _partial_suffix(result: TargetResult) -> str:
    if not result.incomplete:
        return ""

    lowered_warnings = [warning.lower() for warning in result.warnings]
    if any(
        warning.startswith("bot view failed:")
        and (
            "certificate verify failed" in warning
            or "certificate_verify_failed" in warning
            or "unable to get local issuer certificate" in warning
        )
        for warning in lowered_warnings
    ):
        return " (partial evidence: bot TLS failed)"
    if any(warning.startswith("bot view failed:") for warning in lowered_warnings):
        return " (partial evidence: bot view failed)"
    if any(warning.startswith("headless view failed:") for warning in lowered_warnings):
        return " (partial evidence: headless view failed)"
    if any(warning.startswith("browser view failed:") for warning in lowered_warnings):
        return " (partial evidence: browser view failed)"
    return " (partial evidence)"


def print_result(console: Console, result: TargetResult, explain: bool, debug: bool) -> None:
    if result.failed:
        console.print(
            f"[bold red]FAIL[/bold red] {result.target.raw} - {result.error or 'scan failed'}"
        )
    elif result.incomplete and result.risk == "CLEAN":
        console.print(
            f"[bold yellow]PARTIAL[/bold yellow] {result.target.raw} - {result.reason}"
        )
    else:
        risk_style = _RISK_STYLE[result.risk]
        partial_suffix = _partial_suffix(result)
        console.print(
            f"[{risk_style}]{result.risk}[/{risk_style}] "
            f"{result.target.raw} - {result.reason}{partial_suffix}"
        )

    if debug and result.debug_events:
        for event in result.debug_events:
            print_debug_event(console, event)

    if result.incomplete and result.warnings:
        for warning in result.warnings:
            console.print(f"  [yellow]WARNING[/yellow] {warning}")

    if explain and result.signals:
        for signal in result.signals:
            metric_parts = [f"{key}={value}" for key, value in signal.metrics.items()]
            metric_text = ", ".join(metric_parts)
            if metric_text:
                console.print(f"  - {signal.message} ({metric_text})")
            else:
                console.print(f"  - {signal.message}")
            for detail in signal.details:
                console.print(f"    {detail}")


def print_summary(console: Console, summary: RunSummary) -> None:
    console.print("")
    console.print("[bold]Run Summary[/bold]")
    console.print(f"Targets scanned: {summary.targets_total}")
    console.print(f"CLEAN: {summary.clean_count}")
    console.print(f"LOW: {summary.low_count}")
    console.print(f"MEDIUM: {summary.medium_count}")
    console.print(f"HIGH: {summary.high_count}")
    console.print(f"Partial scans: {summary.partial_count}")
    console.print(f"Failures: {summary.failures_count}")
    console.print(f"Runtime: {summary.runtime_seconds:.2f}s")
