from __future__ import annotations

import json

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

BANNER_VERSION = "v1.2.0 by Tommo"

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


def create_loading_indicator(console: Console) -> Progress:
    return Progress(
        TextColumn("[bold blue]{task.description}"),
        console=console,
        transient=True,
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


def _serialize_view(view: object) -> dict[str, object]:
    return {
        "profile": view.profile,
        "requested_url": view.requested_url,
        "final_url": view.final_url,
        "status_code": view.status_code,
        "redirect_chain": list(view.redirect_chain),
        "error": view.error,
    }


def _serialize_signal(signal: object) -> dict[str, object]:
    return {
        "code": signal.code,
        "message": signal.message,
        "points": signal.points,
        "metrics": dict(signal.metrics),
        "details": list(signal.details),
    }


def _serialize_debug_event(event: DebugEvent) -> dict[str, object]:
    return {
        "phase": event.phase,
        "elapsed_seconds": round(event.elapsed_seconds, 3),
        "details": dict(event.details),
    }


def _serialize_result(result: TargetResult) -> dict[str, object]:
    return {
        "target": {
            "raw": result.target.raw,
            "normalized_url": result.target.normalized_url,
            "fallback_url": result.target.fallback_url,
            "used_fallback": result.target.used_fallback,
        },
        "risk": result.risk,
        "score": result.score,
        "reason": result.reason,
        "failed": result.failed,
        "incomplete": result.incomplete,
        "warnings": list(result.warnings),
        "error": result.error,
        "runtime_seconds": round(result.runtime_seconds, 3),
        "signals": [_serialize_signal(signal) for signal in result.signals],
        "debug_events": [_serialize_debug_event(event) for event in result.debug_events],
        "views": {
            profile: _serialize_view(view)
            for profile, view in result.views.items()
        },
    }


def render_json_report(results: list[TargetResult], summary: RunSummary, exit_code: int) -> str:
    payload = {
        "exit_code": exit_code,
        "summary": {
            "targets_total": summary.targets_total,
            "clean_count": summary.clean_count,
            "low_count": summary.low_count,
            "medium_count": summary.medium_count,
            "high_count": summary.high_count,
            "partial_count": summary.partial_count,
            "failures_count": summary.failures_count,
            "runtime_seconds": round(summary.runtime_seconds, 3),
        },
        "results": [_serialize_result(result) for result in results],
    }
    return json.dumps(payload, indent=2, ensure_ascii=True)
