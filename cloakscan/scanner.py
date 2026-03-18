from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack, nullcontext
import secrets
import time
from urllib.parse import urlsplit

import httpx
from rich.console import Console

from cloakscan.detect import detect_signals
from cloakscan.fetch import fetch_http_view
from cloakscan.models import DebugEvent, ScanConfig, TargetResult, TargetSpec, ViewSnapshot
from cloakscan.render import HeadlessRenderer
from cloakscan.score import build_summary, classify_risk, compute_exit_code, summarize_reason
from cloakscan.ui import create_loading_indicator, create_progress, print_debug_event, print_result

_TLS_ERROR_MARKERS = (
    "certificate_verify_failed",
    "certificate verify failed",
    "unable to get local issuer certificate",
)


def _failed_target_result(
    target: TargetSpec,
    views: dict[str, ViewSnapshot],
    runtime_seconds: float,
    error: str,
    debug_events: list[DebugEvent] | None = None,
) -> TargetResult:
    return TargetResult(
        target=target,
        risk="CLEAN",
        score=0,
        reason="Target scan failed",
        signals=[],
        debug_events=debug_events or [],
        views=views,
        failed=True,
        incomplete=False,
        warnings=[],
        error=error,
        runtime_seconds=runtime_seconds,
    )


def _append_debug_event(
    debug_events: list[DebugEvent],
    phase: str,
    elapsed_seconds: float,
    **details: str | int | float | bool | None,
) -> None:
    debug_events.append(
        DebugEvent(
            phase=phase,
            elapsed_seconds=elapsed_seconds,
            details=details,
        )
    )


def _format_redirect_chain(urls: list[str]) -> str:
    if not urls:
        return "(none)"
    if len(urls) <= 4:
        return " -> ".join(urls)
    return " -> ".join([*urls[:2], "...", urls[-1]])


def _normalized_target(url: str) -> tuple[str, str, int | None, str, str]:
    parsed = urlsplit(url)
    normalized_path = parsed.path or "/"
    if normalized_path != "/":
        normalized_path = normalized_path.rstrip("/") or "/"
    return (
        parsed.scheme.lower(),
        (parsed.hostname or "").lower(),
        parsed.port,
        normalized_path,
        parsed.query,
    )


def _has_redirect_path(view: ViewSnapshot | None) -> bool:
    if view is None:
        return False
    if len(view.redirect_chain) > 1:
        return True
    return _normalized_target(view.final_url) != _normalized_target(view.requested_url)


def _is_tls_error(error: str | None) -> bool:
    if not error:
        return False
    lowered = error.lower()
    return any(marker in lowered for marker in _TLS_ERROR_MARKERS)


def _view_debug_details(
    view: ViewSnapshot,
    *,
    include_redirect_chain: bool = False,
) -> dict[str, str | int | float | bool | None]:
    details: dict[str, str | int | float | bool | None] = {
        "requested_url": view.requested_url,
        "final_url": view.final_url,
        "status": view.status_code,
        "error": view.error,
    }
    if include_redirect_chain or len(view.redirect_chain) > 1:
        details["redirect_hops"] = max(len(view.redirect_chain) - 1, 0)
        details["redirect_chain"] = _format_redirect_chain(view.redirect_chain)
    return details


def _discard_result_payloads(result: TargetResult) -> TargetResult:
    # Drop raw page bodies after processing to keep batch memory bounded.
    for view in result.views.values():
        view.html = ""
    return result


def _tls_debug_warnings(
    bot_view: ViewSnapshot | None,
    bot_tls_debug_view: ViewSnapshot | None,
    *,
    tls_debug_requested: bool,
) -> list[str]:
    if bot_view is None or not _is_tls_error(bot_view.error):
        return []

    warnings: list[str] = []
    if not tls_debug_requested:
        warnings.append("possible bot-only redirect or certificate issue; rerun with --tls-debug")
        return warnings

    if bot_tls_debug_view is None:
        warnings.append("tls-debug could not collect additional redirect/certificate details")
        return warnings

    warnings.append(f"bot tls-debug chain: {_format_redirect_chain(bot_tls_debug_view.redirect_chain)}")
    warnings.append(f"bot tls-debug final URL: {bot_tls_debug_view.final_url}")
    if bot_tls_debug_view.error:
        warnings.append(f"bot tls-debug result: {bot_tls_debug_view.error}")
    elif bot_tls_debug_view.status_code is not None:
        warnings.append(f"bot tls-debug status: {bot_tls_debug_view.status_code}")
    return warnings


def _incomplete_view_warnings(
    views: dict[str, ViewSnapshot],
    *,
    headless_expected: bool,
    tls_debug_requested: bool,
    bot_tls_debug_view: ViewSnapshot | None,
) -> list[str]:
    expected_profiles = ["browser", "bot"]
    if headless_expected:
        expected_profiles.append("headless")

    warnings: list[str] = []
    for profile in expected_profiles:
        snapshot = views.get(profile)
        if snapshot is None:
            warnings.append(f"{profile} view missing")
        elif snapshot.error:
            warnings.append(f"{profile} view failed: {snapshot.error}")

    warnings.extend(
        _tls_debug_warnings(
            views.get("bot"),
            bot_tls_debug_view,
            tls_debug_requested=tls_debug_requested,
        )
    )
    return warnings


def _partial_reason(
    views: dict[str, ViewSnapshot],
    *,
    tls_debug_requested: bool,
    bot_tls_debug_view: ViewSnapshot | None,
) -> str:
    bot_view = views.get("bot")
    if bot_view is not None and _is_tls_error(bot_view.error):
        if tls_debug_requested and bot_tls_debug_view is not None:
            if _has_redirect_path(bot_tls_debug_view):
                return "Bot TLS verification failed after redirect; inspect TLS debug details below"
            return "Bot TLS verification failed on the requested URL; inspect TLS debug details below"
        return "Bot TLS verification failed; possible bot-only redirect or certificate issue. Rerun with --tls-debug"
    return "Incomplete scan; no major cloaking/spam indicators from available views"


def _cache_bust_token(run_id: str | None, profile: str) -> str | None:
    if run_id is None:
        return None
    return f"{run_id}-{profile}"


async def _animate_loading_indicator(progress, task_id: int, stop_event: asyncio.Event) -> None:
    frames = ("Loading", "Loading.", "Loading..", "Loading...")
    index = 0
    progress.update(task_id, description=frames[index])
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=0.35)
        except TimeoutError:
            index = (index + 1) % len(frames)
            progress.update(task_id, description=frames[index])


async def _run_bot_tls_debug_fetch(
    *,
    target: TargetSpec,
    config: ScanConfig,
    tls_debug_client: httpx.AsyncClient | None,
    http_semaphore: asyncio.Semaphore,
    bot_start_url: str,
    cache_bust_run_id: str | None,
) -> ViewSnapshot | None:
    del target
    if tls_debug_client is None:
        return None

    async with http_semaphore:
        return await fetch_http_view(
            client=tls_debug_client,
            start_url=bot_start_url,
            profile="bot_tls_debug",
            user_agent=config.user_agents.bot,
            timeout_seconds=config.timeouts.http_seconds,
            max_redirects=config.max_redirects,
            retries=config.retries,
            allow_unsafe=False,
            cache_bust_token=_cache_bust_token(cache_bust_run_id, "bot-tls-debug"),
        )


async def _scan_target(
    target: TargetSpec,
    config: ScanConfig,
    browser_client: httpx.AsyncClient,
    bot_client: httpx.AsyncClient,
    tls_debug_client: httpx.AsyncClient | None,
    renderer: HeadlessRenderer | None,
    http_semaphore: asyncio.Semaphore,
    headless_semaphore: asyncio.Semaphore,
    debug: bool,
    tls_debug: bool,
    cache_bust_run_id: str | None = None,
) -> TargetResult:
    start = time.perf_counter()
    views: dict[str, ViewSnapshot] = {}
    debug_events: list[DebugEvent] = []
    bot_tls_debug_view: ViewSnapshot | None = None

    if debug:
        _append_debug_event(
            debug_events,
            "config",
            0.0,
            preset=config.preset,
            headless_enabled=config.headless_enabled,
            safe_mode=config.safe_mode,
            cache_bust=cache_bust_run_id is not None,
            tls_debug=tls_debug,
        )
        _append_debug_event(
            debug_events,
            "target",
            0.0,
            normalized_url=target.normalized_url,
            fallback_url=target.fallback_url,
        )

    browser_phase_started_at = time.perf_counter()
    async with http_semaphore:
        browser_view = await fetch_http_view(
            client=browser_client,
            start_url=target.normalized_url,
            profile="browser",
            user_agent=config.user_agents.browser,
            timeout_seconds=config.timeouts.http_seconds,
            max_redirects=config.max_redirects,
            retries=config.retries,
            allow_unsafe=False,
            cache_bust_token=_cache_bust_token(cache_bust_run_id, "browser"),
        )
    if debug:
        _append_debug_event(
            debug_events,
            "browser_http",
            time.perf_counter() - browser_phase_started_at,
            **_view_debug_details(browser_view),
        )

    if browser_view.error and target.fallback_url:
        fallback_phase_started_at = time.perf_counter()
        async with http_semaphore:
            fallback_view = await fetch_http_view(
                client=browser_client,
                start_url=target.fallback_url,
                profile="browser",
                user_agent=config.user_agents.browser,
                timeout_seconds=config.timeouts.http_seconds,
                max_redirects=config.max_redirects,
                retries=config.retries,
                allow_unsafe=False,
                cache_bust_token=_cache_bust_token(cache_bust_run_id, "browser"),
            )
        if debug:
            _append_debug_event(
                debug_events,
                "browser_fallback",
                time.perf_counter() - fallback_phase_started_at,
                **_view_debug_details(fallback_view),
            )
        if not fallback_view.error:
            target.used_fallback = True
            browser_view = fallback_view
    views["browser"] = browser_view

    if debug:
        _append_debug_event(
            debug_events,
            "target_resolution",
            0.0,
            used_fallback=target.used_fallback,
            scan_url=browser_view.requested_url,
        )

    bot_start_url = browser_view.requested_url
    bot_phase_started_at = time.perf_counter()
    async with http_semaphore:
        bot_view = await fetch_http_view(
            client=bot_client,
            start_url=bot_start_url,
            profile="bot",
            user_agent=config.user_agents.bot,
            timeout_seconds=config.timeouts.http_seconds,
            max_redirects=config.max_redirects,
            retries=config.retries,
            allow_unsafe=False,
            cache_bust_token=_cache_bust_token(cache_bust_run_id, "bot"),
        )
    views["bot"] = bot_view
    if debug:
        _append_debug_event(
            debug_events,
            "bot_http",
            time.perf_counter() - bot_phase_started_at,
            **_view_debug_details(bot_view),
        )

    if tls_debug and _is_tls_error(bot_view.error):
        tls_debug_phase_started_at = time.perf_counter()
        bot_tls_debug_view = await _run_bot_tls_debug_fetch(
            target=target,
            config=config,
            tls_debug_client=tls_debug_client,
            http_semaphore=http_semaphore,
            bot_start_url=bot_start_url,
            cache_bust_run_id=cache_bust_run_id,
        )
        if debug and bot_tls_debug_view is not None:
            _append_debug_event(
                debug_events,
                "bot_tls_debug",
                time.perf_counter() - tls_debug_phase_started_at,
                insecure_verify=True,
                **_view_debug_details(bot_tls_debug_view, include_redirect_chain=True),
            )

    if config.headless_enabled and renderer is not None:
        headless_phase_started_at = time.perf_counter()
        async with headless_semaphore:
            headless_view = await renderer.render(
                start_url=bot_start_url,
                timeout_seconds=config.timeouts.headless_seconds,
                user_agent=config.user_agents.headless,
                allow_unsafe=False,
                cache_bust_token=_cache_bust_token(cache_bust_run_id, "headless"),
            )
        views["headless"] = headless_view
        if debug:
            _append_debug_event(
                debug_events,
                "headless_render",
                time.perf_counter() - headless_phase_started_at,
                **_view_debug_details(headless_view),
            )
    elif debug:
        _append_debug_event(
            debug_events,
            "headless_render",
            0.0,
            skipped=True,
        )

    all_failed = all(snapshot.error for snapshot in views.values())
    elapsed = time.perf_counter() - start
    if all_failed:
        if debug:
            _append_debug_event(
                debug_events,
                "total",
                elapsed,
                failed=True,
            )
        joined_error = "; ".join(
            f"{name}: {snapshot.error}" for name, snapshot in views.items() if snapshot.error
        )
        return _failed_target_result(
            target=target,
            views=views,
            runtime_seconds=elapsed,
            error=joined_error,
            debug_events=debug_events,
        )

    detect_phase_started_at = time.perf_counter()
    signals = detect_signals(target=target, views=views, config=config)
    risk, score = classify_risk(signals)
    reason = summarize_reason(signals)
    detect_elapsed = time.perf_counter() - detect_phase_started_at
    warnings = _incomplete_view_warnings(
        views,
        headless_expected=config.headless_enabled and renderer is not None,
        tls_debug_requested=tls_debug,
        bot_tls_debug_view=bot_tls_debug_view,
    )
    incomplete = bool(warnings)
    if incomplete and risk == "CLEAN":
        reason = _partial_reason(
            views,
            tls_debug_requested=tls_debug,
            bot_tls_debug_view=bot_tls_debug_view,
        )
    total_elapsed = time.perf_counter() - start
    if debug:
        _append_debug_event(
            debug_events,
            "detect_score",
            detect_elapsed,
            signal_count=len(signals),
            risk=risk,
            score=score,
            incomplete=incomplete,
        )
        _append_debug_event(
            debug_events,
            "total",
            total_elapsed,
            failed=False,
            incomplete=incomplete,
        )
    return TargetResult(
        target=target,
        risk=risk,
        score=score,
        reason=reason,
        signals=signals,
        debug_events=debug_events,
        views=views,
        failed=False,
        incomplete=incomplete,
        warnings=warnings,
        error=None,
        runtime_seconds=total_elapsed,
    )


async def _scan_target_with_timeout(
    target: TargetSpec,
    config: ScanConfig,
    browser_client: httpx.AsyncClient,
    bot_client: httpx.AsyncClient,
    tls_debug_client: httpx.AsyncClient | None,
    renderer: HeadlessRenderer | None,
    http_semaphore: asyncio.Semaphore,
    headless_semaphore: asyncio.Semaphore,
    debug: bool,
    tls_debug: bool,
    cache_bust_run_id: str | None = None,
) -> TargetResult:
    try:
        return await asyncio.wait_for(
            _scan_target(
                target=target,
                config=config,
                browser_client=browser_client,
                bot_client=bot_client,
                tls_debug_client=tls_debug_client,
                renderer=renderer,
                http_semaphore=http_semaphore,
                headless_semaphore=headless_semaphore,
                debug=debug,
                tls_debug=tls_debug,
                cache_bust_run_id=cache_bust_run_id,
            ),
            timeout=config.timeouts.total_target_seconds,
        )
    except TimeoutError:
        debug_events: list[DebugEvent] = []
        if debug:
            _append_debug_event(
                debug_events,
                "target",
                0.0,
                normalized_url=target.normalized_url,
                fallback_url=target.fallback_url,
            )
            _append_debug_event(
                debug_events,
                "timeout",
                config.timeouts.total_target_seconds,
                timed_out=True,
            )
        return _failed_target_result(
            target=target,
            views={},
            runtime_seconds=config.timeouts.total_target_seconds,
            error=f"Target timed out after {config.timeouts.total_target_seconds:.1f}s",
            debug_events=debug_events,
        )


async def run_scan(
    targets: list[TargetSpec],
    config: ScanConfig,
    explain: bool,
    debug: bool,
    tls_debug: bool,
    console: Console,
    cache_bust: bool = True,
) -> tuple[list[TargetResult], int]:
    started_at = time.perf_counter()
    results: list[TargetResult] = []
    http_semaphore = asyncio.Semaphore(config.concurrency.http_workers)
    headless_semaphore = asyncio.Semaphore(config.concurrency.headless_workers)
    show_progress = len(targets) > 1
    progress = create_progress(console) if show_progress else None
    progress_context = progress if progress is not None else nullcontext()
    cache_bust_run_id = secrets.token_hex(4) if cache_bust else None

    with progress_context:
        output_console = progress.console if progress is not None else console
        task_id = None
        if progress is not None:
            task_id = progress.add_task("Preparing scan", total=len(targets))

        setup_started_at = time.perf_counter()
        async with AsyncExitStack() as stack:
            browser_client = await stack.enter_async_context(
                httpx.AsyncClient(
                    verify=True,
                    follow_redirects=False,
                    timeout=httpx.Timeout(config.timeouts.http_seconds),
                )
            )
            bot_client = await stack.enter_async_context(
                httpx.AsyncClient(
                    verify=True,
                    follow_redirects=False,
                    timeout=httpx.Timeout(config.timeouts.http_seconds),
                )
            )
            tls_debug_client: httpx.AsyncClient | None = None
            if tls_debug:
                tls_debug_client = await stack.enter_async_context(
                    httpx.AsyncClient(
                        verify=False,
                        follow_redirects=False,
                        timeout=httpx.Timeout(config.timeouts.http_seconds),
                    )
                )

            renderer: HeadlessRenderer | None = None
            if config.headless_enabled:
                renderer = HeadlessRenderer()
                try:
                    await renderer.start()
                except Exception as exc:
                    raise RuntimeError(
                        f"Headless startup failed: {exc}. "
                        "Install Playwright browser binaries, or run with --no-headless."
                    ) from exc
                await stack.enter_async_context(_RendererContext(renderer))

            if debug:
                print_debug_event(
                    output_console,
                    DebugEvent(
                        phase="run_setup",
                        elapsed_seconds=time.perf_counter() - setup_started_at,
                        details={
                            "preset": config.preset,
                            "targets": len(targets),
                            "headless_enabled": config.headless_enabled,
                            "safe_mode": config.safe_mode,
                            "cache_bust": cache_bust,
                            "tls_debug": tls_debug,
                        },
                    ),
                )

            futures = [
                asyncio.create_task(
                    _scan_target_with_timeout(
                        target=target,
                        config=config,
                        browser_client=browser_client,
                        bot_client=bot_client,
                        tls_debug_client=tls_debug_client,
                        renderer=renderer,
                        http_semaphore=http_semaphore,
                        headless_semaphore=headless_semaphore,
                        debug=debug,
                        tls_debug=tls_debug,
                        cache_bust_run_id=cache_bust_run_id,
                    )
                )
                for target in targets
            ]

            if progress is not None and task_id is not None:
                progress.update(task_id, description="Scanning targets")
                for future in asyncio.as_completed(futures):
                    result = await future
                    progress.update(task_id, advance=1)
                    print_result(output_console, result, explain=explain, debug=debug)
                    results.append(_discard_result_payloads(result))
            else:
                loading_indicator = create_loading_indicator(console)
                stop_event = asyncio.Event()
                with loading_indicator:
                    loading_task_id = loading_indicator.add_task("Loading", total=None)
                    animation_task = asyncio.create_task(
                        _animate_loading_indicator(loading_indicator, loading_task_id, stop_event)
                    )
                    try:
                        result = await futures[0]
                    finally:
                        stop_event.set()
                        await animation_task
                print_result(output_console, result, explain=explain, debug=debug)
                results.append(_discard_result_payloads(result))

    runtime_seconds = time.perf_counter() - started_at
    summary = build_summary(results=results, runtime_seconds=runtime_seconds)
    return results, compute_exit_code(summary)



class _RendererContext:
    def __init__(self, renderer: HeadlessRenderer) -> None:
        self._renderer = renderer

    async def __aenter__(self) -> "_RendererContext":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self._renderer.stop()
