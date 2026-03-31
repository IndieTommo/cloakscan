from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from rich.console import Console

from cloakscan.config import load_scan_config
from cloakscan.models import TargetResult, TargetSpec, ViewSnapshot


class _FakeProgress:
    def __init__(self, console: Console) -> None:
        self.console = console
        self.add_task_calls: list[tuple[str, int | None]] = []
        self.update_calls: list[tuple[int, dict[str, object]]] = []

    def __enter__(self) -> "_FakeProgress":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def add_task(self, description: str, total: int | None) -> int:
        self.add_task_calls.append((description, total))
        return 1

    def update(self, task_id: int, **kwargs: object) -> None:
        self.update_calls.append((task_id, kwargs))


class ScannerBehaviorTests(unittest.IsolatedAsyncioTestCase):
    async def test_single_target_scan_skips_progress(self) -> None:
        from cloakscan import scanner

        config = load_scan_config("balanced", config_path=None)
        config.headless_enabled = False

        async def fake_scan_target(*args, **kwargs) -> TargetResult:
            return TargetResult(
                target=TargetSpec(raw="example.com", normalized_url="https://example.com/"),
                risk="CLEAN",
                score=0,
                reason="No major cloaking/spam indicators",
                views={
                    "browser": ViewSnapshot(
                        profile="browser",
                        requested_url="https://example.com/",
                        final_url="https://example.com/",
                        status_code=200,
                        html="<html><body>ok</body></html>",
                    )
                },
                runtime_seconds=0.2,
            )

        fake_loader = _FakeProgress(Console(record=True))
        with patch("cloakscan.scanner.create_progress", side_effect=AssertionError("batch progress should stay hidden")):
            with patch("cloakscan.scanner.create_loading_indicator", return_value=fake_loader):
                with patch("cloakscan.scanner._scan_target_with_timeout", side_effect=fake_scan_target):
                    results, exit_code = await scanner.run_scan(
                        targets=[TargetSpec(raw="example.com", normalized_url="https://example.com/")],
                        config=config,
                        explain=False,
                        debug=False,
                        tls_debug=False,
                        console=Console(record=True),
                    )

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].views["browser"].html, "")
        self.assertEqual(fake_loader.add_task_calls, [("Loading", None)])
        self.assertTrue(any(update[1].get("description") == "Loading" for update in fake_loader.update_calls))

    async def test_json_mode_skips_terminal_output_helpers(self) -> None:
        from cloakscan import scanner

        config = load_scan_config("balanced", config_path=None)
        config.headless_enabled = False

        async def fake_scan_target(*args, **kwargs) -> TargetResult:
            target = kwargs["target"]
            return TargetResult(
                target=target,
                risk="CLEAN",
                score=0,
                reason="No major cloaking/spam indicators",
                views={},
                runtime_seconds=0.1,
            )

        with patch("cloakscan.scanner.create_progress", side_effect=AssertionError("progress should be hidden")):
            with patch("cloakscan.scanner.create_loading_indicator", side_effect=AssertionError("loader should be hidden")):
                with patch("cloakscan.scanner.print_result", side_effect=AssertionError("result printing should be hidden")):
                    with patch("cloakscan.scanner._scan_target", side_effect=fake_scan_target):
                        results, exit_code = await scanner.run_scan(
                            targets=[
                                TargetSpec(raw="b.example", normalized_url="https://b.example/"),
                                TargetSpec(raw="a.example", normalized_url="https://a.example/"),
                            ],
                            config=config,
                            explain=False,
                            debug=False,
                            tls_debug=False,
                            console=Console(record=True),
                            emit_output=False,
                        )

        self.assertEqual(exit_code, 0)
        self.assertEqual([result.target.raw for result in results], ["b.example", "a.example"])

    async def test_multi_target_scan_uses_progress(self) -> None:
        from cloakscan import scanner

        config = load_scan_config("balanced", config_path=None)
        config.headless_enabled = False
        fake_progress = _FakeProgress(Console(record=True))

        async def fake_scan_target(*args, **kwargs) -> TargetResult:
            target = kwargs["target"]
            return TargetResult(
                target=target,
                risk="CLEAN",
                score=0,
                reason="No major cloaking/spam indicators",
                views={},
                runtime_seconds=0.1,
            )

        with patch("cloakscan.scanner.create_progress", return_value=fake_progress):
            with patch("cloakscan.scanner._scan_target_with_timeout", side_effect=fake_scan_target):
                results, exit_code = await scanner.run_scan(
                    targets=[
                        TargetSpec(raw="a.example", normalized_url="https://a.example/"),
                        TargetSpec(raw="b.example", normalized_url="https://b.example/"),
                    ],
                    config=config,
                    explain=False,
                    debug=False,
                    tls_debug=False,
                    console=Console(record=True),
                )

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(results), 2)
        self.assertEqual(fake_progress.add_task_calls, [("Preparing scan", 2)])
        self.assertTrue(any("description" in update[1] for update in fake_progress.update_calls))

    async def test_batch_timeout_starts_when_target_work_begins(self) -> None:
        from cloakscan import scanner

        config = load_scan_config("balanced", config_path=None)
        config.headless_enabled = False
        config.concurrency.http_workers = 1
        config.timeouts.total_target_seconds = 0.2
        fake_progress = _FakeProgress(Console(record=True))

        async def fake_scan_target(*args, **kwargs) -> TargetResult:
            await asyncio.sleep(0.12)
            target = kwargs["target"]
            return TargetResult(
                target=target,
                risk="CLEAN",
                score=0,
                reason="No major cloaking/spam indicators",
                views={},
                runtime_seconds=0.12,
            )

        with patch("cloakscan.scanner.create_progress", return_value=fake_progress):
            with patch("cloakscan.scanner._scan_target", side_effect=fake_scan_target):
                results, exit_code = await scanner.run_scan(
                    targets=[
                        TargetSpec(raw="a.example", normalized_url="https://a.example/"),
                        TargetSpec(raw="b.example", normalized_url="https://b.example/"),
                    ],
                    config=config,
                    explain=False,
                    debug=False,
                    tls_debug=False,
                    console=Console(record=True),
                )

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(not result.failed for result in results))
        self.assertTrue(all(result.error is None for result in results))

    async def test_browser_and_bot_use_separate_http_clients(self) -> None:
        from cloakscan import scanner

        config = load_scan_config("balanced", config_path=None)
        config.headless_enabled = False
        seen_clients: dict[str, object] = {}
        seen_tokens: dict[str, str | None] = {}
        browser_client = object()
        bot_client = object()

        async def fake_fetch_http_view(*args, **kwargs) -> ViewSnapshot:
            seen_clients[kwargs["profile"]] = kwargs["client"]
            seen_tokens[kwargs["profile"]] = kwargs.get("cache_bust_token")
            return ViewSnapshot(
                profile=kwargs["profile"],
                requested_url=kwargs["start_url"],
                final_url=kwargs["start_url"],
                status_code=200,
                html="<html><body>ok</body></html>",
            )

        with patch("cloakscan.scanner.fetch_http_view", side_effect=fake_fetch_http_view):
            result = await scanner._scan_target(
                target=TargetSpec(raw="example.com", normalized_url="https://example.com/"),
                config=config,
                browser_client=browser_client,
                bot_client=bot_client,
                tls_debug_client=None,
                renderer=None,
                http_semaphore=asyncio.Semaphore(1),
                headless_semaphore=asyncio.Semaphore(1),
                debug=False,
                tls_debug=False,
                cache_bust_run_id="run1234",
            )

        self.assertFalse(result.failed)
        self.assertIs(seen_clients["browser"], browser_client)
        self.assertIs(seen_clients["bot"], bot_client)
        self.assertIsNot(seen_clients["browser"], seen_clients["bot"])
        self.assertEqual(seen_tokens["browser"], "run1234-browser")
        self.assertEqual(seen_tokens["bot"], "run1234-bot")

    async def test_bot_view_error_marks_result_incomplete(self) -> None:
        from cloakscan import scanner

        config = load_scan_config("balanced", config_path=None)
        config.headless_enabled = False

        async def fake_fetch_http_view(*args, **kwargs) -> ViewSnapshot:
            if kwargs["profile"] == "bot":
                return ViewSnapshot(
                    profile="bot",
                    requested_url=kwargs["start_url"],
                    final_url=kwargs["start_url"],
                    status_code=None,
                    html="",
                    error="certificate verify failed",
                )
            return ViewSnapshot(
                profile=kwargs["profile"],
                requested_url=kwargs["start_url"],
                final_url=kwargs["start_url"],
                status_code=200,
                html="<html><body>ok</body></html>",
            )

        with patch("cloakscan.scanner.fetch_http_view", side_effect=fake_fetch_http_view):
            result = await scanner._scan_target(
                target=TargetSpec(raw="example.com", normalized_url="https://example.com/"),
                config=config,
                browser_client=object(),
                bot_client=object(),
                tls_debug_client=None,
                renderer=None,
                http_semaphore=asyncio.Semaphore(1),
                headless_semaphore=asyncio.Semaphore(1),
                debug=False,
                tls_debug=False,
                cache_bust_run_id="run1234",
            )

        self.assertFalse(result.failed)
        self.assertTrue(result.incomplete)
        self.assertIn("Rerun with --tls-debug", result.reason)
        self.assertTrue(any("bot view failed" in warning for warning in result.warnings))
        self.assertTrue(any("rerun with --tls-debug" in warning for warning in result.warnings))

    async def test_tls_debug_reveals_redirect_chain_for_bot_tls_failure(self) -> None:
        from cloakscan import scanner

        config = load_scan_config("balanced", config_path=None)
        config.headless_enabled = False
        secure_bot_client = object()
        insecure_bot_client = object()

        async def fake_fetch_http_view(*args, **kwargs) -> ViewSnapshot:
            profile = kwargs["profile"]
            client = kwargs["client"]
            if profile == "browser":
                return ViewSnapshot(
                    profile="browser",
                    requested_url=kwargs["start_url"],
                    final_url=kwargs["start_url"],
                    status_code=200,
                    html="<html><body>ok</body></html>",
                )
            if profile == "bot" and client is secure_bot_client:
                return ViewSnapshot(
                    profile="bot",
                    requested_url=kwargs["start_url"],
                    final_url="https://redirect.example/offer",
                    status_code=None,
                    html="",
                    redirect_chain=["https://example.com/", "https://redirect.example/offer"],
                    error="certificate verify failed",
                )
            if profile == "bot_tls_debug" and client is insecure_bot_client:
                return ViewSnapshot(
                    profile="bot_tls_debug",
                    requested_url=kwargs["start_url"],
                    final_url="https://redirect.example/offer",
                    status_code=302,
                    html="",
                    redirect_chain=["https://example.com/", "https://redirect.example/offer"],
                    error=None,
                )
            raise AssertionError(f"Unexpected fetch call: profile={profile} client={client!r}")

        with patch("cloakscan.scanner.fetch_http_view", side_effect=fake_fetch_http_view):
            result = await scanner._scan_target(
                target=TargetSpec(raw="example.com", normalized_url="https://example.com/"),
                config=config,
                browser_client=object(),
                bot_client=secure_bot_client,
                tls_debug_client=insecure_bot_client,
                renderer=None,
                http_semaphore=asyncio.Semaphore(1),
                headless_semaphore=asyncio.Semaphore(1),
                debug=True,
                tls_debug=True,
                cache_bust_run_id="run1234",
            )

        self.assertTrue(result.incomplete)
        self.assertEqual(result.risk, "MEDIUM")
        self.assertEqual(result.reason, "Possible sneaky redirect mismatch")
        self.assertTrue(any("bot tls-debug chain:" in warning for warning in result.warnings))
        self.assertTrue(any("redirect.example/offer" in warning for warning in result.warnings))
        self.assertTrue(any(event.phase == "bot_tls_debug" for event in result.debug_events))


if __name__ == "__main__":
    unittest.main()

