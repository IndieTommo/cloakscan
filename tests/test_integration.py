from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import threading
import unittest

from cloakscan.config import load_scan_config
from cloakscan.models import TargetSpec

_HAS_HTTPX = importlib.util.find_spec("httpx") is not None
_HAS_BS4 = importlib.util.find_spec("bs4") is not None
_HAS_PLAYWRIGHT = importlib.util.find_spec("playwright") is not None


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/landing"):
            body = "<html><body>Landing page</body></html>"
        elif self.path.startswith("/js"):
            body = (
                "<html><body><script>"
                "window.location='/landing';"
                "</script>Redirecting</body></html>"
            )
        else:
            user_agent = self.headers.get("User-Agent", "")
            if "Googlebot" in user_agent:
                body = "<html><body>casino betting poker sportsbook jackpot</body></html>"
            else:
                body = "<html><body>normal homepage content</body></html>"
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return


@unittest.skipUnless(_HAS_HTTPX and _HAS_BS4, "httpx/beautifulsoup4 not installed")
class IntegrationTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    async def test_ua_difference_triggers_detection(self) -> None:
        import httpx
        from cloakscan.detect import detect_signals
        from cloakscan.fetch import fetch_http_view

        config = load_scan_config("balanced", config_path=None)
        target = TargetSpec(raw=self.base_url, normalized_url=f"{self.base_url}/")

        async with httpx.AsyncClient() as client:
            browser = await fetch_http_view(
                client=client,
                start_url=f"{self.base_url}/",
                profile="browser",
                user_agent=config.user_agents.browser,
                timeout_seconds=5,
                max_redirects=3,
                retries=0,
                allow_unsafe=True,
            )
            bot = await fetch_http_view(
                client=client,
                start_url=f"{self.base_url}/",
                profile="bot",
                user_agent=config.user_agents.bot,
                timeout_seconds=5,
                max_redirects=3,
                retries=0,
                allow_unsafe=True,
            )

        signals = detect_signals(target=target, views={"browser": browser, "bot": bot}, config=config)
        codes = {signal.code for signal in signals}
        self.assertIn("bot_human_mismatch", codes)
        self.assertIn("casino_keywords", codes)

    @unittest.skipUnless(_HAS_PLAYWRIGHT, "playwright not installed")
    async def test_headless_captures_js_redirect(self) -> None:
        from cloakscan.render import HeadlessRenderer

        renderer = HeadlessRenderer()
        try:
            await renderer.start()
        except Exception as exc:
            self.skipTest(str(exc))

        try:
            snapshot = await renderer.render(
                start_url=f"{self.base_url}/js",
                timeout_seconds=10,
                user_agent=load_scan_config("balanced", None).user_agents.headless,
                allow_unsafe=True,
            )
        finally:
            await renderer.stop()

        self.assertIsNone(snapshot.error)
        self.assertTrue(snapshot.final_url.endswith("/landing"))


if __name__ == "__main__":
    unittest.main()
