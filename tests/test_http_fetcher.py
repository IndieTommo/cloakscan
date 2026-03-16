from __future__ import annotations

import unittest

import httpx

from cloakscan.fetch.http_fetcher import _strip_cache_bust, _with_cache_bust, fetch_http_view


class _FakeResponse:
    def __init__(self, *, status_code: int, url: str, headers: dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self.url = url
        self.headers = headers or {}
        self.encoding = "utf-8"

    async def aiter_bytes(self):
        if False:
            yield b""


class _ResponseContext:
    def __init__(self, response: _FakeResponse) -> None:
        self._response = response

    async def __aenter__(self) -> _FakeResponse:
        return self._response

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


class _ErrorContext:
    def __init__(self, error: httpx.RequestError) -> None:
        self._error = error

    async def __aenter__(self):
        raise self._error

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


class _RedirectThenTlsErrorClient:
    def __init__(self) -> None:
        self.calls = 0

    def stream(self, method: str, url: str, **kwargs):
        del method, kwargs
        self.calls += 1
        if self.calls == 1:
            return _ResponseContext(
                _FakeResponse(
                    status_code=302,
                    url=url,
                    headers={"location": "https://redirect.example/path"},
                )
            )
        return _ErrorContext(httpx.RequestError("certificate verify failed", request=httpx.Request("GET", url)))


class HttpFetcherTests(unittest.IsolatedAsyncioTestCase):
    def test_cache_bust_round_trip_preserves_original_url(self) -> None:
        original = "https://example.com/path?x=1"
        busted = _with_cache_bust(original, "abc123")

        self.assertIn("__cloakscan_cb=abc123", busted)
        self.assertEqual(_strip_cache_bust(busted), original)

    async def test_tls_request_error_keeps_redirect_chain_and_failing_url(self) -> None:
        snapshot = await fetch_http_view(
            client=_RedirectThenTlsErrorClient(),
            start_url="https://example.com/",
            profile="bot",
            user_agent="Googlebot",
            timeout_seconds=5,
            max_redirects=3,
            retries=0,
            allow_unsafe=False,
        )

        self.assertIn("certificate verify failed", snapshot.error or "")
        self.assertEqual(snapshot.final_url, "https://redirect.example/path")
        self.assertEqual(
            snapshot.redirect_chain,
            ["https://example.com/", "https://redirect.example/path"],
        )


if __name__ == "__main__":
    unittest.main()
