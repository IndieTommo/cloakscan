from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from cloakscan.models import ViewSnapshot
from cloakscan.security import validate_remote_url

try:
    from playwright.async_api import Error as PlaywrightError
    from playwright.async_api import async_playwright
except Exception:  # pragma: no cover - import error handled at runtime
    PlaywrightError = Exception  # type: ignore[assignment]
    async_playwright = None  # type: ignore[assignment]


_CACHE_BUST_PARAM = "__cloakscan_cb"
_HEADLESS_HEADERS = {
    "Cache-Control": "no-cache, no-store, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
}


def _with_cache_bust(url: str, token: str | None) -> str:
    if not token:
        return url
    split = urlsplit(url)
    query = parse_qsl(split.query, keep_blank_values=True)
    query = [(key, value) for key, value in query if key != _CACHE_BUST_PARAM]
    query.append((_CACHE_BUST_PARAM, token))
    return urlunsplit(split._replace(query=urlencode(query)))


def _strip_cache_bust(url: str) -> str:
    split = urlsplit(url)
    query = parse_qsl(split.query, keep_blank_values=True)
    filtered = [(key, value) for key, value in query if key != _CACHE_BUST_PARAM]
    normalized_query = urlencode(filtered)
    return urlunsplit(split._replace(query=normalized_query))


class HeadlessRenderer:
    def __init__(self) -> None:
        self._playwright = None
        self._browser = None

    async def start(self) -> None:
        if async_playwright is None:
            raise RuntimeError(
                "Playwright is not available. Install playwright and browser binaries."
            )
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=True)

    async def stop(self) -> None:
        if self._browser is not None:
            await self._browser.close()
            self._browser = None
        if self._playwright is not None:
            await self._playwright.stop()
            self._playwright = None

    async def _handle_route(self, route, request, allow_unsafe: bool) -> None:
        error = validate_remote_url(request.url, allow_unsafe=allow_unsafe)
        if error:
            await route.abort()
            return
        await route.continue_()

    async def render(
        self,
        start_url: str,
        timeout_seconds: float,
        user_agent: str,
        allow_unsafe: bool = False,
        cache_bust_token: str | None = None,
    ) -> ViewSnapshot:
        if self._browser is None:
            return ViewSnapshot(
                profile="headless",
                requested_url=start_url,
                final_url=start_url,
                status_code=None,
                html="",
                redirect_chain=[start_url],
                error="Headless renderer not started",
            )

        requested_url = start_url
        actual_start_url = _with_cache_bust(start_url, cache_bust_token)
        start_error = validate_remote_url(actual_start_url, allow_unsafe=allow_unsafe)
        if start_error:
            return ViewSnapshot(
                profile="headless",
                requested_url=requested_url,
                final_url=requested_url,
                status_code=None,
                html="",
                redirect_chain=[requested_url],
                error=start_error,
            )

        context = await self._browser.new_context(
            user_agent=user_agent,
            ignore_https_errors=False,
            accept_downloads=False,
            service_workers="block",
            extra_http_headers=_HEADLESS_HEADERS,
        )
        await context.route(
            "**/*",
            lambda route, request: self._handle_route(route, request, allow_unsafe=allow_unsafe),
        )
        page = await context.new_page()
        try:
            response = await page.goto(
                actual_start_url,
                wait_until="domcontentloaded",
                timeout=int(timeout_seconds * 1000),
            )
            await page.wait_for_timeout(500)
            final_error = validate_remote_url(page.url, allow_unsafe=allow_unsafe)
            if final_error:
                return ViewSnapshot(
                    profile="headless",
                    requested_url=requested_url,
                    final_url=_strip_cache_bust(page.url),
                    status_code=response.status if response is not None else None,
                    html="",
                    redirect_chain=[requested_url, _strip_cache_bust(page.url)]
                    if _strip_cache_bust(page.url) != requested_url
                    else [requested_url],
                    error=final_error,
                )
            normalized_final_url = _strip_cache_bust(page.url)
            html = await page.content()
            status_code = response.status if response is not None else None
            return ViewSnapshot(
                profile="headless",
                requested_url=requested_url,
                final_url=normalized_final_url,
                status_code=status_code,
                html=html,
                redirect_chain=[requested_url, normalized_final_url]
                if normalized_final_url != requested_url
                else [requested_url],
                error=None,
            )
        except PlaywrightError as exc:
            return ViewSnapshot(
                profile="headless",
                requested_url=requested_url,
                final_url=_strip_cache_bust(page.url) if page.url else requested_url,
                status_code=None,
                html="",
                redirect_chain=[requested_url],
                error=str(exc),
            )
        except Exception as exc:  # pragma: no cover - defensive fallback
            return ViewSnapshot(
                profile="headless",
                requested_url=requested_url,
                final_url=_strip_cache_bust(page.url) if page.url else requested_url,
                status_code=None,
                html="",
                redirect_chain=[requested_url],
                error=str(exc),
            )
        finally:
            await context.close()
