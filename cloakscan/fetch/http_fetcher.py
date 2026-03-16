from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
import httpx

from cloakscan.models import ViewSnapshot
from cloakscan.security import DEFAULT_MAX_RESPONSE_BYTES, validate_remote_url

_CACHE_BUST_PARAM = "__cloakscan_cb"
_REQUEST_HEADERS = {
    "Accept": "text/html,application/xhtml+xml",
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


def _decode_body(payload: bytes, response: httpx.Response) -> str:
    encoding = response.encoding or "utf-8"
    try:
        return payload.decode(encoding, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


async def _fetch_once(
    client: httpx.AsyncClient,
    start_url: str,
    profile: str,
    user_agent: str,
    timeout_seconds: float,
    max_redirects: int,
    allow_unsafe: bool,
    max_response_bytes: int,
    cache_bust_token: str | None,
) -> ViewSnapshot:
    requested_url = start_url
    current_url = _with_cache_bust(start_url, cache_bust_token)
    redirect_chain: list[str] = [_strip_cache_bust(current_url)]
    headers = {**_REQUEST_HEADERS, "User-Agent": user_agent}

    start_error = validate_remote_url(current_url, allow_unsafe=allow_unsafe)
    if start_error:
        return ViewSnapshot(
            profile=profile,
            requested_url=requested_url,
            final_url=requested_url,
            status_code=None,
            html="",
            redirect_chain=redirect_chain,
            error=start_error,
        )

    for _ in range(max_redirects + 1):
        current_error = validate_remote_url(current_url, allow_unsafe=allow_unsafe)
        if current_error:
            return ViewSnapshot(
                profile=profile,
                requested_url=requested_url,
                final_url=_strip_cache_bust(current_url),
                status_code=None,
                html="",
                redirect_chain=redirect_chain,
                error=current_error,
            )

        try:
            async with client.stream(
                "GET",
                current_url,
                headers=headers,
                follow_redirects=False,
                timeout=timeout_seconds,
            ) as response:
                status = response.status_code
                location = response.headers.get("location")
                if location and 300 <= status < 400:
                    next_url = urljoin(current_url, location)
                    redirect_error = validate_remote_url(next_url, allow_unsafe=allow_unsafe)
                    if redirect_error:
                        redirect_chain.append(_strip_cache_bust(next_url))
                        return ViewSnapshot(
                            profile=profile,
                            requested_url=requested_url,
                            final_url=_strip_cache_bust(next_url),
                            status_code=status,
                            html="",
                            redirect_chain=redirect_chain,
                            error=redirect_error,
                        )

                    redirect_chain.append(_strip_cache_bust(next_url))
                    current_url = next_url
                    continue

                payload = bytearray()
                async for chunk in response.aiter_bytes():
                    remaining = max_response_bytes - len(payload)
                    if remaining <= 0:
                        break
                    payload.extend(chunk[:remaining])
                    if len(payload) >= max_response_bytes:
                        break

                return ViewSnapshot(
                    profile=profile,
                    requested_url=requested_url,
                    final_url=_strip_cache_bust(str(response.url)),
                    status_code=status,
                    html=_decode_body(bytes(payload), response),
                    redirect_chain=redirect_chain,
                    error=None,
                )
        except httpx.RequestError as exc:
            return ViewSnapshot(
                profile=profile,
                requested_url=requested_url,
                final_url=_strip_cache_bust(current_url),
                status_code=None,
                html="",
                redirect_chain=redirect_chain,
                error=str(exc),
            )

    return ViewSnapshot(
        profile=profile,
        requested_url=requested_url,
        final_url=_strip_cache_bust(current_url),
        status_code=None,
        html="",
        redirect_chain=redirect_chain,
        error=f"Exceeded redirect limit ({max_redirects})",
    )


async def fetch_http_view(
    client: httpx.AsyncClient,
    start_url: str,
    profile: str,
    user_agent: str,
    timeout_seconds: float,
    max_redirects: int,
    retries: int,
    allow_unsafe: bool = False,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    cache_bust_token: str | None = None,
) -> ViewSnapshot:
    last_error = "Unknown HTTP error"
    for attempt in range(retries + 1):
        try:
            return await _fetch_once(
                client=client,
                start_url=start_url,
                profile=profile,
                user_agent=user_agent,
                timeout_seconds=timeout_seconds,
                max_redirects=max_redirects,
                allow_unsafe=allow_unsafe,
                max_response_bytes=max_response_bytes,
                cache_bust_token=cache_bust_token,
            )
        except httpx.RequestError as exc:
            last_error = str(exc)
            if attempt >= retries:
                break
        except Exception as exc:  # pragma: no cover - defensive fallback
            last_error = str(exc)
            if attempt >= retries:
                break

    return ViewSnapshot(
        profile=profile,
        requested_url=start_url,
        final_url=start_url,
        status_code=None,
        html="",
        redirect_chain=[start_url],
        error=last_error,
    )
