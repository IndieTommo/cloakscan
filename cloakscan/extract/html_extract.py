from __future__ import annotations

from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse

from cloakscan.models import ExtractedView

_JAPANESE_CHAR_RE = re.compile(r"[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff]")
_LATIN_OR_DIGIT_RE = re.compile(r"[A-Za-z0-9]")
_HIDDEN_STYLE_PATTERNS = (
    "display:none",
    "visibility:hidden",
    "opacity:0",
    "text-indent:-999",
)


def _hostname(value: str) -> str:
    return (urlparse(value).hostname or "").lower()


def _is_external_url(base_hostname: str, candidate: str) -> bool:
    host = _hostname(candidate)
    if not host:
        return False
    return host != base_hostname


def _count_hidden_anchors(soup: BeautifulSoup) -> int:
    total = 0
    for anchor in soup.find_all("a"):
        style_value = (anchor.get("style") or "").replace(" ", "").lower()
        class_value = " ".join(anchor.get("class") or []).lower()
        hidden_attr = anchor.get("hidden")
        aria_hidden = anchor.get("aria-hidden")

        hidden_style = any(marker in style_value for marker in _HIDDEN_STYLE_PATTERNS)
        offscreen = "position:absolute" in style_value and (
            "left:-" in style_value or "top:-" in style_value
        )
        hidden_class = "hidden" in class_value
        hidden_aria = str(aria_hidden).lower() == "true"

        if hidden_style or offscreen or hidden_class or hidden_attr is not None or hidden_aria:
            total += 1
    return total


def _extract_visible_text(soup: BeautifulSoup) -> str:
    for element in soup(["script", "style", "noscript", "template"]):
        element.decompose()
    return soup.get_text(separator=" ", strip=True)


def _compute_japanese_ratio(text: str) -> float:
    if not text:
        return 0.0
    japanese_chars = len(_JAPANESE_CHAR_RE.findall(text))
    latin_chars = len(_LATIN_OR_DIGIT_RE.findall(text))
    denominator = max(japanese_chars + latin_chars, 1)
    return japanese_chars / denominator


def extract_view(html: str, page_url: str, base_url: str) -> ExtractedView:
    if not html.strip():
        return ExtractedView(
            title="",
            visible_text="",
            text_length=0,
            outbound_link_count=0,
            external_domain_count=0,
            hidden_anchor_count=0,
            japanese_ratio=0.0,
            outbound_links=[],
            external_domains=[],
        )

    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.get_text(strip=True) if soup.title else ""
    visible_text = _extract_visible_text(soup)

    base_hostname = _hostname(base_url)
    page_hostname = _hostname(page_url)
    comparison_host = page_hostname or base_hostname

    external_domains_seen: set[str] = set()
    external_domains: list[str] = []
    outbound_links: list[str] = []
    outbound_count = 0
    for anchor in soup.find_all("a", href=True):
        absolute = urljoin(page_url, anchor["href"])
        if _is_external_url(comparison_host, absolute):
            outbound_count += 1
            if absolute not in outbound_links:
                outbound_links.append(absolute)
            host = _hostname(absolute)
            if host and host not in external_domains_seen:
                external_domains_seen.add(host)
                external_domains.append(host)

    hidden_count = _count_hidden_anchors(soup)
    return ExtractedView(
        title=title,
        visible_text=visible_text,
        text_length=len(visible_text),
        outbound_link_count=outbound_count,
        external_domain_count=len(external_domains),
        hidden_anchor_count=hidden_count,
        japanese_ratio=_compute_japanese_ratio(visible_text),
        outbound_links=outbound_links,
        external_domains=external_domains,
    )
