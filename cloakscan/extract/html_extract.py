from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, Tag

from cloakscan.models import ExtractedView

_JAPANESE_CHAR_RE = re.compile(r"[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff]")
_LATIN_OR_DIGIT_RE = re.compile(r"[A-Za-z0-9]")
_VISIBLE_CHAR_RE = re.compile(r"[A-Za-z0-9\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff]")
_HIDDEN_STYLE_PATTERNS = (
    "display:none",
    "visibility:hidden",
    "opacity:0",
    "text-indent:-999",
)
_ZERO_SIZE_VALUES = {"0", "0px", "0em", "0rem", "0%"}
_COLOR_TOKEN_RE = re.compile(r"#[0-9a-f]{3,6}|rgba?\([^)]*\)|[a-z]+", re.IGNORECASE)
_COLOR_NAME_MAP = {
    "black": "#000000",
    "white": "#ffffff",
    "red": "#ff0000",
    "green": "#008000",
    "blue": "#0000ff",
    "yellow": "#ffff00",
    "gray": "#808080",
    "grey": "#808080",
    "silver": "#c0c0c0",
    "navy": "#000080",
    "maroon": "#800000",
    "purple": "#800080",
    "teal": "#008080",
    "lime": "#00ff00",
    "transparent": "transparent",
}
_MAX_HIDDEN_SAMPLES = 3
_MAX_SAMPLE_LENGTH = 120


@dataclass(slots=True)
class HiddenTextFragment:
    text: str
    reasons: list[str]


def _hostname(value: str) -> str:
    return (urlparse(value).hostname or "").lower()


def _is_external_url(base_hostname: str, candidate: str) -> bool:
    host = _hostname(candidate)
    if not host:
        return False
    return host != base_hostname


def _parse_style_declarations(style_value: str) -> dict[str, str]:
    declarations: dict[str, str] = {}
    for chunk in style_value.split(";"):
        if ":" not in chunk:
            continue
        key, value = chunk.split(":", 1)
        key = key.strip().lower()
        value = value.strip().lower()
        if key:
            declarations[key] = value
    return declarations


def _normalize_css_color(value: str | None) -> str | None:
    if not value:
        return None

    normalized = value.strip().lower()
    if not normalized:
        return None
    if normalized in _COLOR_NAME_MAP:
        return _COLOR_NAME_MAP[normalized]

    if normalized.startswith("#"):
        digits = normalized[1:]
        if len(digits) == 3 and all(character in "0123456789abcdef" for character in digits):
            return "#" + "".join(character * 2 for character in digits)
        if len(digits) == 6 and all(character in "0123456789abcdef" for character in digits):
            return normalized
        return None

    rgb_match = re.fullmatch(
        r"rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})(?:\s*,\s*([0-9.]+))?\s*\)",
        normalized,
    )
    if not rgb_match:
        return None

    red = min(int(rgb_match.group(1)), 255)
    green = min(int(rgb_match.group(2)), 255)
    blue = min(int(rgb_match.group(3)), 255)
    alpha = rgb_match.group(4)
    if alpha is not None:
        try:
            if float(alpha) <= 0.0:
                return "transparent"
        except ValueError:
            return None
    return f"#{red:02x}{green:02x}{blue:02x}"


def _background_color(style_declarations: dict[str, str]) -> str | None:
    background_color = _normalize_css_color(style_declarations.get("background-color"))
    if background_color:
        return background_color

    shorthand = style_declarations.get("background")
    if not shorthand:
        return None

    for token in _COLOR_TOKEN_RE.findall(shorthand):
        normalized = _normalize_css_color(token)
        if normalized:
            return normalized
    return None


def _style_hidden_reasons(style_value: str) -> list[str]:
    compact_style = style_value.replace(" ", "").lower()
    declarations = _parse_style_declarations(style_value)
    reasons: list[str] = []

    if "display:none" in compact_style:
        reasons.append("display:none")
    if "visibility:hidden" in compact_style:
        reasons.append("visibility:hidden")
    if declarations.get("opacity") == "0" or "opacity:0" in compact_style:
        reasons.append("opacity:0")
    if declarations.get("font-size") in _ZERO_SIZE_VALUES:
        reasons.append("font-size:0")
    if declarations.get("color") == "transparent":
        reasons.append("color:transparent")
    if "text-indent:-" in compact_style:
        reasons.append("negative text-indent")
    if "position:absolute" in compact_style and (
        "left:-" in compact_style or "top:-" in compact_style
    ):
        reasons.append("offscreen absolute positioning")

    foreground = _normalize_css_color(declarations.get("color"))
    background = _background_color(declarations)
    if foreground and background and foreground == background:
        reasons.append("color matches background")

    unique_reasons: list[str] = []
    for reason in reasons:
        if reason not in unique_reasons:
            unique_reasons.append(reason)
    return unique_reasons


def _anchor_hidden_reasons(anchor: Tag) -> list[str]:
    style_value = anchor.get("style") or ""
    class_value = " ".join(anchor.get("class") or []).lower()
    aria_hidden = anchor.get("aria-hidden")

    reasons = _style_hidden_reasons(style_value)
    if "hidden" in class_value:
        reasons.append("hidden class")
    if anchor.get("hidden") is not None:
        reasons.append("hidden attribute")
    if str(aria_hidden).lower() == "true":
        reasons.append("aria-hidden")

    unique_reasons: list[str] = []
    for reason in reasons:
        if reason not in unique_reasons:
            unique_reasons.append(reason)
    return unique_reasons


def _anchor_is_hidden(anchor: Tag) -> bool:
    return bool(_anchor_hidden_reasons(anchor) or _has_hidden_ancestor(anchor))


def _count_hidden_anchors(soup: BeautifulSoup) -> int:
    total = 0
    for anchor in soup.find_all("a"):
        if _anchor_is_hidden(anchor):
            total += 1
    return total


def _extract_hidden_external_links(
    soup: BeautifulSoup,
    page_url: str,
    comparison_host: str,
) -> list[str]:
    hidden_external_links: list[str] = []
    for anchor in soup.find_all("a", href=True):
        if not _anchor_is_hidden(anchor):
            continue
        absolute = urljoin(page_url, anchor["href"])
        if not _is_external_url(comparison_host, absolute):
            continue
        if absolute not in hidden_external_links:
            hidden_external_links.append(absolute)
    return hidden_external_links


def _meaningful_text_length(text: str) -> int:
    return len(_VISIBLE_CHAR_RE.findall(text))


def _short_sample(text: str, max_length: int = _MAX_SAMPLE_LENGTH) -> str:
    compact = re.sub(r"\s+", " ", text).strip()
    if len(compact) <= max_length:
        return compact
    return f"{compact[: max_length - 3].rstrip()}..."


def _text_hidden_reasons(tag: Tag) -> list[str]:
    style_value = tag.get("style") or ""
    reasons = _style_hidden_reasons(style_value)
    if tag.get("hidden") is not None:
        reasons.append("hidden attribute")

    unique_reasons: list[str] = []
    for reason in reasons:
        if reason not in unique_reasons:
            unique_reasons.append(reason)
    return unique_reasons


def _has_hidden_ancestor(tag: Tag) -> bool:
    for parent in tag.parents:
        if not isinstance(parent, Tag):
            continue
        if _text_hidden_reasons(parent):
            return True
    return False


def _extract_hidden_text_fragments(soup: BeautifulSoup) -> list[HiddenTextFragment]:
    fragments: list[HiddenTextFragment] = []
    for element in soup.find_all(True):
        if not isinstance(element, Tag):
            continue

        reasons = _text_hidden_reasons(element)
        if not reasons or _has_hidden_ancestor(element):
            continue

        text = element.get_text(separator=" ", strip=True)
        if _meaningful_text_length(text) < 4:
            continue

        fragments.append(HiddenTextFragment(text=text, reasons=reasons))
    return fragments


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
            hidden_text_count=0,
            hidden_text_char_count=0,
            hidden_external_link_count=0,
            japanese_ratio=0.0,
            outbound_links=[],
            external_domains=[],
            hidden_text_samples=[],
            hidden_text_reasons=[],
            hidden_text_content="",
            hidden_external_links=[],
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
    hidden_external_links = _extract_hidden_external_links(soup, page_url, comparison_host)
    hidden_fragments = _extract_hidden_text_fragments(soup)
    hidden_samples: list[str] = []
    hidden_reasons: list[str] = []
    hidden_char_count = 0
    hidden_text_content = ""
    if hidden_fragments:
        hidden_text_content = " ".join(fragment.text for fragment in hidden_fragments)
    for fragment in hidden_fragments:
        hidden_char_count += len(fragment.text)
        sample = _short_sample(fragment.text)
        if sample and sample not in hidden_samples and len(hidden_samples) < _MAX_HIDDEN_SAMPLES:
            hidden_samples.append(sample)
        for reason in fragment.reasons:
            if reason not in hidden_reasons:
                hidden_reasons.append(reason)

    return ExtractedView(
        title=title,
        visible_text=visible_text,
        text_length=len(visible_text),
        outbound_link_count=outbound_count,
        external_domain_count=len(external_domains),
        hidden_anchor_count=hidden_count,
        hidden_text_count=len(hidden_fragments),
        hidden_text_char_count=hidden_char_count,
        hidden_external_link_count=len(hidden_external_links),
        japanese_ratio=_compute_japanese_ratio(visible_text),
        outbound_links=outbound_links,
        external_domains=external_domains,
        hidden_text_samples=hidden_samples,
        hidden_text_reasons=hidden_reasons,
        hidden_text_content=hidden_text_content,
        hidden_external_links=hidden_external_links,
    )

