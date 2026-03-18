from __future__ import annotations

import difflib
import re
from urllib.parse import urlparse

from cloakscan.extract import extract_view
from cloakscan.models import ScanConfig, Signal, TargetSpec, ViewSnapshot

_TOKEN_RE = re.compile(r"[a-z0-9\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff]+", re.IGNORECASE)
_MAX_EXPLAIN_ITEMS = 5
_MIN_HIDDEN_TEXT_CHARS = 8


def _tokenize(text: str) -> set[str]:
    return set(_TOKEN_RE.findall(text.lower()))


def _jaccard_similarity(text_a: str, text_b: str) -> float:
    tokens_a = _tokenize(text_a)
    tokens_b = _tokenize(text_b)
    if not tokens_a and not tokens_b:
        return 1.0
    union = tokens_a | tokens_b
    if not union:
        return 1.0
    return len(tokens_a & tokens_b) / len(union)


def _length_delta(text_a: str, text_b: str) -> float:
    len_a = len(text_a)
    len_b = len(text_b)
    longest = max(len_a, len_b, 1)
    return abs(len_a - len_b) / longest


def _keyword_hits(text: str, keywords: list[str]) -> int:
    total = 0
    for keyword in keywords:
        marker = keyword.strip()
        if not marker:
            continue

        # Japanese tokens and mixed-script markers are checked by substring.
        # Latin-script phrases are matched as whole words to reduce noise.
        is_latin_phrase = bool(re.fullmatch(r"[A-Za-z0-9 _-]+", marker))
        if is_latin_phrase:
            normalized = re.sub(r"\s+", r"\\s+", re.escape(marker.lower()))
            pattern = re.compile(rf"\b{normalized}\b", re.IGNORECASE)
            total += len(pattern.findall(text))
        else:
            lowered = text.lower()
            total += lowered.count(marker.lower())
    return total


def _hidden_keyword_hits(text: str, config: ScanConfig) -> tuple[int, list[str]]:
    keyword_sets = (
        config.keywords.casino,
        config.keywords.pharma,
        config.keywords.adult,
        config.keywords.japanese,
    )
    total = 0
    matched: list[str] = []
    for keywords in keyword_sets:
        total += _keyword_hits(text, keywords)
        for keyword in _matched_keyword_samples(text, keywords):
            if keyword not in matched:
                matched.append(keyword)
            if len(matched) >= _MAX_EXPLAIN_ITEMS:
                return total, matched
    return total, matched


def _normalized_redirect_target(url: str) -> tuple[str, str, int | None, str, str]:
    parsed = urlparse(url)
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


def _is_redirect_difference(first_view: ViewSnapshot, second_view: ViewSnapshot) -> bool:
    first_final = _normalized_redirect_target(first_view.final_url)
    second_final = _normalized_redirect_target(second_view.final_url)
    if first_final != second_final:
        return True

    first_chain = [_normalized_redirect_target(url) for url in first_view.redirect_chain]
    second_chain = [_normalized_redirect_target(url) for url in second_view.redirect_chain]
    return first_chain != second_chain


def _format_redirect_chain(urls: list[str]) -> str:
    if not urls:
        return "(none)"
    if len(urls) <= 4:
        return " -> ".join(urls)
    return " -> ".join([*urls[:2], "...", urls[-1]])


def _redirect_details(
    baseline_view: ViewSnapshot,
    suspicious_view: ViewSnapshot,
    suspicious_label: str,
) -> list[str]:
    details: list[str] = []
    if _normalized_redirect_target(baseline_view.final_url) != _normalized_redirect_target(suspicious_view.final_url):
        details.append(
            f"final URL diff: browser={baseline_view.final_url} vs {suspicious_label}={suspicious_view.final_url}"
        )
    if baseline_view.redirect_chain != suspicious_view.redirect_chain:
        details.append(f"browser redirect chain: {_format_redirect_chain(baseline_view.redirect_chain)}")
        details.append(f"{suspicious_label} redirect chain: {_format_redirect_chain(suspicious_view.redirect_chain)}")
    return details[:4]


def _shorten_text(text: str, max_length: int = 140) -> str:
    compact = re.sub(r"\s+", " ", text).strip()
    if len(compact) <= max_length:
        return compact
    return f"{compact[: max_length - 3].rstrip()}..."


def _sample_added_values(baseline: list[str], suspicious: list[str], limit: int = _MAX_EXPLAIN_ITEMS) -> list[str]:
    baseline_set = set(baseline)
    return [value for value in suspicious if value not in baseline_set][:limit]


def _text_diff_details(
    baseline_text: str,
    suspicious_text: str,
    suspicious_label: str,
) -> list[str]:
    baseline_words = baseline_text.split()
    suspicious_words = suspicious_text.split()
    if not baseline_words and not suspicious_words:
        return []

    matcher = difflib.SequenceMatcher(a=baseline_words, b=suspicious_words)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue

        details: list[str] = []
        if tag in {"replace", "delete"} and i1 < i2:
            snippet = _shorten_text(" ".join(baseline_words[i1 : min(i2, i1 + 18)]))
            if snippet:
                details.append(f"browser-only text sample: {snippet}")
        if tag in {"replace", "insert"} and j1 < j2:
            snippet = _shorten_text(" ".join(suspicious_words[j1 : min(j2, j1 + 18)]))
            if snippet:
                details.append(f"{suspicious_label}-only text sample: {snippet}")
        if details:
            return details
    return []


def _mismatch_details(
    browser_view: ViewSnapshot,
    browser_extract,
    suspicious_view: ViewSnapshot,
    suspicious_extract,
    suspicious_label: str,
) -> list[str]:
    details: list[str] = []
    if browser_extract.title != suspicious_extract.title:
        details.append(
            f"title diff: browser='{_shorten_text(browser_extract.title, 80)}' "
            f"vs {suspicious_label}='{_shorten_text(suspicious_extract.title, 80)}'"
        )
    if browser_view.final_url != suspicious_view.final_url:
        details.append(
            f"final URL diff: browser={browser_view.final_url} "
            f"vs {suspicious_label}={suspicious_view.final_url}"
        )
    details.extend(
        _text_diff_details(
            browser_extract.visible_text,
            suspicious_extract.visible_text,
            suspicious_label=suspicious_label,
        )
    )
    return details[:4]


def _matched_keyword_samples(text: str, keywords: list[str], limit: int = _MAX_EXPLAIN_ITEMS) -> list[str]:
    matched: list[str] = []
    lowered = text.lower()
    for keyword in keywords:
        marker = keyword.strip()
        if not marker:
            continue
        if marker.lower() in lowered:
            matched.append(marker)
        if len(matched) >= limit:
            break
    return matched


def _format_sample_list(samples: list[str]) -> str:
    formatted: list[str] = []
    for sample in samples:
        if sample.isascii():
            formatted.append(sample)
        else:
            formatted.append(sample.encode('unicode_escape').decode('ascii'))
    return ', '.join(formatted)


def _hidden_text_signal_details(
    extracted_views: list[tuple[str, object, int, list[str]]],
) -> tuple[dict[str, int], list[str]]:
    metrics: dict[str, int] = {}
    details: list[str] = []
    for label, extracted_view, hidden_keyword_hits, hidden_keyword_samples in extracted_views:
        metrics[f"{label}_hidden_blocks"] = extracted_view.hidden_text_count
        metrics[f"{label}_hidden_chars"] = extracted_view.hidden_text_char_count
        if extracted_view.hidden_external_link_count > 0:
            metrics[f"{label}_hidden_external_links"] = extracted_view.hidden_external_link_count
        if hidden_keyword_hits > 0:
            metrics[f"{label}_hidden_keyword_hits"] = hidden_keyword_hits
        if hidden_keyword_samples:
            details.append(f"{label} hidden keywords: {_format_sample_list(hidden_keyword_samples[:_MAX_EXPLAIN_ITEMS])}")
        if extracted_view.hidden_external_links:
            links = ", ".join(extracted_view.hidden_external_links[:_MAX_EXPLAIN_ITEMS])
            details.append(f"{label} hidden external links: {links}")
        if extracted_view.hidden_text_reasons:
            details.append(
                f"{label} hidden text reasons: {', '.join(extracted_view.hidden_text_reasons[:_MAX_EXPLAIN_ITEMS])}"
            )
        if extracted_view.hidden_text_samples:
            details.append(f"{label} hidden text sample: {extracted_view.hidden_text_samples[0]}")
    return metrics, details[:8]


def detect_signals(
    target: TargetSpec,
    views: dict[str, ViewSnapshot],
    config: ScanConfig,
) -> list[Signal]:
    signals: list[Signal] = []
    extracted = {
        key: extract_view(view.html, view.final_url, target.normalized_url)
        for key, view in views.items()
        if view.html
    }

    browser = extracted.get("browser")
    bot = extracted.get("bot")
    headless = extracted.get("headless")
    thresholds = config.thresholds

    mismatch_codes: set[str] = set()

    if browser and bot:
        similarity = _jaccard_similarity(browser.visible_text, bot.visible_text)
        length_delta = _length_delta(browser.visible_text, bot.visible_text)
        if similarity < thresholds.similarity_min or length_delta > thresholds.length_delta_max:
            mismatch_codes.add("bot_human_mismatch")
            signals.append(
                Signal(
                    code="bot_human_mismatch",
                    message="Bot/Human content mismatch",
                    points=3,
                    metrics={
                        "similarity": round(similarity, 3),
                        "length_delta": round(length_delta, 3),
                    },
                    details=_mismatch_details(
                        browser_view=views["browser"],
                        browser_extract=browser,
                        suspicious_view=views["bot"],
                        suspicious_extract=bot,
                        suspicious_label="bot",
                    ),
                )
            )

    if browser and headless:
        similarity = _jaccard_similarity(browser.visible_text, headless.visible_text)
        length_delta = _length_delta(browser.visible_text, headless.visible_text)
        if similarity < thresholds.similarity_min or length_delta > thresholds.length_delta_max:
            mismatch_codes.add("headless_human_mismatch")
            signals.append(
                Signal(
                    code="headless_human_mismatch",
                    message="Rendered/Human content mismatch",
                    points=2,
                    metrics={
                        "similarity": round(similarity, 3),
                        "length_delta": round(length_delta, 3),
                    },
                    details=_mismatch_details(
                        browser_view=views["browser"],
                        browser_extract=browser,
                        suspicious_view=views["headless"],
                        suspicious_extract=headless,
                        suspicious_label="rendered",
                    ),
                )
            )

    hidden_text_views: list[tuple[str, object, int, list[str]]] = []
    for label, extracted_view in (("browser", browser), ("bot", bot), ("rendered", headless)):
        if extracted_view is None:
            continue
        if extracted_view.hidden_text_count <= 0 or extracted_view.hidden_text_char_count < _MIN_HIDDEN_TEXT_CHARS:
            continue
        hidden_keyword_hits, hidden_keyword_samples = _hidden_keyword_hits(
            extracted_view.hidden_text_content,
            config,
        )
        if hidden_keyword_hits <= 0 and extracted_view.hidden_external_link_count <= 0:
            continue
        hidden_text_views.append((label, extracted_view, hidden_keyword_hits, hidden_keyword_samples))
    if hidden_text_views:
        hidden_metrics, hidden_details = _hidden_text_signal_details(hidden_text_views)
        signals.append(
            Signal(
                code="hidden_text_pattern",
                message="Possible hidden text pattern",
                points=1,
                metrics=hidden_metrics,
                details=hidden_details,
            )
        )

    if browser and (bot or headless):
        suspicious_views = [entry for entry in (bot, headless) if entry is not None]
        suspicious_text = " ".join(entry.visible_text for entry in suspicious_views)
        browser_text = browser.visible_text

        categories = {
            "casino": config.keywords.casino,
            "pharma": config.keywords.pharma,
            "adult": config.keywords.adult,
        }
        for category, keywords in categories.items():
            suspicious_hits = _keyword_hits(suspicious_text, keywords)
            browser_hits = _keyword_hits(browser_text, keywords)
            if suspicious_hits - browser_hits >= thresholds.keyword_delta_min:
                keyword_samples = _matched_keyword_samples(suspicious_text, keywords)
                signals.append(
                    Signal(
                        code=f"{category}_keywords",
                        message=f"{category.capitalize()} keyword signal",
                        points=2,
                        metrics={
                            "suspicious_hits": suspicious_hits,
                            "browser_hits": browser_hits,
                        },
                        details=[
                            f"matched keywords: {_format_sample_list(keyword_samples)}"
                        ]
                        if keyword_samples
                        else [],
                    )
                )

        japanese_hits = _keyword_hits(suspicious_text, config.keywords.japanese)
        browser_japanese_hits = _keyword_hits(browser_text, config.keywords.japanese)
        highest_japanese_ratio = max(
            [entry.japanese_ratio for entry in suspicious_views] + [0.0]
        )
        if japanese_hits - browser_japanese_hits >= thresholds.keyword_delta_min:
            token_samples = _matched_keyword_samples(suspicious_text, config.keywords.japanese)
            strong_japanese_pattern = (
                highest_japanese_ratio >= thresholds.japanese_ratio_min
                and bool(mismatch_codes)
            )
            metrics: dict[str, int | float] = {
                "suspicious_hits": japanese_hits,
                "browser_hits": browser_japanese_hits,
            }
            if strong_japanese_pattern:
                metrics["ratio"] = round(highest_japanese_ratio, 3)
            signals.append(
                Signal(
                    code="japanese_spam_signal",
                    message="Japanese keyword spam pattern" if strong_japanese_pattern else "Japanese keyword signal",
                    points=3 if strong_japanese_pattern else 2,
                    metrics=metrics,
                    details=[
                        f"matched token count: {len(token_samples)}"
                    ]
                    if token_samples
                    else [],
                )
            )

    if browser and (bot or headless):
        suspicious_pairs = [
            (name, entry)
            for name, entry in (("bot", bot), ("rendered", headless))
            if entry is not None
        ]
        suspicious_views = [entry for _, entry in suspicious_pairs]
        max_outbound = max(entry.outbound_link_count for entry in suspicious_views)
        max_external_domains = max(entry.external_domain_count for entry in suspicious_views)
        max_hidden = max(entry.hidden_anchor_count for entry in suspicious_views)
        link_source_name, link_source_extract = max(
            suspicious_pairs,
            key=lambda item: (item[1].outbound_link_count, item[1].external_domain_count),
        )

        outbound_delta = max_outbound - browser.outbound_link_count
        external_domain_delta = max_external_domains - browser.external_domain_count
        hidden_delta = max_hidden - browser.hidden_anchor_count

        if (
            outbound_delta >= thresholds.outbound_link_delta_min
            or external_domain_delta >= thresholds.external_domain_delta_min
        ):
            extra_domains = _sample_added_values(browser.external_domains, link_source_extract.external_domains)
            extra_links = _sample_added_values(browser.outbound_links, link_source_extract.outbound_links)
            details: list[str] = []
            if extra_domains:
                details.append(f"new external domains ({link_source_name}): {', '.join(extra_domains)}")
            if extra_links:
                details.append(f"sample added links ({link_source_name}): {', '.join(extra_links)}")
            signals.append(
                Signal(
                    code="outbound_link_injection",
                    message="Suspicious outbound link growth",
                    points=2,
                    metrics={
                        "outbound_delta": outbound_delta,
                        "external_domain_delta": external_domain_delta,
                    },
                    details=details,
                )
            )

        if max_hidden >= thresholds.hidden_link_min and hidden_delta > 0:
            signals.append(
                Signal(
                    code="hidden_link_injection",
                    message="Possible hidden link injection",
                    points=2,
                    metrics={
                        "hidden_anchors_suspicious": max_hidden,
                        "hidden_anchors_browser": browser.hidden_anchor_count,
                    },
                    details=[f"suspicious view hidden anchors increased by {hidden_delta}"],
                )
            )

    browser_view = views.get("browser")
    bot_view = views.get("bot")
    headless_view = views.get("headless")
    if browser_view and bot_view and browser_view.final_url and bot_view.final_url:
        if _is_redirect_difference(browser_view, bot_view):
            signals.append(
                Signal(
                    code="sneaky_redirect",
                    message="Possible sneaky redirect mismatch",
                    points=3,
                    metrics={
                        "browser_final": browser_view.final_url,
                        "bot_final": bot_view.final_url,
                    },
                    details=_redirect_details(browser_view, bot_view, suspicious_label="bot"),
                )
            )
    if browser_view and headless_view and browser_view.final_url and headless_view.final_url:
        if _is_redirect_difference(browser_view, headless_view):
            signals.append(
                Signal(
                    code="js_redirect_difference",
                    message="JS redirect or render-path mismatch",
                    points=2,
                    metrics={
                        "browser_final": browser_view.final_url,
                        "headless_final": headless_view.final_url,
                    },
                    details=_redirect_details(browser_view, headless_view, suspicious_label="rendered"),
                )
            )

    return signals

