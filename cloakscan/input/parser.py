from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import urlparse

from cloakscan.models import TargetSpec


def _normalize_url_parts(parsed_url: str) -> str:
    parsed = urlparse(parsed_url)
    if parsed.path:
        return parsed_url
    suffix = "/" if not parsed_url.endswith("/") else ""
    return f"{parsed_url}{suffix}"


def normalize_target(raw_target: str) -> TargetSpec:
    raw = raw_target.strip()
    parsed = urlparse(raw)
    if parsed.scheme in {"http", "https"}:
        normalized = _normalize_url_parts(raw)
        return TargetSpec(raw=raw, normalized_url=normalized, fallback_url=None)
    if parsed.scheme:
        raise ValueError(f"Unsupported target scheme '{parsed.scheme}'")

    cleaned = raw.lstrip("/")
    https_url = _normalize_url_parts(f"https://{cleaned}")
    http_url = _normalize_url_parts(f"http://{cleaned}")
    return TargetSpec(raw=raw, normalized_url=https_url, fallback_url=http_url)


def parse_text_targets(input_text: str) -> list[str]:
    if not input_text.strip():
        return []

    # Primary separators: newline + semicolon.
    normalized = input_text.replace(";", "\n")
    chunks = [line.strip() for line in normalized.splitlines() if line.strip()]

    targets: list[str] = []
    for chunk in chunks:
        # Colon acts as a separator only when used as a standalone delimiter
        # between targets (spaces required around it), preserving URLs like
        # https://example.com and host:port.
        split_parts = re.split(r"\s+:\s+", chunk.strip())
        for part in split_parts:
            target = part.strip()
            if target and target != ":":
                targets.append(target)
    return targets


def _read_input_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Failed to read input file {path}: {exc}") from exc


def collect_targets(cli_targets: list[str], input_path: Path | None) -> list[TargetSpec]:
    raw_targets: list[str] = []

    for target in cli_targets:
        cleaned = target.strip()
        if not cleaned:
            continue
        if cleaned in {":", ";"}:
            continue
        raw_targets.append(cleaned)

    if input_path is not None:
        file_text = _read_input_file(input_path)
        raw_targets.extend(parse_text_targets(file_text))

    # Preserve order while deduplicating exact target values.
    deduped: list[str] = []
    seen: set[str] = set()
    for target in raw_targets:
        if target not in seen:
            deduped.append(target)
            seen.add(target)

    targets: list[TargetSpec] = []
    for target in deduped:
        try:
            targets.append(normalize_target(target))
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc
    return targets
