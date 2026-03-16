from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
import tomllib
from typing import Any

from cloakscan.models import (
    ConcurrencyConfig,
    KeywordConfig,
    ScanConfig,
    ThresholdsConfig,
    TimeoutsConfig,
    UserAgentConfig,
)


class ConfigError(RuntimeError):
    """Raised when config loading or validation fails."""


_DEFAULT_KEYWORDS: dict[str, list[str]] = {
    "casino": [
        "casino",
        "betting",
        "sportsbook",
        "poker",
        "slots",
        "blackjack",
        "roulette",
        "jackpot",
    ],
    "pharma": [
        "viagra",
        "cialis",
        "levitra",
        "pharmacy",
        "cheap meds",
        "no prescription",
    ],
    "adult": [
        "porn",
        "xxx",
        "adult video",
        "escort",
        "sex cam",
        "adult dating",
    ],
    "japanese": [
        "激安",
        "偽ブランド",
        "ブランドコピー",
        "オンラインカジノ",
        "アダルト",
        "医薬品",
    ],
}

_DEFAULT_USER_AGENTS = {
    "browser": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    ),
    "bot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "headless": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    ),
}

_PRESETS: dict[str, dict[str, Any]] = {
    "quick": {
        "retries": 0,
        "max_redirects": 5,
        "headless_enabled": True,
        "timeouts": {
            "http_seconds": 8.0,
            "headless_seconds": 10.0,
            "total_target_seconds": 20.0,
        },
        "thresholds": {
            "similarity_min": 0.38,
            "length_delta_max": 0.70,
            "hidden_link_min": 9,
            "japanese_ratio_min": 0.25,
            "outbound_link_delta_min": 25,
            "external_domain_delta_min": 8,
            "keyword_delta_min": 2,
        },
        "concurrency": {"http_workers": 3, "headless_workers": 1},
    },
    "balanced": {
        "retries": 1,
        "max_redirects": 8,
        "headless_enabled": True,
        "timeouts": {
            "http_seconds": 12.0,
            "headless_seconds": 18.0,
            "total_target_seconds": 35.0,
        },
        "thresholds": {
            "similarity_min": 0.46,
            "length_delta_max": 0.55,
            "hidden_link_min": 6,
            "japanese_ratio_min": 0.20,
            "outbound_link_delta_min": 15,
            "external_domain_delta_min": 5,
            "keyword_delta_min": 1,
        },
        "concurrency": {"http_workers": 3, "headless_workers": 1},
    },
    "strict": {
        "retries": 2,
        "max_redirects": 10,
        "headless_enabled": True,
        "timeouts": {
            "http_seconds": 16.0,
            "headless_seconds": 24.0,
            "total_target_seconds": 45.0,
        },
        "thresholds": {
            "similarity_min": 0.60,
            "length_delta_max": 0.40,
            "hidden_link_min": 4,
            "japanese_ratio_min": 0.15,
            "outbound_link_delta_min": 8,
            "external_domain_delta_min": 3,
            "keyword_delta_min": 1,
        },
        "concurrency": {"http_workers": 3, "headless_workers": 1},
    },
}


def available_presets() -> tuple[str, ...]:
    return tuple(_PRESETS.keys())


def _deep_merge(base: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(base)
    for key, value in updates.items():
        if (
            isinstance(value, dict)
            and key in merged
            and isinstance(merged[key], dict)
        ):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _validate_numeric_bounds(config: dict[str, Any]) -> None:
    concurrency = config["concurrency"]
    if int(concurrency["http_workers"]) < 1 or int(concurrency["headless_workers"]) < 1:
        raise ConfigError("concurrency.http_workers and concurrency.headless_workers must be >= 1")
    if int(config["retries"]) < 0:
        raise ConfigError("retries must be >= 0")
    if int(config["max_redirects"]) < 1:
        raise ConfigError("max_redirects must be >= 1")


def _sanitize_user_config(raw: dict[str, Any]) -> dict[str, Any]:
    allowed_top_keys = {
        "retries",
        "max_redirects",
        "headless_enabled",
        "timeouts",
        "thresholds",
        "keywords",
        "concurrency",
        "user_agents",
    }
    sanitized: dict[str, Any] = {}
    for key, value in raw.items():
        if key in allowed_top_keys:
            sanitized[key] = value
    return sanitized


def _build_scan_config(merged: dict[str, Any], preset: str) -> ScanConfig:
    keywords_raw = merged.get("keywords", {})
    user_agents_raw = merged.get("user_agents", {})
    return ScanConfig(
        preset=preset,
        retries=int(merged["retries"]),
        max_redirects=int(merged["max_redirects"]),
        headless_enabled=bool(merged.get("headless_enabled", True)),
        safe_mode=False,
        timeouts=TimeoutsConfig(
            http_seconds=float(merged["timeouts"]["http_seconds"]),
            headless_seconds=float(merged["timeouts"]["headless_seconds"]),
            total_target_seconds=float(merged["timeouts"]["total_target_seconds"]),
        ),
        thresholds=ThresholdsConfig(
            similarity_min=float(merged["thresholds"]["similarity_min"]),
            length_delta_max=float(merged["thresholds"]["length_delta_max"]),
            hidden_link_min=int(merged["thresholds"]["hidden_link_min"]),
            japanese_ratio_min=float(merged["thresholds"]["japanese_ratio_min"]),
            outbound_link_delta_min=int(merged["thresholds"]["outbound_link_delta_min"]),
            external_domain_delta_min=int(merged["thresholds"]["external_domain_delta_min"]),
            keyword_delta_min=int(merged["thresholds"]["keyword_delta_min"]),
        ),
        concurrency=ConcurrencyConfig(
            http_workers=int(merged["concurrency"]["http_workers"]),
            headless_workers=int(merged["concurrency"]["headless_workers"]),
        ),
        keywords=KeywordConfig(
            casino=[str(item).lower() for item in keywords_raw["casino"]],
            pharma=[str(item).lower() for item in keywords_raw["pharma"]],
            adult=[str(item).lower() for item in keywords_raw["adult"]],
            japanese=[str(item) for item in keywords_raw["japanese"]],
        ),
        user_agents=UserAgentConfig(
            browser=str(user_agents_raw["browser"]),
            bot=str(user_agents_raw["bot"]),
            headless=str(user_agents_raw["headless"]),
        ),
    )


def _default_config_for_preset(preset: str) -> dict[str, Any]:
    if preset not in _PRESETS:
        raise ConfigError(f"Unknown preset '{preset}'. Valid presets: {', '.join(available_presets())}")
    base = deepcopy(_PRESETS[preset])
    base["keywords"] = deepcopy(_DEFAULT_KEYWORDS)
    base["user_agents"] = deepcopy(_DEFAULT_USER_AGENTS)
    return base


def _read_config_file(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            parsed = tomllib.load(handle)
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid TOML config: {path} ({exc})") from exc

    if not isinstance(parsed, dict):
        raise ConfigError("Config root must be a TOML table")
    return parsed


def load_scan_config(preset: str, config_path: Path | None) -> ScanConfig:
    merged = _default_config_for_preset(preset)

    if config_path is None:
        auto_path = Path("cloakscan.toml")
        if auto_path.exists():
            user_data = _sanitize_user_config(_read_config_file(auto_path))
            merged = _deep_merge(merged, user_data)
    else:
        user_data = _sanitize_user_config(_read_config_file(config_path))
        merged = _deep_merge(merged, user_data)

    _validate_numeric_bounds(merged)
    return _build_scan_config(merged, preset=preset)


def dump_config(config: ScanConfig) -> dict[str, Any]:
    """Mostly useful for tests and debugging."""
    return asdict(config)
