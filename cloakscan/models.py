from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

RiskLabel = Literal["CLEAN", "LOW", "MEDIUM", "HIGH"]
DebugValue = str | int | float | bool | None


@dataclass(slots=True)
class TimeoutsConfig:
    http_seconds: float = 12.0
    headless_seconds: float = 18.0
    total_target_seconds: float = 35.0


@dataclass(slots=True)
class ThresholdsConfig:
    similarity_min: float = 0.46
    length_delta_max: float = 0.55
    hidden_link_min: int = 6
    japanese_ratio_min: float = 0.20
    outbound_link_delta_min: int = 15
    external_domain_delta_min: int = 5
    keyword_delta_min: int = 1


@dataclass(slots=True)
class ConcurrencyConfig:
    http_workers: int = 3
    headless_workers: int = 1


@dataclass(slots=True)
class KeywordConfig:
    casino: list[str] = field(default_factory=list)
    pharma: list[str] = field(default_factory=list)
    adult: list[str] = field(default_factory=list)
    japanese: list[str] = field(default_factory=list)


@dataclass(slots=True)
class UserAgentConfig:
    browser: str
    bot: str
    headless: str


@dataclass(slots=True)
class ScanConfig:
    preset: str
    retries: int
    max_redirects: int
    headless_enabled: bool
    safe_mode: bool
    timeouts: TimeoutsConfig
    thresholds: ThresholdsConfig
    concurrency: ConcurrencyConfig
    keywords: KeywordConfig
    user_agents: UserAgentConfig


@dataclass(slots=True)
class TargetSpec:
    raw: str
    normalized_url: str
    fallback_url: str | None = None
    used_fallback: bool = False


@dataclass(slots=True)
class ViewSnapshot:
    profile: str
    requested_url: str
    final_url: str
    status_code: int | None
    html: str
    redirect_chain: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code is not None and self.status_code < 500


@dataclass(slots=True)
class ExtractedView:
    title: str
    visible_text: str
    text_length: int
    outbound_link_count: int
    external_domain_count: int
    hidden_anchor_count: int
    japanese_ratio: float
    outbound_links: list[str] = field(default_factory=list)
    external_domains: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Signal:
    code: str
    message: str
    points: int
    metrics: dict[str, float | int | str] = field(default_factory=dict)
    details: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DebugEvent:
    phase: str
    elapsed_seconds: float
    details: dict[str, DebugValue] = field(default_factory=dict)


@dataclass(slots=True)
class TargetResult:
    target: TargetSpec
    risk: RiskLabel
    score: int
    reason: str
    signals: list[Signal] = field(default_factory=list)
    debug_events: list[DebugEvent] = field(default_factory=list)
    views: dict[str, ViewSnapshot] = field(default_factory=dict)
    failed: bool = False
    incomplete: bool = False
    warnings: list[str] = field(default_factory=list)
    error: str | None = None
    runtime_seconds: float = 0.0


@dataclass(slots=True)
class RunSummary:
    targets_total: int
    clean_count: int
    low_count: int
    medium_count: int
    high_count: int
    failures_count: int
    runtime_seconds: float
    partial_count: int = 0
