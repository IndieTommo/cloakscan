from __future__ import annotations

from cloakscan.models import RiskLabel, RunSummary, Signal, TargetResult


def classify_risk(signals: list[Signal]) -> tuple[RiskLabel, int]:
    score = sum(signal.points for signal in signals)
    codes = {signal.code for signal in signals}

    if "sneaky_redirect" in codes:
        score = max(score, 3)

    if (
        "bot_human_mismatch" in codes
        and any(code in codes for code in ("casino_keywords", "pharma_keywords", "adult_keywords"))
    ):
        score = max(score, 3)

    # A rendered-only text/link delta is still worth surfacing, but it is too
    # noisy to auto-promote to MEDIUM without stronger signals.
    if "outbound_link_injection" in codes and codes.issubset(
        {"headless_human_mismatch", "outbound_link_injection"}
    ):
        score = min(score, 2)

    if score <= 0:
        return "CLEAN", 0
    if score <= 2:
        return "LOW", score
    if score <= 5:
        return "MEDIUM", score
    return "HIGH", score


def summarize_reason(signals: list[Signal]) -> str:
    if not signals:
        return "No major cloaking/spam indicators"
    top = sorted(signals, key=lambda item: item.points, reverse=True)[:3]
    return " + ".join(signal.message for signal in top)


def build_summary(results: list[TargetResult], runtime_seconds: float) -> RunSummary:
    clean_count = 0
    low_count = 0
    medium_count = 0
    high_count = 0
    failures_count = 0
    partial_count = 0

    for result in results:
        if result.failed:
            failures_count += 1
            continue
        if result.incomplete:
            partial_count += 1
            if result.risk == "CLEAN":
                continue
        if result.risk == "CLEAN":
            clean_count += 1
        elif result.risk == "LOW":
            low_count += 1
        elif result.risk == "MEDIUM":
            medium_count += 1
        elif result.risk == "HIGH":
            high_count += 1

    return RunSummary(
        targets_total=len(results),
        clean_count=clean_count,
        low_count=low_count,
        medium_count=medium_count,
        high_count=high_count,
        failures_count=failures_count,
        runtime_seconds=runtime_seconds,
        partial_count=partial_count,
    )


def compute_exit_code(summary: RunSummary) -> int:
    if summary.medium_count > 0 or summary.high_count > 0:
        return 1
    if summary.failures_count > 0 or summary.partial_count > 0:
        return 3
    return 0
