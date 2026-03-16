# Cloakscan

Cloakscan is a terminal-first scanner for SEO professionals to triage likely cloaked SEO spam and related hacked-site symptoms.

## Features

- Compare three views of each target:
  - Browser-like HTTP fetch
  - Bot-like HTTP fetch
  - Headless-rendered DOM (Playwright)
- Detect likely cloaking, spam keyword injections, hidden/outbound link anomalies, and redirect mismatches.
- Print compact per-target results, optional explain-mode metrics, and batch progress with ETA.
- Return automation-friendly exit codes:
  - `0`: all targets CLEAN/LOW
  - `1`: at least one MEDIUM/HIGH
  - `2`: fatal runtime/config error
  - `3`: partial target failures, none MEDIUM/HIGH

## Usage

```bash
python cloakscan.py scan https://example.com --preset balanced
python cloakscan.py scan --input targets.txt --explain
python cloakscan.py scan example.com --no-headless --no-new-window
```

## Input separators

Supported separators for `--input` files:

- newline
- semicolon (`;`)
- standalone colon delimiter (` : ` with spaces around it)

`/` is not treated as a separator.

## Config file

Default config file path: `./cloakscan.toml` (loaded automatically if present). You can also pass `--config`.

Top-level configurable keys:

- `retries`
- `max_redirects`
- `headless_enabled`
- `[timeouts]`
- `[thresholds]`
- `[keywords]`
- `[concurrency]`
- `[user_agents]`

## New terminal behavior

When launched as `python cloakscan.py ...`, Cloakscan attempts to open a new terminal window by default. This is best-effort only:

- If unsupported or unavailable, Cloakscan continues in the current terminal.
- Fallback is setting terminal title to `Cloakscan`.
- Disable spawning via `--no-new-window`.
- Spawning is automatically suppressed in CI/non-interactive environments.

## Security posture

- Dependencies should be pinned by deployment tooling.
- Prefer hash-checked installs for integrity (`pip --require-hashes` workflows).
- Optional environment audit with `pip-audit`.

## Limitations

- Cloakscan does not and will not emulate Googlebot IP/DNS identity.
- Cloakscan is heuristic triage, not full forensic analysis or remediation.
