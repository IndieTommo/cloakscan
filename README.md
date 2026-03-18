# Cloakscan

Cloakscan is a terminal-first Python scanner for spotting cloaked SEO spam, bot-only redirects, suspicious rendered content changes, and related hacked-site symptoms.

## Quick Start

PowerShell, from the project folder:

```powershell
python -m pip install typer rich httpx playwright beautifulsoup4
python -m playwright install chromium
python cloakscan.py
```

That opens the Cloakscan terminal window. Inside it, run commands like:

```powershell
scan https://example.com
scan https://example.com --explain
scan domains.txt
help
clear
exit
```

If you do not want a separate window:

```powershell
python cloakscan.py scan https://example.com --no-new-window
```

## Interactive Commands

When you start with:

```powershell
python cloakscan.py
```

You can type these directly in the Cloakscan window:

- `scan <target...> [options]`
- `help`
- `clear` or `cls`
- `exit` or `quit`

## What Cloakscan Checks

For each target, Cloakscan compares up to three views:

- browser-like HTTP fetch
- bot-like HTTP fetch
- headless rendered DOM via Playwright

It can detect:

- bot/human content mismatch
- rendered/human content mismatch
- suspicious outbound link growth
- hidden link injection
- spam keyword signals
- bot-only or JS redirect mismatches
- incomplete scans caused by TLS/fetch problems on one of the views

## Main Scan Options

```text
--input PATH
--preset [quick|balanced|strict]
--config PATH
--explain
--debug
--tls-debug
--cache-bust / --no-cache-bust
--safe
--no-headless
--no-new-window
--help
```

What they do:

- `--input PATH`
  - read targets from a text file
- `--preset`
  - `quick`: faster, less sensitive
  - `balanced`: default
  - `strict`: slower, more sensitive
- `--config PATH`
  - use a specific TOML config file
- `--explain`
  - print measured signal details and evidence snippets
- `--debug`
  - print phase timings and scan metadata
- `--tls-debug`
  - after a bot TLS failure, retry that bot fetch without certificate verification to reveal redirect/certificate path details for debugging
  - diagnostic only
  - not the default behavior
- `--cache-bust`
  - enabled by default
  - adds per-profile cache-busting tokens to reduce false negatives on cached sites
- `--no-cache-bust`
  - disables cache-busting
- `--safe`
  - safer mode
  - disables headless rendering
  - keeps strict network safeguards
- `--no-headless`
  - disables the rendered DOM check only
- `--no-new-window`
  - stay in the current terminal

## Examples

Single target:

```powershell
scan https://example.com
```

Single target with more detail:

```powershell
scan https://example.com --explain --debug
```

TLS/redirect diagnosis for bot-only issues:

```powershell
scan https://example.com --explain --debug --tls-debug
```

Safer HTTP-only style triage:

```powershell
scan https://example.com --safe
```

Batch scan from file:

```powershell
scan domains.txt
```

Direct one-shot invocation from PowerShell:

```powershell
python cloakscan.py scan https://example.com --preset balanced --no-new-window
```

## Input Rules

Targets can come from CLI arguments or `--input`.

Supported separators inside input text:

- newline
- semicolon (`;`)
- standalone colon delimiter (` : `)

Not supported as separators:

- `/`

That means URLs like `https://example.com/` are preserved correctly.

Useful behavior:

- `scan domains.txt` auto-detects a single existing local text file and treats it as input
- bare domains are normalized to `https://domain/`
- if the HTTPS browser fetch fails and a fallback exists, Cloakscan can fall back to `http://domain/`

## Presets

Current built-in presets are:

- `quick`
  - shortest timeouts
  - least sensitive thresholds
  - good for fast first-pass checks
- `balanced`
  - default
  - recommended for normal use
- `strict`
  - longest timeouts
  - most sensitive thresholds
  - more likely to surface borderline differences

## Config File

Default config file:

```text
./cloakscan.toml
```

If present, it is loaded automatically. You can also pass `--config`.

Recommended workflow:

```powershell
Copy-Item .\cloakscan.toml.example .\cloakscan.toml
```

Config areas available in TOML:

- `retries`
- `max_redirects`
- `headless_enabled`
- `[timeouts]`
- `[thresholds]`
- `[keywords]`
- `[concurrency]`
- `[user_agents]`

See `cloakscan.toml.example` for the current template.

## Output Meanings

Per target, you will typically see one of these:

- `CLEAN`
  - no significant signal found
- `LOW`
  - weak or noisy signal found
- `MEDIUM`
  - meaningful suspicious evidence found
- `HIGH`
  - strong evidence found
- `PARTIAL`
  - the scan did not complete cleanly for all expected views

You may also see partial evidence wording such as:

```text
MEDIUM example.com - Possible sneaky redirect mismatch (partial evidence: bot TLS failed)
```

That means:

- Cloakscan found a real suspicious signal
- but one required fetch path also had an acquisition problem

Summary lines:

- `Partial scans`
  - targets where one or more expected views did not complete cleanly
- `Failures`
  - hard failures where the target scan itself failed

## Exit Codes

- `0`
  - all targets are `CLEAN` or `LOW`, with no partials/failures
- `1`
  - at least one target is `MEDIUM` or `HIGH`
- `2`
  - fatal runtime or config error
- `3`
  - no `MEDIUM`/`HIGH`, but at least one partial scan or failure

## Security Notes

Defaults are intentionally conservative:

- strict TLS verification is on by default
- private/local destinations are blocked by default
- only `http` and `https` are allowed
- raw HTML is not saved to disk by default

Important flags:

- `--safe`
  - best low-risk mode for routine checks
- `--tls-debug`
  - opt-in diagnostic mode for bot TLS failures
  - uses insecure verification only for the debug retry path
  - useful for your own sites and investigations
  - should not be your default workflow for unknown targets

Practical safety note:

- By default cloakscan does not persist crawled page bodies to disk.
- `--safe` is the lowest-risk mode for normal use.
- Normal mode is still not zero-risk, because headless rendering executes untrusted page JavaScript in Chromium.
- For highly suspicious targets, a VM, container, or separate low-privilege user account is still the better operating model.

## Terminal Behavior

When you launch with:

```powershell
python cloakscan.py
```

Cloakscan tries to open a dedicated terminal window titled `Cloakscan`.

Behavior:

- best effort only
- if unsupported, it stays in the current terminal
- `--no-new-window` disables spawning
- in CI/non-interactive environments, spawning is suppressed automatically

## Limitations

- Cloakscan does not emulate Googlebot IP identity or reverse-DNS trust
- Cloakscan is heuristic triage, not a full forensic platform
- `--tls-debug` is diagnostic; it helps explain a bot TLS failure, but it does not change the secure default scan path
- headless rendering executes untrusted page JavaScript, so `--safe` is the lower-risk option for routine use
