# OffSeq Threat Finder

[![CI](https://github.com/offseq/threat-finder/actions/workflows/ci.yml/badge.svg)](https://github.com/offseq/threat-finder/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/threat-finder.svg)](https://crates.io/crates/threat-finder)
[![docs.rs](https://img.shields.io/docsrs/threat-finder)](https://docs.rs/threat-finder)
[![license](https://img.shields.io/crates/l/threat-finder.svg)](#license)

**threat-finder** finds the vulnerable software _actually running_ on a host — not
what a manifest claims — and tells you which findings are **network-reachable**.
It resolves each running service (and, with `--scope all`, every installed OS
package) to an exact [Package-URL](https://github.com/package-url/purl-spec) and
matches it against the [OffSeq Radar](https://radar.offseq.com) catalog using
ecosystem-native version rules, so backported/fixed builds aren't false-flagged.

![OffSeq Threat Finder](https://static.offseq.com/threat-finder-preview.svg)

```text
Vulnerability summary (highest risk first):

  openssh-server@1:8.9p1-3ubuntu0.6 — 1 finding(s)  [PUBLIC tcp 0.0.0.0:22]
      [ACT-NOW 92]  HIGH  CVE-2024-6387  [KEV]  regreSSHion: remote code execution in OpenSSH
                          → fix: 1:8.9p1-3ubuntu0.10   https://radar.offseq.com/threat/…
  nginx@1.18.0-6ubuntu14.4 — 1 finding(s)
      [SCHEDULE 41] MED   CVE-2023-44487        HTTP/2 Rapid Reset

2 confirmed finding(s) across 2 asset(s); 1 exposed, 1 known-exploited.
```

## Install

```sh
brew install offseq/tap/threat-finder   # Homebrew (macOS/Linux), prebuilt
cargo binstall threat-finder            # prebuilt binary, no toolchain
cargo install threat-finder             # from source
```

Prebuilt archives for Linux/macOS (x86_64 + arm64) and Windows (x86_64) are on
the [releases page](https://github.com/offseq/threat-finder/releases/latest).
Requires Rust ≥ 1.87 to build from source. Linux, macOS, the BSDs, and Windows
are all supported.

## Quickstart

```sh
export OFFSEQ_API_KEY=...    # from https://radar.offseq.com/console
threat-finder
```

Scans the running services, prints a risk-ranked summary, and writes the full
JSON report to `/tmp/threats.json`. Add `--scope all` to also scan every
installed OS package.

## Usage

```sh
threat-finder [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `-o, --output <PATH>` | Write the JSON report to `PATH` (default: prompt, or `/tmp/threats.json`) |
| `--json` | Print the JSON report to stdout instead of a file |
| `--scope <SCOPE>` | `running` (default) or `all` (+ every installed OS package) |
| `--severity <LEVEL>` | Only report findings at/above `critical\|high\|medium\|low` |
| `--strict` | Drop coordinate-unconfirmed findings (report only confirmed) |
| `--fail-on <WHAT>` | Exit `5` if matching findings exist: `any\|critical\|high\|medium\|low\|kev\|exposed` |
| `--sarif <PATH>` | Also write a SARIF 2.1.0 report (for code-scanning UIs) |
| `--include <GLOB>` / `--exclude <GLOB>` | Filter assets by name glob (repeatable) |
| `-q, --quiet` | Suppress the banner, progress, and summary |
| `--no-color` | Disable ANSI colors |
| `-y, --yes` | Assume defaults, never prompt (CI/cron) |
| `--reset` | Re-enter the API key, ignoring the saved one |
| `--register` | Register the scanned host with Radar for continuous monitoring (no prompt) |
| `--no-register` | Don't register or prompt for monitoring this run |
| `--host-name <NAME>` | Friendly hostname to send with a registration |
| `--unregister` | Remove this host's inventory from Radar and exit |
| `--windows-missing-updates` | (Windows) Also list pending security updates from the Windows Update Agent (online scan; run elevated) |
| `-h, --help` / `-V, --version` | Help / version |

```sh
# CI: only high+ findings, JSON to stdout, no prompts
OFFSEQ_API_KEY=… threat-finder --yes --json --severity high > report.json

# Fail the build only when a network-exposed service has a known-exploited CVE
OFFSEQ_API_KEY=… threat-finder --yes --quiet --fail-on exposed
```

**Exit codes:** `0` ok · `1` lookup/IO error · `2` no API key · `3` unsupported
OS · `4` rate limit/quota, or API access required (upgrade needed) · `5`
`--fail-on` threshold met.

**API key** (get one from the [Radar Console](https://radar.offseq.com/console)),
resolved in order:

1. `OFFSEQ_API_KEY` environment variable (best for CI/cron).
2. The saved key in `$XDG_CONFIG_HOME/offseq-rust/config.toml` (`0600`),
   unless `--reset` is given.
3. An interactive, hidden prompt on a TTY — then saved for next time.

Non-interactive (`--yes` / no TTY) with no key available exits `2`.

Set `OFFSEQ_CONFIG_DIR` to override where the config lives (default: the OS
per-user config dir) — handy for containers/CI that need a deterministic path.

## How it works

**Exact-coordinate matching.** Each asset becomes a purl carrying its _full_
version (epoch + distro revision) and a `?distro=` qualifier, e.g.
`pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.6?distro=jammy`. The inventory is
matched in batched `POST /match/batch` calls (one request per tier-sized chunk)
**server-side, with ecosystem-native version rules** (dpkg/rpm/apk/semver) — so a
backported-and-fixed build like `1.18.0-6+deb11u3` is correctly not flagged, and
there's no client-side version guessing. Findings are split by the API's
`confirmed` flag: confirmed matches are reported; coordinate matches whose
version can't be confirmed are surfaced separately as **unconfirmed / triage**
(excluded from the count, `byCve`, and `--fail-on`; drop them with `--strict`).

**Network-exposure correlation.** Manifest scanners (Trivy, Grype, osv-scanner)
read package lists; external scanners (Nessus, OpenVAS) need a second host. This
tool maps each running service's process to the sockets it is **listening** on
(`/proc/net` on Linux, `lsof` on the other Unixes, `Get-NetTCPConnection` /
`netstat` on Windows) and classifies reachability —
`loopback` / `private` / `public`. A vulnerable service on `0.0.0.0` is a very
different risk from one on `127.0.0.1`: findings rank exposed-first and
`--fail-on exposed` gates CI on exactly that. No packets are sent. Findings also
carry CISA **KEV** and **EPSS**.

**Exposure-aware prioritization.** Every finding gets a `riskScore` (0–100) and an
SSVC-style `decision` band — **`act-now` · `soon` · `schedule` · `track`** — fused
from severity, EPSS, KEV, and the owning asset's **network exposure**. The summary
leads each line with a `[ACT-NOW 92]`-style badge and sorts by it, so the handful
of public-facing, known-exploited issues float to the top of a noisy host. The
score uses the same formula locally and server-side (the Radar monitoring view
adds a small bonus when a KEV finding is past its due date — a date the CLI
doesn't have), and appears in `--json` and SARIF (`properties`).

## Continuous monitoring

A one-off scan is a point in time. Register a host once and Radar keeps watching:
when a **newly-published CVE** affects one of its coordinates, you get an alert
(email + Console), prioritized by exposure — no re-scan needed.

After an interactive scan, the tool asks:

```text
Add these 42 services to Radar for continuous monitoring & alerts? [Y/n/never]
```

`Y` registers this host; `n` skips this run; `never` remembers your choice (it's
saved to the config and you won't be asked again). On a re-scan it also reports
**drift** (`+added / -removed / ~changed`) and any findings **new since your last
scan**. Manage your hosts — toggle monitoring, view findings, deregister — under
**Inventory** in the [Radar Console](https://radar.offseq.com/console).

For automation, skip the prompt: `--register` registers non-interactively (off by
default in CI), `--no-register` opts out, `--host-name <NAME>` labels the host, and
`--unregister` removes it. A stable per-host id and your prompt preference live in
`$XDG_CONFIG_HOME/offseq-rust/config.toml`. Registration never changes the exit
code — a monitoring hiccup won't fail your scan. Requires a Basic/Pro/Enterprise
plan (or Pro Console).

## Scope & coverage

`--scope running` (default) scans live services — the small, high-signal set
whose exposure can be correlated. `--scope all` additionally enumerates **every
installed OS package** (`dpkg`/`rpm`/`pacman`/`apk`/`brew`/`pkg`/`pkg_info`),
expanding the matched surface 10–50×. A package that also backs a running,
exposed process keeps that exposure (assets are deduplicated and merged by
coordinate). The kernel is covered as its package (`linux-image…`) under
`--scope all`.

> `--scope all` can yield hundreds–thousands of packages. On the free tier
> (15 lookups/hour) this will rate-limit; the tool warns when the inventory
> exceeds the budget. (Lookups are already batched; a local result cache is on
> the roadmap.)

## Per-OS support

| OS | Discovery | Coordinate source |
|----|-----------|-------------------|
| Linux (systemd) | `ListUnits` → `/proc/<pid>/exe` | dpkg / rpm / pacman / apk |
| Linux (SysV/OpenRC) | `service --status-all` / `rc-status` | package DB |
| macOS | `launchctl list` → `ps` (third-party only) | Homebrew |
| FreeBSD / DragonFly | `service -e` | `pkg` |
| OpenBSD | `rcctl ls started` | `pkg_info` |
| NetBSD | `/etc/rc.d` status | `pkg_info` |
| Solaris / illumos | `svcs` → `svcprop` | probe (`--version`) |
| Windows | `Win32_Service` → `Get-NetTCPConnection` / `netstat` | registry / winget / Appx / Chocolatey / Scoop → CPE; npm / pip / dotnet → purl; the OS build → CPE |

Where no package owns a binary, the version falls back to a hardened `--version`
probe (absolute path only, sanitized env). On macOS, Apple system services
(`com.apple.*`, SIP-protected paths) are skipped — they're covered by the OS
version, and probing hundreds of them is pointless.

On **Windows**, everything is gathered via the built-in `powershell.exe`
(no extra runtime, no admin for the core inventory). Installed apps map to NVD
CPEs through a curated name table (unmapped apps fall back to a name search
rather than a wrong guess); the OS edition/build becomes a feature-qualified OS
CPE (e.g. `windows_11_23h2`); and `--windows-missing-updates` adds an opt-in
Windows Update Agent advisory of pending security patches.

## Output

JSON, with deterministic (sorted) keys and no timestamp, so reports diff cleanly:

- **`services`** — `pkg@version` → confirmed findings (`cveId`, `severity`,
  `cvssScore`, `epss`, `kev`, `riskScore`, `decision`, `confirmed`, `matchedRange`,
  `matchBasis`, `fixedVersions`, `remediation`, `cwes`, `references`, `radarUrl`),
  highest-risk first.
- **`unconfirmed`** — coordinate matches whose version couldn't be confirmed (triage).
- **`assets`** — `pkg@version` → `{ exe, versionSource, exposed, reachability, listeners }`
  (`versionSource` = `package-db` | `probe`; `reachability` covers TCP **and** UDP).
- **`byCve`** — each CVE rolled up across every affected asset ("patch once, fix many").
- **`errors`** — per-asset lookup failures, so a failure never reads as "clean".
- **`registration`** — present when the run registered the host: `host_id`,
  `monitoring`, `drift`, `summary`, `newSinceLastCount`.
- **`meta`** — `{ tool, version, schemaVersion }` (`schemaVersion` 2).

A SARIF 2.1.0 report (`--sarif`) is also available for code-scanning UIs.

## The OffSeq ecosystem

| | |
|---|---|
| [**OffSeq**](https://offseq.com) | EU security audits, threat monitoring, CISO-as-a-Service, NIS2 compliance |
| [**Radar**](https://radar.offseq.com) | Real-time threat intelligence — the catalog threat-finder matches against |
| [**Radar Console**](https://radar.offseq.com/console) | Subscriptions, custom feeds, and your `OFFSEQ_API_KEY` |
| [**Radar API**](https://radar.offseq.com/api-docs) | REST docs for the `/match` endpoint used here |
| [**Radar Threats**](https://radar.offseq.com/threats) | Searchable CVE / malware / threat-actor database |
| [**Radar Feeds**](https://radar.offseq.com/feeds) | Custom feeds aggregating CISA, CIRCL, ThreatFox, … |
| [**Radar Pricing**](https://radar.offseq.com/pricing) | Free tier through Enterprise |
| [**Breach**](https://breach.offseq.com) | Dark-web data-leak & exposed-credential monitoring |
| [**Veil**](https://veil.offseq.com) | Client-side PNG steganography (AES-256-GCM) |
| [**Guard**](https://offseq.com/guard/) | AI website security & compliance analyst |
| [**Training**](https://training.offseq.com) | PECB-accredited security & privacy courses |

## Development

```sh
cargo build --release
cargo test                 # unit tests
cargo test -- --ignored    # + macOS live-discovery smoke test
cargo clippy --all-targets
```

The engine is a library crate (`find_threats`) with a `Collector` abstraction
(running-services and os-packages today; lockfiles / containers / SBOM next), so
the binary is a thin CLI over it.

## License

Dual-licensed under [MIT](LICENSE) or [Apache-2.0](LICENSE), at your option.
