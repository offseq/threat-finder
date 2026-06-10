# OffSeq Threat Finder

[![CI](https://github.com/offseq/threat-finder/actions/workflows/ci.yml/badge.svg)](https://github.com/offseq/threat-finder/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/threat-finder.svg)](https://crates.io/crates/threat-finder)
[![docs.rs](https://img.shields.io/docsrs/threat-finder)](https://docs.rs/threat-finder)
![license](https://img.shields.io/crates/l/threat-finder.svg)

A command-line tool that discovers the services running on a host, determines
their versions, and matches them against known vulnerabilities from the
[OffSeq](https://radar.offseq.com) threat API.

It works across Linux (systemd / SysV / OpenRC), macOS (launchd), the BSDs, and
Solaris/illumos, resolving each running service to its real binary and — where
possible — reading the version straight from the OS package database rather than
executing the service.

## Install

```sh
# From crates.io (compiles from source)
cargo install threat-finder

# Prebuilt binary, no toolchain needed (Linux/macOS, x86_64 + arm64)
cargo binstall threat-finder
```

Or grab a prebuilt archive from the
[latest release](https://github.com/offseq/threat-finder/releases/latest)
and put `threat-finder` on your `PATH`. To build from source:

```sh
cargo build --release   # -> target/release/threat-finder
```

Requires a recent stable Rust toolchain (edition 2021, Rust ≥ 1.87). Linux and
macOS are supported (Windows is not — discovery relies on Unix facilities).

## Usage

```sh
threat-finder [OPTIONS]
```
![OffSeq Threat Finder Preview](https://static.offseq.com/threat-finder-preview.svg)

| Flag | Description |
|------|-------------|
| `-o, --output <PATH>` | Write the JSON report to `PATH` (default: prompt, or `/tmp/threats.json`) |
| `--json` | Print the JSON report to stdout instead of a file |
| `--scope <SCOPE>` | `running` (default — live services only) or `all` (+ every installed OS package) |
| `--severity <LEVEL>` | Only report threats at/above a severity (`critical\|high\|medium\|low`) |
| `--fail-on <WHAT>` | Exit `5` if matching findings exist: `any\|critical\|high\|medium\|low\|kev\|exposed` (CI gating) |
| `--strict` | Only report confirmed matches (ask the API to omit coordinate-unconfirmed) |
| `--sarif <PATH>` | Also write a SARIF 2.1.0 report (for code-scanning UIs) |
| `--include <GLOB>` / `--exclude <GLOB>` | Filter scanned services by name glob (repeatable) |
| `-q, --quiet` | Suppress the banner, progress, and summary |
| `--no-color` | Disable ANSI colors in the summary |
| `-y, --yes` | Assume defaults, never prompt — for CI/cron |
| `--reset` | Re-enter the API key, ignoring the saved one |
| `-h, --help` / `-V, --version` | Help / version |

### Exit codes

`0` success · `1` lookup/IO error · `2` no API key · `3` unsupported OS ·
`4` rate limit/quota exhausted · `5` `--fail-on` threshold met.

### API key

You need an OffSeq API key (get one at <https://radar.offseq.com/console>).
It is resolved in this order:

The `OFFSEQ_API_KEY` environment variable (best for CI/cron).

### Examples

```sh
# Interactive, writes /tmp/threats.json by default
threat-finder

# CI/cron: env key, no prompts, only high+ findings, report to stdout
OFFSEQ_API_KEY=… threat-finder --yes --json --severity high > report.json

# Fail the build only when a network-exposed service has a known-exploited CVE
OFFSEQ_API_KEY=… threat-finder --yes --quiet --fail-on exposed
```

## How matching works

Each discovered asset is turned into a **Package-URL (purl)** carrying its *full*
version — epoch and distro revision included — plus a `?distro=` qualifier, e.g.
`pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.16?distro=focal`. The whole host
inventory is sent in batched `POST /match/batch` calls (one request per
tier-sized chunk) and matched **server-side with ecosystem-native version rules**
(dpkg/rpm/apk/semver). This means a backported-and-fixed build such as
`1.18.0-6+deb11u3` is correctly **not** flagged — there is no client-side version
guessing anymore.

Results are split by the API's `confirmed` flag: confirmed matches (the target
version is inside an affected range) are the reported findings; coordinate
matches whose version can't be confirmed are surfaced separately as
**unconfirmed / triage** (kept out of the count, `byCve`, and `--fail-on`). Use
`--strict` to drop the unconfirmed set entirely. Assets with no buildable
coordinate (currently the BSDs) fall back to a name `?search=` and are reported
as unconfirmed.

## What makes it different: network-exposure correlation

Most scanners read package *manifests* (Trivy, Grype, osv-scanner) or probe a
host from the *outside* (Nessus, OpenVAS). This tool inspects what is actually
**running**, maps each service's process to the TCP sockets it is **listening**
on (via `/proc/net` on Linux, `lsof` elsewhere), and flags whether any listener
is reachable off-host. A vulnerable service bound to `0.0.0.0` is a very
different risk from one bound to `127.0.0.1` — findings are ranked
exposed-first, and `--fail-on exposed` gates CI on exactly that. No packets are
sent; it is all local runtime state.

Findings are also enriched with CISA **KEV** (known-exploited) flags, **EPSS**
scores, and CVSS vectors, and sorted highest-risk-first deterministically.

## Scan scope & coverage

By default the tool scans **running services** — the small, high-signal set whose
exposure it can correlate. `--scope all` additionally enumerates **every
installed OS package** (`dpkg`/`rpm`/`pacman`/`apk`/`brew`/`pkg`/`pkg_info`),
expanding the matched surface from a handful of services to the full package
inventory (10–50×) so far more of the Radar catalog applies. A package that also
backs a running, exposed process keeps its exposure (assets are deduplicated and
merged), so prioritization survives the wider inventory.

> Note: `--scope all` can produce hundreds–thousands of unique packages. On the
> free tier (15 lookups/hour) this will rate-limit; bulk lookups and a local
> cache are planned. The tool warns when the inventory exceeds the free-tier
> budget.

Internally the engine is a library crate (`find_threats`) with a `Collector`
abstraction (running-services and os-packages today; lockfiles / containers /
SBOM are future collectors), so the binary is a thin CLI over it.

## Per-OS support

| OS | Discovery | Version source |
|----|-----------|----------------|
| Linux (systemd) | `ListUnits` → `/proc/<pid>/exe` / `ExecStart` | dpkg / rpm / pacman / apk → probe |
| Linux (SysV/OpenRC) | `service --status-all` / `rc-status` | package DB → probe |
| macOS | `launchctl list` → `ps` (third-party only) | Homebrew Cellar → probe |
| FreeBSD / DragonFly | `service -e` (running) | `pkg which` → probe |
| OpenBSD | `rcctl ls started` | `pkg_info -E` → probe |
| NetBSD | `/etc/rc.d` status | `pkg_info -Fe` → probe |
| Solaris / illumos | `svcs` → `svcprop start/exec` | probe |

On macOS, Apple system services (`com.apple.*` and SIP-protected system
binaries) are intentionally skipped — they are covered by the OS-version system
lookup, and probing hundreds of them is pointless and slow.

## Output

JSON with:

- `services` — `name@version` → array of **confirmed** findings (each with
  `severity`, `kev`, `epss`, `cvssScore`, `references`, `confirmed`,
  `matchedRange`, and `matchBasis` = `coordinate` / `cpe` / `search-fallback`),
  sorted highest-risk-first.
- `unconfirmed` — `name@version` → coordinate matches whose version couldn't be
  confirmed (triage), kept out of the primary count.
- `assets` — `name@version` → `{ exe, versionSource, exposed, reachability, listeners }`,
  where `versionSource` is `package-db` (authoritative) or `probe` (heuristic) and
  `reachability` is `loopback` / `private` / `public` (TCP **and** UDP listeners).
- `byCve` — each CVE rolled up across every confirmed-affected asset (the "patch
  once, fix many" remediation view).
- `errors` — per-asset lookup failures, so a failed lookup is never silently
  reported as "no vulnerabilities".
- `meta` — `{ tool, version, schemaVersion }`.

Keys are sorted (BTreeMap) and there is no timestamp, so reports diff cleanly
across runs.

## Tests

```sh
cargo test                 # unit tests (matching engine, helpers, CLI)
cargo test -- --ignored    # also run the macOS live-discovery smoke test
```
