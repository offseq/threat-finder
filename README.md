# OffSeq Threat Finder

A command-line tool that discovers the services running on a host, determines
their versions, and matches them against known vulnerabilities from the
[OffSeq](https://radar.offseq.com) threat API.

It works across Linux (systemd / SysV / OpenRC), macOS (launchd), the BSDs, and
Solaris/illumos, resolving each running service to its real binary and — where
possible — reading the version straight from the OS package database rather than
executing the service.

## Build

```sh
cargo build --release
# binary at target/release/threat-finder
```

Requires a recent stable Rust toolchain (edition 2021, Rust ≥ 1.87 — the
dependency set pulls in crates that need it).

## Usage

```sh
threat-finder [OPTIONS]
```
![OffSeq Threat Finder Preview](https://static.offseq.com/threat-finder-preview.svg)

| Flag | Description |
|------|-------------|
| `-o, --output <PATH>` | Write the JSON report to `PATH` (default: prompt, or `/tmp/threats.json`) |
| `--json` | Print the JSON report to stdout instead of a file |
| `--severity <LEVEL>` | Only report threats at/above a severity (`critical\|high\|medium\|low`) |
| `--fail-on <WHAT>` | Exit `5` if matching findings exist: `any\|critical\|high\|medium\|low\|kev\|exposed` (CI gating) |
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

- `services` — `name@version` → array of findings (each with `severity`, `kev`,
  `epss`, `cvssScore`/`cvssVector`, `references`, and `matchBasis` showing whether
  the match was a structured constraint or a free-text fallback), sorted
  highest-risk-first.
- `assets` — `name@version` → `{ exe, versionSource, exposed, reachability, listeners }`,
  where `versionSource` is `package-db` (authoritative) or `probe` (heuristic) and
  `reachability` is `loopback` / `private` / `public` (TCP **and** UDP listeners).
- `byCve` — each CVE rolled up across every service it affects (the "patch once,
  fix many" remediation view).
- `system` — optional kernel/distro findings.
- `errors` — per-service lookup failures, so a failed lookup is never silently
  reported as "no vulnerabilities".
- `meta` — `{ tool, version, schemaVersion }`.

Keys are sorted (BTreeMap) and there is no timestamp, so reports diff cleanly
across runs.

## Tests

```sh
cargo test                 # unit tests (matching engine, helpers, CLI)
cargo test -- --ignored    # also run the macOS live-discovery smoke test
```
