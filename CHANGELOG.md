# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

### Fixed
- Coordinates are now built from the **real owning package name** (e.g. a running
  `ssh` unit resolves to `openssh-server`), so the purl and the report key always
  agree — fixing coordinate misses and dedup loss for normalized service names.
- rpm `?distro` uses the conventional `id-version` (e.g. `rhel-9`).
- `publish-crate` now waits for the binary builds; the Homebrew auto-bump template
  is the single source of truth (removed the drift-prone static formula).

### Added
- MSRV (1.87) CI job.

### Removed
- Dead `ServiceEntry` / `SystemInfo` API types left over from the match migration.

## [Unreleased]

### Changed
- **Migrated to Radar exact-coordinate matching** (`POST /match/batch`). Each
  asset becomes a Package-URL with its full version + `?distro=` and the whole
  inventory is matched server-side with ecosystem-native version rules, in one
  request per tier-sized chunk (replacing per-service free-text search). Removed
  the client-side version-constraint engine and the hard-coded nginx blocklist.
  Backported-and-fixed builds are no longer false-flagged.
- Findings now split into `confirmed` (reported) and `unconfirmed` (triage,
  excluded from the count / `byCve` / `--fail-on`); added `--strict`. `?search=`
  is retained only as a fallback for assets with no buildable coordinate.

### Added
- Split into a reusable library crate (`find_threats`) + thin binary, with a
  generic `Asset`/`Collector` abstraction (running-services is now a collector).
- `--scope all`: a full installed-OS-package inventory collector
  (dpkg/rpm/pacman/apk/brew/pkg/pkg_info), expanding matched coverage ~10–50×.
  Assets are deduplicated and merged so a package backing a running, exposed
  process keeps its runtime exposure. Defaults to `--scope running` (quota-safe),
  with a warning when the inventory exceeds the free-tier budget.

### Added (prior)
- Reachability classification (loopback / private / public) for listeners, and
  UDP listener coverage in addition to TCP.
- Cross-service CVE grouping (`byCve`) — one fix mapped to every affected service.
- SARIF 2.1.0 output (`--sarif`) and `--include`/`--exclude` service globs.
- Output `meta` envelope with `schemaVersion`.

### Fixed
- **Critical:** `lsof`-based exposure correlation returned nothing on
  macOS/BSD/Solaris (the `(LISTEN)` suffix defeated the parser), silently
  disabling the headline feature off-Linux. Now uses `lsof -Fn` field output,
  with a non-vacuous regression test.

### Changed
- `ThreatError` now implements `std::error::Error`; single canonical
  `severity_rank`; pure per-OS parse functions extracted and unit-tested.

## [0.1.0-prev]

### Added
- Network-exposure correlation: each running service is mapped to its listening
  sockets (`/proc/net` on Linux, `lsof` elsewhere) and flagged when reachable
  off-host. Findings rank exposed-first.
- Enriched findings: CISA-KEV (known-exploited) flag, EPSS score, CVSS vector,
  full reference list, and match provenance (constraint vs free-text).
- `--fail-on <any|critical|high|medium|low|kev|exposed>` for CI gating, with a
  documented exit-code scheme (0–5).
- `--json`, `--severity`, `--quiet`, `--no-color`, `--yes`, `--reset` flags;
  `OFFSEQ_API_KEY` environment variable; ranked, colored terminal summary.
- Per-OS package-database version sourcing (dpkg/rpm/pacman/apk/pkg/pkg_info/brew).

### Fixed
- macOS/BSD/Solaris/SysV discovery (previously probed a service name/label as a
  binary); FreeBSD empty-result bug; NetBSD scanner.
- Structured `affectedVersions` constraint matching (`*`, `=`, `<`, `<=`, `>`,
  `>=`, compound AND, OR-across-array) with a correct version model.
- Pagination cap; deterministic (sorted) JSON output; transient-error retries
  with backoff and `Retry-After` handling.

### Security
- Hardened version probing (absolute paths only, sanitized env) and `0600`/`0700`
  API-key storage.

## [0.1.0]
- Initial release.
