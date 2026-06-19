# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **First-class Windows support.** Threat Finder now scans Windows hosts and
  matches them against Radar, alongside the existing Linux/macOS/BSD coverage.
  Everything is gathered by shelling out to the built-in `powershell.exe`
  (`ConvertTo-Json`) — no extra runtime, no admin needed for the core inventory.
  - **The OS itself → an NVD OS CPE.** The Windows edition, feature update, build
    and UBR are read from the registry (`CurrentVersion`) and turned into a
    feature-qualified CPE (e.g. `cpe:2.3:o:microsoft:windows_11_23h2:10.0.22631.3155:*:*:*:*:*:x64:*`),
    trusting the build number over the `ProductName` (which still says
    "Windows 10" on Windows 11). Client and Server SKUs are both recognised.
  - **Installed applications → app CPEs.** Registry Uninstall keys (64-bit,
    WOW6432Node and per-user), `winget list`, Appx/MSIX, Chocolatey and Scoop are
    inventoried and mapped to NVD `vendor:product` via a curated alias table.
    Unmapped apps fall back to a `?search=` lookup by cleaned name, so coverage
    degrades gracefully rather than guessing a wrong CPE.
  - **Language managers → purls.** Global npm, pip and `dotnet tool` packages are
    matched by exact purl coordinate (`pkg:npm`, `pkg:pypi`, `pkg:nuget`).
  - **Running services + network exposure.** Running Win32 services are correlated
    with listening sockets (`Get-NetTCPConnection`) by PID, so a finding is
    flagged loopback/private/public exactly as on Linux/macOS (svchost-hosted
    services are skipped to avoid mis-attributing shared sockets).
  - **`--windows-missing-updates`** (opt-in): queries the Windows Update Agent for
    pending security updates and lists them most-severe-first. This is an online
    scan (needs network, best run elevated), so it is off by default.
- Windows (`x86_64-pc-windows-msvc`) is now built and tested in CI, shipped as a
  release binary, and installable via `cargo binstall`.

## [0.1.7]

### Fixed
- **Registration report JSON now uses `hostId` (camelCase) instead of
  `host_id`.** Every sibling field in the report (`assetCount`,
  `newSinceLastCount`, …) and the Radar API already use camelCase, so the lone
  snake_case `host_id` broke any consumer keying the report by `hostId`. If you
  parse the `--json` report's `registration.hostId`, it is now present.

### Changed
- Listener discovery streams `/proc/net/{tcp,tcp6,udp,udp6}` line-by-line via a
  buffered reader instead of reading each table fully into memory, bounding peak
  memory on hosts with very large connection tables.

## [0.1.6]

### Changed
- **Tier-boundary responses now carry clear upgrade guidance — one line per
  event, never on a clean run.**
  - A `403 API access required` (a Free account with no active subscription / Pro
    Console hitting the first lookup) is no longer reported as a generic
    `Match lookup failed` with exit `1`. It now surfaces the server's own
    explanation plus `Upgrade your plan: https://radar.offseq.com/pricing` and
    `Manage access: https://radar.offseq.com/console`, and exits `4` (the
    "needs upgrade / quota" family). Other 403s stay generic.
  - The `429` rate-limit message from the server (which distinguishes an hourly
    burst from a daily/monthly quota and includes the reset time) is now shown
    verbatim above the pricing URL instead of being discarded for a generic line.
  - Monitoring-registration failures caused by a plan cap (host limit or asset
    cap) now append a single hint pointing at pricing/console. Registration
    remains non-fatal and the exit code is unchanged.
  - The `--scope all` budget warning no longer asserts every user is on the free
    tier's "15 lookups/hour"; it is worded conditionally and links the pricing
    page, since higher plans lift the cap.
- Exit code `4` now also covers "API access required (upgrade needed)", reflected
  in `--help` and the README.

## [0.1.5]

### Fixed
- **Multiarch dpkg coordinates now match the catalog.** When a running service's
  binary is owned by a multi-arch (`M-A: same`) library package, `dpkg-query -S`
  reports an arch-qualified name (e.g. `libssl3:amd64`). The trailing `:<arch>`
  qualifier is now stripped (for recognised dpkg arch tokens only) before the
  name becomes a purl coordinate, so `libssl3` matches Radar instead of silently
  missing. Names containing a colon for any other reason are left untouched.
- **`--unregister` no longer mints a host id.** It previously called
  `get_or_create_host_id()`, which generated and persisted a fresh UUID when none
  existed, then sent a DELETE for an id the server never saw. It now reads the
  saved id without side effects and, when this machine was never registered,
  prints a friendly notice and exits `0` without an API call.

### Changed
- **Registration prompt wording tracks the scan scope.** Under `--scope all` the
  count is installed packages, so the prompt now reads
  `Add these N packages to Radar…` instead of `…N services…`; the running-services
  scope is unchanged. Correct singular/plural in both cases.
- Exposure matching in the local risk computation is now trimmed and lowercased
  before comparison, mirroring the server exactly. This is defensive hardening
  only — it does not change any score for the lowercase exposure strings the
  client emits today.

## [0.1.4]

### Added
- **Continuous-monitoring registration (opt-in).** After a scan, the tool can
  register the discovered assets with Radar's host-inventory API for ongoing
  monitoring and alerts. In an interactive human session it asks
  `Add these N services to Radar for continuous monitoring & alerts? [Y/n/never]`
  — `never` persists a "don't ask again" preference. New flags: `--register`
  (register without prompting, for CI/automation), `--no-register` (never register
  this run), `--host-name <NAME>` (friendly hostname to send), and `--unregister`
  (delete this host's inventory and exit). Registration is **off by default** in
  non-interactive/CI runs unless `--register` or the `always` prompt mode is set,
  and a registration failure is non-fatal (a one-line warning; the exit code is
  unchanged). The payload is built only from assets with a real purl, so no
  malformed coordinate is ever sent. A stable per-host `host_id` (UUID) and the
  prompt mode live in a new `[monitoring]` section of the config file.
- **Exposure-aware risk score + SSVC decision per finding.** Every finding now
  carries a `riskScore` (0–100) and a `decision` band (`act-now` | `soon` |
  `schedule` | `track`), computed locally from the finding plus the **owning
  asset's network exposure**, mirroring the server formula so local and server
  scores agree. The terminal summary shows a `[ACT-NOW 92]`-style badge and
  findings are sorted by decision then score; `decision`/`riskScore` are exposed
  in the JSON report and in SARIF result `properties`.
- **Two-way surfacing (drift + new-since-last).** A successful registration adds
  an optional `registration` object to the JSON report (`host_id`, `monitoring`,
  `assetCount`, `drift{added,removed,changed}`, `summary{…}`, `newSinceLastCount`)
  and, in human mode, prints the drift (`+added / -removed / ~changed`), the
  act-now / exposed / KEV counts, and the top few findings new since the last scan.
- `uuid` dependency (v4) for the stable host identity.

### Changed
- Report `schemaVersion` bumped to **2** (findings gained `riskScore`/`decision`;
  the report gained the optional `registration` object).

## [0.1.3]

### Added
- **Radar detail link per finding.** Every finding now carries a `radarUrl`
  (`https://radar.offseq.com/threat/<slug>`) built from the server-provided
  `slug`. It appears in the JSON report, is appended to each finding line in the
  terminal summary, and is used as the SARIF rule `helpUri` (preferred over a raw
  reference URL) so an operator can open the curated write-up directly.
- **Actionable remediation.** Findings now surface `fixedVersions`, `remediation`,
  and `cwes` from the match API. The summary shows `→ fix: <versions>` and a short
  remediation hint; SARIF folds the fix/remediation into the result message, adds
  a `fixes` entry, and exposes `cwe` / `fixedVersions` in result `properties`.
  Turns a bare "vulnerable" into "upgrade to X".
- `references` is now populated on match hits (the server began projecting it).

### Fixed
- **Per-asset CVE double-count.** The same `cveId` could appear twice for one
  coordinate (two affected-range rows, or a coordinate+cpe double match),
  inflating the finding count, the summary, and SARIF. Each asset bucket is now
  deduplicated by `cveId` after risk-sorting, keeping the highest-risk instance.
- **`publishedDate` format consistency.** The match path stored the raw ISO
  timestamp (`2024-01-01T00:00:00.000Z`) while the search path emitted a date
  (`2024-01-01`). Both now emit the date-only form, so the field has one shape.
- **Long `Retry-After` cool-downs honored.** An explicit server `Retry-After`
  (e.g. `3600`) was clamped to 30s and then hammered. Explicit values are now
  honored up to a 300s ceiling; beyond that the client surfaces
  `RateLimitExceeded` instead of silently sleeping. The 30s clamp still applies
  only to the computed exponential fallback when no header is present.
- **systemd `ListUnits` errors no longer silently empty.** A typed-decode failure
  used to become an empty unit list, making a pure-systemd host scan as "clean."
  The error is now logged to stderr and an empty list is returned explicitly.
- **dpkg multiarch package names.** `dpkg-query -S` output is now split on the
  last `": "` field separator, so a multiarch name (`libssl3:amd64: /path`) is
  preserved instead of being truncated at the architecture colon.

## [0.1.2]

### Fixed
- **Critical: `match/batch` decode no longer fails on real responses.** The
  server sends `epss` as an object `{score, percentile}` (or `null`) and `kev` as
  an object `{addedDate, dueDate, ransomwareUse}` (or `null`), but the client
  modelled them as a bare `f64` / `bool`. A present, wrong-typed value made serde
  fail the *entire* chunk decode (`match/batch decode error`), breaking virtually
  every scan (most CVEs carry EPSS). `epss` and `kev` are now decoded tolerantly —
  accepting object, bare number/bool, `null`, or absent — collapsing to the
  numeric EPSS score and an "is-KEV-listed" boolean. The `?search=` fallback
  (`GET /threats`, where `epss`/`kev` are *also* objects) now reads them the same
  way, so both code paths agree.
- **Exposure:** IPv4-mapped IPv6 listeners (`::ffff:a.b.c.d`) are classified by the
  embedded IPv4 — loopback/LAN services are no longer mislabeled `public`.
- **Severity filter:** `--severity` no longer drops known-exploited (KEV) findings,
  so `--fail-on kev` still fires under a severity floor.
- `dpkg -S` diversion lines no longer corrupt package resolution.
- rpm `(none)` release token no longer leaks into the EVR / purl.
- Atoms with embedded numeric segments (e.g. `gtk-3-3.24.0`) split correctly.
- `--include`/`--exclude` match both the unit name and the resolved package.
- Rate-limit counters reflect the latest response (handles quota-window resets).
- SARIF `security-severity` uses the highest CVSS seen per CVE.
- Clearer auth errors: a 403 (valid key, but the account lacks API access — wrong
  tier / no Pro Console) now shows the server's explanation instead of the
  misleading "check your API key — re-run with --reset" hint, which is reserved
  for a 401 (missing/invalid key).

### Removed
- Vestigial always-empty `system` field and its dead readers.

### Added
- Match findings now surface `publishedDate` and `patchAvailable` per hit (the
  server provides them; previously only the search fallback did). The EPSS
  percentile from the object shape is now exposed too.
- HTTP 413 handling for over-cap batches: the per-chunk batch cap is recomputed
  inside the send loop (so Pro/Enterprise keys stop sending 25-item chunks once
  the first response reveals the tier), and a 413 (`{ "data": { "maxBatch": N } }`)
  shrinks the working cap to the advertised max — or halves the chunk when absent —
  and retries the same slice instead of aborting the run. The existing
  429/`Retry-After` and 5xx retry logic is unchanged.

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
