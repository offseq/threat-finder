//! Asset / Collector abstraction.
//!
//! A `Collector` discovers a normalized list of `Asset`s from the host. Running
//! services and installed OS packages are each a collector; future phases
//! (language lockfiles, containers, SBOM) plug in the same way. Assets from all
//! collectors are deduplicated and matched once, with runtime exposure merged on
//! so the "what's actually running and reachable" signal survives the wider
//! inventory.

use std::collections::BTreeMap;

use crate::api::{
    match_to_entry, search_to_entry, severity_rank, BatchOutcome, MatchQuery, ThreatClient,
    ThreatEntry, ThreatError,
};
use crate::engine::{
    enrich_exposure, list_installed, normalize_service_name, os_release_field, scan_services,
    strip_instance, LinuxDistro, OsType, Reachability, ServiceInfo, VersionSource,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ecosystem {
    Deb,
    Rpm,
    Arch,
    Alpine,
    Homebrew,
    FreeBsdPkg,
    OpenBsdPkg,
    NetBsdPkg,
    /// Cross-ecosystem language managers present on Windows (and elsewhere).
    /// These map to a real Package-URL type → confirmed-coordinate matching.
    Npm,
    PyPI,
    NuGet,
    /// A Windows application from the registry / winget / Appx / Chocolatey /
    /// Scoop. No canonical purl exists, so it matches via a best-effort CPE.
    WinApp,
    /// The Windows operating system itself → an NVD OS CPE.
    WindowsOs,
    Generic,
}

impl Ecosystem {
    pub fn for_os(os: &OsType) -> Ecosystem {
        use crate::engine::LinuxDistro::*;
        match os {
            OsType::Linux(d) => match d {
                Debian | Ubuntu | Kali => Ecosystem::Deb,
                Fedora | Rhel | CentOs | OpenSuse => Ecosystem::Rpm,
                Arch => Ecosystem::Arch,
                Alpine => Ecosystem::Alpine,
                _ => Ecosystem::Generic,
            },
            OsType::MacOs => Ecosystem::Homebrew,
            OsType::FreeBsd | OsType::DragonFlyBsd => Ecosystem::FreeBsdPkg,
            OsType::OpenBsd => Ecosystem::OpenBsdPkg,
            OsType::NetBsd => Ecosystem::NetBsdPkg,
            OsType::Windows(_) => Ecosystem::WinApp,
            _ => Ecosystem::Generic,
        }
    }
}

/// How an asset's version was sourced (a trust signal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    PackageDb,
    Probe,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::PackageDb => "package-db",
            Source::Probe => "probe",
        }
    }
}

/// Runtime facet — present only for assets that back a live process.
#[derive(Debug, Clone)]
pub struct Runtime {
    pub pid: Option<u32>,
    pub listeners: Vec<String>,
    pub reachability: Reachability,
    pub exposed: bool,
}

#[derive(Debug, Clone)]
pub struct Asset {
    pub ecosystem: Ecosystem,
    /// Display name (service/unit name, or package name).
    pub name: String,
    /// Real owning-package name when known — the authoritative coordinate.
    pub pkg_name: Option<String>,
    pub version: String,
    pub sources: Vec<Source>,
    pub locations: Vec<String>,
    pub runtime: Option<Runtime>,
    /// Pre-built CPE 2.3 string when the source could form one (Windows apps /
    /// the OS). Takes precedence over a purl in `to_match_query`. `None` for
    /// everything matched by coordinate or `?search=`.
    pub cpe: Option<String>,
}

impl Asset {
    /// The canonical package name used for BOTH the coordinate (purl) and the
    /// report key, so they never disagree. Prefers the resolved package name;
    /// otherwise normalizes the service alias (ssh -> openssh).
    pub fn coordinate_name(&self) -> String {
        self.pkg_name
            .clone()
            .unwrap_or_else(|| normalize_service_name(strip_instance(&self.name)).to_string())
    }

    /// Name used for the `?search=` fallback (when no purl can be built).
    pub fn lookup_key(&self) -> String {
        self.coordinate_name()
    }

    /// Stable map key, shared between the coordinate and the results: name@version.
    pub fn report_key(&self) -> String {
        format!("{}@{}", self.coordinate_name(), self.version)
    }

    /// "package-db" if any source is authoritative, else "probe".
    pub fn version_source_label(&self) -> &'static str {
        if self.sources.contains(&Source::PackageDb) {
            "package-db"
        } else {
            "probe"
        }
    }
}

pub trait Collector: Sync {
    fn name(&self) -> &'static str;
    /// Never panics; returns an empty Vec on an unhandled OS.
    fn collect(&self, os: &OsType) -> Vec<Asset>;
}

/// Running services (the original discovery), wrapped as a collector. Exposure
/// is enriched here so every Asset is born with its runtime reachability.
pub struct RunningServiceCollector;

impl Collector for RunningServiceCollector {
    fn name(&self) -> &'static str {
        "running-services"
    }
    fn collect(&self, os: &OsType) -> Vec<Asset> {
        let mut services = scan_services(os);
        enrich_exposure(&mut services);
        let eco = Ecosystem::for_os(os);
        services.into_iter().map(|s| service_to_asset(s, eco)).collect()
    }
}

fn service_to_asset(s: ServiceInfo, eco: Ecosystem) -> Asset {
    let src = match s.source {
        VersionSource::PackageDb => Source::PackageDb,
        VersionSource::Probe => Source::Probe,
    };
    Asset {
        ecosystem: eco,
        name: s.name,
        pkg_name: s.pkg_name,
        version: s.version,
        sources: vec![src],
        locations: vec![s.exe],
        runtime: Some(Runtime {
            pid: s.pid,
            listeners: s.listeners,
            reachability: s.reach,
            exposed: s.exposed,
        }),
        cpe: None,
    }
}

/// Every installed OS package (Phase 1) — no runtime facet (not necessarily
/// running). Correlation with running services happens in `dedup_and_merge`.
pub struct OsPackageCollector;

impl Collector for OsPackageCollector {
    fn name(&self) -> &'static str {
        "os-packages"
    }
    fn collect(&self, os: &OsType) -> Vec<Asset> {
        let eco = Ecosystem::for_os(os);
        list_installed(os)
            .into_iter()
            .map(|p| Asset {
                ecosystem: eco,
                name: p.name.clone(),
                pkg_name: Some(p.name), // inventory names ARE the package coordinate
                version: p.version,
                sources: vec![Source::PackageDb],
                locations: Vec::new(),
                runtime: None,
                cpe: None,
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ScanScope {
    /// Only live services (default — quota-friendly).
    Running,
    /// Live services + every installed OS package.
    All,
}

/// Windows discovery, produced as `Asset`s directly (multi-ecosystem: registry/
/// winget/Appx/Chocolatey/Scoop → CPE; npm/pip/nuget → purl; plus the OS CPE and
/// running services with exposure). Self-gates: a no-op on every other OS, so it
/// is always safe to include in the collector set.
pub struct WindowsCollector {
    /// Full inventory (every installed app) vs. running services + OS only.
    pub full: bool,
}

impl Collector for WindowsCollector {
    fn name(&self) -> &'static str {
        "windows"
    }
    fn collect(&self, os: &OsType) -> Vec<Asset> {
        match os {
            OsType::Windows(w) => crate::windows::collect_windows(w, self.full),
            _ => Vec::new(),
        }
    }
}

pub fn for_scope(scope: ScanScope) -> Vec<Box<dyn Collector>> {
    let mut collectors: Vec<Box<dyn Collector>> = vec![Box::new(RunningServiceCollector)];
    if scope == ScanScope::All {
        collectors.push(Box::new(OsPackageCollector));
    }
    // Self-gating; on non-Windows hosts this yields nothing.
    collectors.push(Box::new(WindowsCollector { full: scope == ScanScope::All }));
    collectors
}

pub fn collect_assets(os: &OsType, collectors: &[Box<dyn Collector>]) -> Vec<Asset> {
    collectors.iter().flat_map(|c| c.collect(os)).collect()
}

/// Merge assets sharing a `report_key`: union sources/locations and keep the
/// richest runtime, so a package that also backs a running, exposed process
/// inherits that exposure instead of being double-counted.
pub fn dedup_and_merge(assets: Vec<Asset>) -> Vec<Asset> {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<String, Asset> = BTreeMap::new();
    for asset in assets {
        match map.get_mut(&asset.report_key()) {
            Some(existing) => merge_into(existing, asset),
            None => {
                map.insert(asset.report_key(), asset);
            }
        }
    }
    map.into_values().collect()
}

fn merge_into(dst: &mut Asset, src: Asset) {
    for s in src.sources {
        if !dst.sources.contains(&s) {
            dst.sources.push(s);
        }
    }
    for l in src.locations {
        if !dst.locations.contains(&l) {
            dst.locations.push(l);
        }
    }
    match (&dst.runtime, &src.runtime) {
        (None, Some(_)) => dst.runtime = src.runtime,
        (Some(d), Some(s)) if s.reachability > d.reachability => dst.runtime = src.runtime,
        _ => {}
    }
}

// ── Coordinate (purl) construction ───────────────────────────────────────────

/// Percent-encode a purl component value (RFC3986-ish). Keeps `.`/`-`/`~`/`:`/`_`
/// literal (they appear in deb/rpm versions); encodes the reserved characters
/// that would otherwise break the purl/qualifier grammar.
fn pct(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '+' => o.push_str("%2B"),
            '@' => o.push_str("%40"),
            ' ' => o.push_str("%20"),
            '?' => o.push_str("%3F"),
            '#' => o.push_str("%23"),
            '%' => o.push_str("%25"),
            _ => o.push(c),
        }
    }
    o
}

fn deb_namespace(d: &LinuxDistro) -> &'static str {
    match d {
        LinuxDistro::Ubuntu => "ubuntu",
        LinuxDistro::Kali => "kali",
        _ => "debian",
    }
}

fn rpm_namespace(d: &LinuxDistro) -> &'static str {
    match d {
        LinuxDistro::Fedora => "fedora",
        LinuxDistro::OpenSuse => "opensuse",
        LinuxDistro::CentOs => "centos",
        _ => "redhat",
    }
}

/// Build a Package-URL for an asset, keeping the FULL version (epoch/revision)
/// and adding `?distro=` so Radar compares with the native package rules
/// (a backported-and-fixed build is then correctly NOT flagged). Returns None
/// for ecosystems with no reliable purl type (BSD/generic) — caller falls back.
pub fn build_purl(a: &Asset, os: &OsType) -> Option<String> {
    let ver = pct(&a.version);
    let name = a.coordinate_name();
    match a.ecosystem {
        Ecosystem::Deb => {
            let ns = match os {
                OsType::Linux(d) => deb_namespace(d),
                _ => "debian",
            };
            let mut p = format!("pkg:deb/{ns}/{}@{ver}", pct(&name.to_lowercase()));
            if let Some(c) = os_release_field("VERSION_CODENAME") {
                p.push_str(&format!("?distro={}", pct(&c)));
            }
            Some(p)
        }
        Ecosystem::Rpm => {
            // rpm names are case-sensitive — do NOT lowercase.
            let ns = match os {
                OsType::Linux(d) => rpm_namespace(d),
                _ => "redhat",
            };
            let mut p = format!("pkg:rpm/{ns}/{}@{ver}", pct(&name));
            // distro qualifier uses the conventional id-version (e.g. rhel-9).
            if let (Some(id), Some(rel)) =
                (os_release_field("ID"), os_release_field("VERSION_ID"))
            {
                p.push_str(&format!("?distro={}-{}", pct(&id), pct(&rel)));
            }
            Some(p)
        }
        Ecosystem::Alpine => {
            let mut p = format!("pkg:apk/alpine/{}@{ver}", pct(&name.to_lowercase()));
            if let Some(vid) = os_release_field("VERSION_ID") {
                let mm: Vec<&str> = vid.split('.').take(2).collect();
                p.push_str(&format!("?distro=v{}", mm.join(".")));
            }
            Some(p)
        }
        Ecosystem::Arch => Some(format!("pkg:pacman/arch/{}@{ver}", pct(&name.to_lowercase()))),
        Ecosystem::Homebrew => Some(format!("pkg:brew/{}@{ver}", pct(&name))),
        // Cross-ecosystem language managers (npm/pip/nuget global installs).
        Ecosystem::Npm => Some(format!("pkg:npm/{}@{ver}", pct(&name))),
        // PyPI: PEP 503 normalization — lowercase, `_`/`.` → `-`.
        Ecosystem::PyPI => {
            let norm = name.to_lowercase().replace(['_', '.'], "-");
            Some(format!("pkg:pypi/{}@{ver}", pct(&norm)))
        }
        // NuGet ids are case-sensitive — preserve casing.
        Ecosystem::NuGet => Some(format!("pkg:nuget/{}@{ver}", pct(&name))),
        _ => None, // BSD / Generic / Windows apps+OS → CPE or search fallback
    }
}

/// Pick the strongest match query for an asset: a pre-built CPE (Windows apps /
/// OS) wins, else a purl coordinate, else `None` so the caller uses `?search=`.
fn to_match_query(a: &Asset, os: &OsType) -> Option<MatchQuery> {
    if let Some(cpe) = &a.cpe {
        return Some(MatchQuery::cpe(cpe.clone()));
    }
    build_purl(a, os).map(MatchQuery::purl)
}

/// Collapse duplicate `cveId`s within one asset's already risk-sorted bucket,
/// keeping the FIRST (highest-risk) instance. The same CVE can legitimately come
/// back twice for one coordinate — two affected-range rows, or a coordinate+cpe
/// double match — which otherwise inflates `total_vulns()`, the "N findings"
/// line, the summary, and SARIF. Entries with no `cveId` are always kept.
fn dedup_by_cve(entries: &mut Vec<ThreatEntry>) {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    entries.retain(|e| match e.cve_id.as_deref() {
        Some(id) => seen.insert(id.to_string()),
        None => true,
    });
}

/// Match a host inventory against Radar by exact coordinate (purl) in batched
/// POSTs, falling back to `?search=` for assets with no buildable coordinate.
/// Confirmed matches go to `results`; coordinate-unconfirmed to `unconfirmed`.
pub fn run_scan(
    client: &ThreatClient,
    assets: &[Asset],
    os: &OsType,
    strict: bool,
    severity_floor: u8,
) -> Result<BatchOutcome, ThreatError> {
    let mut queries: Vec<MatchQuery> = Vec::new();
    let mut query_keys: Vec<String> = Vec::new();
    let mut fallback: BTreeMap<String, Vec<String>> = BTreeMap::new(); // search-name -> report_keys

    for a in assets {
        match to_match_query(a, os) {
            Some(q) => {
                queries.push(q);
                query_keys.push(a.report_key());
            }
            None => fallback.entry(a.lookup_key()).or_default().push(a.report_key()),
        }
    }

    let mut results: BTreeMap<String, Vec<ThreatEntry>> = BTreeMap::new();
    let mut unconfirmed: BTreeMap<String, Vec<ThreatEntry>> = BTreeMap::new();
    let mut errors: BTreeMap<String, String> = BTreeMap::new();

    // Known-exploited findings are never filtered out by the severity floor —
    // dropping a KEV CVE on a severity threshold would contradict risk ranking
    // and hide it from `--fail-on kev`.
    let keep = |e: &ThreatEntry| e.kev || severity_rank(e.severity.as_deref()) >= severity_floor;

    if !queries.is_empty() {
        let matched = client.match_batch(&queries, strict)?;
        for (key, result) in query_keys.iter().zip(matched) {
            for hit in result.matches {
                let entry = match_to_entry(hit);
                if !keep(&entry) {
                    continue;
                }
                let bucket = if entry.confirmed { &mut results } else { &mut unconfirmed };
                bucket.entry(key.clone()).or_default().push(entry);
            }
        }
    }

    // One ?search= per unique name; apply to every asset key sharing it.
    for (name, keys) in fallback {
        match client.search_threats(&name, 100) {
            Ok(threats) => {
                let entries: Vec<ThreatEntry> =
                    threats.iter().map(search_to_entry).filter(|e| keep(e)).collect();
                for key in keys {
                    if !entries.is_empty() {
                        unconfirmed.entry(key).or_default().extend(entries.iter().cloned());
                    }
                }
            }
            Err(ThreatError::RateLimitExceeded(m)) => return Err(ThreatError::RateLimitExceeded(m)),
            Err(e) => {
                errors.insert(name, e.to_string());
            }
        }
    }

    for v in results.values_mut().chain(unconfirmed.values_mut()) {
        v.sort_by_key(|e| std::cmp::Reverse(e.risk_key()));
        dedup_by_cve(v);
    }

    Ok(BatchOutcome { results, unconfirmed, errors })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg_asset(name: &str, ver: &str) -> Asset {
        Asset { ecosystem: Ecosystem::Deb, name: name.into(), pkg_name: None, version: ver.into(),
            sources: vec![Source::PackageDb], locations: vec![], runtime: None, cpe: None }
    }

    #[test]
    fn keys_normalize() {
        // No resolved package name → fall back to the normalized service alias.
        let a = pkg_asset("ssh", "9.6");
        assert_eq!(a.coordinate_name(), "openssh");
        assert_eq!(a.report_key(), "openssh@9.6");
    }

    #[test]
    fn resolved_package_name_is_the_coordinate() {
        // A running unit "ssh" resolved to the real package "openssh-server".
        let mut a = pkg_asset("ssh", "1:9.6p1-3");
        a.pkg_name = Some("openssh-server".into());
        assert_eq!(a.coordinate_name(), "openssh-server");
        assert_eq!(a.report_key(), "openssh-server@1:9.6p1-3");
        let purl = build_purl(&a, &OsType::Linux(LinuxDistro::Debian)).unwrap();
        assert!(purl.starts_with("pkg:deb/debian/openssh-server@1:9.6p1-3"), "{purl}");
    }

    #[test]
    fn merge_preserves_runtime_and_unions_sources() {
        let running = Asset {
            ecosystem: Ecosystem::Deb, name: "nginx".into(), pkg_name: None, version: "1.24.0".into(),
            sources: vec![Source::Probe], locations: vec!["/usr/sbin/nginx".into()],
            runtime: Some(Runtime { pid: Some(7), listeners: vec!["tcp 0.0.0.0:443".into()],
                reachability: Reachability::Public, exposed: true }),
            cpe: None,
        };
        let installed = pkg_asset("nginx", "1.24.0");
        let merged = dedup_and_merge(vec![installed, running]);
        assert_eq!(merged.len(), 1, "same coordinate collapses to one asset");
        let a = &merged[0];
        assert!(a.runtime.as_ref().unwrap().exposed, "runtime/exposure preserved");
        assert!(a.sources.contains(&Source::PackageDb) && a.sources.contains(&Source::Probe));
        assert_eq!(a.version_source_label(), "package-db");
    }

    fn linux(d: LinuxDistro) -> OsType { OsType::Linux(d) }
    fn asset_eco(eco: Ecosystem, name: &str, ver: &str) -> Asset {
        Asset { ecosystem: eco, name: name.into(), pkg_name: Some(name.into()), version: ver.into(),
            sources: vec![Source::PackageDb], locations: vec![], runtime: None, cpe: None }
    }

    #[test]
    fn purl_deb_keeps_full_version() {
        let a = asset_eco(Ecosystem::Deb, "OpenSSL", "1.1.1f-1ubuntu2.16");
        let p = build_purl(&a, &linux(LinuxDistro::Ubuntu)).unwrap();
        assert!(p.starts_with("pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.16"), "{p}");
    }

    #[test]
    fn purl_deb_encodes_plus() {
        let a = asset_eco(Ecosystem::Deb, "nginx", "1.18.0-6+deb11u3");
        let p = build_purl(&a, &linux(LinuxDistro::Debian)).unwrap();
        assert!(p.starts_with("pkg:deb/debian/nginx@1.18.0-6%2Bdeb11u3"), "{p}");
    }

    #[test]
    fn purl_rpm_case_and_evr() {
        let a = asset_eco(Ecosystem::Rpm, "NetworkManager", "1:1.42.2-1.el9");
        let p = build_purl(&a, &linux(LinuxDistro::Rhel)).unwrap();
        assert!(p.starts_with("pkg:rpm/redhat/NetworkManager@1:1.42.2-1.el9"), "{p}");
    }

    #[test]
    fn purl_apk_arch_brew_and_bsd() {
        assert!(build_purl(&asset_eco(Ecosystem::Alpine, "musl", "1.2.5-r0"), &linux(LinuxDistro::Alpine))
            .unwrap().starts_with("pkg:apk/alpine/musl@1.2.5-r0"));
        assert!(build_purl(&asset_eco(Ecosystem::Arch, "nginx", "1.27.0-1"), &linux(LinuxDistro::Arch))
            .unwrap().starts_with("pkg:pacman/arch/nginx@1.27.0-1"));
        assert_eq!(build_purl(&asset_eco(Ecosystem::Homebrew, "openssl@3", "3.3.2"), &OsType::MacOs)
            .unwrap(), "pkg:brew/openssl%403@3.3.2");
        assert_eq!(build_purl(&asset_eco(Ecosystem::FreeBsdPkg, "nginx", "1.27.0"), &OsType::FreeBsd), None);
    }

    #[test]
    fn pct_encoding() {
        assert_eq!(pct("a+b@c d"), "a%2Bb%40c%20d");
        assert_eq!(pct("1.2.3-4ubuntu5"), "1.2.3-4ubuntu5");
    }

    #[test]
    fn dedup_keeps_highest_risk_per_cve() {
        use crate::api::match_to_entry;
        use serde_json::json;
        // Two rows for the same CVE on one coordinate (e.g. two affected ranges):
        // a low-severity, non-KEV instance and a high-severity KEV instance, plus
        // a distinct CVE. The bucket is risk-sorted then deduped.
        let mk = |cve: &str, sev: &str, kev: bool, range: &str| {
            match_to_entry(serde_json::from_value(json!({
                "cveId": cve, "severity": sev, "kev": kev,
                "matchBasis": "coordinate", "matchedRange": range, "confirmed": true
            })).unwrap())
        };
        let mut v = vec![
            mk("CVE-2024-1", "low", false, "<1.0"),
            mk("CVE-2024-1", "critical", true, "<2.0"),
            mk("CVE-2024-2", "medium", false, "<3.0"),
        ];
        v.sort_by_key(|e| std::cmp::Reverse(e.risk_key()));
        dedup_by_cve(&mut v);
        assert_eq!(v.len(), 2, "duplicate CVE collapsed");
        let kept = v.iter().find(|e| e.cve_id.as_deref() == Some("CVE-2024-1")).unwrap();
        // The surviving instance is the highest-risk one (KEV / critical).
        assert!(kept.kev);
        assert_eq!(kept.severity.as_deref(), Some("critical"));
        assert_eq!(kept.matched_range.as_deref(), Some("<2.0"));
    }

    #[test]
    fn dedup_keeps_entries_without_cve_id() {
        use crate::api::match_to_entry;
        use serde_json::json;
        let mut v = vec![
            match_to_entry(serde_json::from_value(json!({ "matchBasis": "coordinate" })).unwrap()),
            match_to_entry(serde_json::from_value(json!({ "matchBasis": "coordinate" })).unwrap()),
        ];
        dedup_by_cve(&mut v);
        assert_eq!(v.len(), 2, "id-less entries are never collapsed");
    }
}
