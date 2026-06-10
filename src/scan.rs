//! Asset / Collector abstraction.
//!
//! A `Collector` discovers a normalized list of `Asset`s from the host. Running
//! services and installed OS packages are each a collector; future phases
//! (language lockfiles, containers, SBOM) plug in the same way. Assets from all
//! collectors are deduplicated and matched once, with runtime exposure merged on
//! so the "what's actually running and reachable" signal survives the wider
//! inventory.

use crate::api::ServiceEntry;
use crate::engine::{
    enrich_exposure, list_installed, normalize_service_name, scan_services, strip_instance,
    OsType, Reachability, ServiceInfo, VersionSource,
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
    pub name: String,
    pub version: String,
    pub sources: Vec<Source>,
    pub locations: Vec<String>,
    pub runtime: Option<Runtime>,
}

impl Asset {
    /// Normalized name used as the API search term.
    pub fn lookup_key(&self) -> String {
        normalize_service_name(strip_instance(&self.name)).to_string()
    }

    /// Stable map key shared with `run_batch` results: normalized-name@version.
    pub fn report_key(&self) -> String {
        format!("{}@{}", self.lookup_key(), self.version)
    }

    pub fn to_service_entry(&self) -> ServiceEntry {
        ServiceEntry { name: self.lookup_key(), version: self.version.clone() }
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
        version: s.version,
        sources: vec![src],
        locations: vec![s.exe],
        runtime: Some(Runtime {
            pid: s.pid,
            listeners: s.listeners,
            reachability: s.reach,
            exposed: s.exposed,
        }),
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
                name: p.name,
                version: p.version,
                sources: vec![Source::PackageDb],
                locations: Vec::new(),
                runtime: None,
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

pub fn for_scope(scope: ScanScope) -> Vec<Box<dyn Collector>> {
    let mut collectors: Vec<Box<dyn Collector>> = vec![Box::new(RunningServiceCollector)];
    if scope == ScanScope::All {
        collectors.push(Box::new(OsPackageCollector));
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg_asset(name: &str, ver: &str) -> Asset {
        Asset { ecosystem: Ecosystem::Deb, name: name.into(), version: ver.into(),
            sources: vec![Source::PackageDb], locations: vec![], runtime: None }
    }

    #[test]
    fn keys_normalize() {
        let a = pkg_asset("ssh", "9.6");
        assert_eq!(a.lookup_key(), "openssh");
        assert_eq!(a.report_key(), "openssh@9.6");
        assert_eq!(a.to_service_entry().name, "openssh");
    }

    #[test]
    fn merge_preserves_runtime_and_unions_sources() {
        let running = Asset {
            ecosystem: Ecosystem::Deb, name: "nginx".into(), version: "1.24.0".into(),
            sources: vec![Source::Probe], locations: vec!["/usr/sbin/nginx".into()],
            runtime: Some(Runtime { pid: Some(7), listeners: vec!["tcp 0.0.0.0:443".into()],
                reachability: Reachability::Public, exposed: true }),
        };
        let installed = pkg_asset("nginx", "1.24.0");
        let merged = dedup_and_merge(vec![installed, running]);
        assert_eq!(merged.len(), 1, "same coordinate collapses to one asset");
        let a = &merged[0];
        assert!(a.runtime.as_ref().unwrap().exposed, "runtime/exposure preserved");
        assert!(a.sources.contains(&Source::PackageDb) && a.sources.contains(&Source::Probe));
        assert_eq!(a.version_source_label(), "package-db");
    }
}
