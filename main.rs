use std::io::{self, IsTerminal, Read, Write};
use std::process::{Command, Stdio, ExitCode};
use std::time::{Duration, Instant};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use find_threats::{
    ThreatClient,
    ThreatError,
    BatchResults,
    ThreatEntry,
    run_batch,
    run_system_lookup,
    print_plan_info,
    ServiceEntry as ThreatServiceEntry,
    SystemInfo as ThreatSystemInfo,
};

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use once_cell::sync::Lazy;
use serde::Serialize;
use rayon::prelude::*;
use regex::Regex;
use zbus::blocking::Connection;
use zbus::zvariant::OwnedValue;

mod auth;
mod find_threats;

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    fn as_api(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum FailOn {
    /// Any finding at all
    Any,
    Critical,
    High,
    Medium,
    Low,
    /// Only CISA known-exploited findings
    Kev,
    /// Only findings on a network-exposed service
    Exposed,
}

#[derive(Parser, Debug)]
#[command(
    name = "threat-finder",
    version,
    about = "OffSeq Threat Finder — scan running services for known vulnerabilities",
    after_help = "EXIT CODES:\n  0  success\n  1  lookup or I/O error\n  2  no API key available\n  3  unsupported OS\n  4  rate limit / quota exhausted\n  5  --fail-on threshold met",
)]
struct Cli {
    /// Write the JSON report to this path (default: prompt, or /tmp/threats.json)
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,

    /// Print the JSON report to stdout instead of writing a file
    #[arg(long)]
    json: bool,

    /// Only report threats at or above this severity
    #[arg(long, value_enum, value_name = "LEVEL")]
    severity: Option<Severity>,

    /// Exit non-zero (5) when matching findings exist — for CI gating
    #[arg(long, value_enum, value_name = "WHAT")]
    fail_on: Option<FailOn>,

    /// Reduce output: no banner or progress indicators
    #[arg(short, long)]
    quiet: bool,

    /// Never use ANSI colors in the summary
    #[arg(long)]
    no_color: bool,

    /// Assume defaults and never prompt — for CI/cron use
    #[arg(short = 'y', long)]
    yes: bool,

    /// Re-enter the API key, ignoring any saved one
    #[arg(long)]
    reset: bool,
}

#[derive(Debug, Clone)]
pub enum LinuxDistro {
    Debian, Ubuntu, Kali, Fedora, Rhel, CentOs,
    Arch, Alpine, OpenSuse, Gentoo, NixOs, Unknown(String),
}

#[derive(Debug, Clone)]
pub enum OsType {
    Linux(LinuxDistro),
    MacOs, FreeBsd, OpenBsd, NetBsd, DragonFlyBsd, Solaris, Illumos,
    Unsupported(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionSource {
    PackageDb,
    Probe,
}

impl VersionSource {
    fn as_str(self) -> &'static str {
        match self {
            VersionSource::PackageDb => "package-db",
            VersionSource::Probe => "probe",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name:      String,
    pub version:   String,
    pub exe:       String,
    pub pid:       Option<u32>,
    pub source:    VersionSource,
    pub listeners: Vec<String>,
    pub exposed:   bool,
}

#[derive(Serialize)]
pub struct SystemInfo {
    pub kernel_name:    String,
    pub kernel_version: String,
    pub distro_name:    String,
    pub distro_version: String,
}

fn detect_linux_distro() -> LinuxDistro {
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        let field = |key: &str| -> String {
            content.lines()
                .find(|l| l.starts_with(key))
                .map(|l| l[key.len()..].trim_matches('"').to_lowercase())
                .unwrap_or_default()
        };
        for candidate in [field("ID="), field("ID_LIKE=")] {
            let d = match candidate.as_str() {
                s if s.contains("kali")                         => Some(LinuxDistro::Kali),
                s if s.contains("ubuntu")                       => Some(LinuxDistro::Ubuntu),
                s if s.contains("debian")                       => Some(LinuxDistro::Debian),
                s if s.contains("fedora")                       => Some(LinuxDistro::Fedora),
                s if s.contains("rhel") || s.contains("redhat")=> Some(LinuxDistro::Rhel),
                s if s.contains("centos")                       => Some(LinuxDistro::CentOs),
                s if s.contains("arch")                         => Some(LinuxDistro::Arch),
                s if s.contains("alpine")                       => Some(LinuxDistro::Alpine),
                s if s.contains("suse")                         => Some(LinuxDistro::OpenSuse),
                s if s.contains("gentoo")                       => Some(LinuxDistro::Gentoo),
                s if s.contains("nix")                          => Some(LinuxDistro::NixOs),
                _ => None,
            };
            if let Some(d) = d { return d; }
        }
        return LinuxDistro::Unknown(field("ID="));
    }
    for (path, distro) in &[
        ("/etc/debian_version", LinuxDistro::Debian),
        ("/etc/fedora-release",  LinuxDistro::Fedora),
        ("/etc/arch-release",    LinuxDistro::Arch),
        ("/etc/alpine-release",  LinuxDistro::Alpine),
    ] {
        if std::path::Path::new(path).exists() { return distro.clone(); }
    }
    LinuxDistro::Unknown("unknown".into())
}

pub fn detect_os() -> OsType {
    match std::env::consts::OS {
        "linux"     => OsType::Linux(detect_linux_distro()),
        "macos"     => OsType::MacOs,
        "freebsd"   => OsType::FreeBsd,
        "openbsd"   => OsType::OpenBsd,
        "netbsd"    => OsType::NetBsd,
        "dragonfly" => OsType::DragonFlyBsd,
        "solaris"   => OsType::Solaris,
        "illumos"   => OsType::Illumos,
        other       => OsType::Unsupported(other.to_string()),
    }
}

/// Human-readable OS label for display (instead of Debug formatting).
fn os_label(os: &OsType) -> String {
    match os {
        OsType::Linux(d) => format!("Linux ({})", parse_linux_distro_version(d).0),
        OsType::MacOs => "macOS".into(),
        OsType::FreeBsd => "FreeBSD".into(),
        OsType::OpenBsd => "OpenBSD".into(),
        OsType::NetBsd => "NetBSD".into(),
        OsType::DragonFlyBsd => "DragonFly BSD".into(),
        OsType::Solaris => "Solaris".into(),
        OsType::Illumos => "illumos".into(),
        OsType::Unsupported(s) => format!("Unsupported ({s})"),
    }
}

fn gather_system_info(os: &OsType) -> Option<SystemInfo> {
    let kernel_version = run_cmd("uname", &["-r"])
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    if kernel_version.is_empty() {
        return None;
    }

    match os {
        OsType::Linux(distro) => {
            let (distro_name, distro_version) = parse_linux_distro_version(distro);
            Some(SystemInfo {
                kernel_name: "linux".into(),
                kernel_version,
                distro_name,
                distro_version,
            })
        }
        OsType::MacOs => {
            let version = run_cmd("sw_vers", &["-productVersion"])
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            Some(SystemInfo {
                kernel_name: "darwin".into(),
                kernel_version,
                distro_name: "macos".into(),
                distro_version: version,
            })
        }
        OsType::FreeBsd => {
            Some(SystemInfo {
                kernel_name:    "freebsd".into(),
                kernel_version: kernel_version.clone(),
                distro_name:    "freebsd".into(),
                distro_version: kernel_version,
            })
        }
        OsType::DragonFlyBsd => {
            Some(SystemInfo {
                kernel_name:    "dragonfly".into(),
                kernel_version: kernel_version.clone(),
                distro_name:    "dragonfly".into(),
                distro_version: kernel_version,
            })
        }
        OsType::OpenBsd => {
            Some(SystemInfo {
                kernel_name:    "openbsd".into(),
                kernel_version: kernel_version.clone(),
                distro_name:    "openbsd".into(),
                distro_version: kernel_version,
            })
        }
        OsType::NetBsd => {
            Some(SystemInfo {
                kernel_name:    "netbsd".into(),
                kernel_version: kernel_version.clone(),
                distro_name:    "netbsd".into(),
                distro_version: kernel_version,
            })
        }
        OsType::Solaris => {
            let version = run_cmd("uname", &["-v"])
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            Some(SystemInfo {
                kernel_name: "sunos".into(),
                kernel_version,
                distro_name: "solaris".into(),
                distro_version: version,
            })
        }
        OsType::Illumos => {
            Some(SystemInfo {
                kernel_name:    "illumos".into(),
                kernel_version: kernel_version.clone(),
                distro_name:    "illumos".into(),
                distro_version: kernel_version,
            })
        }
        OsType::Unsupported(_) => None,
    }
}

struct UnitEntry {
    name: String,
    exe:  String,
    pid:  Option<u32>,
}

static EXECSTART_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#""/([^"]+)""#).unwrap());

// One row of systemd's Manager.ListUnits() reply:
// (name, description, load_state, active_state, sub_state, following,
//  unit_obj_path, job_id, job_type, job_obj_path)
type SystemdUnit = (
    String, String, String, String, String, String,
    zbus::zvariant::OwnedObjectPath, u32, String,
    zbus::zvariant::OwnedObjectPath,
);

fn list_systemd_units(conn: &Connection) -> Vec<UnitEntry> {
    let proxy = match zbus::blocking::Proxy::new(
        conn,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[!] could not open systemd manager proxy: {e}");
            return vec![];
        }
    };

    let units: Vec<SystemdUnit> = proxy.call("ListUnits", &()).unwrap_or_default();

    units.into_iter()
        .filter(|u| u.3 == "active" && u.0.ends_with(".service"))
        // parallel, resolve the exe path for each unit
        .collect::<Vec<_>>()
        .into_par_iter()
        .filter_map(|u| {
            let unit_name = u.0.trim_end_matches(".service").to_string();
            let obj_path  = u.6.as_str().to_string();

            let (exe, pid) = resolve_exe(conn, &obj_path, &unit_name)?;

            let exe_base = exe.rsplit('/').next().unwrap_or("");
            if exe_base == "true" || exe_base == "false" { return None; }

            Some(UnitEntry { name: unit_name, exe, pid })
        })
        .collect()
}

/// Resolve a unit to (absolute binary, MainPID). PID is kept for exposure
/// correlation even when the path comes from a non-PID strategy.
fn resolve_exe(conn: &Connection, obj_path: &str, unit_name: &str) -> Option<(String, Option<u32>)> {
    let svc_proxy = zbus::blocking::Proxy::new(
        conn,
        "org.freedesktop.systemd1",
        obj_path,
        "org.freedesktop.systemd1.Service",
    ).ok()?;

    let pid = svc_proxy.get_property::<u32>("MainPID").ok().filter(|p| *p > 0);

    if let Some(pid_val) = pid {
        let proc_exe = format!("/proc/{pid_val}/exe");
        if let Ok(resolved) = std::fs::read_link(&proc_exe) {
            let path = resolved.to_string_lossy().into_owned();
            // strip " (deleted)" suffix left when a binary is updated while running
            let path = path.trim_end_matches(" (deleted)").to_string();
            if !path.is_empty() && path.starts_with('/') {
                return Some((path, pid));
            }
        }
    }

    if let Ok(val) = svc_proxy.get_property::<OwnedValue>("ExecStart") {
        let raw = format!("{val:?}");
        if let Some(cap) = EXECSTART_RE.captures(&raw) {
            let path = format!("/{}", &cap[1]);
            if std::path::Path::new(&path).exists() {
                return Some((path, pid));
            }
        }
    }

    for prefix in &["/usr/lib/systemd/", "/lib/systemd/"] {
        let candidate = format!("{prefix}{unit_name}");
        if std::path::Path::new(&candidate).exists() {
            return Some((candidate, pid));
        }
    }

    let one_shots = [
        "systemd-journal-flush", "systemd-tmpfiles-setup",
        "systemd-tmpfiles-setup-dev", "systemd-tmpfiles-setup-dev-early",
        "systemd-udev-trigger", "systemd-update-utmp", "systemd-user-sessions",
        "systemd-remount-fs", "systemd-random-seed", "systemd-binfmt",
        "systemd-modules-load", "systemd-sysctl",
    ];
    if one_shots.contains(&unit_name) {
        return None;
    }

    if unit_name.starts_with("systemd-") {
        return Some(("/usr/lib/systemd/systemd".to_string(), pid));
    }

    None
}

fn normalize_service_name(name: &str) -> &str {
    match name {
        "ssh"           => "openssh",
        "apache2"       => "apache",
        "httpd"         => "apache",
        "mariadb"       => "mysql",
        "postgres"      => "postgresql",
        _               => name,
    }
}

/// systemd template instance: "postgresql@15-main" -> "postgresql". The instance
/// part is host-specific and never matches an API product name, so it is dropped
/// from the search term (the full name is still kept for display).
fn strip_instance(name: &str) -> &str {
    name.split('@').next().unwrap_or(name)
}

fn parse_linux_distro_version(distro: &LinuxDistro) -> (String, String) {
    let name = match distro {
        LinuxDistro::Ubuntu   => "ubuntu",
        LinuxDistro::Debian   => "debian",
        LinuxDistro::Kali     => "kali",
        LinuxDistro::Fedora   => "fedora",
        LinuxDistro::Rhel     => "rhel",
        LinuxDistro::CentOs   => "centos",
        LinuxDistro::Arch     => "arch",
        LinuxDistro::Alpine   => "alpine",
        LinuxDistro::OpenSuse => "opensuse",
        LinuxDistro::Gentoo   => "gentoo",
        LinuxDistro::NixOs    => "nixos",
        LinuxDistro::Unknown(s) => s.as_str(),
    };

    let version = std::fs::read_to_string("/etc/os-release")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("VERSION_ID="))
        .map(|l| l["VERSION_ID=".len()..].trim_matches('"').to_string())
        .unwrap_or_default();

    (name.to_string(), version)
}

fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return format!("{}/{}", home.display(), rest);
        }
    }
    path.to_string()
}

fn prompt_output_path() -> String {
    let default = "/tmp/threats.json";
    print!("Output path [{}]: ", default);
    let _ = io::stdout().flush();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).unwrap_or(0) == 0 {
        return default.to_string(); // EOF
    }
    let input = input.trim();

    if input.is_empty() {
        default.to_string()
    } else {
        let expanded = expand_tilde(input);

        let path = std::path::Path::new(&expanded);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                eprintln!(
                    "Warning: directory '{}' does not exist. Output may fail.",
                    parent.display()
                );
            }
        }

        expanded
    }
}

//
// Two principles from the analysis:
//   1. NEVER execute a bare name resolved through an attacker-influenceable PATH
//      (run_timed enforces this — absolute, real files only).
//   2. Prefer the package database over executing the daemon for its version;
//      probing the binary is a last resort.

const SAFE_PATH_DIRS: &[&str] = &[
    "/usr/local/sbin", "/usr/local/bin",
    "/usr/sbin", "/usr/bin", "/sbin", "/bin",
    "/opt/homebrew/bin", "/opt/homebrew/sbin",
    "/usr/pkg/sbin", "/usr/pkg/bin",
];

/// A few service names whose daemon binary is reliably different from the name.
fn daemon_alias(service: &str) -> &str {
    match service {
        "ssh" => "sshd",
        _ => service,
    }
}

/// Resolve a service/command name to an absolute binary path by reading the
/// filesystem only (no execution). Tries the name, then a "<name>d" daemon
/// variant, across common bin dirs and any absolute $PATH entries.
fn resolve_binary(name: &str) -> Option<String> {
    let first = name.split_whitespace().next().unwrap_or(name);
    if first.starts_with('/') {
        return Path::new(first).is_file().then(|| first.to_string());
    }
    let base = daemon_alias(first.rsplit('/').next().unwrap_or(first));
    if base.is_empty() {
        return None;
    }
    let candidates = [base.to_string(), format!("{base}d")];

    let path_env = std::env::var("PATH").unwrap_or_default();
    let dirs = SAFE_PATH_DIRS.iter().map(|s| s.to_string())
        .chain(path_env.split(':').filter(|d| d.starts_with('/')).map(|s| s.to_string()));

    for dir in dirs {
        for cand in &candidates {
            let p = format!("{dir}/{cand}");
            if Path::new(&p).is_file() {
                return Some(p);
            }
        }
    }
    None
}

// "name-1.2.3-r0" / "nginx-1.26.2nb1" -> "1.2.3" / "1.26.2"
static ATOM_VER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"-(\d[0-9A-Za-z.+~]*)").unwrap());

fn atom_version(atom: &str) -> Option<String> {
    ATOM_VER_RE.captures(atom.trim()).map(|c| c[1].to_string())
}

/// Ask the OS package database for the version that owns `exe`. Returns None when
/// no package owns it (e.g. a base-system binary) so the caller can fall back.
fn package_version(exe: &str, os: &OsType) -> Option<String> {
    let real = fs::canonicalize(exe).ok()?;
    let path = real.to_string_lossy().to_string();

    match os {
        OsType::Linux(distro) => match distro {
            LinuxDistro::Debian | LinuxDistro::Ubuntu | LinuxDistro::Kali => dpkg_version(&path),
            LinuxDistro::Fedora | LinuxDistro::Rhel | LinuxDistro::CentOs | LinuxDistro::OpenSuse => rpm_version(&path),
            LinuxDistro::Arch => pacman_version(&path),
            LinuxDistro::Alpine => apk_version(&path),
            _ => dpkg_version(&path)
                .or_else(|| rpm_version(&path))
                .or_else(|| pacman_version(&path))
                .or_else(|| apk_version(&path)),
        },
        OsType::MacOs => homebrew_version(&path),
        OsType::FreeBsd | OsType::DragonFlyBsd => freebsd_pkg_version(&path),
        OsType::OpenBsd => pkg_info_version(&path, false),
        OsType::NetBsd | OsType::Illumos => pkg_info_version(&path, true),
        OsType::Solaris => None, // IPS resolution deferred; falls back to probe
        OsType::Unsupported(_) => None,
    }
}

fn dpkg_version(path: &str) -> Option<String> {
    // dpkg-query -S <path> -> "pkg: /path"  (or "pkg1, pkg2: /path")
    let owner = run_cmd("dpkg-query", &["-S", path])?;
    let pkg = owner.split(':').next()?.split(',').next()?.trim().to_string();
    if pkg.is_empty() {
        return None;
    }
    let ver = run_cmd("dpkg-query", &["-W", "-f=${Version}", &pkg])?;
    let ver = ver.trim().to_string();
    (!ver.is_empty()).then_some(ver)
}

fn rpm_version(path: &str) -> Option<String> {
    let out = run_cmd("rpm", &["-qf", "--queryformat", "%{VERSION}\n", path])?;
    let v = out.lines().next()?.trim().to_string();
    if v.is_empty() || v.to_lowercase().contains("not owned") {
        None
    } else {
        Some(v)
    }
}

fn pacman_version(path: &str) -> Option<String> {
    // pacman -Qo <path> -> "/usr/bin/nginx is owned by nginx 1.27.0-1"
    let out = run_cmd("pacman", &["-Qo", path])?;
    let after = out.split(" is owned by ").nth(1)?;
    after.split_whitespace().nth(1).map(|s| s.to_string())
}

fn apk_version(path: &str) -> Option<String> {
    // apk info -W <path> -> "<path> is owned by nginx-1.26.2-r0"
    let out = run_cmd("apk", &["info", "-W", path])?;
    let atom = out.split("owned by ").nth(1)?;
    atom_version(atom)
}

fn homebrew_version(path: &str) -> Option<String> {
    // canonicalized brew binaries live at .../Cellar/<name>/<version>/...
    let idx = path.find("/Cellar/")?;
    let rest = &path[idx + "/Cellar/".len()..];
    let mut it = rest.split('/');
    let _name = it.next()?;
    let version = it.next()?.to_string();
    (!version.is_empty()).then_some(version)
}

fn freebsd_pkg_version(path: &str) -> Option<String> {
    // pkg which -q <path> -> "nginx-1.27.0"
    let atom = run_cmd("pkg", &["which", "-q", path])?;
    atom_version(&atom)
}

fn pkg_info_version(path: &str, file_flag: bool) -> Option<String> {
    // OpenBSD: pkg_info -E <path> -> "nginx-1.26.2: /usr/local/sbin/nginx"
    // NetBSD : pkg_info -Fe <path> -> "nginx-1.26.2nb1"
    let out = if file_flag {
        run_cmd("pkg_info", &["-Fe", path])?
    } else {
        run_cmd("pkg_info", &["-E", path])?
    };
    let atom = out.split(':').next().unwrap_or(&out);
    atom_version(atom)
}

/// Get a version for a resolved binary: package DB first, probe as last resort.
/// Also reports which source produced the version (a trust signal).
fn version_for_binary(exe: &str, os: &OsType) -> Option<(String, VersionSource)> {
    if let Some(v) = package_version(exe, os) {
        return Some((v, VersionSource::PackageDb));
    }
    probe_version(exe).map(|v| (v, VersionSource::Probe))
}

fn make_service(name: &str, exe: &str, pid: Option<u32>, os: &OsType) -> Option<ServiceInfo> {
    let (version, source) = version_for_binary(exe, os)?;
    Some(ServiceInfo {
        name: name.to_string(),
        version,
        exe: exe.to_string(),
        pid,
        source,
        listeners: Vec::new(),
        exposed: false,
    })
}

/// Build a ServiceInfo from a service name by resolving its binary and version.
fn service_from_name(display_name: &str, os: &OsType) -> Option<ServiceInfo> {
    let exe = resolve_binary(display_name)?;
    make_service(display_name, &exe, None, os)
}

// Network-exposure correlation
//
// Mapping each running service to the sockets it is LISTENING on — and whether
// any is reachable off-host — is the tool's signature capability: manifest
// scanners can't see runtime state, and external scanners need a second host.

fn listening_endpoints(pid: u32) -> Vec<String> {
    let mut eps = if cfg!(target_os = "linux") {
        linux_listeners(pid)
    } else {
        lsof_listeners(pid)
    };
    eps.sort();
    eps.dedup();
    eps
}

fn lsof_listeners(pid: u32) -> Vec<String> {
    let out = run_cmd("lsof", &["-nP", "-p", &pid.to_string(), "-iTCP", "-sTCP:LISTEN"])
        .unwrap_or_default();
    out.lines().skip(1)
        .filter_map(|l| l.split_whitespace().last())
        .map(|n| n.trim_end_matches("(LISTEN)").trim().to_string())
        .filter(|s| s.contains(':'))
        .collect()
}

fn linux_listeners(pid: u32) -> Vec<String> {
    let mut inodes: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) {
        for fd in fds.flatten() {
            if let Ok(link) = fs::read_link(fd.path()) {
                let s = link.to_string_lossy();
                if let Some(rest) = s.strip_prefix("socket:[") {
                    if let Some(inode) = rest.strip_suffix(']') {
                        inodes.insert(inode.to_string());
                    }
                }
            }
        }
    }
    if inodes.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (path, v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        let Ok(content) = fs::read_to_string(path) else { continue };
        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 || cols[3] != "0A" {
                continue; // 0A = TCP_LISTEN
            }
            if inodes.contains(cols[9]) {
                if let Some(ep) = parse_proc_addr(cols[1], v6) {
                    out.push(ep);
                }
            }
        }
    }
    out
}

/// Parse a /proc/net/tcp{,6} hex "addr:port" (little-endian) into "ip:port".
fn parse_proc_addr(s: &str, v6: bool) -> Option<String> {
    let (addr, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    if v6 {
        if addr.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for i in 0..4 {
            let word = u32::from_str_radix(&addr[i * 8..i * 8 + 8], 16).ok()?;
            bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        Some(format!("[{}]:{port}", std::net::Ipv6Addr::from(bytes)))
    } else {
        if addr.len() != 8 {
            return None;
        }
        let v = u32::from_str_radix(addr, 16).ok()?;
        Some(format!("{}:{port}", std::net::Ipv4Addr::from(v.to_le_bytes())))
    }
}

/// True if a listener endpoint is reachable from off-host (not loopback-bound).
fn endpoint_is_exposed(ep: &str) -> bool {
    let host = ep.rsplit_once(':').map(|(h, _)| h).unwrap_or(ep);
    let host = host.trim_matches(|c| c == '[' || c == ']');
    match host {
        "127.0.0.1" | "::1" | "localhost" => false,
        "0.0.0.0" | "::" | "*" => true,
        h => !h.starts_with("127."),
    }
}

/// Fill in listening endpoints + exposure for services that resolved to a PID.
fn enrich_exposure(services: &mut [ServiceInfo]) {
    for s in services.iter_mut() {
        if let Some(pid) = s.pid {
            let eps = listening_endpoints(pid);
            s.exposed = eps.iter().any(|e| endpoint_is_exposed(e));
            s.listeners = eps;
        }
    }
}

static VERSION_EXTRACT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ix)
        (?:version:\s*)?
        (?:[a-z][a-z0-9_\-]*[/_\s])?
        v?
        (
            \d+
            (?:\.\d+)*
            (?:[a-z]\d*)?
            (?:[-+~][0-9a-z][0-9a-z.+:~_-]*)?
        )
        "
    ).unwrap()
});

fn run_timed(exe: &str, flag: &str, timeout: Duration) -> Option<(bool, String, String)> {
    // Only ever execute an absolute path to a real file. This function runs
    // discovered binaries (often as root), so a bare name resolved via PATH is
    // refused outright to close the PATH-hijack code-execution hole.
    if !exe.starts_with('/') || !Path::new(exe).is_file() {
        return None;
    }

    let mut child = Command::new(exe)
        .arg(flag)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(30)),
            Err(_)   => break None,
        }
    }?;

    let mut out = String::new();
    let mut err = String::new();
    if let Some(mut o) = child.stdout.take() { let _ = o.read_to_string(&mut out); }
    if let Some(mut e) = child.stderr.take() { let _ = e.read_to_string(&mut err); }
    Some((status.success(), out, err))
}

// Extract a clean version token from raw `--version` output.

fn extract_version(text: &str) -> Option<String> {
    let bad = [
        "invalid",
        "unknown option",
        "usage:",
        "error:",
        "must be",
        "superuser",
        "permission",
    ];

    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()).take(10) {
        let lower = line.to_lowercase();

        if bad.iter().any(|b| lower.contains(b)) {
            continue;
        }

        if lower.contains("copyright") {
            continue;
        }

        if let Some(cap) = VERSION_EXTRACT_RE.captures(line) {
            let version = cap.get(1)?.as_str().trim().to_string();

            if looks_like_real_version(&version) {
                return Some(version);
            }
        }
    }

    None
}

fn looks_like_real_version(version: &str) -> bool {
    if version.is_empty() {
        return false;
    }

    if let Ok(num) = version.parse::<u32>() {
        if (1900..=2100).contains(&num) {
            return false;
        }
    }

    true
}

const TIMEOUT: Duration = Duration::from_secs(2);

fn probe_version(exe: &str) -> Option<String> {
    let bin_name = exe.rsplit('/').next().unwrap_or(exe);

    for flag in &["--version", "-V", "-v", "version"] {
        let Some((success, stdout, stderr)) = run_timed(exe, flag, TIMEOUT) else { continue };

        let candidate = if success {
            if !stdout.is_empty() { stdout } else { stderr }
        } else if stderr.contains(bin_name) {
            stderr
        } else {
            continue;
        };

        if let Some(v) = extract_version(&candidate) {
            return Some(v);
        }
    }
    None
}

fn run_cmd(program: &str, args: &[&str]) -> Option<String> {
    Command::new(program).args(args).output().ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
}

fn scan_sysvinit(os: &OsType) -> Vec<ServiceInfo> {
    let output = run_cmd("service", &["--status-all"])
        .or_else(|| run_cmd("rc-status", &["--all"]));

    let output = match output {
        Some(o) => o,
        None => {
            eprintln!("[!] no init scanner available (tried `service`, `rc-status`)");
            return vec![];
        }
    };

    let running: Vec<String> = output.lines()
        .filter_map(|line| {
            let t = line.trim();
            if t.starts_with("[ + ]") {
                Some(t.trim_start_matches("[ + ]").trim().to_string())
            } else if t.contains('[') && t.contains("started") {
                Some(t[..t.find('[').unwrap()].trim().to_string())
            } else { None }
        })
        .filter(|s| !s.is_empty())
        .collect();

    running.into_par_iter()
        .filter_map(|name| service_from_name(&name, os))
        .collect()
}

/// macOS relevance filter. Apple OS components (com.apple.* labels, binaries
/// under the SIP-protected system roots) are NOT scanned per-binary — they are
/// covered by the macOS system-version lookup, and probing hundreds of them with
/// `--version` is both useless (they don't report versions) and a subprocess
/// storm. Only third-party software (Homebrew, /usr/local, /Applications,
/// /Library) is worth a CVE lookup.
fn macos_relevant_path(exe: &str) -> bool {
    if exe.starts_with("/opt/")
        || exe.starts_with("/usr/local/")
        || exe.starts_with("/Applications/")
        || exe.starts_with("/Library/")
    {
        return true;
    }
    !(exe.starts_with("/System/")
        || exe.starts_with("/usr/")
        || exe.starts_with("/bin/")
        || exe.starts_with("/sbin/"))
}

fn scan_launchctl(os: &OsType) -> Vec<ServiceInfo> {
    // `launchctl list` columns: PID  Status  Label. A numeric PID means running.
    // Resolve the running process's absolute binary via `ps -o comm=` (the old
    // code fed the reverse-DNS Label straight into Command::new, which never
    // resolved a binary, so the macOS list was always empty).
    let output = run_cmd("launchctl", &["list"]).unwrap_or_default();

    let running: Vec<(String, String)> = output.lines().skip(1)
        .filter_map(|line| {
            let mut cols = line.split('\t');
            let pid = cols.next()?.trim().to_string();
            let _status = cols.next()?;
            let label = cols.next()?.trim().to_string();
            if pid == "-" || label.is_empty() || pid.parse::<u32>().is_err() {
                return None;
            }
            // Skip Apple system services up front (saves a `ps` per daemon).
            if label.starts_with("com.apple.") {
                return None;
            }
            Some((label, pid))
        })
        .collect();

    running.into_par_iter()
        .filter_map(|(label, pid)| {
            let exe = run_cmd("ps", &["-p", &pid, "-o", "comm="])
                .map(|s| s.trim().to_string())
                .filter(|s| s.starts_with('/'))?;
            // Only third-party software; skip OS-managed binaries.
            if !macos_relevant_path(&exe) {
                return None;
            }
            let name = homebrew_formula(&exe)
                .or_else(|| friendly_label(&label))
                .unwrap_or_else(|| binary_basename(&exe));
            make_service(&name, &exe, pid.parse::<u32>().ok(), os)
        })
        .collect()
}

fn binary_basename(exe: &str) -> String {
    exe.rsplit('/').next().unwrap_or(exe).to_string()
}

/// "/opt/homebrew/Cellar/nginx/1.27.0/bin/nginx" (canonicalized) -> "nginx"
fn homebrew_formula(exe: &str) -> Option<String> {
    let real = fs::canonicalize(exe).ok()?;
    let s = real.to_string_lossy();
    let idx = s.find("/Cellar/")?;
    s[idx + "/Cellar/".len()..].split('/').next().map(|x| x.to_string())
}

/// Turn a reverse-DNS launchd label into a friendlier service name, e.g.
/// "homebrew.mxcl.postgresql" -> "postgresql", "org.postgresql.postgres" -> "postgres".
fn friendly_label(label: &str) -> Option<String> {
    let last = label.rsplit('.').next()?.trim();
    (!last.is_empty()).then(|| last.to_string())
}

fn scan_bsd_rc(os: &OsType) -> Vec<ServiceInfo> {
    // `service -e` prints absolute rc.d script PATHS; the old code intersected
    // those against the bare names from `service -l`, yielding the empty set.
    // Take the basename of each enabled script instead.
    let enabled: Vec<String> = run_cmd("service", &["-e"])
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().rsplit('/').next())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .collect();

    enabled.into_par_iter()
        .filter_map(|name| {
            // Confirm actually running.
            let status = run_cmd("service", &[&name, "status"])?;
            if !status.to_lowercase().contains("running") {
                return None;
            }
            service_from_name(&name, os)
        })
        .collect()
}

fn scan_openbsd(os: &OsType) -> Vec<ServiceInfo> {
    // `rcctl ls started` = currently running (the old `rcctl ls on` listed
    // merely *enabled* services, including stopped ones).
    let names: Vec<String> = run_cmd("rcctl", &["ls", "started"])
        .unwrap_or_default()
        .lines().map(|l| l.trim().to_string())
        .filter(|s| !s.is_empty()).collect();

    names.into_par_iter()
        .filter_map(|name| service_from_name(&name, os))
        .collect()
}

fn scan_netbsd(os: &OsType) -> Vec<ServiceInfo> {
    // NetBSD has no rcctl. Enumerate /etc/rc.d and ask each script its status.
    let names: Vec<String> = match fs::read_dir("/etc/rc.d") {
        Ok(d) => d.filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect(),
        Err(_) => {
            eprintln!("[!] /etc/rc.d not readable; cannot enumerate NetBSD services");
            return vec![];
        }
    };

    names.into_par_iter()
        .filter_map(|name| {
            let script = format!("/etc/rc.d/{name}");
            let status = run_cmd(&script, &["status"])?;
            if !status.to_lowercase().contains("running") {
                return None;
            }
            service_from_name(&name, os)
        })
        .collect()
}

fn scan_smf(os: &OsType) -> Vec<ServiceInfo> {
    // svcs -H -o state,fmri  (machine-readable, no header)
    let output = run_cmd("svcs", &["-H", "-o", "state,fmri"]).unwrap_or_default();
    if output.is_empty() {
        eprintln!("[!] `svcs` returned nothing; SMF may be unavailable");
    }

    let online: Vec<String> = output.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let state = it.next()?;
            let fmri = it.next()?;
            (state == "online").then(|| fmri.to_string())
        })
        .collect();

    online.into_par_iter()
        .filter_map(|fmri| {
            // svcprop start/exec gives the start method command line.
            let exec = run_cmd("svcprop", &["-p", "start/exec", &fmri])
                .or_else(|| run_cmd("svcprop", &["-p", "method/exec", &fmri]))?;
            // First absolute-path token is the binary.
            let exe = exec.split_whitespace()
                .find(|t| t.starts_with('/'))
                .map(|s| s.to_string())
                .or_else(|| resolve_binary(exec.split_whitespace().next().unwrap_or("")))?;

            let display = fmri.trim_start_matches("svc:/")
                .split(':').next().unwrap_or(&fmri)
                .rsplit('/').next().unwrap_or(&fmri)
                .to_string();

            make_service(&display, &exe, None, os)
        })
        .collect()
}

fn scan_services(os: &OsType) -> Vec<ServiceInfo> {
    match os {
        OsType::Linux(_) => {
            if let Ok(conn) = Connection::system() {
                let units = list_systemd_units(&conn);
                if !units.is_empty() {
                    return units.into_par_iter()
                        .filter_map(|u| make_service(&u.name, &u.exe, u.pid, os))
                        .collect();
                }
                // D-Bus reachable but no units found — fall back to SysV/OpenRC.
                scan_sysvinit(os)
            } else {
                scan_sysvinit(os)
            }
        }
        OsType::MacOs                           => scan_launchctl(os),
        OsType::FreeBsd | OsType::DragonFlyBsd  => scan_bsd_rc(os),
        OsType::OpenBsd                          => scan_openbsd(os),
        OsType::NetBsd                           => scan_netbsd(os),
        OsType::Solaris | OsType::Illumos        => scan_smf(os),
        OsType::Unsupported(name) => {
            eprintln!("Unsupported OS: {name}");
            vec![]
        }
    }
}

fn spinner(msg: &str, quiet: bool) -> Option<ProgressBar> {
    if quiet {
        return None;
    }
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner()),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(100));
    Some(pb)
}

fn sev_rank(sev: Option<&str>) -> u8 {
    match sev.map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("critical") => 4,
        Some("high")     => 3,
        Some("medium")   => 2,
        Some("low")      => 1,
        _                => 0,
    }
}

fn severity_floor(s: Option<Severity>) -> u8 {
    match s {
        Some(Severity::Critical) => 4,
        Some(Severity::High)     => 3,
        Some(Severity::Medium)   => 2,
        Some(Severity::Low)      => 1,
        None                     => 0,
    }
}

fn paint(s: &str, code: &str, color: bool) -> String {
    if color { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() }
}

fn sev_label(sev: Option<&str>, color: bool) -> String {
    let (txt, code) = match sev_rank(sev) {
        4 => ("CRIT", "1;31"),
        3 => ("HIGH", "31"),
        2 => ("MED ", "33"),
        1 => ("LOW ", "2"),
        _ => ("UNK ", "2"),
    };
    paint(txt, code, color)
}

/// Ranked, optionally-colored terminal summary — exposed and highest-risk first.
fn print_summary(results: &BatchResults, color: bool) {
    let mut rows: Vec<(&String, bool, &Vec<ThreatEntry>)> = results.services.iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| (k, results.assets.get(k).map(|a| a.exposed).unwrap_or(false), v))
        .collect();
    if rows.is_empty() {
        return;
    }
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.len().cmp(&a.2.len())).then(a.0.cmp(b.0)));

    println!("\n{}", paint("Vulnerability summary (highest risk first):", "1", color));
    for (key, exposed, threats) in &rows {
        let badge = if *exposed {
            let eps = results.assets.get(*key).map(|a| a.listeners.join(", ")).unwrap_or_default();
            format!("  {}", paint(&format!("[EXPOSED {eps}]"), "1;31", color))
        } else {
            String::new()
        };
        println!("\n  {} — {} finding(s){badge}", paint(key, "1;36", color), threats.len());
        for t in threats.iter().take(5) {
            let cve = t.cve_id.as_deref().unwrap_or("(no id)");
            let kev = if t.kev { format!(" {}", paint("[KEV]", "1;31", color)) } else { String::new() };
            let title: String = t.title.as_deref().unwrap_or("").chars().take(72).collect();
            println!("      {}  {cve}{kev}  {title}", sev_label(t.severity.as_deref(), color));
        }
        if threats.len() > 5 {
            println!("      … and {} more", threats.len() - 5);
        }
    }

    let total: usize = rows.iter().map(|r| r.2.len()).sum();
    let exposed_svcs = rows.iter().filter(|r| r.1).count();
    let kev = rows.iter().flat_map(|r| r.2.iter()).filter(|t| t.kev).count();
    println!(
        "\n{total} finding(s) across {} service(s); {exposed_svcs} exposed, {kev} known-exploited.",
        rows.len()
    );
}

/// Whether the configured --fail-on threshold is met by any finding.
fn fail_triggered(results: &BatchResults, fail_on: FailOn, floor: Option<Severity>) -> bool {
    let floor = severity_floor(floor);
    let hit = |t: &ThreatEntry, exposed: bool| match fail_on {
        FailOn::Any      => sev_rank(t.severity.as_deref()) >= floor,
        FailOn::Critical => sev_rank(t.severity.as_deref()) >= 4,
        FailOn::High     => sev_rank(t.severity.as_deref()) >= 3,
        FailOn::Medium   => sev_rank(t.severity.as_deref()) >= 2,
        FailOn::Low      => sev_rank(t.severity.as_deref()) >= 1,
        FailOn::Kev      => t.kev,
        FailOn::Exposed  => exposed && sev_rank(t.severity.as_deref()) >= floor,
    };
    for (key, threats) in &results.services {
        let exposed = results.assets.get(key).map(|a| a.exposed).unwrap_or(false);
        if threats.iter().any(|t| hit(t, exposed)) {
            return true;
        }
    }
    if let Some(sys) = &results.system {
        if sys.values().flatten().any(|t| hit(t, false)) {
            return true;
        }
    }
    false
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let os = detect_os();
    if let OsType::Unsupported(name) = &os {
        eprintln!("Unsupported OS: {name}. Nothing to scan.");
        return ExitCode::from(3);
    }

    let interactive = !cli.yes && io::stdin().is_terminal();

    let api_key = match auth::resolve_api_key(cli.reset, interactive) {
        Some(k) => k,
        None => {
            eprintln!(
                "No API key available. Set OFFSEQ_API_KEY, or run interactively to enter one."
            );
            return ExitCode::from(2);
        }
    };

    // Decide where output goes before doing any slow work.
    let to_stdout = cli.json;
    let mut threats_path = if to_stdout {
        PathBuf::new()
    } else {
        cli.output.clone().unwrap_or_else(|| {
            if interactive {
                PathBuf::from(prompt_output_path())
            } else {
                PathBuf::from("/tmp/threats.json")
            }
        })
    };

    if !cli.quiet {
        println!("\nDetected OS: {}\n", os_label(&os));
    }

    let scan_pb = spinner("Scanning running services…", cli.quiet);
    let mut services = scan_services(&os);
    let system_info = gather_system_info(&os);
    if let Some(pb) = scan_pb {
        pb.finish_and_clear();
    }

    if !cli.quiet {
        if let Some(ref sys) = system_info {
            println!("System:");
            println!("  Kernel:  {} {}", sys.kernel_name, sys.kernel_version);
            println!("  Distro:  {} {}", sys.distro_name, sys.distro_version);
        }
    }

    services.sort_by(|a, b| a.name.cmp(&b.name));

    let exposure_pb = spinner("Correlating network exposure…", cli.quiet);
    enrich_exposure(&mut services);
    if let Some(pb) = exposure_pb { pb.finish_and_clear(); }

    if !cli.quiet {
        let exposed = services.iter().filter(|s| s.exposed).count();
        let suffix = if exposed > 0 { format!(", {exposed} network-exposed") } else { String::new() };
        println!("Found {} service(s){suffix}\n", services.len());
        if services.is_empty() {
            eprintln!("[!] No running services discovered — you may need elevated privileges (try sudo) for full discovery.");
        }
    }

    let entries: Vec<ThreatServiceEntry> = services
        .iter()
        .map(|svc| ThreatServiceEntry {
            name: normalize_service_name(strip_instance(&svc.name)).to_string(),
            version: svc.version.clone(),
        })
        .collect();

    let client = Arc::new(ThreatClient::new(&api_key));
    let lookup_pb = spinner("Querying the OffSeq threat API…", cli.quiet);
    let severity = cli.severity.map(|s| s.as_api());

    let batch = match run_batch(&client, &entries, 100, severity, None, None) {
        Ok(r) => r,
        Err(ThreatError::RateLimitExceeded(_)) => {
            if let Some(pb) = lookup_pb { pb.finish_and_clear(); }
            auth::prompt_upgrade();
            return ExitCode::from(4);
        }
        Err(e) => {
            if let Some(pb) = lookup_pb { pb.finish_and_clear(); }
            eprintln!("Threat lookup failed: {e}");
            return ExitCode::from(1);
        }
    };

    let system_results = if let Some(ref sys) = system_info {
        let threat_sys = ThreatSystemInfo {
            kernel_name: sys.kernel_name.clone(),
            kernel_version: sys.kernel_version.clone(),
            distro_name: sys.distro_name.clone(),
            distro_version: sys.distro_version.clone(),
        };

        match run_system_lookup(&client, &threat_sys, 100, severity, None, None) {
            Ok(r) => Some(r),
            Err(ThreatError::RateLimitExceeded(_)) => {
                if let Some(pb) = lookup_pb { pb.finish_and_clear(); }
                auth::prompt_upgrade();
                return ExitCode::from(4);
            }
            Err(e) => {
                eprintln!("System lookup failed: {e}");
                None
            }
        }
    } else {
        None
    };

    if let Some(pb) = lookup_pb { pb.finish_and_clear(); }
    if !cli.quiet { print_plan_info(&client.last_rate_limit()); }

    let mut assets: std::collections::BTreeMap<String, find_threats::AssetInfo> =
        std::collections::BTreeMap::new();
    for svc in &services {
        let key = format!("{}@{}", normalize_service_name(strip_instance(&svc.name)), svc.version);
        let a = assets.entry(key).or_insert_with(|| find_threats::AssetInfo {
            exe: svc.exe.clone(),
            version: svc.version.clone(),
            version_source: svc.source.as_str().to_string(),
            exposed: false,
            listeners: Vec::new(),
        });
        a.exposed |= svc.exposed;
        for l in &svc.listeners {
            if !a.listeners.contains(l) { a.listeners.push(l.clone()); }
        }
    }

    let final_results = BatchResults {
        services: batch.results,
        assets,
        system:   system_results,
        errors:   batch.errors,
    };

    let output_json = match serde_json::to_string_pretty(&final_results) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Failed to serialize results: {e}");
            return ExitCode::from(1);
        }
    };

    if to_stdout {
        println!("{output_json}");
    } else {
        loop {
            match fs::write(&threats_path, &output_json) {
                Ok(_) => break,
                Err(e) => {
                    eprintln!("\n[!] Couldn't write to '{}': {e}", threats_path.display());
                    if !interactive {
                        return ExitCode::from(1);
                    }
                    print!("Enter a new output path: ");
                    let _ = io::stdout().flush();
                    let mut new_path = String::new();
                    if io::stdin().read_line(&mut new_path).unwrap_or(0) == 0 {
                        return ExitCode::from(1);
                    }
                    let new_path = new_path.trim();
                    threats_path = PathBuf::from(expand_tilde(
                        if new_path.is_empty() { "/tmp/threats.json" } else { new_path },
                    ));
                }
            }
        }
    }

    if !cli.quiet && !to_stdout {
        let color = !cli.no_color
            && std::env::var_os("NO_COLOR").is_none()
            && io::stdout().is_terminal();
        print_summary(&final_results, color);
    }

    let total = final_results.total_vulns();
    let word = if total == 1 { "vulnerability" } else { "vulnerabilities" };
    if !final_results.errors.is_empty() {
        eprintln!(
            "[!] {} service lookup(s) failed; see the \"errors\" map in the output.",
            final_results.errors.len()
        );
    }
    if to_stdout {
        eprintln!("Found {total} {word}.");
    } else if !cli.quiet {
        println!("\nReport saved to {}", threats_path.display());
    }

    if let Some(f) = cli.fail_on {
        if fail_triggered(&final_results, f, cli.severity) {
            return ExitCode::from(5);
        }
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses() {
        // verify the derive layout is valid
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn atom_version_extraction() {
        assert_eq!(atom_version("nginx-1.26.2-r0").as_deref(), Some("1.26.2"));
        assert_eq!(atom_version("nginx-1.26.2nb1").as_deref(), Some("1.26.2nb1"));
        assert_eq!(atom_version("openssl-3.0.7").as_deref(), Some("3.0.7"));
        assert_eq!(atom_version("no-version-here"), None);
    }

    #[test]
    fn homebrew_version_from_cellar_path() {
        let p = "/opt/homebrew/Cellar/nginx/1.27.0/bin/nginx";
        assert_eq!(homebrew_version(p).as_deref(), Some("1.27.0"));
        assert_eq!(homebrew_formula(p), None); // formula needs a real canonicalize
        assert_eq!(homebrew_version("/usr/sbin/sshd"), None);
    }

    #[test]
    fn friendly_label_extraction() {
        assert_eq!(friendly_label("homebrew.mxcl.postgresql").as_deref(), Some("postgresql"));
        assert_eq!(friendly_label("org.postgresql.postgres").as_deref(), Some("postgres"));
        assert_eq!(friendly_label("com.apple.WindowServer").as_deref(), Some("WindowServer"));
    }

    #[test]
    fn strip_instance_and_normalize() {
        assert_eq!(strip_instance("postgresql@15-main"), "postgresql");
        assert_eq!(strip_instance("nginx"), "nginx");
        assert_eq!(normalize_service_name("ssh"), "openssh");
        assert_eq!(normalize_service_name(strip_instance("ssh@foo")), "openssh");
    }

    #[test]
    fn resolve_binary_finds_real_tool_and_rejects_garbage() {
        // `sh` exists in /bin on every unix
        let sh = resolve_binary("sh").expect("sh should resolve");
        assert!(sh.starts_with('/') && Path::new(&sh).is_file());
        assert_eq!(resolve_binary("definitely-not-a-real-binary-xyz"), None);
    }

    #[test]
    fn run_timed_refuses_non_absolute() {
        // bare name must be refused (PATH-hijack guard), even though `sh` exists
        assert!(run_timed("sh", "--version", Duration::from_secs(1)).is_none());
    }

    // Real integration smoke test for the macOS discovery rewrite. Only meaningful
    // on macOS; runs actual launchctl/ps so it is #[ignore]d by default (run with
    // `cargo test -- --ignored`). The old code returned an empty list here.
    #[test]
    #[ignore]
    #[cfg(target_os = "macos")]
    fn macos_discovery_finds_services() {
        let mut found = scan_launchctl(&OsType::MacOs);
        assert!(
            !found.is_empty(),
            "macOS scan should discover at least one running service with a version"
        );
        for s in &found {
            assert!(s.exe.starts_with('/'), "exe should be absolute: {}", s.exe);
            assert!(!s.version.is_empty(), "version should be non-empty for {}", s.name);
        }
        // Exercise the exposure-correlation (lsof) path end to end.
        enrich_exposure(&mut found);
        for s in &found {
            for ep in &s.listeners {
                assert!(ep.contains(':'), "listener endpoint should be host:port: {ep}");
            }
        }
    }

    #[test]
    fn endpoint_exposure_classification() {
        assert!(endpoint_is_exposed("0.0.0.0:443"));
        assert!(endpoint_is_exposed("[::]:443"));
        assert!(endpoint_is_exposed("192.168.1.5:22"));
        assert!(!endpoint_is_exposed("127.0.0.1:8080"));
        assert!(!endpoint_is_exposed("[::1]:631"));
    }

    #[test]
    fn proc_addr_parsing() {
        // little-endian hex 0100007F = 127.0.0.1, port 0x1F90 = 8080
        assert_eq!(parse_proc_addr("0100007F:1F90", false).as_deref(), Some("127.0.0.1:8080"));
        // 0.0.0.0:443
        assert_eq!(parse_proc_addr("00000000:01BB", false).as_deref(), Some("0.0.0.0:443"));
    }
}
