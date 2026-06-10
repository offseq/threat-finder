//! Host engine: OS detection, service discovery, binary resolution, version
//! sourcing (package DB first, `--version` probe as fallback), and
//! network-exposure correlation. Pure host interaction — no API types.

use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use rayon::prelude::*;
use regex::Regex;
use serde::Serialize;
use zbus::blocking::Connection;
use zbus::zvariant::OwnedValue;

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
    pub fn as_str(self) -> &'static str {
        match self {
            VersionSource::PackageDb => "package-db",
            VersionSource::Probe => "probe",
        }
    }
}

/// How reachable a listening socket is. Ordered least → most exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reachability {
    None,
    Loopback,
    Private,
    Public,
}

impl Reachability {
    pub fn as_str(self) -> &'static str {
        match self {
            Reachability::None => "none",
            Reachability::Loopback => "loopback",
            Reachability::Private => "private",
            Reachability::Public => "public",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name:      String,
    /// Owning package name when resolved from the package DB (the real coordinate).
    pub pkg_name:  Option<String>,
    pub version:   String,
    pub exe:       String,
    pub pid:       Option<u32>,
    pub source:    VersionSource,
    pub listeners: Vec<String>,
    pub reach:     Reachability,
    pub exposed:   bool,
}

#[derive(Serialize)]
pub struct SystemFacts {
    pub kernel_name:    String,
    pub kernel_version: String,
    pub distro_name:    String,
    pub distro_version: String,
}

pub fn detect_linux_distro() -> LinuxDistro {
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
pub fn os_label(os: &OsType) -> String {
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

pub fn gather_system_info(os: &OsType) -> Option<SystemFacts> {
    let kernel_version = run_cmd("uname", &["-r"])
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    if kernel_version.is_empty() {
        return None;
    }

    match os {
        OsType::Linux(distro) => {
            let (distro_name, distro_version) = parse_linux_distro_version(distro);
            Some(SystemFacts {
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
            Some(SystemFacts {
                kernel_name: "darwin".into(),
                kernel_version,
                distro_name: "macos".into(),
                distro_version: version,
            })
        }
        OsType::FreeBsd => {
            Some(SystemFacts {
                kernel_name:    "freebsd".into(),
                kernel_version: kernel_version.clone(),
                distro_name:    "freebsd".into(),
                distro_version: kernel_version,
            })
        }
        OsType::DragonFlyBsd => {
            Some(SystemFacts {
                kernel_name:    "dragonfly".into(),
                kernel_version: kernel_version.clone(),
                distro_name:    "dragonfly".into(),
                distro_version: kernel_version,
            })
        }
        OsType::OpenBsd => {
            Some(SystemFacts {
                kernel_name:    "openbsd".into(),
                kernel_version: kernel_version.clone(),
                distro_name:    "openbsd".into(),
                distro_version: kernel_version,
            })
        }
        OsType::NetBsd => {
            Some(SystemFacts {
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
            Some(SystemFacts {
                kernel_name: "sunos".into(),
                kernel_version,
                distro_name: "solaris".into(),
                distro_version: version,
            })
        }
        OsType::Illumos => {
            Some(SystemFacts {
                kernel_name:    "illumos".into(),
                kernel_version: kernel_version.clone(),
                distro_name:    "illumos".into(),
                distro_version: kernel_version,
            })
        }
        OsType::Unsupported(_) => None,
    }
}

pub struct UnitEntry {
    name: String,
    exe:  String,
    pid:  Option<u32>,
}

pub static EXECSTART_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#""/([^"]+)""#).unwrap());

// One row of systemd's Manager.ListUnits() reply:
// (name, description, load_state, active_state, sub_state, following,
//  unit_obj_path, job_id, job_type, job_obj_path)
pub type SystemdUnit = (
    String, String, String, String, String, String,
    zbus::zvariant::OwnedObjectPath, u32, String,
    zbus::zvariant::OwnedObjectPath,
);

pub fn list_systemd_units(conn: &Connection) -> Vec<UnitEntry> {
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

    // A typed-decode error here used to be swallowed (`unwrap_or_default()`),
    // turning a pure-systemd host into a silent "clean" scan. Log it and return
    // an explicit empty list so the failure is visible rather than masked.
    let units: Vec<SystemdUnit> = match proxy.call("ListUnits", &()) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("[!] systemd ListUnits failed ({e}); no services discovered via systemd.");
            return vec![];
        }
    };

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
pub fn resolve_exe(conn: &Connection, obj_path: &str, unit_name: &str) -> Option<(String, Option<u32>)> {
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

    if SYSTEMD_ONE_SHOTS.contains(&unit_name) {
        return None;
    }

    if unit_name.starts_with("systemd-") {
        return Some(("/usr/lib/systemd/systemd".to_string(), pid));
    }

    None
}

pub fn normalize_service_name(name: &str) -> &str {
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
pub fn strip_instance(name: &str) -> &str {
    name.split('@').next().unwrap_or(name)
}

pub fn parse_linux_distro_version(distro: &LinuxDistro) -> (String, String) {
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


pub const SYSTEMD_ONE_SHOTS: &[&str] = &[
    "systemd-journal-flush", "systemd-tmpfiles-setup",
    "systemd-tmpfiles-setup-dev", "systemd-tmpfiles-setup-dev-early",
    "systemd-udev-trigger", "systemd-update-utmp", "systemd-user-sessions",
    "systemd-remount-fs", "systemd-random-seed", "systemd-binfmt",
    "systemd-modules-load", "systemd-sysctl",
];

pub const SAFE_PATH_DIRS: &[&str] = &[
    "/usr/local/sbin", "/usr/local/bin",
    "/usr/sbin", "/usr/bin", "/sbin", "/bin",
    "/opt/homebrew/bin", "/opt/homebrew/sbin",
    "/usr/pkg/sbin", "/usr/pkg/bin",
];

/// A few service names whose daemon binary is reliably different from the name.
pub fn daemon_alias(service: &str) -> &str {
    match service {
        "ssh" => "sshd",
        _ => service,
    }
}

/// Resolve a service/command name to an absolute binary path by reading the
/// filesystem only (no execution). Tries the name, then a "<name>d" daemon
/// variant, across common bin dirs and any absolute $PATH entries.
pub fn resolve_binary(name: &str) -> Option<String> {
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
pub static ATOM_VER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"-(\d[0-9A-Za-z.+~]*)").unwrap());

pub fn atom_version(atom: &str) -> Option<String> {
    ATOM_VER_RE.captures(atom.trim()).map(|c| c[1].to_string())
}

/// Ask the OS package database for the version that owns `exe`. Returns None when
/// no package owns it (e.g. a base-system binary) so the caller can fall back.
/// Resolve the owning package's (name, full-version) for a binary, querying the
/// OS package database. The package NAME is the real coordinate (e.g. a unit
/// "ssh" resolves to "openssh-server"), so the purl is built from the true
/// package, not the service alias.
pub fn package_of(exe: &str, os: &OsType) -> Option<(String, String)> {
    let real = fs::canonicalize(exe).ok()?;
    let path = real.to_string_lossy().to_string();

    match os {
        OsType::Linux(distro) => match distro {
            LinuxDistro::Debian | LinuxDistro::Ubuntu | LinuxDistro::Kali => dpkg_of(&path),
            LinuxDistro::Fedora | LinuxDistro::Rhel | LinuxDistro::CentOs | LinuxDistro::OpenSuse => rpm_of(&path),
            LinuxDistro::Arch => pacman_of(&path),
            LinuxDistro::Alpine => apk_of(&path),
            _ => dpkg_of(&path)
                .or_else(|| rpm_of(&path))
                .or_else(|| pacman_of(&path))
                .or_else(|| apk_of(&path)),
        },
        OsType::MacOs => homebrew_of(&path),
        OsType::FreeBsd | OsType::DragonFlyBsd => freebsd_of(&path),
        OsType::OpenBsd => pkg_info_of(&path, false),
        OsType::NetBsd | OsType::Illumos => pkg_info_of(&path, true),
        OsType::Solaris => None, // IPS resolution deferred; falls back to probe
        OsType::Unsupported(_) => None,
    }
}

pub fn dpkg_of(path: &str) -> Option<(String, String)> {
    // dpkg-query -S <path> -> "pkg: /path" (or "pkg1, pkg2: /path"), possibly
    // preceded by "diversion by <pkg> from: /path" lines for diverted files.
    let owner = run_cmd("dpkg-query", &["-S", path])?;
    let pkg = dpkg_owner_name(&owner)?;
    let ver = run_cmd("dpkg-query", &["-W", "-f=${Version}", &pkg])?.trim().to_string();
    (!ver.is_empty()).then_some((pkg, ver))
}

/// Extract the owning package name from `dpkg-query -S` output. The field
/// separator before the path is `": "`, so we split on the LAST one — names can
/// carry a multiarch suffix (`libssl3:amd64: /path`) that a naive `split(':')`
/// would truncate. Diversion lines are skipped; the first comma-listed name wins.
fn dpkg_owner_name(out: &str) -> Option<String> {
    out.lines()
        .filter(|l| !l.starts_with("diversion by ") && !l.starts_with("local diversion "))
        .find_map(|l| l.rsplit_once(": "))
        .map(|(names, _path)| names)
        .and_then(|names| names.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn rpm_of(path: &str) -> Option<(String, String)> {
    let out = run_cmd("rpm", &["-qf", "--queryformat", "%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\n", path])?;
    let line = out.lines().next()?;
    if line.to_lowercase().contains("not owned") {
        return None;
    }
    let mut c = line.split('\t');
    let name = c.next()?.trim().to_string();
    let epoch = c.next().unwrap_or("").trim();
    let version = c.next()?.trim();
    let release = c.next().unwrap_or("").trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    let mut evr = String::new();
    if !epoch.is_empty() && epoch != "(none)" {
        evr.push_str(epoch);
        evr.push(':');
    }
    evr.push_str(version);
    if !release.is_empty() && release != "(none)" {
        evr.push('-');
        evr.push_str(release);
    }
    Some((name, evr))
}

pub fn pacman_of(path: &str) -> Option<(String, String)> {
    // pacman -Qo <path> -> "/usr/bin/nginx is owned by nginx 1.27.0-1"
    let out = run_cmd("pacman", &["-Qo", path])?;
    let after = out.split(" is owned by ").nth(1)?;
    let mut it = after.split_whitespace();
    Some((it.next()?.to_string(), it.next()?.to_string()))
}

pub fn apk_of(path: &str) -> Option<(String, String)> {
    // apk info -W <path> -> "<path> is owned by nginx-1.26.2-r0"
    let out = run_cmd("apk", &["info", "-W", path])?;
    atom_split(out.split("owned by ").nth(1)?.trim())
}

pub fn homebrew_version(path: &str) -> Option<String> {
    homebrew_of(path).map(|(_, v)| v)
}

pub fn homebrew_of(path: &str) -> Option<(String, String)> {
    // canonicalized brew binaries live at .../Cellar/<name>/<version>/...
    let idx = path.find("/Cellar/")?;
    let rest = &path[idx + "/Cellar/".len()..];
    let mut it = rest.split('/');
    let name = it.next()?.to_string();
    let version = it.next()?.to_string();
    (!name.is_empty() && !version.is_empty()).then_some((name, version))
}

pub fn freebsd_of(path: &str) -> Option<(String, String)> {
    // pkg which -q <path> -> "nginx-1.27.0"
    atom_split(run_cmd("pkg", &["which", "-q", path])?.trim())
}

pub fn pkg_info_of(path: &str, file_flag: bool) -> Option<(String, String)> {
    // OpenBSD: pkg_info -E <path> -> "nginx-1.26.2: /usr/local/sbin/nginx"
    // NetBSD : pkg_info -Fe <path> -> "nginx-1.26.2nb1"
    let out = if file_flag {
        run_cmd("pkg_info", &["-Fe", path])?
    } else {
        run_cmd("pkg_info", &["-E", path])?
    };
    let atom = out.split(':').next().unwrap_or(&out).split_whitespace().next()?;
    atom_split(atom)
}

/// Resolve (owning-package-name, version, source) for a binary: package DB
/// first, then a `--version` probe (no package name) as last resort.
pub fn version_for_binary(exe: &str, os: &OsType) -> Option<(Option<String>, String, VersionSource)> {
    if let Some((name, version)) = package_of(exe, os) {
        return Some((Some(name), version, VersionSource::PackageDb));
    }
    probe_version(exe).map(|v| (None, v, VersionSource::Probe))
}

pub fn make_service(name: &str, exe: &str, pid: Option<u32>, os: &OsType) -> Option<ServiceInfo> {
    let (pkg_name, version, source) = version_for_binary(exe, os)?;
    Some(ServiceInfo {
        name: name.to_string(),
        pkg_name,
        version,
        exe: exe.to_string(),
        pid,
        source,
        listeners: Vec::new(),
        reach: Reachability::None,
        exposed: false,
    })
}

/// Build a ServiceInfo from a service name by resolving its binary and version.
pub fn service_from_name(display_name: &str, os: &OsType) -> Option<ServiceInfo> {
    let exe = resolve_binary(display_name)?;
    make_service(display_name, &exe, None, os)
}

// Network-exposure correlation
//
// Mapping each running service to the sockets it is LISTENING on — and whether
// any is reachable off-host — is the tool's signature capability: manifest
// scanners can't see runtime state, and external scanners need a second host.

pub fn listening_endpoints(pid: u32) -> Vec<String> {
    let mut eps = if cfg!(target_os = "linux") {
        linux_listeners(pid)
    } else {
        lsof_listeners(pid)
    };
    eps.sort();
    eps.dedup();
    eps
}

/// Listening endpoints via `lsof` (macOS/BSD/Solaris). Uses field output (`-Fn`)
/// so the address is a clean `n`-prefixed line — the human format suffixes each
/// row with "(LISTEN)", which the old `.last()` parser picked up instead of the
/// address, leaving exposure silently dead on every non-Linux platform.
pub fn lsof_listeners(pid: u32) -> Vec<String> {
    let mut out = Vec::new();
    for ep in lsof_names(pid, &["-iTCP", "-sTCP:LISTEN"]) {
        out.push(format!("tcp {ep}"));
    }
    for ep in lsof_names(pid, &["-iUDP"]) {
        out.push(format!("udp {ep}"));
    }
    out
}

pub fn lsof_names(pid: u32, filter: &[&str]) -> Vec<String> {
    let pid = pid.to_string();
    let mut args = vec!["-nP", "-p", &pid];
    args.extend_from_slice(filter);
    args.push("-Fn");
    run_cmd("lsof", &args)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.strip_prefix('n'))
        .map(|s| s.trim().to_string())
        // A bound listener has a local address; connected sockets contain "->".
        .filter(|s| s.contains(':') && !s.contains("->"))
        .collect()
}

pub fn proc_socket_inodes(pid: u32) -> std::collections::HashSet<String> {
    let mut inodes = std::collections::HashSet::new();
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
    inodes
}

pub fn linux_listeners(pid: u32) -> Vec<String> {
    let inodes = proc_socket_inodes(pid);
    if inodes.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();

    // TCP: state 0A = LISTEN.
    for (path, v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        let Ok(content) = fs::read_to_string(path) else { continue };
        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 || cols[3] != "0A" {
                continue;
            }
            if inodes.contains(cols[9]) {
                if let Some(ep) = parse_proc_addr(cols[1], v6) {
                    out.push(format!("tcp {ep}"));
                }
            }
        }
    }

    // UDP: a bound listener has no remote peer (remote port == 0).
    for (path, v6) in [("/proc/net/udp", false), ("/proc/net/udp6", true)] {
        let Ok(content) = fs::read_to_string(path) else { continue };
        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 || !cols[2].ends_with(":0000") {
                continue;
            }
            if inodes.contains(cols[9]) {
                if let Some(ep) = parse_proc_addr(cols[1], v6) {
                    out.push(format!("udp {ep}"));
                }
            }
        }
    }
    out
}

/// Parse a /proc/net hex "addr:port" (little-endian) into "ip:port".
pub fn parse_proc_addr(s: &str, v6: bool) -> Option<String> {
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

/// Bare host of an endpoint (drops a `tcp `/`udp ` prefix, port, and brackets).
pub fn endpoint_host(ep: &str) -> &str {
    let ep = ep.strip_prefix("tcp ").or_else(|| ep.strip_prefix("udp ")).unwrap_or(ep);
    let host = ep.rsplit_once(':').map(|(h, _)| h).unwrap_or(ep);
    host.trim_matches(|c| c == '[' || c == ']')
}

fn classify_v4(v4: std::net::Ipv4Addr) -> Reachability {
    let o = v4.octets();
    if v4.is_loopback() {
        Reachability::Loopback
    } else if v4.is_private()
        || v4.is_link_local()
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT 100.64.0.0/10
    {
        Reachability::Private
    } else {
        Reachability::Public
    }
}

/// Classify how reachable a listener is: loopback, private (LAN/CGNAT/ULA), or
/// public (routable / wildcard). Sharpens the "internet-exposed" signal.
pub fn endpoint_reachability(ep: &str) -> Reachability {
    use std::net::{Ipv4Addr, Ipv6Addr};
    let host = endpoint_host(ep);
    match host {
        "0.0.0.0" | "::" | "*" => Reachability::Public,
        "127.0.0.1" | "::1" | "localhost" => Reachability::Loopback,
        h => {
            if let Ok(v4) = h.parse::<Ipv4Addr>() {
                classify_v4(v4)
            } else if let Ok(v6) = h.parse::<Ipv6Addr>() {
                // ::ffff:a.b.c.d — classify by the embedded IPv4 (else a
                // loopback/LAN service appears Public).
                if let Some(v4) = v6.to_ipv4_mapped() {
                    classify_v4(v4)
                } else if v6.is_loopback() {
                    Reachability::Loopback
                } else {
                    let seg0 = v6.segments()[0];
                    if (seg0 & 0xfe00) == 0xfc00      // ULA fc00::/7
                        || (seg0 & 0xffc0) == 0xfe80  // link-local fe80::/10
                    {
                        Reachability::Private
                    } else {
                        Reachability::Public
                    }
                }
            } else {
                Reachability::Public // unknown host string: assume worst
            }
        }
    }
}

/// Fill in listening endpoints + reachability for services that resolved to a PID.
pub fn enrich_exposure(services: &mut [ServiceInfo]) {
    for s in services.iter_mut() {
        if let Some(pid) = s.pid {
            let eps = listening_endpoints(pid);
            s.reach = eps.iter().map(|e| endpoint_reachability(e)).max().unwrap_or(Reachability::None);
            s.exposed = s.reach >= Reachability::Private;
            s.listeners = eps;
        }
    }
}

pub static VERSION_EXTRACT_RE: Lazy<Regex> = Lazy::new(|| {
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

pub fn run_timed(exe: &str, flag: &str, timeout: Duration) -> Option<(bool, String, String)> {
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

pub fn extract_version(text: &str) -> Option<String> {
    const BAD: &[&str] = &[
        "invalid", "unknown option", "usage:", "error:",
        "must be", "superuser", "permission",
    ];
    let bad = BAD;

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

pub fn looks_like_real_version(version: &str) -> bool {
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

pub const TIMEOUT: Duration = Duration::from_secs(2);

pub fn probe_version(exe: &str) -> Option<String> {
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

pub fn run_cmd(program: &str, args: &[&str]) -> Option<String> {
    Command::new(program).args(args).output().ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
}

pub fn scan_sysvinit(os: &OsType) -> Vec<ServiceInfo> {
    let output = run_cmd("service", &["--status-all"])
        .or_else(|| run_cmd("rc-status", &["--all"]));

    let output = match output {
        Some(o) => o,
        None => {
            eprintln!("[!] no init scanner available (tried `service`, `rc-status`)");
            return vec![];
        }
    };

    parse_sysvinit_running(&output)
        .into_par_iter()
        .filter_map(|name| service_from_name(&name, os))
        .collect()
}

/// Parse running service names from `service --status-all` / `rc-status --all`.
pub fn parse_sysvinit_running(output: &str) -> Vec<String> {
    output.lines()
        .filter_map(|line| {
            let t = line.trim();
            if t.starts_with("[ + ]") {
                Some(t.trim_start_matches("[ + ]").trim().to_string())
            } else if t.contains('[') && t.contains("started") {
                Some(t[..t.find('[').unwrap()].trim().to_string())
            } else {
                None
            }
        })
        .filter(|s| !s.is_empty())
        .collect()
}

/// macOS relevance filter. Apple OS components (com.apple.* labels, binaries
/// under the SIP-protected system roots) are NOT scanned per-binary — they are
/// covered by the macOS system-version lookup, and probing hundreds of them with
/// `--version` is both useless (they don't report versions) and a subprocess
/// storm. Only third-party software (Homebrew, /usr/local, /Applications,
/// /Library) is worth a CVE lookup.
pub fn macos_relevant_path(exe: &str) -> bool {
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

pub fn scan_launchctl(os: &OsType) -> Vec<ServiceInfo> {
    // `launchctl list` columns: PID  Status  Label. A numeric PID means running.
    // Resolve the running process's absolute binary via `ps -o comm=` (the old
    // code fed the reverse-DNS Label straight into Command::new, which never
    // resolved a binary, so the macOS list was always empty).
    let output = run_cmd("launchctl", &["list"]).unwrap_or_default();

    parse_launchctl_running(&output)
        .into_par_iter()
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

/// Parse running (label, pid) pairs from `launchctl list`, skipping non-running
/// entries (PID "-") and Apple system services.
pub fn parse_launchctl_running(output: &str) -> Vec<(String, String)> {
    output.lines().skip(1)
        .filter_map(|line| {
            let mut cols = line.split('\t');
            let pid = cols.next()?.trim().to_string();
            let _status = cols.next()?;
            let label = cols.next()?.trim().to_string();
            if pid == "-" || label.is_empty() || pid.parse::<u32>().is_err() {
                return None;
            }
            if label.starts_with("com.apple.") {
                return None;
            }
            Some((label, pid))
        })
        .collect()
}

pub fn binary_basename(exe: &str) -> String {
    exe.rsplit('/').next().unwrap_or(exe).to_string()
}

/// "/opt/homebrew/Cellar/nginx/1.27.0/bin/nginx" (canonicalized) -> "nginx"
pub fn homebrew_formula(exe: &str) -> Option<String> {
    let real = fs::canonicalize(exe).ok()?;
    let s = real.to_string_lossy();
    let idx = s.find("/Cellar/")?;
    s[idx + "/Cellar/".len()..].split('/').next().map(|x| x.to_string())
}

/// Turn a reverse-DNS launchd label into a friendlier service name, e.g.
/// "homebrew.mxcl.postgresql" -> "postgresql", "org.postgresql.postgres" -> "postgres".
pub fn friendly_label(label: &str) -> Option<String> {
    let last = label.rsplit('.').next()?.trim();
    (!last.is_empty()).then(|| last.to_string())
}

pub fn scan_bsd_rc(os: &OsType) -> Vec<ServiceInfo> {
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

pub fn scan_openbsd(os: &OsType) -> Vec<ServiceInfo> {
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

pub fn scan_netbsd(os: &OsType) -> Vec<ServiceInfo> {
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

/// Parse online FMRIs from `svcs -H -o state,fmri`.
pub fn parse_svcs_online(output: &str) -> Vec<String> {
    output.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let state = it.next()?;
            let fmri = it.next()?;
            (state == "online").then(|| fmri.to_string())
        })
        .collect()
}

pub fn scan_smf(os: &OsType) -> Vec<ServiceInfo> {
    // svcs -H -o state,fmri  (machine-readable, no header)
    let output = run_cmd("svcs", &["-H", "-o", "state,fmri"]).unwrap_or_default();
    if output.is_empty() {
        eprintln!("[!] `svcs` returned nothing; SMF may be unavailable");
    }

    parse_svcs_online(&output)
        .into_par_iter()
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

pub fn scan_services(os: &OsType) -> Vec<ServiceInfo> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::time::Duration;

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
        assert_eq!(homebrew_formula(p), None); // needs a real canonicalize
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
        let sh = resolve_binary("sh").expect("sh should resolve");
        assert!(sh.starts_with('/') && Path::new(&sh).is_file());
        assert_eq!(resolve_binary("definitely-not-a-real-binary-xyz"), None);
    }

    #[test]
    fn run_timed_refuses_non_absolute() {
        assert!(run_timed("sh", "--version", Duration::from_secs(1)).is_none());
    }

    #[test]
    #[ignore]
    #[cfg(target_os = "macos")]
    fn macos_discovery_finds_services() {
        let mut found = scan_launchctl(&OsType::MacOs);
        assert!(!found.is_empty(), "macOS scan should discover at least one service");
        for s in &found {
            assert!(s.exe.starts_with('/'), "exe should be absolute: {}", s.exe);
            assert!(!s.version.is_empty(), "version should be non-empty for {}", s.name);
        }
        enrich_exposure(&mut found);
        let total_listeners: usize = found.iter().map(|s| s.listeners.len()).sum();
        assert!(total_listeners > 0, "lsof exposure parsing returned no listeners");
        for s in &found {
            for ep in &s.listeners {
                assert!(ep.contains(':'), "listener endpoint should be host:port: {ep}");
            }
        }
    }

    #[test]
    fn reachability_classification() {
        use Reachability::*;
        assert_eq!(endpoint_reachability("tcp 0.0.0.0:443"), Public);
        assert_eq!(endpoint_reachability("[::]:443"), Public);
        assert_eq!(endpoint_reachability("203.0.113.5:22"), Public);
        assert_eq!(endpoint_reachability("192.168.1.5:22"), Private);
        assert_eq!(endpoint_reachability("10.0.0.9:5432"), Private);
        assert_eq!(endpoint_reachability("udp 100.64.0.1:53"), Private);
        assert_eq!(endpoint_reachability("127.0.0.1:8080"), Loopback);
        assert_eq!(endpoint_reachability("[::1]:631"), Loopback);
        // IPv4-mapped IPv6 must classify by the embedded v4 (not fall to Public).
        assert_eq!(endpoint_reachability("[::ffff:127.0.0.1]:8080"), Loopback);
        assert_eq!(endpoint_reachability("[::ffff:192.168.1.1]:443"), Private);
        assert_eq!(endpoint_reachability("[::ffff:203.0.113.5]:443"), Public);
        assert!(Public > Private && Private > Loopback && Loopback > None);
    }

    #[test]
    fn proc_addr_parsing() {
        assert_eq!(parse_proc_addr("0100007F:1F90", false).as_deref(), Some("127.0.0.1:8080"));
        assert_eq!(parse_proc_addr("00000000:01BB", false).as_deref(), Some("0.0.0.0:443"));
    }

    #[test]
    fn parse_launchctl_fixture() {
        let out = "PID\tStatus\tLabel\n\
                   653\t0\thomebrew.mxcl.nginx\n\
                   -\t0\tcom.example.stopped\n\
                   42\t0\tcom.apple.something\n\
                   88\t0\torg.postgresql.postgres\n";
        assert_eq!(parse_launchctl_running(out), vec![
            ("homebrew.mxcl.nginx".to_string(), "653".to_string()),
            ("org.postgresql.postgres".to_string(), "88".to_string()),
        ]);
    }

    #[test]
    fn parse_sysvinit_fixture() {
        let out = " [ + ]  ssh\n [ - ]  cups\n nginx        [ started ]\n [ ? ]  weird\n";
        assert_eq!(parse_sysvinit_running(out), vec!["ssh".to_string(), "nginx".to_string()]);
    }

    #[test]
    fn parse_svcs_fixture() {
        let out = "online\tsvc:/network/ssh:default\n\
                   disabled\tsvc:/network/telnet:default\n\
                   online\tsvc:/system/system-log:default\n";
        assert_eq!(parse_svcs_online(out), vec![
            "svc:/network/ssh:default".to_string(),
            "svc:/system/system-log:default".to_string(),
        ]);
    }
}

// ── Phase 1: full installed-package inventory ────────────────────────────────
//
// Enumerate EVERY installed package (not just those backing a running process)
// so the scanner can match the full Radar catalog. Each list_* shells out once
// and parses with a pure helper (fixture-tested below).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledPkg {
    pub name: String,
    pub version: String,
    pub tool: &'static str,
}

/// Split a package atom like "nginx-1.26.2-r0" / "openssl-3.0.7" into
/// (name, upstream-version). Names may contain hyphens, so anchor on the first
/// "-<digit>" run.
fn atom_split(atom: &str) -> Option<(String, String)> {
    let atom = atom.trim();
    // Anchor on the LAST "-<digit…>" run: the version is the trailing component,
    // so names with embedded numeric segments (e.g. "gtk-3-3.24.0") split right.
    let m = ATOM_VER_RE.find_iter(atom).last()?;
    let name = atom[..m.start()].trim().to_string();
    // Keep the FULL version (incl. -rN / nbN / patchlevel) for ecosystem-native
    // comparison; the upstream-only capture would be lossy.
    let ver = atom[m.start() + 1..].trim().to_string();
    (!name.is_empty() && !ver.is_empty()).then_some((name, ver))
}

/// Read a single field from /etc/os-release (e.g. VERSION_CODENAME, VERSION_ID).
pub fn os_release_field(key: &str) -> Option<String> {
    let content = std::fs::read_to_string("/etc/os-release").ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix(key).and_then(|r| r.strip_prefix('=')) {
            let v = rest.trim().trim_matches('"').to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

pub fn parse_dpkg_list(out: &str) -> Vec<(String, String)> {
    out.lines().filter_map(|l| {
        let mut c = l.split('\t');
        let status = c.next()?;
        let name = c.next()?;
        let ver = c.next()?;
        // 2nd status char 'i' = installed/held; drops 'rc' config-only etc.
        if status.chars().nth(1) != Some('i') || name.is_empty() || ver.is_empty() {
            return None;
        }
        Some((name.to_string(), ver.to_string()))
    }).collect()
}

pub fn parse_rpm_list(out: &str) -> Vec<(String, String)> {
    out.lines().filter_map(|l| {
        let mut c = l.split('\t');
        let name = c.next()?;
        let epoch = c.next()?;
        let version = c.next()?;
        let release = c.next().unwrap_or("");
        if name == "gpg-pubkey" || name.is_empty() || version.is_empty() {
            return None;
        }
        // Full EVR so Radar can compare with rpm rules: [epoch:]version-release.
        let mut evr = String::new();
        if !epoch.is_empty() && epoch != "(none)" {
            evr.push_str(epoch);
            evr.push(':');
        }
        evr.push_str(version);
        if !release.is_empty() && release != "(none)" {
            evr.push('-');
            evr.push_str(release);
        }
        Some((name.to_string(), evr))
    }).collect()
}

pub fn parse_pacman_list(out: &str) -> Vec<(String, String)> {
    out.lines().filter_map(|l| {
        let mut it = l.split_whitespace();
        Some((it.next()?.to_string(), it.next()?.to_string()))
    }).collect()
}

pub fn parse_apk_list(out: &str) -> Vec<(String, String)> {
    out.lines().filter_map(|l| atom_split(l.trim())).collect()
}

pub fn parse_brew_list(out: &str) -> Vec<(String, String)> {
    // "name v1 v2 ..." — one entry per kept version.
    out.lines().flat_map(|l| {
        let mut it = l.split_whitespace();
        let name = match it.next() { Some(n) => n.to_string(), None => return Vec::new() };
        it.map(|v| (name.clone(), v.to_string())).collect::<Vec<_>>()
    }).collect()
}

pub fn parse_pkg_query_list(out: &str) -> Vec<(String, String)> {
    // FreeBSD `pkg query '%n %v'`
    out.lines().filter_map(|l| {
        let mut it = l.split_whitespace();
        Some((it.next()?.to_string(), it.next()?.to_string()))
    }).collect()
}

pub fn parse_pkg_info_list(out: &str) -> Vec<(String, String)> {
    // OpenBSD/NetBSD `pkg_info` — first token is the PKGNAME atom.
    out.lines().filter_map(|l| atom_split(l.split_whitespace().next()?)).collect()
}

fn tagged(tool: &'static str, pairs: Vec<(String, String)>) -> Vec<InstalledPkg> {
    pairs.into_iter().map(|(name, version)| InstalledPkg { name, version, tool }).collect()
}

/// Enumerate all installed packages for the host's OS. Empty when no supported
/// package manager is available (e.g. Solaris IPS — deferred).
pub fn list_installed(os: &OsType) -> Vec<InstalledPkg> {
    match os {
        OsType::Linux(distro) => match distro {
            LinuxDistro::Debian | LinuxDistro::Ubuntu | LinuxDistro::Kali =>
                tagged("dpkg", run_cmd("dpkg-query", &["-W", "-f=${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${Architecture}\n"]).map(|o| parse_dpkg_list(&o)).unwrap_or_default()),
            LinuxDistro::Fedora | LinuxDistro::Rhel | LinuxDistro::CentOs | LinuxDistro::OpenSuse =>
                tagged("rpm", run_cmd("rpm", &["-qa", "--qf", "%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n"]).map(|o| parse_rpm_list(&o)).unwrap_or_default()),
            LinuxDistro::Arch =>
                tagged("pacman", run_cmd("pacman", &["-Q"]).map(|o| parse_pacman_list(&o)).unwrap_or_default()),
            LinuxDistro::Alpine =>
                tagged("apk", run_cmd("apk", &["info", "-v"]).map(|o| parse_apk_list(&o)).unwrap_or_default()),
            _ => Vec::new(),
        },
        OsType::MacOs =>
            tagged("brew", run_cmd("brew", &["list", "--versions"]).map(|o| parse_brew_list(&o)).unwrap_or_default()),
        OsType::FreeBsd | OsType::DragonFlyBsd =>
            tagged("pkg", run_cmd("pkg", &["query", "%n %v"]).map(|o| parse_pkg_query_list(&o)).unwrap_or_default()),
        OsType::OpenBsd =>
            tagged("pkg_info", run_cmd("pkg_info", &["-q"]).map(|o| parse_pkg_info_list(&o)).unwrap_or_default()),
        OsType::NetBsd =>
            tagged("pkg_info", run_cmd("pkg_info", &[]).map(|o| parse_pkg_info_list(&o)).unwrap_or_default()),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod inventory_tests {
    use super::*;

    #[test]
    fn dpkg_parse() {
        let out = "ii \topenssl\t3.0.11-1~deb12u2\tamd64\n\
                   rc \toldpkg\t1.0\tamd64\n\
                   ii \tnginx\t1.22.1-9\tall\n";
        assert_eq!(parse_dpkg_list(out), vec![
            ("openssl".into(), "3.0.11-1~deb12u2".into()),
            ("nginx".into(), "1.22.1-9".into()),
        ]);
    }

    #[test]
    fn rpm_parse() {
        let out = "openssl\t1\t3.0.7\t18.el9\tx86_64\n\
                   gpg-pubkey\t(none)\tfd431d51\t4ae0493b\t(none)\n\
                   httpd\t(none)\t2.4.57\t5.el9\tx86_64\n\
                   basesystem\t(none)\t11\t(none)\tnoarch\n";
        assert_eq!(parse_rpm_list(out), vec![
            ("openssl".into(), "1:3.0.7-18.el9".into()),
            ("httpd".into(), "2.4.57-5.el9".into()),
            // literal "(none)" release must not leak into the EVR
            ("basesystem".into(), "11".into()),
        ]);
    }

    #[test]
    fn pacman_parse() {
        assert_eq!(parse_pacman_list("nginx 1.27.0-1\nopenssl 3.3.2-1\n"),
            vec![("nginx".into(), "1.27.0-1".into()), ("openssl".into(), "3.3.2-1".into())]);
    }

    #[test]
    fn apk_and_pkginfo_atoms() {
        assert_eq!(parse_apk_list("nginx-1.26.2-r0\nmusl-1.2.5-r0\n"),
            vec![("nginx".into(), "1.26.2-r0".into()), ("musl".into(), "1.2.5-r0".into())]);
        assert_eq!(parse_pkg_info_list("nginx-1.26.2 web server\nbash-5.2.15nb1 shell\n"),
            vec![("nginx".into(), "1.26.2".into()), ("bash".into(), "5.2.15nb1".into())]);
        // name with an embedded numeric segment splits at the LAST version run
        assert_eq!(parse_pkg_info_list("gtk-3-3.24.0 toolkit\n"), vec![("gtk-3".into(), "3.24.0".into())]);
    }

    #[test]
    fn dpkg_owner_name_handles_multiarch_and_diversions() {
        // Plain owner line.
        assert_eq!(dpkg_owner_name("nginx: /usr/sbin/nginx").as_deref(), Some("nginx"));
        // Multiarch name carries a `:arch` suffix; split on the LAST ": " so the
        // architecture qualifier is NOT mistaken for the field separator.
        assert_eq!(
            dpkg_owner_name("libssl3:amd64: /usr/lib/x86_64-linux-gnu/libssl.so.3").as_deref(),
            Some("libssl3:amd64")
        );
        // Multiple owners: the first comma-listed package wins.
        assert_eq!(
            dpkg_owner_name("pkg-a, pkg-b: /shared/path").as_deref(),
            Some("pkg-a")
        );
        // Diversion preamble lines are skipped in favor of the real owner.
        let out = "diversion by libc6 from: /lib/x.so\n\
                   diversion by libc6 to: /lib/x.so.usr-is-merged\n\
                   libc6:amd64: /lib/x.so\n";
        assert_eq!(dpkg_owner_name(out).as_deref(), Some("libc6:amd64"));
    }

    #[test]
    fn brew_multi_version() {
        assert_eq!(parse_brew_list("openssl@3 3.3.1 3.3.2\nnginx 1.27.0\n"),
            vec![("openssl@3".into(), "3.3.1".into()), ("openssl@3".into(), "3.3.2".into()),
                 ("nginx".into(), "1.27.0".into())]);
    }
}
