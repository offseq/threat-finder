//! Windows host discovery.
//!
//! Everything here shells out to the built-in `powershell.exe` (and a few
//! optional CLIs) and asks for `ConvertTo-Json`, so the only platform-specific
//! cost is the child process — there are no COM/registry crate bindings. Each
//! source is split into an impure *fetch* (runs the command) and a pure *parse*
//! (string → data), and the parsers are fixture-tested on every platform.
//!
//! Coverage:
//!   * the OS itself                          → NVD OS CPE
//!   * registry Uninstall keys (Programs)     → app CPE (curated alias)
//!   * winget list                            → app CPE
//!   * Appx / MSIX (Store)                    → app CPE
//!   * Chocolatey / Scoop                     → app CPE
//!   * global npm / pip / dotnet tools        → purl (npm / pypi / nuget)
//!   * running services + listening sockets   → exposure correlation
//!   * pending security updates (WUA, opt-in) → local advisory
//!
//! On a non-Windows host every fetch returns nothing, so the public entry points
//! are safe no-ops there (the collector only runs them when the OS is Windows).

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::cpe::{clean_app_name, cpe_for_app, cpe_for_os, win_os_product};
use crate::engine::{endpoint_reachability, Reachability, WinOs};
use crate::scan::{Asset, Ecosystem, Runtime, Source};

// ── command helpers ──────────────────────────────────────────────────────────

/// Run a PowerShell script non-interactively and return stdout on success.
fn ps(script: &str) -> Option<String> {
    crate::engine::run_cmd(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
    )
}

/// Run a command and capture stdout **regardless of exit status** (npm exits
/// non-zero on benign dependency warnings, yet still emits the JSON we want).
fn run_capture(program: &str, args: &[&str]) -> Option<String> {
    use std::process::Command;
    let out = Command::new(program).args(args).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout).into_owned();
    if s.trim().is_empty() { None } else { Some(s) }
}

/// Run a PowerShell script capturing stdout regardless of exit status. Used when
/// the wrapped tool (e.g. winget) may return non-zero or needs PowerShell to fix
/// up its console encoding/width first.
fn ps_capture(script: &str) -> Option<String> {
    run_capture(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
    )
}

/// Strip ANSI/VT escape sequences and carriage returns that tools like winget
/// draw even with `--disable-interactivity`.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            continue;
        }
        if c == '\u{1b}' {
            // CSI: ESC '[' ... final byte in @-~ ; also handle ESC ']' (OSC).
            if let Some(&next) = chars.peek() {
                if next == '[' {
                    chars.next();
                    for cc in chars.by_ref() {
                        if ('@'..='~').contains(&cc) {
                            break;
                        }
                    }
                    continue;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// Reduce a free-text version (e.g. a binary's `ProductVersion`,
/// `"10.0.19041.1 (WinBuild.160101.0800)"` or `"6,0,0,0"`) to the leading
/// dotted-numeric token so it forms a usable CPE/coordinate version. Returns the
/// input trimmed if no numeric prefix is found.
fn sanitize_version(raw: &str) -> String {
    let first = raw.split_whitespace().next().unwrap_or("");
    // Comma-grouped versions ("6,0,0,0") → dots, only when there are no dots.
    let first = if first.contains(',') && !first.contains('.') {
        first.replace(',', ".")
    } else {
        first.to_string()
    };
    // Keep the leading run of version-ish characters.
    let v: String = first
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-' || *c == '_' || c.is_ascii_alphabetic())
        .collect();
    let v = v.trim_matches(|c: char| c == '.' || c == '-' || c == '_');
    if v.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        v.to_string()
    } else {
        first.trim().to_string()
    }
}

/// Parse a PowerShell `ConvertTo-Json` payload that is an array of `T` — but
/// tolerate the 5.1 quirk where a single element is emitted as a bare object.
fn parse_json_array<T: DeserializeOwned>(s: &str) -> Vec<T> {
    let t = s.trim();
    if t.is_empty() || t == "null" {
        return Vec::new();
    }
    if let Ok(v) = serde_json::from_str::<Vec<T>>(t) {
        return v;
    }
    if let Ok(one) = serde_json::from_str::<T>(t) {
        return vec![one];
    }
    Vec::new()
}

// ── OS detection ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct WinCurrentVersion {
    product_name: Option<String>,
    display_version: Option<String>,
    release_id: Option<String>,
    current_build: Option<String>,
    #[serde(rename = "UBR")]
    ubr: Option<u32>,
    #[serde(rename = "EditionID")]
    edition_id: Option<String>,
    installation_type: Option<String>,
    arch: Option<String>,
}

const DETECT_OS_SCRIPT: &str = r#"$ErrorActionPreference='SilentlyContinue'
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
[pscustomobject]@{
  ProductName=$cv.ProductName; DisplayVersion=$cv.DisplayVersion; ReleaseId=$cv.ReleaseId
  CurrentBuild=$cv.CurrentBuild; UBR=$cv.UBR; EditionID=$cv.EditionID
  InstallationType=$cv.InstallationType
  Arch=$(if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE })
} | ConvertTo-Json -Compress"#;

/// Detect the running Windows identity (registry `CurrentVersion`). On a host
/// where the read fails, returns a `WinOs` with empty/zero fields — the OS CPE
/// then degrades to the generic `windows` product rather than failing the scan.
pub fn detect_win_os() -> WinOs {
    ps(DETECT_OS_SCRIPT)
        .and_then(|s| serde_json::from_str::<WinCurrentVersion>(s.trim()).ok())
        .map(winos_from_cv)
        .unwrap_or_default()
}

/// Pure: turn the parsed registry view into a `WinOs`. Trusts the build number
/// over `ProductName` (which still reports "Windows 10" on Windows 11).
fn winos_from_cv(cv: WinCurrentVersion) -> WinOs {
    let build = cv.current_build.as_deref().and_then(|s| s.trim().parse::<u32>().ok()).unwrap_or(0);
    let ubr = cv.ubr.unwrap_or(0);
    let feature = cv.display_version.or(cv.release_id).unwrap_or_default();
    let edition = cv.edition_id.unwrap_or_default();
    let install_type = cv.installation_type.unwrap_or_default();
    let is_server = install_type.eq_ignore_ascii_case("Server")
        || install_type.eq_ignore_ascii_case("Server Core")
        || edition.to_lowercase().starts_with("server");

    let arch = match cv.arch.unwrap_or_default().to_uppercase().as_str() {
        "AMD64" => "x64",
        "ARM64" => "arm64",
        "X86" => "x86",
        _ => "",
    }
    .to_string();

    let product = win_os_product(build, is_server, &feature);

    // ProductName lies on Win11 — fix the display label for client builds.
    let mut display_name = cv.product_name.unwrap_or_default();
    if !is_server && build >= 22000 && display_name.starts_with("Windows 10") {
        display_name = display_name.replacen("Windows 10", "Windows 11", 1);
    }
    if display_name.is_empty() {
        display_name = if is_server { "Windows Server".into() } else { "Windows".into() };
    }

    WinOs { product, display_name, feature, build, ubr, is_server, edition, arch }
}

// ── orchestration ────────────────────────────────────────────────────────────

/// Collect Windows assets: the OS CPE + running services (with exposure) always;
/// the full installed-software inventory when `full` (scope = All).
pub fn collect_windows(w: &WinOs, full: bool) -> Vec<Asset> {
    let mut assets = vec![os_asset(w)];
    assets.extend(running_services());
    if full {
        assets.extend(installed_apps());
        assets.extend(language_packages());
    }
    assets
}

/// The OS as a single CPE-bearing asset.
fn os_asset(w: &WinOs) -> Asset {
    Asset {
        ecosystem: Ecosystem::WindowsOs,
        name: w.display_name.clone(),
        pkg_name: Some(w.display_name.clone()),
        version: w.version_string(),
        sources: vec![Source::PackageDb],
        locations: Vec::new(),
        runtime: None,
        cpe: Some(cpe_for_os(w)),
    }
}

/// Build a Windows application asset: alias-resolved CPE when possible, else a
/// cleaned name for the `?search=` fallback.
fn app_asset(eco: Ecosystem, raw_name: &str, version: &str, source_tag: &str) -> Option<Asset> {
    let name = clean_app_name(raw_name);
    if name.is_empty() {
        return None;
    }
    let version = sanitize_version(version);
    let cpe = cpe_for_app(&name, &version);
    Some(Asset {
        ecosystem: eco,
        name: name.clone(),
        pkg_name: Some(name),
        version,
        sources: vec![Source::PackageDb],
        locations: vec![source_tag.to_string()],
        runtime: None,
        cpe,
    })
}

// ── installed applications (registry / winget / Appx / choco / scoop) ─────────

fn installed_apps() -> Vec<Asset> {
    let mut out = Vec::new();
    out.extend(registry_apps());
    out.extend(winget_apps());
    out.extend(appx_apps());
    out.extend(choco_apps());
    out.extend(scoop_apps());
    out
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UninstallEntry {
    display_name: Option<String>,
    display_version: Option<String>,
}

const REGISTRY_APPS_SCRIPT: &str = r#"$ErrorActionPreference='SilentlyContinue'
$paths=@(
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
@(Get-ItemProperty $paths | Where-Object { $_.DisplayName } |
  Select-Object DisplayName,DisplayVersion) | ConvertTo-Json -Compress"#;

fn registry_apps() -> Vec<Asset> {
    let raw = match ps(REGISTRY_APPS_SCRIPT) {
        Some(s) => s,
        None => return Vec::new(),
    };
    parse_registry_apps(&raw)
}

/// Pure: registry JSON → assets.
fn parse_registry_apps(raw: &str) -> Vec<Asset> {
    parse_json_array::<UninstallEntry>(raw)
        .into_iter()
        .filter_map(|e| {
            let name = e.display_name?;
            app_asset(Ecosystem::WinApp, &name, e.display_version.as_deref().unwrap_or(""), "registry")
        })
        .collect()
}

// Run winget through PowerShell so we can force UTF-8 output (winget emits
// UTF-16/VT noise on a redirected pipe) and a wide buffer (so long names don't
// truncate the Version column). winget isn't present on Server 2019/2022 by
// default; absence is fine.
const WINGET_SCRIPT: &str = r#"$ErrorActionPreference='SilentlyContinue'
try { [Console]::OutputEncoding=[System.Text.Encoding]::UTF8 } catch {}
winget list --disable-interactivity --accept-source-agreements | Out-String -Width 512"#;

fn winget_apps() -> Vec<Asset> {
    match ps_capture(WINGET_SCRIPT) {
        Some(out) => parse_winget_list(&out),
        None => Vec::new(),
    }
}

/// Pure: parse `winget list` fixed-width columns. Detects the `Name`/`Id`/
/// `Version` columns from the header so a missing `Available` column doesn't
/// shift fields, and skips the dashed separator and progress lines. Column
/// offsets are measured in **chars** (not bytes) so multibyte names in data rows
/// stay aligned with the ASCII header.
fn parse_winget_list(out: &str) -> Vec<Asset> {
    let cleaned = strip_ansi(out);
    let mut lines = cleaned.lines().filter(|l| !l.trim().is_empty());
    // Find the header row (contains both "Name" and "Version").
    let header = match lines.by_ref().find(|l| l.contains("Name") && l.contains("Version")) {
        Some(h) => h,
        None => return Vec::new(),
    };
    // Char-index positions (header is ASCII, so this equals visual columns).
    let char_index_of = |hay: &str, needle: &str| hay.find(needle).map(|b| hay[..b].chars().count());
    let name_col = char_index_of(header, "Name");
    let id_col = char_index_of(header, "Id");
    let ver_col = char_index_of(header, "Version");
    let (Some(name_col), Some(ver_col)) = (name_col, ver_col) else {
        return Vec::new();
    };
    // Name ends where Id begins (or Version, if no Id column).
    let name_end = id_col.filter(|&i| i > name_col).unwrap_or(ver_col);

    let mut out_assets = Vec::new();
    for line in lines {
        // Skip the dashed separator under the header.
        if line.chars().all(|c| c == '-' || c.is_whitespace()) {
            continue;
        }
        let chars: Vec<char> = line.chars().collect();
        let slice = |start: usize, end: usize| -> String {
            if start >= chars.len() {
                return String::new();
            }
            let end = end.min(chars.len());
            chars[start..end].iter().collect::<String>().trim().trim_end_matches('…').trim().to_string()
        };
        let name = slice(name_col, name_end);
        let version = slice(ver_col, ver_col + 24);
        // Take only the first token of the version cell (drops "Available"/source).
        let version = version.split_whitespace().next().unwrap_or("").to_string();
        if name.is_empty() || version.is_empty() || version == "Version" {
            continue;
        }
        if let Some(a) = app_asset(Ecosystem::WinApp, &name, &version, "winget") {
            out_assets.push(a);
        }
    }
    out_assets
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AppxEntry {
    name: Option<String>,
    version: Option<String>,
}

const APPX_SCRIPT: &str =
    "@(Get-AppxPackage | Select-Object Name,Version) | ConvertTo-Json -Compress";

fn appx_apps() -> Vec<Asset> {
    let raw = match ps(APPX_SCRIPT) {
        Some(s) => s,
        None => return Vec::new(),
    };
    parse_appx(&raw)
}

/// Pure: Appx JSON → assets. Appx names are reverse-DNS-ish (`Microsoft.Foo`),
/// so the last dotted segment is the human-ish product name to alias on.
fn parse_appx(raw: &str) -> Vec<Asset> {
    parse_json_array::<AppxEntry>(raw)
        .into_iter()
        .filter_map(|e| {
            let full = e.name?;
            let short = full.rsplit('.').next().unwrap_or(&full).to_string();
            app_asset(Ecosystem::WinApp, &short, e.version.as_deref().unwrap_or(""), "appx")
        })
        .collect()
}

fn choco_apps() -> Vec<Asset> {
    match run_capture("choco", &["list", "-r"]) {
        Some(out) => parse_choco_list(&out),
        None => Vec::new(),
    }
}

/// Pure: parse `choco list -r` ("name|version" per line).
fn parse_choco_list(out: &str) -> Vec<Asset> {
    out.lines()
        .filter_map(|l| {
            let (name, ver) = l.split_once('|')?;
            app_asset(Ecosystem::WinApp, name.trim(), ver.trim(), "chocolatey")
        })
        .collect()
}

#[derive(Debug, Deserialize)]
struct ScoopExport {
    apps: Option<Vec<ScoopApp>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ScoopApp {
    name: Option<String>,
    version: Option<String>,
}

fn scoop_apps() -> Vec<Asset> {
    match run_capture("scoop", &["export"]) {
        Some(out) => parse_scoop_export(&out),
        None => Vec::new(),
    }
}

/// Pure: parse `scoop export` — newer `{ "apps": [...] }` or the older bare
/// array form.
fn parse_scoop_export(out: &str) -> Vec<Asset> {
    let t = out.trim();
    let apps: Vec<ScoopApp> = serde_json::from_str::<ScoopExport>(t)
        .ok()
        .and_then(|e| e.apps)
        .or_else(|| serde_json::from_str::<Vec<ScoopApp>>(t).ok())
        .unwrap_or_default();
    apps.into_iter()
        .filter_map(|a| {
            app_asset(Ecosystem::WinApp, a.name.as_deref()?, a.version.as_deref().unwrap_or(""), "scoop")
        })
        .collect()
}

// ── language package managers (→ purl) ───────────────────────────────────────

fn language_packages() -> Vec<Asset> {
    let mut out = Vec::new();
    out.extend(npm_global());
    out.extend(pip_packages());
    out.extend(dotnet_tools());
    out
}

#[derive(Debug, Deserialize)]
struct NpmList {
    dependencies: Option<BTreeMap<String, NpmDep>>,
}

#[derive(Debug, Deserialize)]
struct NpmDep {
    version: Option<String>,
}

fn npm_global() -> Vec<Asset> {
    match run_capture("npm", &["ls", "-g", "--json", "--depth=0"]) {
        Some(out) => parse_npm_list(&out),
        None => Vec::new(),
    }
}

/// Pure: parse `npm ls -g --json` into npm-ecosystem assets.
fn parse_npm_list(out: &str) -> Vec<Asset> {
    let list: NpmList = match serde_json::from_str(out.trim()) {
        Ok(l) => l,
        Err(_) => return Vec::new(),
    };
    list.dependencies
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(name, dep)| {
            let version = dep.version?;
            Some(lang_asset(Ecosystem::Npm, &name, &version))
        })
        .collect()
}

#[derive(Debug, Deserialize)]
struct PipEntry {
    name: Option<String>,
    version: Option<String>,
}

fn pip_packages() -> Vec<Asset> {
    // Prefer the py launcher's pip, then a bare pip; both emit the same JSON.
    let out = run_capture("python", &["-m", "pip", "list", "--format=json"])
        .or_else(|| run_capture("pip", &["list", "--format=json"]));
    match out {
        Some(o) => parse_pip_list(&o),
        None => Vec::new(),
    }
}

/// Pure: parse `pip list --format=json` into PyPI-ecosystem assets.
fn parse_pip_list(out: &str) -> Vec<Asset> {
    parse_json_array::<PipEntry>(out)
        .into_iter()
        .filter_map(|e| Some(lang_asset(Ecosystem::PyPI, &e.name?, &e.version?)))
        .collect()
}

fn dotnet_tools() -> Vec<Asset> {
    match run_capture("dotnet", &["tool", "list", "-g"]) {
        Some(out) => parse_dotnet_tools(&out),
        None => Vec::new(),
    }
}

/// Pure: parse `dotnet tool list -g` columns (Package Id / Version / Commands).
fn parse_dotnet_tools(out: &str) -> Vec<Asset> {
    let mut assets = Vec::new();
    for line in out.lines() {
        let line = line.trim_end();
        // Skip header and the dashed separator.
        if line.is_empty()
            || line.starts_with("Package Id")
            || line.chars().all(|c| c == '-' || c.is_whitespace())
        {
            continue;
        }
        let mut cols = line.split_whitespace();
        let (Some(id), Some(ver)) = (cols.next(), cols.next()) else { continue };
        assets.push(lang_asset(Ecosystem::NuGet, id, ver));
    }
    assets
}

/// A language-ecosystem package asset (matched by purl, no CPE).
fn lang_asset(eco: Ecosystem, name: &str, version: &str) -> Asset {
    Asset {
        ecosystem: eco,
        name: name.to_string(),
        pkg_name: Some(name.to_string()),
        version: version.to_string(),
        sources: vec![Source::PackageDb],
        locations: Vec::new(),
        runtime: None,
        cpe: None,
    }
}

// ── running services + network exposure ──────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WinService {
    name: Option<String>,
    display: Option<String>,
    exe: Option<String>,
    pid: Option<u32>,
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WinListener {
    local_address: Option<String>,
    local_port: Option<u32>,
    owning_process: Option<u32>,
}

const SERVICES_SCRIPT: &str = r#"$ErrorActionPreference='SilentlyContinue'
@(Get-CimInstance Win32_Service -Filter "State='Running'" | ForEach-Object {
  $p=$_.PathName; $exe=$null; $ver=$null
  if ($p) { if ($p -match '^"([^"]+)"') { $exe=$matches[1] } else { $exe=($p -split ' ')[0] } }
  if ($exe -and (Test-Path $exe)) { try { $vi=(Get-Item $exe).VersionInfo; $ver=$vi.FileVersion; if (-not $ver) { $ver=$vi.ProductVersion } } catch {} }
  [pscustomobject]@{ Name=$_.Name; Display=$_.DisplayName; Exe=$exe; Pid=[int]$_.ProcessId; Version=$ver }
}) | ConvertTo-Json -Compress"#;

const LISTENERS_SCRIPT: &str = r#"$ErrorActionPreference='SilentlyContinue'
@(Get-NetTCPConnection -State Listen |
  Select-Object LocalAddress,LocalPort,OwningProcess) | ConvertTo-Json -Compress"#;

fn running_services() -> Vec<Asset> {
    let services = ps(SERVICES_SCRIPT).map(|s| parse_json_array::<WinService>(&s)).unwrap_or_default();
    if services.is_empty() {
        return Vec::new();
    }
    // Get-NetTCPConnection is absent on Server Core / older images; fall back to
    // `netstat -ano` (always present) so the exposure signal doesn't vanish.
    let mut listeners = ps(LISTENERS_SCRIPT).map(|s| parse_json_array::<WinListener>(&s)).unwrap_or_default();
    if listeners.is_empty() {
        if let Some(out) = run_capture("netstat", &["-ano"]) {
            listeners = parse_netstat(&out);
        }
    }
    build_service_assets(services, listeners)
}

/// Pure: parse `netstat -ano` LISTENING rows into listener records. Lines look
/// like `TCP  0.0.0.0:135  0.0.0.0:0  LISTENING  1234` (or `[::]:445` for IPv6).
fn parse_netstat(out: &str) -> Vec<WinListener> {
    let mut listeners = Vec::new();
    for line in out.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // Proto Local Foreign State PID  — only TCP rows carry a LISTENING state.
        if cols.len() < 5 || !cols[0].eq_ignore_ascii_case("TCP") {
            continue;
        }
        if !cols[3].eq_ignore_ascii_case("LISTENING") {
            continue;
        }
        let Ok(pid) = cols[4].parse::<u32>() else { continue };
        // Local address is "host:port"; host may be bracketed IPv6.
        let local = cols[1];
        let Some((host, port_s)) = local.rsplit_once(':') else { continue };
        let Ok(port) = port_s.parse::<u32>() else { continue };
        let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
        listeners.push(WinListener {
            local_address: Some(host),
            local_port: Some(port),
            owning_process: Some(pid),
        });
    }
    listeners
}

/// Pure: join running services with their listening sockets (by PID) and build
/// exposure-bearing assets. svchost-hosted services are skipped — their CVEs are
/// the OS's, and their shared PID would mis-attribute every socket to each one.
fn build_service_assets(services: Vec<WinService>, listeners: Vec<WinListener>) -> Vec<Asset> {
    // PID → endpoint strings ("[::]:443", "0.0.0.0:80", ...).
    let mut by_pid: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    for l in listeners {
        let (Some(addr), Some(port), Some(pid)) = (l.local_address, l.local_port, l.owning_process)
        else {
            continue;
        };
        // Drop any IPv6 zone index ("fe80::1%12") so the address parses.
        let addr = addr.split('%').next().unwrap_or(&addr);
        let ep = if addr.contains(':') {
            format!("[{addr}]:{port}") // IPv6
        } else {
            format!("{addr}:{port}")
        };
        by_pid.entry(pid).or_default().push(ep);
    }

    let mut assets = Vec::new();
    for s in services {
        let exe = s.exe.unwrap_or_default();
        let base = exe.rsplit(['\\', '/']).next().unwrap_or(&exe).to_lowercase();
        if base == "svchost.exe" {
            continue;
        }
        // Prefer the friendly DisplayName; fall back to the service key name.
        let display = match s.display.filter(|d| !d.trim().is_empty()) {
            Some(d) => d,
            None => s.name.unwrap_or_default(),
        };
        if display.trim().is_empty() {
            continue;
        }
        let listeners = s.pid.and_then(|p| by_pid.get(&p)).cloned().unwrap_or_default();
        let reach = listeners
            .iter()
            .map(|e| endpoint_reachability(e))
            .max()
            .unwrap_or(Reachability::None);
        let exposed = reach >= Reachability::Private;

        let name = clean_app_name(&display);
        if name.is_empty() {
            continue;
        }
        let version = sanitize_version(&s.version.unwrap_or_default());
        let cpe = cpe_for_app(&name, &version);
        assets.push(Asset {
            ecosystem: Ecosystem::WinApp,
            name: name.clone(),
            pkg_name: Some(name),
            version,
            sources: vec![Source::Probe],
            locations: if exe.is_empty() { Vec::new() } else { vec![exe] },
            runtime: Some(Runtime { pid: s.pid, listeners, reachability: reach, exposed }),
            cpe,
        });
    }
    assets
}

// ── pending security updates (opt-in advisory) ───────────────────────────────

/// A pending Windows update from the Windows Update Agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinUpdate {
    pub title: String,
    pub kbs: Vec<String>,
    pub severity: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WuaUpdate {
    title: Option<String>,
    #[serde(rename = "KBs", default)]
    kbs: KbField,
    severity: Option<String>,
}

/// `KBArticleIDs` deserializes as a string, a list, or null depending on count.
#[derive(Debug, Default, Deserialize)]
#[serde(untagged)]
enum KbField {
    #[default]
    None,
    One(String),
    Many(Vec<String>),
}

impl KbField {
    fn into_vec(self) -> Vec<String> {
        match self {
            KbField::None => Vec::new(),
            KbField::One(s) => vec![s],
            KbField::Many(v) => v,
        }
    }
}

const MISSING_UPDATES_SCRIPT: &str = r#"$ErrorActionPreference='Stop'
try {
  $s = New-Object -ComObject Microsoft.Update.Session
  $r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software'")
  @($r.Updates | ForEach-Object {
    [pscustomobject]@{ Title=$_.Title; KBs=@($_.KBArticleIDs); Severity=$_.MsrcSeverity }
  }) | ConvertTo-Json -Compress
} catch { '[]' }"#;

/// Query the Windows Update Agent for pending (not-installed) software updates.
/// This is an **online** scan (needs network, may take a while, best run
/// elevated), so it is opt-in via `--windows-missing-updates`.
pub fn gather_missing_updates() -> Vec<WinUpdate> {
    match ps(MISSING_UPDATES_SCRIPT) {
        Some(s) => parse_missing_updates(&s),
        None => Vec::new(),
    }
}

/// Pure: WUA JSON → updates, most severe first.
fn parse_missing_updates(raw: &str) -> Vec<WinUpdate> {
    let mut updates: Vec<WinUpdate> = parse_json_array::<WuaUpdate>(raw)
        .into_iter()
        .filter_map(|u| {
            let title = u.title?;
            Some(WinUpdate {
                title,
                kbs: u.kbs.into_vec(),
                severity: u.severity.unwrap_or_default(),
            })
        })
        .collect();
    updates.sort_by_key(|u| std::cmp::Reverse(msrc_rank(&u.severity)));
    updates
}

/// Rank MSRC severities so the advisory leads with the most urgent.
fn msrc_rank(sev: &str) -> u8 {
    match sev.to_lowercase().as_str() {
        "critical" => 4,
        "important" => 3,
        "moderate" => 2,
        "low" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_win11_fixing_productname_lie() {
        let cv = WinCurrentVersion {
            product_name: Some("Windows 10 Pro".into()),
            display_version: Some("23H2".into()),
            current_build: Some("22631".into()),
            ubr: Some(3155),
            edition_id: Some("Professional".into()),
            installation_type: Some("Client".into()),
            arch: Some("AMD64".into()),
            ..Default::default()
        };
        let w = winos_from_cv(cv);
        assert_eq!(w.product, "windows_11_23h2");
        assert_eq!(w.display_name, "Windows 11 Pro");
        assert_eq!(w.version_string(), "10.0.22631.3155");
        assert_eq!(w.arch, "x64");
        assert!(!w.is_server);
    }

    #[test]
    fn detects_server_from_installation_type() {
        let cv = WinCurrentVersion {
            product_name: Some("Windows Server 2022 Datacenter".into()),
            display_version: Some("21H2".into()),
            current_build: Some("20348".into()),
            ubr: Some(2227),
            edition_id: Some("ServerDatacenter".into()),
            installation_type: Some("Server".into()),
            arch: Some("AMD64".into()),
            ..Default::default()
        };
        let w = winos_from_cv(cv);
        assert!(w.is_server);
        assert_eq!(w.product, "windows_server_2022");
        assert_eq!(cpe_for_os(&w), "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.2227:*:*:*:*:*:x64:*");
    }

    #[test]
    fn registry_apps_alias_and_search_fallback() {
        let raw = r#"[
          {"DisplayName":"Google Chrome","DisplayVersion":"120.0.6099.130"},
          {"DisplayName":"7-Zip 23.01 (x64)","DisplayVersion":"23.01"},
          {"DisplayName":"Contoso LOB App","DisplayVersion":"1.2.3"}
        ]"#;
        let assets = parse_registry_apps(raw);
        assert_eq!(assets.len(), 3);
        let chrome = assets.iter().find(|a| a.name == "Google Chrome").unwrap();
        assert_eq!(chrome.cpe.as_deref(), Some("cpe:2.3:a:google:chrome:120.0.6099.130:*:*:*:*:*:*:*"));
        let zip = assets.iter().find(|a| a.name == "7-Zip").unwrap();
        assert_eq!(zip.cpe.as_deref(), Some("cpe:2.3:a:7-zip:7-zip:23.01:*:*:*:*:*:*:*"));
        // Unmapped app: no CPE, but still present for the ?search= fallback.
        let lob = assets.iter().find(|a| a.name == "Contoso LOB App").unwrap();
        assert!(lob.cpe.is_none());
    }

    #[test]
    fn registry_single_object_is_tolerated() {
        // PowerShell 5.1 emits a lone item as an object, not a 1-element array.
        let raw = r#"{"DisplayName":"Wireshark","DisplayVersion":"4.2.0"}"#;
        let assets = parse_registry_apps(raw);
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].cpe.as_deref(), Some("cpe:2.3:a:wireshark:wireshark:4.2.0:*:*:*:*:*:*:*"));
    }

    #[test]
    fn winget_list_columns_parsed() {
        let out = "\
Name                 Id                        Version      Available  Source
-------------------------------------------------------------------------------
Mozilla Firefox      Mozilla.Firefox           121.0        122.0      winget
7-Zip                7zip.7zip                 23.01                   winget
Some Tool…           Vendor.SomeTool           1.0.0                   winget";
        let assets = parse_winget_list(out);
        let ff = assets.iter().find(|a| a.name == "Mozilla Firefox").unwrap();
        assert_eq!(ff.version, "121.0");
        assert_eq!(ff.cpe.as_deref(), Some("cpe:2.3:a:mozilla:firefox:121.0:*:*:*:*:*:*:*"));
        let zip = assets.iter().find(|a| a.name == "7-Zip").unwrap();
        assert_eq!(zip.version, "23.01");
    }

    #[test]
    fn appx_uses_last_segment() {
        let raw = r#"[{"Name":"Microsoft.WindowsTerminal","Version":"1.18.0"}]"#;
        let assets = parse_appx(raw);
        assert_eq!(assets[0].name, "WindowsTerminal");
        assert_eq!(assets[0].version, "1.18.0");
    }

    #[test]
    fn choco_pipe_format() {
        let out = "googlechrome|120.0.6099.130\nvlc|3.0.20\n7zip|23.1.0";
        let assets = parse_choco_list(out);
        assert_eq!(assets.len(), 3);
        let vlc = assets.iter().find(|a| a.name == "vlc").unwrap();
        assert_eq!(vlc.cpe.as_deref(), Some("cpe:2.3:a:videolan:vlc_media_player:3.0.20:*:*:*:*:*:*:*"));
    }

    #[test]
    fn scoop_both_export_shapes() {
        let new_form = r#"{"apps":[{"Name":"git","Version":"2.43.0"},{"Name":"curl","Version":"8.5.0"}]}"#;
        assert_eq!(parse_scoop_export(new_form).len(), 2);
        let old_form = r#"[{"Name":"git","Version":"2.43.0"}]"#;
        assert_eq!(parse_scoop_export(old_form).len(), 1);
    }

    #[test]
    fn npm_global_to_purl() {
        let out = r#"{"dependencies":{"npm":{"version":"10.2.3"},"typescript":{"version":"5.3.3"}}}"#;
        let assets = parse_npm_list(out);
        assert_eq!(assets.len(), 2);
        let ts = assets.iter().find(|a| a.name == "typescript").unwrap();
        assert_eq!(ts.ecosystem, Ecosystem::Npm);
        assert!(ts.cpe.is_none());
    }

    #[test]
    fn pip_json_to_pypi() {
        let out = r#"[{"name":"Django","version":"4.2.0"},{"name":"requests","version":"2.31.0"}]"#;
        let assets = parse_pip_list(out);
        assert_eq!(assets.len(), 2);
        assert_eq!(assets[0].ecosystem, Ecosystem::PyPI);
    }

    #[test]
    fn dotnet_tools_columns() {
        let out = "\
Package Id      Version      Commands
------------------------------------------
dotnet-ef       8.0.0        dotnet-ef
nbgv            3.6.133      nbgv";
        let assets = parse_dotnet_tools(out);
        assert_eq!(assets.len(), 2);
        assert_eq!(assets[0].name, "dotnet-ef");
        assert_eq!(assets[0].ecosystem, Ecosystem::NuGet);
    }

    #[test]
    fn service_exposure_joins_by_pid_and_skips_svchost() {
        let services = vec![
            WinService {
                name: Some("W3SVC".into()),
                display: Some("World Wide Web Publishing Service".into()),
                exe: Some(r"C:\Windows\System32\inetsrv\w3wp.exe".into()),
                pid: Some(1234),
                version: Some("10.0.0".into()),
            },
            WinService {
                name: Some("SharedSvc".into()),
                display: Some("Some Shared Svc".into()),
                exe: Some(r"C:\Windows\System32\svchost.exe".into()),
                pid: Some(900),
                version: None,
            },
        ];
        let listeners = vec![
            WinListener { local_address: Some("0.0.0.0".into()), local_port: Some(443), owning_process: Some(1234) },
            WinListener { local_address: Some("::".into()), local_port: Some(80), owning_process: Some(900) },
        ];
        let assets = build_service_assets(services, listeners);
        // svchost is dropped.
        assert_eq!(assets.len(), 1);
        let web = &assets[0];
        let rt = web.runtime.as_ref().unwrap();
        assert!(rt.exposed);
        assert_eq!(rt.reachability, Reachability::Public);
        assert!(rt.listeners.iter().any(|l| l.contains("443")));
    }

    #[test]
    fn missing_updates_parsed_and_ranked() {
        let raw = r#"[
          {"Title":"2024-01 Cumulative Update","KBs":["5034441"],"Severity":"Important"},
          {"Title":"Critical Security Update","KBs":"5034123","Severity":"Critical"},
          {"Title":"Defender Update","KBs":[],"Severity":""}
        ]"#;
        let ups = parse_missing_updates(raw);
        assert_eq!(ups.len(), 3);
        // Critical sorts first; the scalar KB string is normalized to a vec.
        assert_eq!(ups[0].severity, "Critical");
        assert_eq!(ups[0].kbs, vec!["5034123".to_string()]);
        assert_eq!(ups[1].kbs, vec!["5034441".to_string()]);
    }

    #[test]
    fn version_sanitization() {
        assert_eq!(sanitize_version("10.0.19041.1 (WinBuild.160101.0800)"), "10.0.19041.1");
        assert_eq!(sanitize_version("6,0,0,0"), "6.0.0.0");
        assert_eq!(sanitize_version("  3.0.20  "), "3.0.20");
        assert_eq!(sanitize_version("23.01"), "23.01");
        assert_eq!(sanitize_version("1.2.3-rc1"), "1.2.3-rc1");
        // No numeric prefix → returned as the first token, unmangled.
        assert_eq!(sanitize_version("unknown"), "unknown");
    }

    #[test]
    fn netstat_fallback_parsed() {
        let out = "\
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234
  TCP    [::]:445               [::]:0                LISTENING       4
  TCP    192.168.1.5:50012      93.184.216.34:443     ESTABLISHED     5678
  UDP    0.0.0.0:5353           *:*                                   900";
        let l = parse_netstat(out);
        // Only the two TCP LISTENING rows.
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].local_port, Some(135));
        assert_eq!(l[0].owning_process, Some(1234));
        assert_eq!(l[1].local_address.as_deref(), Some("::"));
        assert_eq!(l[1].local_port, Some(445));
    }

    #[test]
    fn ansi_is_stripped() {
        let s = "\u{1b}[2K\u{1b}[31mName\u{1b}[0m\r\nfoo";
        assert_eq!(strip_ansi(s), "Name\nfoo");
    }

    #[test]
    fn empty_and_null_payloads_are_safe() {
        assert!(parse_registry_apps("").is_empty());
        assert!(parse_registry_apps("null").is_empty());
        assert!(parse_npm_list("not json").is_empty());
        assert!(parse_winget_list("").is_empty());
    }

    // Keep the const scripts referenced so an accidental unused-const slip fails
    // the build rather than silently shipping a dead query.
    #[test]
    fn scripts_are_nonempty() {
        for s in [
            DETECT_OS_SCRIPT, REGISTRY_APPS_SCRIPT, WINGET_SCRIPT, APPX_SCRIPT,
            SERVICES_SCRIPT, LISTENERS_SCRIPT, MISSING_UPDATES_SCRIPT,
        ] {
            assert!(!s.is_empty());
        }
    }
}
