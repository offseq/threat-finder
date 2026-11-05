use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;
use std::time::Duration;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use tracing::{error, warn};

use find_threats::{
    auth, logging, sarif, scan,
    ScanScope,
    engine::*,
    ThreatClient,
    ThreatError,
    BatchResults,
    ThreatEntry,
    InventoryAsset,
    InventoryOs,
    RegisterResponse,
    RegistrationReport,
    decision_rank,
    Asset,
    plan_info,
    scan_body,
    severity_rank as sev_rank,
};

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum FailOn {
    /// Any finding at all
    Any,
    Critical,
    High,
    Medium,
    Low,
    /// Only CISA KEV-listed findings
    Kev,
    /// Findings exploited in the wild: KEV, ENISA EUVD or OffSeq Mirage
    Exploited,
    /// Findings whose exposure-aware decision is act-now
    ActNow,
    /// Only findings on a network-exposed service
    Exposed,
}

#[derive(Parser, Debug)]
#[command(
    name = "threat-finder",
    version,
    about = "OffSeq Threat Finder — scan running services for known vulnerabilities",
    after_help = "EXIT CODES:\n  0  success\n  1  lookup or I/O error\n  2  no API key available\n  3  unsupported OS\n  4  rate limit / quota exhausted, or API access required (upgrade needed)\n  5  --fail-on threshold met",
)]
struct Cli {
    /// Write the JSON report to this path (default: prompt, or ./threats.json)
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,

    /// Print the JSON report to stdout instead of writing a file
    #[arg(long)]
    json: bool,

    /// What to scan: running services only, or every installed OS package
    #[arg(long, value_enum, value_name = "SCOPE", default_value_t = ScanScope::Running)]
    scope: ScanScope,

    /// Only report threats at or above this severity
    #[arg(long, value_enum, value_name = "LEVEL")]
    severity: Option<Severity>,

    /// Only report confirmed matches (ask the API to omit coordinate-unconfirmed)
    #[arg(long)]
    strict: bool,

    /// Exit non-zero (5) when matching findings exist — for CI gating
    #[arg(long, value_enum, value_name = "WHAT")]
    fail_on: Option<FailOn>,

    /// Also write a SARIF 2.1.0 report to this path (for code-scanning UIs)
    #[arg(long, value_name = "PATH")]
    sarif: Option<PathBuf>,

    /// Only scan services whose name matches this glob (repeatable)
    #[arg(long, value_name = "GLOB")]
    include: Vec<String>,

    /// Skip services whose name matches this glob (repeatable)
    #[arg(long, value_name = "GLOB")]
    exclude: Vec<String>,

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

    /// Register the scanned assets for continuous monitoring without prompting
    #[arg(long, conflicts_with = "no_register")]
    register: bool,

    /// Never register this run and don't prompt for monitoring
    #[arg(long)]
    no_register: bool,

    /// Friendly hostname to send with a monitoring registration
    #[arg(long, value_name = "NAME")]
    host_name: Option<String>,

    /// Delete this host's monitored inventory from Radar, then exit
    #[arg(long)]
    unregister: bool,

    /// (Windows) Also query the Windows Update Agent for pending security
    /// updates and list them. This is an online scan: it needs network access,
    /// can take a while, and is best run from an elevated shell.
    #[arg(long)]
    windows_missing_updates: bool,

    /// Scan this SBOM or lockfile (CycloneDX, SPDX, purl list, npm/yarn/pnpm, Cargo,
    /// Poetry, uv, Go, Composer, Gemfile, requirements) instead of the host. One request.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["register", "unregister", "respect_decisions", "vex", "scope", "include", "exclude", "windows_missing_updates"])]
    sbom: Option<PathBuf>,

    /// Exclude findings silenced by a decision recorded in Radar from --fail-on
    /// (needs registration; one extra request)
    #[arg(long)]
    respect_decisions: bool,

    /// Write this host's Radar decisions as a VEX document to this path (needs
    /// registration and a paid plan; one extra request)
    #[arg(long, value_name = "PATH")]
    vex: Option<PathBuf>,

    /// VEX document format
    #[arg(long, value_name = "FORMAT", default_value = "openvex", value_parser = ["openvex", "cyclonedx"], requires = "vex")]
    vex_format: String,

    /// Log at debug level to the runtime log file (~/.local/share/threat-finder/logs
    /// on Linux). Overridden by RUST_LOG if that's set. Does not affect terminal output.
    #[arg(short, long)]
    verbose: bool,
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
    let default = DEFAULT_REPORT;
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

const DEFAULT_REPORT: &str = "threats.json";

/// Write a report readable by its owner only, refusing to follow a planted symlink.
fn write_private(path: &std::path::Path, data: &[u8]) -> io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = opts.open(path)?;
    // `mode` applies only on create; tighten a pre-existing report too.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(data)
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

/// Minimal case-insensitive glob: `*` matches any run of characters.
fn glob_match(pattern: &str, s: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let s = s.to_lowercase();
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return s == pattern; // no wildcard → exact
    }
    let mut idx = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !s[idx..].starts_with(part) {
                return false;
            }
            idx += part.len();
        } else if i == parts.len() - 1 {
            return s[idx..].ends_with(part);
        } else {
            match s[idx..].find(part) {
                Some(p) => idx += p + part.len(),
                None => return false,
            }
        }
    }
    true
}

/// Whether an asset passes the include/exclude globs, matched against any of its
/// `names` (display name + resolved package coordinate): include keeps if any
/// name matches; exclude drops if any name matches.
fn asset_allowed(names: &[&str], include: &[String], exclude: &[String]) -> bool {
    let hits = |globs: &[String]| globs.iter().any(|g| names.iter().any(|n| glob_match(g, n)));
    !hits(exclude) && (include.is_empty() || hits(include))
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

/// `[ACT-NOW 92]`-style decision band + risk score, colored by urgency. Empty
/// when the finding hasn't been scored.
fn decision_badge(t: &ThreatEntry, color: bool) -> String {
    let Some(decision) = t.decision.as_deref() else { return String::new() };
    let score = t.risk_score.unwrap_or(0);
    let code = match decision_rank(Some(decision)) {
        3 => "1;31", // act-now
        2 => "33",   // soon
        1 => "2",    // schedule
        _ => "2",    // track
    };
    format!("{} ", paint(&format!("[{} {score}]", decision.to_uppercase()), code, color))
}

/// `[KEV]`/`[EXPLOITED]`, `[RANSOMWARE]`, `[OVERDUE]` and exploit-maturity tags.
fn signal_badges(t: &ThreatEntry, color: bool) -> String {
    let mut tags: Vec<&str> = Vec::new();
    if t.kev {
        tags.push("KEV");
    } else if t.exploited {
        tags.push("EXPLOITED");
    }
    if t.ransomware {
        tags.push("RANSOMWARE");
    }
    if t.kev_overdue {
        tags.push("OVERDUE");
    }
    if t.exploit_maturity.as_deref() == Some("WEAPONIZED") {
        tags.push("WEAPONIZED");
    }
    tags.iter().map(|tag| format!(" {}", paint(&format!("[{tag}]"), "1;31", color))).collect()
}

/// Ranked, optionally-colored terminal summary — exposed and highest-risk first.
fn print_summary(results: &BatchResults, color: bool) {
    for key in results.assets.iter().filter(|(_, a)| a.restart_pending).map(|(k, _)| k) {
        println!("{}", paint(&format!("[!] {key}: running binary was replaced on disk; restart to apply the update"), "1;33", color));
    }
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
            let asset = results.assets.get(*key);
            let reach = asset.map(|a| a.reachability.as_str()).unwrap_or("private");
            let eps = asset.map(|a| a.listeners.join(", ")).unwrap_or_default();
            let code = if reach == "public" { "1;31" } else { "1;33" };
            format!("  {}", paint(&format!("[{} {eps}]", reach.to_uppercase()), code, color))
        } else {
            String::new()
        };
        let upgrade = results.assets.get(*key).and_then(|a| a.upgrade_to.as_deref())
            .map(|v| format!("  {}", paint(&format!("→ upgrade to {v} fixes all"), "32", color)))
            .unwrap_or_default();
        println!("\n  {} — {} finding(s){badge}{upgrade}", paint(key, "1;36", color), threats.len());
        for t in threats.iter().take(5) {
            let cve = t.cve_id.as_deref().or(t.id.as_deref()).unwrap_or("(no id)");
            let mut kev = signal_badges(t, color);
            if let Some(d) = t.recorded_decision.as_ref().filter(|d| d.suppressing) {
                kev += &format!(" {}", paint(&format!("[DECIDED {}]", d.verdict.to_uppercase()), "32", color));
            }
            let title: String = t.title.as_deref().unwrap_or("").chars().take(72).collect();
            // Concrete fix versions turn "vulnerable" into "upgrade to X".
            let fix = if t.fixed_versions.is_empty() {
                String::new()
            } else {
                format!("  {}", paint(&format!("→ fix: {}", t.fixed_versions.join(", ")), "32", color))
            };
            let band = decision_badge(t, color);
            println!("      {band}{}  {cve}{kev}  {title}{fix}", sev_label(t.severity.as_deref(), color));
            if let Some(url) = &t.radar_url {
                println!("            {}", paint(url, "4;34", color));
            }
            if let Some(rem) = &t.remediation {
                let hint: String = rem.chars().take(96).collect();
                println!("            {}", paint(&hint, "2", color));
            }
        }
        if threats.len() > 5 {
            println!("      … and {} more", threats.len() - 5);
        }
    }

    // CVEs that hit more than one service — the highest-leverage fixes.
    let mut shared: Vec<(&String, &find_threats::CveGroup)> = results.by_cve.iter()
        .filter(|(_, g)| g.assets.len() > 1)
        .collect();
    if !shared.is_empty() {
        shared.sort_by(|a, b| {
            (b.1.kev, sev_rank(b.1.severity.as_deref()), b.1.assets.len())
                .cmp(&(a.1.kev, sev_rank(a.1.severity.as_deref()), a.1.assets.len()))
                .then(a.0.cmp(b.0))
        });
        println!("\n{}", paint("Top shared CVEs (one fix, many services):", "1", color));
        for (cve, g) in shared.iter().take(5) {
            let kev = if g.kev { format!(" {}", paint("[KEV]", "1;31", color)) } else { String::new() };
            println!(
                "  {}  {}{kev}  affects {} services",
                sev_label(g.severity.as_deref(), color), cve, g.assets.len()
            );
        }
    }

    let total: usize = rows.iter().map(|r| r.2.len()).sum();
    let exposed_svcs = rows.iter().filter(|r| r.1).count();
    let exploited = rows.iter().flat_map(|r| r.2.iter()).filter(|t| t.exploited).count();
    println!(
        "\n{total} confirmed finding(s) across {} asset(s); {exposed_svcs} exposed, {exploited} exploited in the wild.",
        rows.len()
    );
    let decided = rows.iter().flat_map(|r| r.2.iter()).filter(|t| t.suppressed()).count();
    if decided > 0 {
        println!("{}", paint(&format!("{decided} of them decided in the Radar ledger (not counted by --fail-on)."), "2", color));
    }
    let unconfirmed: usize = results.unconfirmed.values().map(|v| v.len()).sum();
    if unconfirmed > 0 {
        println!(
            "{}",
            paint(
                &format!("{unconfirmed} coordinate-unconfirmed finding(s) for triage (see \"unconfirmed\" in the report)."),
                "2",
                color,
            )
        );
    }
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
        FailOn::Exploited => t.exploited,
        FailOn::ActNow   => t.decision.as_deref() == Some("act-now"),
        FailOn::Exposed  => exposed && sev_rank(t.severity.as_deref()) >= floor,
    };
    for (key, threats) in &results.services {
        let exposed = results.assets.get(key).map(|a| a.exposed).unwrap_or(false);
        if threats.iter().any(|t| !t.suppressed() && hit(t, exposed)) {
            return true;
        }
    }
    false
}

/// Score every finding (confirmed + unconfirmed) with the exposure of its owning
/// asset, so each entry gains `riskScore`/`decision`. Exposure defaults to "none"
/// for an asset with no recorded reachability.
fn score_findings(results: &mut BatchResults) {
    let exposure_of = |key: &str| -> String {
        results
            .assets
            .get(key)
            .map(|a| a.reachability.clone())
            .unwrap_or_else(|| "none".to_string())
    };
    // Snapshot exposures first to avoid borrowing `results.assets` mutably+immutably.
    let exposures: std::collections::BTreeMap<String, String> = results
        .services
        .keys()
        .chain(results.unconfirmed.keys())
        .map(|k| (k.clone(), exposure_of(k)))
        .collect();
    for (key, entries) in results.services.iter_mut().chain(results.unconfirmed.iter_mut()) {
        let exposure = exposures.get(key).map(String::as_str).unwrap_or("none");
        for e in entries.iter_mut() {
            e.apply_risk(exposure);
        }
    }
}

/// The user's answer to the monitoring prompt (only meaningful when we actually
/// prompted). `Empty`/`Yes` register; `No` skips this run; `Never` persists opt-out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromptAnswer {
    Yes,
    No,
    Never,
}

/// Parse a free-text prompt response. Empty (just Enter) defaults to Yes.
fn parse_prompt_answer(raw: &str) -> PromptAnswer {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "y" | "yes"   => PromptAnswer::Yes,
        "never"            => PromptAnswer::Never,
        _                  => PromptAnswer::No,
    }
}

/// What the post-scan registration step should do — the decision is pulled out
/// of `main` into a pure function so the (flag × prompt-mode × interactivity ×
/// answer) matrix is unit-testable without touching stdin/network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegisterAction {
    /// Register silently (flag/always/mode), no prompt.
    Register,
    /// Skip this run without persisting anything.
    Skip,
    /// Interactive + human output: ask the user, then act on the answer.
    Prompt,
}

/// Decide what to do BEFORE any prompt, from the flags, persisted prompt mode,
/// and whether this run is an interactive human session (terminal, not --json/
/// --quiet/stdout). Mirrors the precedence in the feature spec.
fn register_action(
    no_register: bool,
    register: bool,
    prompt_mode: &str,
    interactive_human: bool,
) -> RegisterAction {
    if no_register {
        RegisterAction::Skip
    } else if register || prompt_mode == "always" {
        RegisterAction::Register
    } else if prompt_mode == "never" {
        RegisterAction::Skip
    } else if interactive_human {
        RegisterAction::Prompt
    } else {
        RegisterAction::Skip
    }
}

/// Map a scanned asset into an inventory payload entry, or None when it has no
/// buildable coordinate (so a malformed entry is never registered). Uses the
/// asset's CPE for Windows apps / the OS, and a purl otherwise.
fn asset_to_inventory(a: &Asset, os: &OsType) -> Option<InventoryAsset> {
    let purl = scan::build_purl(a, os);
    let cpe = a.cpe.clone();
    if purl.is_none() && cpe.is_none() {
        return None;
    }
    let rt = a.runtime.as_ref();
    // Exposure mirrors the report's reachability ("none" when nothing is running).
    let exposure = rt.map(|r| r.reachability.as_str()).unwrap_or("none").to_string();
    Some(InventoryAsset {
        purl: purl.unwrap_or_default(),
        cpe,
        version: a.version.clone(),
        ecosystem: ecosystem_label(a.ecosystem).to_string(),
        name: a.coordinate_name(),
        exposure,
        exposed: rt.map(|r| r.exposed).unwrap_or(false),
        runtime: a.runtime.is_some(),
    })
}

/// Short ecosystem token sent in the inventory payload.
fn ecosystem_label(eco: find_threats::Ecosystem) -> &'static str {
    use find_threats::Ecosystem::*;
    match eco {
        Deb => "deb",
        Rpm => "rpm",
        Arch => "pacman",
        Alpine => "apk",
        Homebrew => "brew",
        FreeBsdPkg | OpenBsdPkg | NetBsdPkg => "bsd",
        Npm => "npm",
        PyPI => "pypi",
        NuGet => "nuget",
        WinApp => "windows",
        WindowsOs => "windows-os",
        Generic => "generic",
    }
}

/// Build the OS descriptor for a registration from the gathered system facts.
fn inventory_os(os: &OsType, sys: Option<&SystemFacts>) -> Option<InventoryOs> {
    let sys = sys?;
    let os_type = match os {
        OsType::Linux(_) => Some("linux".to_string()),
        OsType::MacOs => Some("macos".to_string()),
        OsType::FreeBsd | OsType::OpenBsd | OsType::NetBsd | OsType::DragonFlyBsd => {
            Some("bsd".to_string())
        }
        _ => Some(sys.kernel_name.clone()),
    };
    Some(InventoryOs {
        os_type,
        distro: Some(sys.distro_name.clone()).filter(|s| !s.is_empty()),
        version: Some(sys.distro_version.clone()).filter(|s| !s.is_empty()),
    })
}

/// Print a concise human-readable outcome after a successful registration.
fn print_registration(resp: &RegisterResponse, alerts: bool, color: bool) {
    let state = if resp.new { "registered" } else { "updated" };
    let mon = match (resp.monitoring, alerts) {
        (false, _) => "monitoring off",
        (true, true) => "monitoring on",
        (true, false) => "alerts need a paid plan",
    };
    println!(
        "\n{} Host {state}; {mon} ({} asset(s) tracked).",
        paint("✓", "32", color),
        resp.asset_count
    );

    let d = &resp.drift;
    if d.added + d.removed + d.changed > 0 {
        println!(
            "  Drift vs last scan: {} / {} / {}",
            paint(&format!("+{} added", d.added), "32", color),
            paint(&format!("-{} removed", d.removed), "31", color),
            paint(&format!("~{} changed", d.changed), "33", color),
        );
    }

    let s = &resp.summary;
    println!(
        "  {} act-now, {} exposed, {} known-exploited.",
        paint(&s.act_now.to_string(), "1;31", color),
        s.exposed,
        s.kev,
    );

    if resp.resolved_count > 0 {
        println!(
            "  {}",
            paint(&format!("{} resolved since your last scan.", resp.resolved_count), "32", color)
        );
    }

    if resp.new_since_last_count > 0 {
        println!(
            "{}",
            paint(
                &format!("  {} new since your last scan:", resp.new_since_last_count),
                "1;33",
                color,
            )
        );
        for f in resp.new_since_last.iter().take(3) {
            let cve = f.cve_id.as_deref().unwrap_or("(no id)");
            let decision = f.decision.as_deref().unwrap_or("track");
            let coord = f.coordinate.as_deref().unwrap_or("");
            let kev: String = [(f.kev, "[KEV]"), (f.kev_overdue, "[OVERDUE]")].iter()
                .filter(|(on, _)| *on)
                .map(|(_, tag)| format!(" {}", paint(tag, "1;31", color)))
                .collect();
            let fix = if f.fixed_versions.is_empty() {
                String::new()
            } else {
                format!("  {}", paint(&format!("→ fix: {}", f.fixed_versions.join(", ")), "32", color))
            };
            println!("      {} {cve}{kev}  {coord}{fix}", paint(&format!("[{}]", decision.to_uppercase()), "1;33", color));
            if let Some(url) = &f.radar_url {
                println!("            {}", paint(url, "4;34", color));
            }
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Flushes the log on drop; must outlive the run.
    let _log_guard = logging::init(cli.verbose);

    let os = detect_os();
    if let (None, OsType::Unsupported(name)) = (&cli.sbom, &os) {
        error!(os = %name, "unsupported OS; nothing to scan");
        eprintln!("Unsupported OS: {name}. Nothing to scan.");
        return ExitCode::from(3);
    }

    let interactive = !cli.yes && io::stdin().is_terminal();

    let api_key = match auth::resolve_api_key(cli.reset, interactive) {
        Some(k) => k,
        None => {
            error!("no API key available");
            eprintln!(
                "No API key available. Set OFFSEQ_API_KEY, or run interactively to enter one."
            );
            return ExitCode::from(2);
        }
    };

    // `--unregister` is a standalone action: delete this host's inventory and exit
    // without scanning. Treated as best-effort but its result drives the exit code.
    if cli.unregister {
        // Read-only lookup: never mint a host id just to delete it. With no saved
        // id the server has nothing for this machine, so skip the API call.
        let Some(host_id) = auth::host_id() else {
            if !cli.quiet {
                println!("No host is registered from this machine; nothing to unregister.");
            }
            return ExitCode::SUCCESS;
        };
        let client = ThreatClient::new(&api_key);
        match client.unregister(&host_id) {
            Ok(()) => {
                if !cli.quiet {
                    println!("Host {host_id} removed from Radar monitoring.");
                }
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                error!(error = %e, host_id = %host_id, "failed to unregister host");
                eprintln!("[!] Failed to unregister host: {e}");
                return ExitCode::from(1);
            }
        }
    }

    // Decide where output goes before doing any slow work.
    let to_stdout = cli.json;
    let mut threats_path = if to_stdout {
        PathBuf::new()
    } else {
        cli.output.clone().unwrap_or_else(|| {
            if interactive {
                PathBuf::from(prompt_output_path())
            } else {
                PathBuf::from(DEFAULT_REPORT)
            }
        })
    };

    // With --json, stdout carries only the report.
    macro_rules! say {
        ($($a:tt)*) => {{ if !cli.quiet { if to_stdout { eprintln!($($a)*) } else { println!($($a)*) } } }};
    }

    let client = Arc::new(ThreatClient::new(&api_key));
    let sev_floor = severity_floor(cli.severity);

    let (mut final_results, assets, system_info) = if let Some(path) = &cli.sbom {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[!] Couldn't read '{}': {e}", path.display());
                return ExitCode::from(1);
            }
        };
        let filename = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default();
        let body = match scan_body(&content, &filename, cli.strict) {
            Ok(b) => b,
            Err(msg) => {
                eprintln!("[!] {msg}");
                return ExitCode::from(1);
            }
        };
        let pb = spinner(&format!("Scanning {filename} against OffSeq Radar…"), cli.quiet);
        let scanned = client.scan(body);
        if let Some(pb) = pb { pb.finish_and_clear(); }
        let report = match scanned {
            Ok(r) => r,
            Err(ThreatError::BatchTooLarge(cap)) => {
                let cap = cap.map(|n| format!(" ({n})")).unwrap_or_default();
                warn!("SBOM exceeds the plan's packages-per-scan cap{cap}");
                eprintln!("{filename} has more packages than your plan checks per scan{cap}. Split the file, or upgrade: https://radar.offseq.com/pricing");
                return ExitCode::from(4);
            }
            Err(e) => return lookup_failed(e, "SBOM scan"),
        };
        say!("\nScanned {} package(s) from {} ({}).\n", report.packages, path.display(), report.format);
        (report.into_results(&path.display().to_string(), sev_floor), Vec::new(), None)
    } else {
        say!("\nDetected OS: {}\n", os_label(&os));

        let scan_pb = spinner("Discovering assets…", cli.quiet);
        let collectors = scan::for_scope(cli.scope);
        let mut assets = scan::dedup_and_merge(scan::collect_assets(&os, &collectors));
        let system_info = gather_system_info(&os);
        if let Some(pb) = scan_pb {
            pb.finish_and_clear();
        }
        tracing::debug!(asset_count = assets.len(), scope = ?cli.scope, "asset discovery complete");

        if !cli.include.is_empty() || !cli.exclude.is_empty() {
            // Match against BOTH the display name and the resolved package coordinate
            // (a unit "ssh" resolves to "openssh-server"): include keeps if either
            // matches; exclude drops if either matches.
            assets.retain(|a| {
                let coord = a.coordinate_name();
                asset_allowed(&[a.name.as_str(), &coord], &cli.include, &cli.exclude)
            });
        }
        assets.sort_by_key(|a| a.report_key());

        if let Some(sys) = &system_info {
            say!("System:");
            say!("  Kernel:  {} {}", sys.kernel_name, sys.kernel_version);
            say!("  Distro:  {} {}", sys.distro_name, sys.distro_version);
        }
        let exposed = assets.iter()
            .filter(|a| a.runtime.as_ref().map(|r| r.exposed).unwrap_or(false))
            .count();
        let suffix = if exposed > 0 { format!(", {exposed} network-exposed") } else { String::new() };
        let label = if cli.scope == ScanScope::All { "asset" } else { "service" };
        say!("Found {} {label}(s){suffix}\n", assets.len());
        if !cli.quiet {
            if assets.is_empty() {
                warn!("discovery returned zero assets; may need elevated privileges");
                eprintln!("[!] Nothing discovered — you may need elevated privileges (try sudo) for full discovery.");
            }
            if cli.scope == ScanScope::All && assets.len() > FREE_BATCH {
                eprintln!("{}", scope_all_budget_warning(assets.len()));
            }
        }

        let lookup_pb = spinner("Matching coordinates against OffSeq Radar…", cli.quiet);
        let scanned = scan::run_scan(&client, &assets, &os, cli.strict, sev_floor);
        if let Some(pb) = lookup_pb { pb.finish_and_clear(); }
        let outcome = match scanned {
            Ok(o) => o,
            Err(e) => return lookup_failed(e, "Match lookup"),
        };

        // Assets were already deduped/merged before lookup; map them 1:1 (report_key
        // matches the run_batch result keys).
        let asset_map = assets.iter().map(|a| {
            let rt = a.runtime.as_ref();
            (a.report_key(), find_threats::AssetInfo {
                exe: a.locations.first().cloned().unwrap_or_default(),
                version: a.version.clone(),
                version_source: a.version_source_label().to_string(),
                exposed: rt.map(|r| r.exposed).unwrap_or(false),
                reachability: rt.map(|r| r.reachability.as_str()).unwrap_or("none").to_string(),
                listeners: rt.map(|r| r.listeners.clone()).unwrap_or_default(),
                upgrade_to: outcome.upgrades.get(&a.report_key()).cloned(),
                restart_pending: rt.is_some_and(|r| r.restart_pending),
            })
        }).collect();

        let mut results = BatchResults {
            meta: find_threats::Meta::default(),
            services: outcome.results,
            by_cve: std::collections::BTreeMap::new(),
            unconfirmed: outcome.unconfirmed,
            assets: asset_map,
            errors:   outcome.errors,
            rejected: outcome.rejected,
            truncated: outcome.truncated,
            registration: None,
        };
        // Exposure-aware risk score + SSVC decision per finding, computed from the
        // OWNING asset's reachability so local scores agree with the server's.
        score_findings(&mut results);
        (results, assets, system_info)
    };

    if let Some(info) = plan_info(&client.last_rate_limit()) {
        say!("{info}");
    }
    final_results.sort_findings();
    final_results.compute_cve_groups();

    // ── Post-scan: opt-in continuous-monitoring registration ─────────────────
    // Done before serialization so the server response lands in the JSON report.
    // Output is "human" only when not piping JSON, not quiet, and writing a file.
    let human_output = !to_stdout && !cli.quiet;
    let interactive_human = interactive && human_output;
    let prompt_mode = auth::monitoring_prompt_mode();
    let mut action = register_action(cli.no_register || cli.sbom.is_some(), cli.register, &prompt_mode, interactive_human);

    // If we'd prompt, ask now and fold the answer back into the action.
    if action == RegisterAction::Prompt {
        let inventory_count = assets
            .iter()
            .filter(|a| a.cpe.is_some() || scan::build_purl(a, &os).is_some())
            .count();
        match prompt_register(inventory_count, cli.scope) {
            PromptAnswer::Yes => action = RegisterAction::Register,
            PromptAnswer::No => action = RegisterAction::Skip,
            PromptAnswer::Never => {
                if let Err(e) = auth::set_monitoring_prompt_mode("never") {
                    warn!(error = %e, "failed to save monitoring preference");
                    eprintln!("[!] Couldn't save monitoring preference: {e}");
                }
                action = RegisterAction::Skip;
            }
        }
    }

    // Captured here so the human-readable outcome can be printed after the
    // vulnerability summary, while the JSON report below already includes it.
    let mut registration: Option<RegisterResponse> = None;
    let mut vex_doc: Option<Vec<u8>> = None;
    if action == RegisterAction::Register {
        let (keys, inventory): (Vec<String>, Vec<InventoryAsset>) = assets
            .iter()
            .filter_map(|a| Some((a.report_key(), asset_to_inventory(a, &os)?)))
            .unzip();
        let host_id = auth::get_or_create_host_id();
        let os_desc = inventory_os(&os, system_info.as_ref());
        match client.register_inventory(
            &host_id,
            cli.host_name.as_deref(),
            os_desc,
            env!("CARGO_PKG_VERSION"),
            true,
            &inventory,
        ) {
            Ok(resp) => {
                tracing::info!(host_id = %host_id, "monitoring registration succeeded");
                final_results.registration = Some(RegistrationReport::from(&resp));
                registration = Some(resp);
                if cli.respect_decisions {
                    let coordinates = keys.into_iter().zip(inventory.iter().map(InventoryAsset::coordinate)).collect();
                    match client.host_findings(&host_id) {
                        // The detail endpoint isn't plan-gated, but only paid plans can record decisions.
                        Ok(findings) => {
                            if final_results.apply_decisions(&coordinates, findings) == 0 && client.last_rate_limit().is_free_plan() {
                                say!("No recorded decisions: the Radar decision ledger needs a paid plan.");
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, host_id = %host_id, "decision lookup skipped");
                            eprintln!("[!] --respect-decisions skipped: {e}");
                        }
                    }
                }
                if cli.vex.is_some() {
                    match client.host_vex(&host_id, &cli.vex_format) {
                        Ok(doc) => vex_doc = Some(doc),
                        Err(e) => {
                            warn!(error = %e, host_id = %host_id, "VEX export skipped");
                            eprintln!("[!] VEX export skipped: {e}");
                        }
                    }
                }
            }
            // Non-fatal: a one-line warning, exit code unchanged.
            Err(e) => {
                warn!(error = %e, host_id = %host_id, "monitoring registration skipped");
                eprintln!("[!] Monitoring registration skipped: {e}");
                if is_host_or_asset_cap(&e) {
                    eprintln!("    Your plan's host/asset cap was reached — raise it at https://radar.offseq.com/pricing (manage hosts: https://radar.offseq.com/console).");
                }
            }
        }
    }
    if registration.is_none() {
        for (wanted, flag) in [(cli.respect_decisions, "--respect-decisions"), (cli.vex.is_some(), "--vex")] {
            if wanted {
                eprintln!("[!] {flag} skipped: the host was not registered this run (see --register).");
            }
        }
    }

    let output_json = match serde_json::to_string_pretty(&final_results) {
        Ok(j) => j,
        Err(e) => {
            error!(error = %e, "failed to serialize results");
            eprintln!("Failed to serialize results: {e}");
            return ExitCode::from(1);
        }
    };

    if to_stdout {
        println!("{output_json}");
    } else {
        loop {
            match write_private(&threats_path, output_json.as_bytes()) {
                Ok(_) => break,
                Err(e) => {
                    error!(error = %e, path = %threats_path.display(), "failed to write threats report");
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
                        if new_path.is_empty() { DEFAULT_REPORT } else { new_path },
                    ));
                }
            }
        }
    }

    if let Some(ref sarif_path) = cli.sarif {
        if let Err(e) = write_private(sarif_path, sarif::to_sarif(&final_results).as_bytes()) {
            error!(error = %e, path = %sarif_path.display(), "failed to write SARIF report");
            eprintln!("[!] Couldn't write SARIF to '{}': {e}", sarif_path.display());
            return ExitCode::from(1);
        }
        say!("SARIF report written to {}", sarif_path.display());
    }

    if let (Some(vex_path), Some(doc)) = (&cli.vex, &vex_doc) {
        if let Err(e) = write_private(vex_path, doc) {
            error!(error = %e, path = %vex_path.display(), "failed to write VEX document");
            eprintln!("[!] Couldn't write VEX to '{}': {e}", vex_path.display());
            return ExitCode::from(1);
        }
        say!("VEX document written to {}", vex_path.display());
    }

    let color = !cli.no_color && std::env::var_os("NO_COLOR").is_none() && io::stdout().is_terminal();
    if !cli.quiet && !to_stdout {
        print_summary(&final_results, color);
    }

    let total = final_results.total_vulns();
    let word = if total == 1 { "vulnerability" } else { "vulnerabilities" };
    if !final_results.errors.is_empty() {
        warn!(
            failed_count = final_results.errors.len(),
            "one or more service lookups failed; see the errors map in the JSON report for details"
        );
        eprintln!(
            "[!] {} service lookup(s) failed; see the \"errors\" map in the output.",
            final_results.errors.len()
        );
    }
    if !final_results.rejected.is_empty() {
        eprintln!(
            "[!] Radar could not check {} package(s); see the \"rejected\" map in the output.",
            final_results.rejected.len()
        );
    }
    if !final_results.truncated.is_empty() {
        eprintln!(
            "[!] {} asset(s) have more matches than your plan returns per query (riskiest kept; see \"truncated\"). Full results: https://radar.offseq.com/pricing",
            final_results.truncated.len()
        );
    }
    if to_stdout {
        eprintln!("Found {total} {word}.");
    } else if !cli.quiet {
        println!("\nReport saved to {}", threats_path.display());
    }

    // Print the monitoring-registration outcome (human mode only) AFTER the
    // vulnerability summary. The network call itself already happened before
    // serialization so the response is captured in the JSON report too.
    if let (true, Some(resp)) = (human_output, &registration) {
        print_registration(resp, !client.last_rate_limit().is_free_plan(), color);
    }

    // Opt-in Windows Update Agent advisory: pending (not-installed) security
    // updates. Independent of the Radar match (these are KB-keyed, not
    // coordinate-keyed), so it's printed as its own section.
    if cli.windows_missing_updates {
        if matches!(os, OsType::Windows(_)) {
            let pb = spinner("Querying Windows Update for pending updates…", cli.quiet);
            let updates = find_threats::windows::gather_missing_updates();
            if let Some(pb) = pb { pb.finish_and_clear(); }
            print_missing_updates(&updates, color, to_stdout);
        } else if !cli.quiet {
            warn!("--windows-missing-updates ignored: not running on Windows");
            eprintln!("[!] --windows-missing-updates is only available on Windows; ignoring.");
        }
    }

    if let Some(f) = cli.fail_on {
        if fail_triggered(&final_results, f, cli.severity) {
            tracing::info!(threshold = ?f, "run finished; --fail-on threshold met");
            return ExitCode::from(5);
        }
        // A gate that could not see every asset must not pass.
        if !final_results.errors.is_empty() {
            eprintln!("[!] --fail-on could not evaluate every asset; failing the run.");
            return ExitCode::from(1);
        }
    }

    tracing::info!(total_vulns = total, "run finished successfully");
    ExitCode::SUCCESS
}

/// Exit code for a failed Radar lookup: 4 when the plan or quota is the cause, else 1.
fn lookup_failed(e: ThreatError, what: &str) -> ExitCode {
    match e {
        ThreatError::RateLimitExceeded(msg) => {
            warn!(message = %msg, "rate limit exceeded: {what}");
            auth::prompt_upgrade(Some(&msg));
            ExitCode::from(4)
        }
        // A plan gate or incomplete profile: the server message says how to fix
        // it (with links), and exit 4 rather than 1, which reads as a network failure.
        ThreatError::AccessDenied(msg) => {
            warn!(message = %msg, "access denied: {what}");
            eprintln!("{msg}");
            ExitCode::from(4)
        }
        e => {
            error!(error = %e, "{what} failed");
            eprintln!("{what} failed: {e}");
            ExitCode::from(1)
        }
    }
}

/// Print the Windows Update Agent advisory (pending updates, most severe first).
/// Goes to stderr when stdout is reserved for the JSON report, so piping stays
/// clean.
fn print_missing_updates(updates: &[find_threats::windows::WinUpdate], color: bool, to_stdout: bool) {
    macro_rules! out {
        ($($a:tt)*) => {{ if to_stdout { eprintln!($($a)*) } else { println!($($a)*) } }};
    }
    out!("\n┌─────────────────────────────────────────────┐");
    out!("│        Pending Windows Updates (WUA)        │");
    out!("└─────────────────────────────────────────────┘");
    if updates.is_empty() {
        out!("No pending updates found (or the update scan was unavailable).");
        return;
    }
    out!("{} pending update(s):", updates.len());
    for u in updates {
        let sev = if u.severity.is_empty() { "—".to_string() } else { u.severity.clone() };
        let kbs = if u.kbs.is_empty() {
            String::new()
        } else {
            format!("  [KB{}]", u.kbs.join(", KB"))
        };
        let tag = paint(&format!("[{sev}]"), severity_ansi(&u.severity), color);
        out!("  {tag} {}{kbs}", u.title);
    }
    out!("\nApply these from Windows Update / WSUS, or: https://catalog.update.microsoft.com");
}

/// ANSI color code for an MSRC severity label.
fn severity_ansi(sev: &str) -> &'static str {
    match sev.to_lowercase().as_str() {
        "critical" => "1;31",
        "important" => "31",
        "moderate" => "33",
        "low" => "32",
        _ => "0",
    }
}

/// Scope-aware noun for the inventory being registered: under `--scope all` the
/// count is installed packages (often thousands), otherwise running services.
/// Matches the "asset"/"service" wording used in the post-scan summary.
fn inventory_noun(scope: ScanScope, count: usize) -> &'static str {
    match (scope, count) {
        (ScanScope::All, 1) => "package",
        (ScanScope::All, _) => "packages",
        (_, 1) => "service",
        (_, _) => "services",
    }
}

/// Free-plan batch size and daily request quota (utils/planLimits.js).
const FREE_BATCH: usize = 50;
const FREE_REQUESTS_PER_DAY: usize = 30;

/// Shown before matching (the plan is unknown until the first response), so it
/// is worded for the free plan rather than asserting the caller's limits.
fn scope_all_budget_warning(count: usize) -> String {
    let requests = count.div_ceil(FREE_BATCH);
    format!(
        "[!] --scope all produced {count} unique package(s): {requests} batched request(s) on the free tier \
         ({FREE_BATCH} per request, {FREE_REQUESTS_PER_DAY}/day). Higher plans batch more per request: \
         https://radar.offseq.com/pricing"
    )
}

/// Whether a registration error is a plan cap (monitored-host limit or per-host
/// asset cap) rather than a transient failure. A 413 surfaces as `BatchTooLarge`;
/// a host-limit 403 surfaces as a message we keyword-match. Used only to decide
/// whether to append an upgrade hint — registration stays non-fatal either way.
fn is_host_or_asset_cap(err: &ThreatError) -> bool {
    match err {
        ThreatError::BatchTooLarge(_) => true,
        ThreatError::Other(msg) | ThreatError::AccessDenied(msg) => {
            let m = msg.to_ascii_lowercase();
            m.contains("limit") || m.contains("hosts") || m.contains("assets")
        }
        _ => false,
    }
}

/// Prompt the user to register N items for monitoring. A bare Enter accepts;
/// EOF answers No. The noun tracks the scan scope so `--scope all` says
/// "packages", not "services".
fn prompt_register(count: usize, scope: ScanScope) -> PromptAnswer {
    let noun = inventory_noun(scope, count);
    print!(
        "\nAdd these {count} {noun} to Radar for continuous monitoring & alerts? [Y/n/never] "
    );
    let _ = io::stdout().flush();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).unwrap_or(0) == 0 {
        return PromptAnswer::No; // EOF: don't register on a closed stdin
    }
    parse_prompt_answer(&input)
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
    fn inventory_noun_is_scope_aware_and_pluralised() {
        // Default/running scope counts services.
        assert_eq!(inventory_noun(ScanScope::Running, 1), "service");
        assert_eq!(inventory_noun(ScanScope::Running, 3), "services");
        assert_eq!(inventory_noun(ScanScope::Running, 0), "services");
        // --scope all counts installed packages, often thousands.
        assert_eq!(inventory_noun(ScanScope::All, 1), "package");
        assert_eq!(inventory_noun(ScanScope::All, 2400), "packages");
    }

    #[test]
    fn scope_all_warning_is_plan_agnostic_and_links_pricing() {
        let w = scope_all_budget_warning(2400);
        assert!(w.contains("2400 unique package(s): 48 batched request(s)"));
        // Conditional wording — never asserts the caller IS rate-limited or names
        // their plan; just points at the free-tier cap and the upgrade path.
        assert!(w.contains("on the free tier"));
        assert!(w.contains("https://radar.offseq.com/pricing"));
        assert!(!w.to_lowercase().contains("expect rate limiting"));
    }

    #[test]
    fn host_or_asset_cap_detected_for_plan_limits_only() {
        // 413 (asset cap) always qualifies.
        assert!(is_host_or_asset_cap(&ThreatError::BatchTooLarge(Some(50))));
        assert!(is_host_or_asset_cap(&ThreatError::BatchTooLarge(None)));
        // Host-limit / too-many-assets 403 bodies (keyword match).
        assert!(is_host_or_asset_cap(&ThreatError::Other(
            "Host limit reached. Your plan allows up to 5 monitored hosts.".into()
        )));
        assert!(is_host_or_asset_cap(&ThreatError::Other(
            "Too many assets. Your plan allows up to 100 assets.".into()
        )));
        // Unrelated registration failures don't get the upgrade hint.
        assert!(!is_host_or_asset_cap(&ThreatError::Other("decode error".into())));
        assert!(!is_host_or_asset_cap(&ThreatError::RateLimitExceeded("slow down".into())));
    }

    #[test]
    fn glob_matching() {
        assert!(glob_match("nginx", "nginx"));
        assert!(!glob_match("nginx", "nginx-ui"));
        assert!(glob_match("*sql*", "postgresql"));
        assert!(glob_match("postgres*", "postgresql"));
        assert!(glob_match("*.service", "ssh.service"));
        assert!(!glob_match("ngin?", "nginx")); // no '?' support, treated literally
        // include/exclude over an asset's names (display + coordinate)
        assert!(asset_allowed(&["nginx"], &[], &["sshd".into()]));
        assert!(!asset_allowed(&["sshd"], &[], &["ssh*".into()]));
        assert!(asset_allowed(&["nginx"], &["ngin*".into()], &[]));
        assert!(!asset_allowed(&["redis"], &["ngin*".into()], &[]));
        // a unit "ssh" whose package is "openssh-server": excluded via either name
        assert!(!asset_allowed(&["ssh", "openssh-server"], &[], &["openssh*".into()]));
        assert!(asset_allowed(&["ssh", "openssh-server"], &["openssh*".into()], &[]));
    }

    #[test]
    fn register_action_precedence() {
        // --no-register always wins.
        assert_eq!(register_action(true, true, "always", true), RegisterAction::Skip);
        // --register (no --no-register) registers without prompting.
        assert_eq!(register_action(false, true, "ask", false), RegisterAction::Register);
        // prompt_mode "always" registers even non-interactively.
        assert_eq!(register_action(false, false, "always", false), RegisterAction::Register);
        // prompt_mode "never" skips.
        assert_eq!(register_action(false, false, "never", true), RegisterAction::Skip);
        // ask + interactive human → prompt.
        assert_eq!(register_action(false, false, "ask", true), RegisterAction::Prompt);
        // ask + non-interactive (CI) → skip silently. THIS is the "off by default
        // in CI" guarantee.
        assert_eq!(register_action(false, false, "ask", false), RegisterAction::Skip);
    }

    #[test]
    fn prompt_answer_parsing() {
        assert_eq!(parse_prompt_answer(""), PromptAnswer::Yes);
        assert_eq!(parse_prompt_answer("\n"), PromptAnswer::Yes);
        assert_eq!(parse_prompt_answer("y"), PromptAnswer::Yes);
        assert_eq!(parse_prompt_answer("YES"), PromptAnswer::Yes);
        assert_eq!(parse_prompt_answer("never"), PromptAnswer::Never);
        assert_eq!(parse_prompt_answer(" Never "), PromptAnswer::Never);
        assert_eq!(parse_prompt_answer("n"), PromptAnswer::No);
        assert_eq!(parse_prompt_answer("nope"), PromptAnswer::No);
    }

    #[test]
    fn asset_to_inventory_maps_purl_and_exposure() {
        use find_threats::{Asset, Ecosystem, Source};
        use find_threats::engine::{LinuxDistro, OsType, Reachability};
        use find_threats::scan::Runtime;

        let os = OsType::Linux(LinuxDistro::Ubuntu);
        // An exposed running service → exposure mapped from runtime reachability.
        let running = Asset {
            ecosystem: Ecosystem::Deb, name: "nginx".into(), pkg_name: Some("nginx".into()),
            version: "1.24.0".into(), sources: vec![Source::Probe], locations: vec![],
            runtime: Some(Runtime {
                pid: Some(9), listeners: vec!["tcp 0.0.0.0:443".into()],
                reachability: Reachability::Public, exposed: true, restart_pending: false,
            }),
            cpe: None,
        };
        let inv = asset_to_inventory(&running, &os).expect("buildable purl");
        assert!(inv.purl.starts_with("pkg:deb/ubuntu/nginx@1.24.0"), "{}", inv.purl);
        assert_eq!(inv.ecosystem, "deb");
        assert_eq!(inv.name, "nginx");
        assert_eq!(inv.exposure, "public");
        assert!(inv.exposed && inv.runtime);

        // A non-running installed package → exposure "none", runtime false.
        let installed = Asset {
            ecosystem: Ecosystem::Deb, name: "openssl".into(), pkg_name: Some("openssl".into()),
            version: "1.1.1f".into(), sources: vec![Source::PackageDb], locations: vec![],
            runtime: None, cpe: None,
        };
        let inv = asset_to_inventory(&installed, &os).unwrap();
        assert_eq!(inv.exposure, "none");
        assert!(!inv.exposed && !inv.runtime);

        // No buildable purl (BSD/generic) and no CPE → skipped entirely.
        let bsd = Asset {
            ecosystem: Ecosystem::FreeBsdPkg, name: "nginx".into(), pkg_name: Some("nginx".into()),
            version: "1.27.0".into(), sources: vec![Source::PackageDb], locations: vec![],
            runtime: None, cpe: None,
        };
        assert!(asset_to_inventory(&bsd, &OsType::FreeBsd).is_none());

        // A Windows app carries its CPE into the inventory entry (no purl).
        let win = Asset {
            ecosystem: Ecosystem::WinApp, name: "Google Chrome".into(),
            pkg_name: Some("Google Chrome".into()), version: "120.0".into(),
            sources: vec![Source::PackageDb], locations: vec![], runtime: None,
            cpe: Some("cpe:2.3:a:google:chrome:120.0:*:*:*:*:*:*:*".into()),
        };
        let inv = asset_to_inventory(&win, &OsType::Windows(Default::default())).unwrap();
        assert!(inv.purl.is_empty());
        assert_eq!(inv.cpe.as_deref(), Some("cpe:2.3:a:google:chrome:120.0:*:*:*:*:*:*:*"));
        assert_eq!(inv.ecosystem, "windows");
    }

    #[test]
    fn findings_sort_by_decision_then_score() {
        use find_threats::{BatchResults, Meta, ThreatEntry};
        let mk = |cve: &str, sev: &str, kev: bool| -> ThreatEntry {
            serde_json::from_value(serde_json::json!({
                "cveId": cve, "severity": sev, "kev": kev,
                "matchBasis": "coordinate", "confirmed": true, "references": []
            })).unwrap()
        };
        // low/no-kev (track), critical+kev (act-now), medium (track/schedule).
        let mut entries = vec![mk("CVE-LOW", "low", false), mk("CVE-CRIT", "critical", true), mk("CVE-MED", "medium", false)];
        for e in &mut entries { e.apply_risk("public"); }
        let mut services = std::collections::BTreeMap::new();
        services.insert("svc@1".to_string(), entries);
        let mut results = BatchResults {
            meta: Meta::default(), services, by_cve: std::collections::BTreeMap::new(),
            unconfirmed: std::collections::BTreeMap::new(),
            assets: std::collections::BTreeMap::new(),
            errors: std::collections::BTreeMap::new(), rejected: std::collections::BTreeMap::new(),
            truncated: vec![], registration: None,
        };
        results.sort_findings();
        let v = &results.services["svc@1"];
        // Highest decision/score first.
        assert_eq!(v[0].cve_id.as_deref(), Some("CVE-CRIT"));
        assert_eq!(v[0].decision.as_deref(), Some("act-now"));
        // Deterministic and monotonically non-increasing by (decision, score).
        let ranks: Vec<(u8, u32)> = v.iter()
            .map(|e| (decision_rank(e.decision.as_deref()), e.risk_score.unwrap_or(0)))
            .collect();
        assert!(ranks.windows(2).all(|w| w[0] >= w[1]), "{ranks:?}");
    }

    #[test]
    fn suppressed_findings_skip_fail_on_and_sarif_marks_them() {
        use find_threats::{BatchResults, Meta, RecordedDecision, ThreatEntry};
        let decided = ThreatEntry {
            cve_id: Some("CVE-2024-1".into()), severity: Some("critical".into()), kev: true, confirmed: true,
            recorded_decision: Some(RecordedDecision { verdict: "accept".into(), status: "active".into(), suppressing: true, ..Default::default() }),
            ..Default::default()
        };
        let mut results = BatchResults {
            meta: Meta::default(),
            services: std::collections::BTreeMap::from([("svc@1".to_string(), vec![decided])]),
            by_cve: std::collections::BTreeMap::new(), unconfirmed: std::collections::BTreeMap::new(),
            assets: std::collections::BTreeMap::new(), errors: std::collections::BTreeMap::new(),
            rejected: std::collections::BTreeMap::new(), truncated: vec![], registration: None,
        };
        assert!(!fail_triggered(&results, FailOn::Kev, None));
        let v: serde_json::Value = serde_json::from_str(&sarif::to_sarif(&results)).unwrap();
        assert_eq!(v["runs"][0]["results"][0]["suppressions"][0]["justification"], "accept");

        results.services.get_mut("svc@1").unwrap()[0].recorded_decision.as_mut().unwrap().suppressing = false;
        assert!(fail_triggered(&results, FailOn::Kev, None));
    }

    #[test]
    fn sarif_is_valid_json_with_runs() {
        use find_threats::*;
        let entry = serde_json::from_value::<ThreatEntry>(serde_json::json!({
            "cveId": "CVE-2024-0001", "title": "x", "severity": "high",
            "kev": true, "references": ["https://e/1"], "matchBasis": "constraint"
        })).unwrap();
        let services = std::collections::BTreeMap::from([
            ("nginx@1.24.0".to_string(), vec![entry.clone()]),
            ("zlib@1.2.11".to_string(), vec![entry]),
        ]);
        let asset = |exe: &str| AssetInfo {
            exe: exe.into(), version: "1".into(), version_source: "probe".into(), exposed: false,
            reachability: "none".into(), listeners: vec![], upgrade_to: None, restart_pending: false,
        };
        let results = BatchResults {
            meta: Meta::default(), services, by_cve: std::collections::BTreeMap::new(),
            unconfirmed: std::collections::BTreeMap::new(),
            assets: std::collections::BTreeMap::from([
                ("nginx@1.24.0".to_string(), asset("/usr/sbin/nginx")),
                ("zlib@1.2.11".to_string(), asset("")),
            ]),
            errors: std::collections::BTreeMap::new(),
            rejected: std::collections::BTreeMap::new(),
            truncated: vec![],
            registration: None,
        };
        let s = sarif::to_sarif(&results);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["results"][0]["ruleId"], "CVE-2024-0001");
        assert_eq!(v["runs"][0]["results"][0]["level"], "error");
        let loc = &v["runs"][0]["results"][0]["locations"][0];
        assert_eq!(loc["physicalLocation"]["artifactLocation"]["uri"], "usr/sbin/nginx");
        assert_eq!(loc["physicalLocation"]["region"]["startLine"], 1);
        let loc = &v["runs"][0]["results"][1]["locations"][0];
        assert!(loc.get("physicalLocation").is_none());
        assert_eq!(loc["logicalLocations"][0]["fullyQualifiedName"], "zlib@1.2.11");
    }
}
