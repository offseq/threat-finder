use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;
use std::time::Duration;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};

use find_threats::{
    auth, sarif, scan,
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
    print_plan_info,
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
            let asset = results.assets.get(*key);
            let reach = asset.map(|a| a.reachability.as_str()).unwrap_or("private");
            let eps = asset.map(|a| a.listeners.join(", ")).unwrap_or_default();
            let code = if reach == "public" { "1;31" } else { "1;33" };
            format!("  {}", paint(&format!("[{} {eps}]", reach.to_uppercase()), code, color))
        } else {
            String::new()
        };
        println!("\n  {} — {} finding(s){badge}", paint(key, "1;36", color), threats.len());
        for t in threats.iter().take(5) {
            let cve = t.cve_id.as_deref().unwrap_or("(no id)");
            let kev = if t.kev { format!(" {}", paint("[KEV]", "1;31", color)) } else { String::new() };
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
    let kev = rows.iter().flat_map(|r| r.2.iter()).filter(|t| t.kev).count();
    println!(
        "\n{total} confirmed finding(s) across {} asset(s); {exposed_svcs} exposed, {kev} known-exploited.",
        rows.len()
    );
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
        FailOn::Exposed  => exposed && sev_rank(t.severity.as_deref()) >= floor,
    };
    for (key, threats) in &results.services {
        let exposed = results.assets.get(key).map(|a| a.exposed).unwrap_or(false);
        if threats.iter().any(|t| hit(t, exposed)) {
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
/// buildable purl (so a malformed coordinate is never registered).
fn asset_to_inventory(a: &Asset, os: &OsType) -> Option<InventoryAsset> {
    let purl = scan::build_purl(a, os)?;
    let rt = a.runtime.as_ref();
    // Exposure mirrors the report's reachability ("none" when nothing is running).
    let exposure = rt.map(|r| r.reachability.as_str()).unwrap_or("none").to_string();
    Some(InventoryAsset {
        purl,
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
fn print_registration(resp: &RegisterResponse, color: bool) {
    let state = if resp.new { "registered" } else { "updated" };
    let mon = if resp.monitoring { "monitoring on" } else { "monitoring off" };
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
            println!("      {} {cve}  {coord}", paint(&format!("[{}]", decision.to_uppercase()), "1;33", color));
        }
    }
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

    // `--unregister` is a standalone action: delete this host's inventory and exit
    // without scanning. Treated as best-effort but its result drives the exit code.
    if cli.unregister {
        let host_id = auth::get_or_create_host_id();
        let client = ThreatClient::new(&api_key);
        match client.unregister(&host_id) {
            Ok(()) => {
                if !cli.quiet {
                    println!("Host {host_id} removed from Radar monitoring.");
                }
                return ExitCode::SUCCESS;
            }
            Err(e) => {
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
                PathBuf::from("/tmp/threats.json")
            }
        })
    };

    if !cli.quiet {
        println!("\nDetected OS: {}\n", os_label(&os));
    }

    let scan_pb = spinner("Discovering assets…", cli.quiet);
    let collectors = scan::for_scope(cli.scope);
    let mut assets = scan::dedup_and_merge(scan::collect_assets(&os, &collectors));
    let system_info = gather_system_info(&os);
    if let Some(pb) = scan_pb {
        pb.finish_and_clear();
    }

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

    if !cli.quiet {
        if let Some(ref sys) = system_info {
            println!("System:");
            println!("  Kernel:  {} {}", sys.kernel_name, sys.kernel_version);
            println!("  Distro:  {} {}", sys.distro_name, sys.distro_version);
        }
        let exposed = assets.iter()
            .filter(|a| a.runtime.as_ref().map(|r| r.exposed).unwrap_or(false))
            .count();
        let suffix = if exposed > 0 { format!(", {exposed} network-exposed") } else { String::new() };
        let label = if cli.scope == ScanScope::All { "asset" } else { "service" };
        println!("Found {} {label}(s){suffix}\n", assets.len());
        if assets.is_empty() {
            eprintln!("[!] Nothing discovered — you may need elevated privileges (try sudo) for full discovery.");
        }
        if cli.scope == ScanScope::All && assets.len() > 15 {
            eprintln!(
                "[!] --scope all produced {} unique package(s); the free tier allows 15 lookups/hour — expect rate limiting.",
                assets.len()
            );
        }
    }

    let client = Arc::new(ThreatClient::new(&api_key));
    let lookup_pb = spinner("Matching coordinates against OffSeq Radar…", cli.quiet);
    let sev_floor = severity_floor(cli.severity);

    let outcome = match scan::run_scan(&client, &assets, &os, cli.strict, sev_floor) {
        Ok(o) => o,
        Err(ThreatError::RateLimitExceeded(_)) => {
            if let Some(pb) = lookup_pb { pb.finish_and_clear(); }
            auth::prompt_upgrade();
            return ExitCode::from(4);
        }
        Err(e) => {
            if let Some(pb) = lookup_pb { pb.finish_and_clear(); }
            eprintln!("Match lookup failed: {e}");
            return ExitCode::from(1);
        }
    };

    if let Some(pb) = lookup_pb { pb.finish_and_clear(); }
    if !cli.quiet { print_plan_info(&client.last_rate_limit()); }

    // Assets were already deduped/merged before lookup; map them 1:1 (report_key
    // matches the run_batch result keys).
    let mut asset_map: std::collections::BTreeMap<String, find_threats::AssetInfo> =
        std::collections::BTreeMap::new();
    for a in &assets {
        let rt = a.runtime.as_ref();
        asset_map.insert(a.report_key(), find_threats::AssetInfo {
            exe: a.locations.first().cloned().unwrap_or_default(),
            version: a.version.clone(),
            version_source: a.version_source_label().to_string(),
            exposed: rt.map(|r| r.exposed).unwrap_or(false),
            reachability: rt.map(|r| r.reachability.as_str()).unwrap_or("none").to_string(),
            listeners: rt.map(|r| r.listeners.clone()).unwrap_or_default(),
        });
    }

    let mut final_results = BatchResults {
        meta: find_threats::Meta::default(),
        services: outcome.results,
        by_cve: std::collections::BTreeMap::new(),
        unconfirmed: outcome.unconfirmed,
        assets: asset_map,
        errors:   outcome.errors,
        registration: None,
    };

    // Exposure-aware risk score + SSVC decision per finding, computed from the
    // OWNING asset's reachability so local scores agree with the server's. Then
    // re-sort each bucket by decision/score (risk_key now leads with those).
    score_findings(&mut final_results);
    final_results.sort_findings();

    final_results.compute_cve_groups();

    // ── Post-scan: opt-in continuous-monitoring registration ─────────────────
    // Done before serialization so the server response lands in the JSON report.
    // Output is "human" only when not piping JSON, not quiet, and writing a file.
    let human_output = !to_stdout && !cli.quiet;
    let interactive_human = interactive && human_output;
    let prompt_mode = auth::monitoring_prompt_mode();
    let mut action = register_action(cli.no_register, cli.register, &prompt_mode, interactive_human);

    // If we'd prompt, ask now and fold the answer back into the action.
    if action == RegisterAction::Prompt {
        let inventory_count = assets.iter().filter(|a| scan::build_purl(a, &os).is_some()).count();
        match prompt_register(inventory_count) {
            PromptAnswer::Yes => action = RegisterAction::Register,
            PromptAnswer::No => action = RegisterAction::Skip,
            PromptAnswer::Never => {
                if let Err(e) = auth::set_monitoring_prompt_mode("never") {
                    eprintln!("[!] Couldn't save monitoring preference: {e}");
                }
                action = RegisterAction::Skip;
            }
        }
    }

    // Captured here so the human-readable outcome can be printed after the
    // vulnerability summary, while the JSON report below already includes it.
    let mut registration: Option<RegisterResponse> = None;
    if action == RegisterAction::Register {
        let inventory: Vec<InventoryAsset> = assets
            .iter()
            .filter_map(|a| asset_to_inventory(a, &os))
            .collect();
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
                final_results.registration = Some(RegistrationReport::from(&resp));
                registration = Some(resp);
            }
            // Non-fatal: a one-line warning, exit code unchanged.
            Err(e) => eprintln!("[!] Monitoring registration skipped: {e}"),
        }
    }

    let output_json = match serde_json::to_string_pretty(&final_results) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Failed to serialize results: {e}");
            return ExitCode::from(1);
        }
    };

    if let Some(ref sarif_path) = cli.sarif {
        if let Err(e) = fs::write(sarif_path, sarif::to_sarif(&final_results)) {
            eprintln!("[!] Couldn't write SARIF to '{}': {e}", sarif_path.display());
            return ExitCode::from(1);
        } else if !cli.quiet {
            println!("SARIF report written to {}", sarif_path.display());
        }
    }

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

    // Print the monitoring-registration outcome (human mode only) AFTER the
    // vulnerability summary. The network call itself already happened before
    // serialization so the response is captured in the JSON report too.
    if let (true, Some(resp)) = (human_output, &registration) {
        let color = !cli.no_color
            && std::env::var_os("NO_COLOR").is_none()
            && io::stdout().is_terminal();
        print_registration(resp, color);
    }

    if let Some(f) = cli.fail_on {
        if fail_triggered(&final_results, f, cli.severity) {
            return ExitCode::from(5);
        }
    }

    ExitCode::SUCCESS
}

/// Prompt the user to register N services for monitoring. Returns the parsed
/// answer (defaulting to Yes on EOF/empty so a bare Enter accepts).
fn prompt_register(count: usize) -> PromptAnswer {
    print!(
        "\nAdd these {count} services to Radar for continuous monitoring & alerts? [Y/n/never] "
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
                reachability: Reachability::Public, exposed: true,
            }),
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
            runtime: None,
        };
        let inv = asset_to_inventory(&installed, &os).unwrap();
        assert_eq!(inv.exposure, "none");
        assert!(!inv.exposed && !inv.runtime);

        // No buildable purl (BSD/generic) → skipped entirely.
        let bsd = Asset {
            ecosystem: Ecosystem::FreeBsdPkg, name: "nginx".into(), pkg_name: Some("nginx".into()),
            version: "1.27.0".into(), sources: vec![Source::PackageDb], locations: vec![],
            runtime: None,
        };
        assert!(asset_to_inventory(&bsd, &OsType::FreeBsd).is_none());
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
            errors: std::collections::BTreeMap::new(), registration: None,
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
    fn sarif_is_valid_json_with_runs() {
        use find_threats::*;
        let mut services = std::collections::BTreeMap::new();
        services.insert("nginx@1.24.0".to_string(), vec![
            serde_json::from_value::<ThreatEntry>(serde_json::json!({
                "cveId": "CVE-2024-0001", "title": "x", "severity": "high",
                "kev": true, "references": ["https://e/1"], "matchBasis": "constraint"
            })).unwrap()
        ]);
        let results = BatchResults {
            meta: Meta::default(), services, by_cve: std::collections::BTreeMap::new(),
            unconfirmed: std::collections::BTreeMap::new(),
            assets: std::collections::BTreeMap::new(),
            errors: std::collections::BTreeMap::new(),
            registration: None,
        };
        let s = sarif::to_sarif(&results);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["results"][0]["ruleId"], "CVE-2024-0001");
        assert_eq!(v["runs"][0]["results"][0]["level"], "error");
    }
}
