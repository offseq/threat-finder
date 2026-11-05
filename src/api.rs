use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const BASE_URL: &str = "https://radar.offseq.com/api/v1";
/// Public site root, i.e. `BASE_URL` with the `/api/v1` API path trimmed off.
/// Used to build per-finding Radar detail URLs (`{SITE_URL}/threat/<slug>`).
/// A unit test pins this to the value actually derived from `BASE_URL`, so the
/// two can't silently drift if `BASE_URL` ever changes.
const SITE_URL: &str = "https://radar.offseq.com";

const MAX_RETRIES: u32 = 4;
const BASE_BACKOFF_MS: u64 = 300;
/// Clamp for the *computed* fallback backoff when no `Retry-After` header is sent.
const MAX_RETRY_AFTER_SECS: u64 = 30;
/// Ceiling for an *explicit* server `Retry-After`; a longer cool-down is honored
/// up to this, beyond which we surface `RateLimitExceeded` rather than sleep.
const MAX_EXPLICIT_RETRY_AFTER_SECS: u64 = 300;
/// `?search=` fallback results are unconfirmed triage; a few pages is plenty and
/// keeps the quota cost per uncoordinated asset bounded.
const MAX_PAGES: u32 = 3;
const USER_AGENT: &str = concat!("threat-finder/", env!("CARGO_PKG_VERSION"));

const FREE_REQUESTS_PER_HOUR: u64 = 20;

/// Plan label from the hourly quota, which is unique per plan (utils/planLimits.js).
fn plan_name(limit_hourly: u64) -> String {
    match limit_hourly {
        FREE_REQUESTS_PER_HOUR => "Free".to_string(),
        25   => "Individual".to_string(),
        45   => "Lifetime".to_string(),
        75   => "Base".to_string(),
        375  => "Pro".to_string(),
        1500 => "Enterprise".to_string(),
        n    => format!("Custom ({n}/hr)"),
    }
}

#[derive(Debug, Clone, Default)]
pub struct RateLimitInfo {
    pub limit_hourly:      u64,
    pub remaining_hourly:  u64,
    pub limit_daily:       u64,
    pub remaining_daily:   u64,
    pub limit_monthly:     u64,
    pub remaining_monthly: u64,
}

fn parse_header(headers: &reqwest::header::HeaderMap, name: &str) -> Option<u64> {
    headers.get(name)?.to_str().ok()?.parse().ok()
}

impl RateLimitInfo {
    /// Free accounts can register hosts, but Radar never alerts them.
    pub fn is_free_plan(&self) -> bool {
        self.limit_hourly == FREE_REQUESTS_PER_HOUR
    }

    /// Merge whatever rate-limit headers are present; each is parsed on its own.
    /// Requests are sequential, so the latest response is authoritative.
    fn merge_from_headers(&mut self, headers: &reqwest::header::HeaderMap) {
        for (name, slot) in [
            ("X-RateLimit-Limit-Hourly", &mut self.limit_hourly),
            ("X-RateLimit-Remaining-Hourly", &mut self.remaining_hourly),
            ("X-RateLimit-Limit-Daily", &mut self.limit_daily),
            ("X-RateLimit-Remaining-Daily", &mut self.remaining_daily),
            ("X-RateLimit-Limit-Monthly", &mut self.limit_monthly),
            ("X-RateLimit-Remaining-Monthly", &mut self.remaining_monthly),
        ] {
            if let Some(v) = parse_header(headers, name) {
                *slot = v;
            }
        }
    }
}

/// Plan and remaining quota, once a response has carried the rate-limit headers.
pub fn plan_info(info: &RateLimitInfo) -> Option<String> {
    if info.limit_hourly == 0 {
        return None;
    }
    let row = |label: &str, left: u64, limit: u64| {
        format!("{label:<9} {:>6} / {:>6} remaining\n", format_num(left), format_num(limit))
    };
    let mut out = format!("Plan:     {}\n", plan_name(info.limit_hourly));
    out += &row("Hourly:", info.remaining_hourly, info.limit_hourly);
    if info.limit_daily > 0 {
        out += &row("Daily:", info.remaining_daily, info.limit_daily);
    }
    out += &row("Monthly:", info.remaining_monthly, info.limit_monthly);
    Some(out)
}

fn format_num(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}

#[derive(Debug)]
pub enum ThreatError {
    RateLimitExceeded(String),
    /// HTTP 413 Payload Too Large: the batch exceeded the tier cap. Carries the
    /// server-advertised `data.maxBatch`, when present, so the caller can resize
    /// and retry instead of aborting.
    BatchTooLarge(Option<usize>),
    /// HTTP 403 where the body indicates the account lacks API access (no active
    /// subscription / Pro Console). Distinct from a generic 403 so the caller can
    /// surface upgrade guidance and a quota exit code instead of a network-style
    /// failure. Carries the server's explanatory message.
    AccessDenied(String),
    Http(reqwest::Error),
    Other(String),
}

impl std::fmt::Display for ThreatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatError::RateLimitExceeded(msg) => write!(f, "Rate limit exceeded: {msg}"),
            ThreatError::BatchTooLarge(Some(n)) => write!(f, "Batch too large (max {n})"),
            ThreatError::BatchTooLarge(None)    => write!(f, "Batch too large"),
            ThreatError::AccessDenied(msg)      => write!(f, "{msg}"),
            ThreatError::Http(e)                => write!(f, "HTTP error: {e}"),
            ThreatError::Other(msg)             => write!(f, "{msg}"),
        }
    }
}

impl From<reqwest::Error> for ThreatError {
    fn from(e: reqwest::Error) -> Self {
        ThreatError::Http(e)
    }
}

impl std::error::Error for ThreatError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ThreatError::Http(e) => Some(e),
            _ => None,
        }
    }
}

/// Canonical severity ordering used across ranking, gating, and display.
pub fn severity_rank(sev: Option<&str>) -> u8 {
    match sev.map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("critical") => 4,
        Some("high")     => 3,
        Some("medium")   => 2,
        Some("low")      => 1,
        _                => 0,
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreatEntry {
    /// Radar threat id — stable even when `cveId` is null.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id:                    Option<String>,
    #[serde(rename = "cveId")]
    pub cve_id:                Option<String>,
    pub title:                 Option<String>,
    pub severity:              Option<String>,
    #[serde(rename = "cvssScore")]
    pub cvss_score:            Option<Value>,
    #[serde(rename = "cvssVector", skip_serializing_if = "Option::is_none")]
    pub cvss_vector:           Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss:                  Option<f64>,
    /// Listed in CISA KEV.
    pub kev:                   bool,
    #[serde(rename = "kevDueDate", default, skip_serializing_if = "Option::is_none")]
    pub kev_due_date:          Option<String>,
    /// Past the KEV remediation due date.
    #[serde(rename = "kevOverdue", default, skip_serializing_if = "std::ops::Not::not")]
    pub kev_overdue:           bool,
    /// KEV records known ransomware campaign use.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ransomware:            bool,
    /// Any in-the-wild evidence: KEV, the threat's own flag, ENISA EUVD or OffSeq Mirage.
    #[serde(default)]
    pub exploited:             bool,
    /// Exploited per EUVD or Mirage (scored separately from KEV, as on the server).
    #[serde(rename = "exploitedOutsideKev", default, skip_serializing_if = "std::ops::Not::not")]
    pub exploited_outside_kev: bool,
    /// Public exploit maturity: WEAPONIZED | PUBLIC_EXPLOIT_REMOTE | PUBLIC_EXPLOIT | POC_HIGH | POC_LOW.
    #[serde(rename = "exploitMaturity", default, skip_serializing_if = "Option::is_none")]
    pub exploit_maturity:      Option<String>,
    #[serde(rename = "publishedDate")]
    pub published_date:        Option<String>,
    #[serde(rename = "affectedVersions")]
    pub affected_versions:     Option<Value>,
    #[serde(rename = "patchAvailable")]
    pub patch_available:       Option<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references:            Vec<String>,
    /// URLs leading to the fix (vendor patch or distro security notice).
    #[serde(rename = "patchLinks", default, skip_serializing_if = "Vec::is_empty")]
    pub patch_links:           Vec<String>,
    /// Whether the target version is inside an affected range (report) vs a
    /// coordinate match whose version is unconfirmed (triage).
    #[serde(default)]
    pub confirmed:             bool,
    #[serde(rename = "matchedRange", skip_serializing_if = "Option::is_none")]
    pub matched_range:         Option<String>,
    /// How the API matched: coordinate | cpe | coordinate-unconfirmed | search-fallback.
    #[serde(rename = "matchBasis")]
    pub match_basis:           String,
    /// Link to the finding's Radar page (`{SITE_URL}/threat/<slug>`), when a slug
    /// is known. Turns each finding into something an operator can open and read.
    #[serde(rename = "radarUrl", skip_serializing_if = "Option::is_none")]
    pub radar_url:             Option<String>,
    /// Concrete fixed version(s) — turns "vulnerable" into "upgrade to X".
    #[serde(rename = "fixedVersions", default, skip_serializing_if = "Vec::is_empty")]
    pub fixed_versions:        Vec<String>,
    /// Human-readable remediation guidance, when the server provides it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation:           Option<String>,
    /// Associated CWE identifiers (e.g. `CWE-77`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwes:                  Vec<String>,
    /// Exposure-aware risk score (0..=100), computed locally from this finding +
    /// the owning asset's exposure, mirroring the server formula so the two agree.
    /// `None` until [`ThreatEntry::apply_risk`] is called.
    #[serde(rename = "riskScore", default, skip_serializing_if = "Option::is_none")]
    pub risk_score:            Option<u32>,
    /// SSVC-style remediation band (`act-now` | `soon` | `schedule` | `track`),
    /// derived from `risk_score`, KEV, EPSS and exposure. `None` until scored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision:              Option<String>,
    /// The Radar decision ledger's entry for this finding (`--respect-decisions`).
    #[serde(rename = "recordedDecision", default, skip_serializing_if = "Option::is_none")]
    pub recorded_decision:     Option<RecordedDecision>,
}

/// Numeric rank for a decision band (higher = more urgent) — used to sort
/// findings by decision then score deterministically.
pub fn decision_rank(decision: Option<&str>) -> u8 {
    match decision {
        Some("act-now")  => 3,
        Some("soon")     => 2,
        Some("schedule") => 1,
        _                => 0, // "track" / unscored
    }
}

/// Points for `exploit.maturity`, as `EXPLOIT_POINTS` in server/utils/riskScore.js.
fn exploit_points(maturity: Option<&str>) -> i64 {
    match maturity {
        Some("WEAPONIZED") => 10,
        Some("PUBLIC_EXPLOIT_REMOTE" | "PUBLIC_EXPLOIT") => 7,
        Some("POC_HIGH" | "POC_LOW") => 3,
        _ => 0,
    }
}

/// Highest score reachable without KEV is 77, so act-now stays reachable without it.
const ACT_NOW_SCORE: u32 = 74;

/// Exposure-aware risk score (0..=100) and SSVC decision for a finding on an
/// asset with this `exposure` (`public`|`private`|`loopback`|`none`). Mirrors
/// `computeRiskScore` in server/utils/riskScore.js term for term.
pub fn compute_risk(t: &ThreatEntry, exposure: &str) -> (u32, String) {
    let cvss = t.cvss_num();
    let sev = match severity_rank(t.severity.as_deref()) {
        4 => 40,
        3 => 30,
        2 => 18,
        1 => 8,
        _ if cvss >= 9.0 => 40,
        _ if cvss >= 7.0 => 30,
        _ if cvss >= 4.0 => 18,
        _ => 8,
    };
    let epss = t.epss.unwrap_or(0.0).clamp(0.0, 1.0);
    let epss_pts = (epss * 25.0).round() as i64;
    let kev_pts = if t.kev { 20 } else { 0 };
    let overdue_pts = if t.kev && t.kev_overdue { 5 } else { 0 };
    let exploited_pts = if !t.kev && t.exploited_outside_kev { 15 } else { 0 };
    let exposure = exposure.trim().to_ascii_lowercase();
    let exp_pts = match exposure.as_str() {
        "public" => 12,
        "private" => 7,
        _ => 0,
    };
    let confirm_mul = if t.confirmed { 1.0 } else { 0.6 };
    let raw = (sev + epss_pts + kev_pts + overdue_pts + exploit_points(t.exploit_maturity.as_deref())
        + exploited_pts + exp_pts) as f64 * confirm_mul;
    let score = raw.round().clamp(0.0, 100.0) as u32;

    let exposed = exposure == "public" || exposure == "private";
    let decision = if (t.kev && exposed && t.confirmed) || score >= ACT_NOW_SCORE {
        "act-now"
    } else if score >= 58 || (t.kev && t.confirmed) || (epss >= 0.5 && exposed) {
        "soon"
    } else if score >= 32 {
        "schedule"
    } else {
        "track"
    };
    (score, decision.to_string())
}

impl ThreatEntry {
    fn severity_rank(&self) -> u8 {
        severity_rank(self.severity.as_deref())
    }

    fn cvss_num(&self) -> f64 {
        self.cvss_score.as_ref().and_then(|v| v.as_f64()).unwrap_or(0.0)
    }

    /// Compute and store the exposure-aware `risk_score`/`decision` for this
    /// finding given the owning asset's `exposure` (reachability string). Idempotent.
    pub fn apply_risk(&mut self, exposure: &str) {
        let (score, decision) = compute_risk(self, exposure);
        self.risk_score = Some(score);
        self.decision = Some(decision);
    }

    /// A recorded decision silences this finding.
    pub fn suppressed(&self) -> bool {
        self.recorded_decision.as_ref().is_some_and(|d| d.suppressing)
    }

    /// Highest-risk first. Once scored, decision band then risk score dominate
    /// (so the exposure-aware ordering wins); the legacy signals remain as a
    /// deterministic tie-break (and the sole ordering before `apply_risk`).
    pub(crate) fn risk_key(&self) -> (u8, u32, bool, bool, u8, i64, i64, String) {
        (
            decision_rank(self.decision.as_deref()),
            self.risk_score.unwrap_or(0),
            self.kev,
            self.exploited,
            self.severity_rank(),
            (self.epss.unwrap_or(0.0) * 1000.0) as i64,
            (self.cvss_num() * 100.0) as i64,
            self.cve_id.clone().unwrap_or_default(),
        )
    }
}

/// Per-service asset metadata: where the version came from, and — uniquely — the
/// network exposure of the running process (which listeners it holds and whether
/// any is reachable off-host). This is what turns a flat CVE list into a
/// prioritized attack-surface report.
#[derive(Debug, Serialize)]
pub struct AssetInfo {
    pub exe: String,
    pub version: String,
    #[serde(rename = "versionSource")]
    pub version_source: String,
    pub exposed: bool,
    /// loopback | private | public | none
    pub reachability: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub listeners: Vec<String>,
    /// Smallest version Radar knows fixes every match on this asset.
    #[serde(rename = "upgradeTo", skip_serializing_if = "Option::is_none")]
    pub upgrade_to: Option<String>,
}

/// Report envelope metadata (stable across runs — no timestamp, so reports diff).
#[derive(Debug, Serialize)]
pub struct Meta {
    pub tool: &'static str,
    pub version: &'static str,
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
}

impl Default for Meta {
    fn default() -> Self {
        // 3: `kev` means KEV-listed only (in-the-wild moved to `exploited`), plus
        // exploitation/patch fields, `assets.*.upgradeTo` and `truncated`.
        Meta { tool: "threat-finder", version: env!("CARGO_PKG_VERSION"), schema_version: 3 }
    }
}

/// One CVE rolled up across every service it affects — the remediation view
/// ("patch openssl → closes CVE-X across 6 services").
#[derive(Debug, Serialize)]
pub struct CveGroup {
    pub severity: Option<String>,
    pub kev: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss: Option<f64>,
    pub title: Option<String>,
    pub assets: Vec<String>,
}

/// Slim, JSON-facing capture of the inventory server's registration response —
/// the drift + summary surfaced in the `registration` field of the report.
#[derive(Debug, Clone, Serialize)]
pub struct RegistrationReport {
    // camelCase to match the sibling fields (assetCount/newSinceLastCount) and
    // the Radar contract — the rest of the JSON report is camelCase.
    #[serde(rename = "hostId")]
    pub host_id: String,
    pub monitoring: bool,
    #[serde(rename = "assetCount")]
    pub asset_count: u64,
    pub drift: RegisterDrift,
    pub summary: RegisterSummary,
    #[serde(rename = "newSinceLastCount")]
    pub new_since_last_count: u64,
    #[serde(rename = "resolvedCount")]
    pub resolved_count: u64,
}

impl From<&RegisterResponse> for RegistrationReport {
    fn from(r: &RegisterResponse) -> Self {
        RegistrationReport {
            host_id: r.host_id.clone(),
            monitoring: r.monitoring,
            asset_count: r.asset_count,
            drift: r.drift.clone(),
            summary: r.summary.clone(),
            new_since_last_count: r.new_since_last_count,
            resolved_count: r.resolved_count,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BatchResults {
    pub meta: Meta,
    pub services: BTreeMap<String, Vec<ThreatEntry>>,
    #[serde(rename = "byCve", skip_serializing_if = "BTreeMap::is_empty")]
    pub by_cve:   BTreeMap<String, CveGroup>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub assets:   BTreeMap<String, AssetInfo>,
    /// Coordinate matched but the version is unconfirmed (triage). Kept out of
    /// the primary count, by_cve, and --fail-on.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub unconfirmed: BTreeMap<String, Vec<ThreatEntry>>,
    /// Per-service lookup failures (name -> error). Distinguishes "lookup failed"
    /// from "no CVEs found".
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub errors:   BTreeMap<String, String>,
    /// Packages Radar could not evaluate (bad coordinate, unsupported ecosystem, no
    /// version), name -> reason. Unlike `errors`, these never fail --fail-on.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub rejected: BTreeMap<String, String>,
    /// Assets whose matches the server capped; more findings exist than reported.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub truncated: Vec<String>,
    /// Inventory-server registration outcome, present only when this run
    /// registered the host for monitoring (drift + new-since-last summary).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration: Option<RegistrationReport>,
}

impl BatchResults {
    pub fn total_vulns(&self) -> usize {
        self.services.values().map(|v| v.len()).sum()
    }

    /// Re-sort every finding bucket (confirmed + unconfirmed) highest-risk first.
    /// Call after [`ThreatEntry::apply_risk`] so the exposure-aware decision/score
    /// drive the order (with the legacy KEV/severity/EPSS/CVSS tie-break).
    pub fn sort_findings(&mut self) {
        for v in self.services.values_mut().chain(self.unconfirmed.values_mut()) {
            v.sort_by_key(|e| std::cmp::Reverse(e.risk_key()));
        }
    }

    /// Roll findings up by CVE id across all (confirmed) service entries.
    pub fn compute_cve_groups(&mut self) {
        let mut groups: BTreeMap<String, CveGroup> = BTreeMap::new();
        for (key, entries) in &self.services {
            for t in entries {
                let Some(cve) = t.cve_id.clone() else { continue };
                let g = groups.entry(cve).or_insert_with(|| CveGroup {
                    severity: t.severity.clone(),
                    kev: t.kev,
                    epss: t.epss,
                    title: t.title.clone(),
                    assets: Vec::new(),
                });
                g.kev |= t.kev;
                if severity_rank(t.severity.as_deref()) > severity_rank(g.severity.as_deref()) {
                    g.severity = t.severity.clone();
                }
                if !g.assets.iter().any(|a| a == key) {
                    g.assets.push(key.clone());
                }
            }
        }
        for g in groups.values_mut() {
            g.assets.sort();
            g.assets.dedup();
        }
        self.by_cve = groups;
    }

    /// Attach the server's recorded decisions by CVE + asset (`coordinates`: report
    /// key -> registered coordinate). Returns how many findings got one.
    pub fn apply_decisions(&mut self, coordinates: &BTreeMap<String, String>, findings: Vec<HostFinding>) -> usize {
        self.apply_decisions_at(coordinates, findings, now_secs())
    }

    fn apply_decisions_at(&mut self, coordinates: &BTreeMap<String, String>, findings: Vec<HostFinding>, now: i64) -> usize {
        let ledger: std::collections::HashMap<(String, String), RecordedDecision> = findings.into_iter()
            .filter_map(|f| {
                let mut d = f.recorded_decision?;
                d.suppressing = d.suppresses(now);
                Some(((f.cve_id?.to_ascii_uppercase(), f.coordinate?), d))
            })
            .collect();
        let mut marked = 0;
        for (key, entries) in self.services.iter_mut().chain(self.unconfirmed.iter_mut()) {
            let Some(coord) = coordinates.get(key) else { continue };
            for e in entries {
                let Some(cve) = &e.cve_id else { continue };
                if let Some(d) = ledger.get(&(cve.to_ascii_uppercase(), coord.clone())) {
                    e.recorded_decision = Some(d.clone());
                    marked += 1;
                }
            }
        }
        marked
    }
}

pub struct BatchOutcome {
    pub results: BTreeMap<String, Vec<ThreatEntry>>,
    pub unconfirmed: BTreeMap<String, Vec<ThreatEntry>>,
    pub errors:  BTreeMap<String, String>,
    /// Asset key -> why Radar rejected its query.
    pub rejected: BTreeMap<String, String>,
    /// Asset key -> Radar's `upgradeTo`.
    pub upgrades: BTreeMap<String, String>,
    /// Asset keys whose matches the server capped (plan result cap or candidate cap).
    pub truncated: Vec<String>,
}

pub struct ThreatClient {
    client:         Client,
    base:           String,
    api_key:        String,
    rate_limit:     Arc<Mutex<RateLimitInfo>>,
}

impl ThreatClient {
    pub fn new(api_key: &str) -> Self {
        Self::with_base(api_key, BASE_URL)
    }

    fn with_base(api_key: &str, base: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(90))
            .connect_timeout(Duration::from_secs(8))
            .user_agent(USER_AGENT)
            .build()
            .expect("Failed to build HTTP client");

        ThreatClient {
            client,
            base: base.to_string(),
            api_key: api_key.to_string(),
            rate_limit: Arc::new(Mutex::new(RateLimitInfo::default())),
        }
    }

    pub fn last_rate_limit(&self) -> RateLimitInfo {
        self.rate_limit.lock().unwrap().clone()
    }

    fn backoff_sleep(&self, attempt: u32) {
        let base = BASE_BACKOFF_MS.saturating_mul(1u64 << attempt.min(10));
        // Cheap decorrelated jitter from the wall clock — no rand dependency.
        let jitter = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| (d.subsec_nanos() as u64) % base.max(1))
            .unwrap_or(0);
        std::thread::sleep(Duration::from_millis(base + jitter));
    }

    /// Send a request (built fresh each attempt) with retry/backoff, lenient
    /// rate-limit header capture, Retry-After handling, and descriptive errors.
    /// Returns the 2xx response with its body unread.
    fn send(
        &self,
        accept: &str,
        build: impl Fn() -> reqwest::blocking::RequestBuilder,
    ) -> Result<reqwest::blocking::Response, ThreatError> {
        let mut attempt = 0u32;
        loop {
            let send_result = build()
                .header("X-API-Key", &self.api_key)
                .header("Accept", accept)
                .send();

            let response = match send_result {
                Ok(r) => r,
                Err(e) => {
                    if attempt < MAX_RETRIES && (e.is_timeout() || e.is_connect() || e.is_request()) {
                        self.backoff_sleep(attempt);
                        attempt += 1;
                        continue;
                    }
                    return Err(ThreatError::Http(e));
                }
            };

            let status = response.status();
            if let Ok(mut info) = self.rate_limit.lock() {
                info.merge_from_headers(response.headers());
            }

            if status.as_u16() == 429 {
                let retry_after = parse_header(response.headers(), "Retry-After");
                let body = response.json::<Value>().unwrap_or(Value::Null);
                let message = error_message(&body).unwrap_or_else(|| "Rate limit exceeded.".to_string());
                // Only the hourly window can reopen within a run; the 30s clamp is
                // for the computed fallback, an explicit Retry-After gets a higher ceiling.
                let hourly = body.pointer("/upgrade/reason").and_then(Value::as_str).is_none_or(|r| r == "api-hour");
                let wait = match retry_after {
                    Some(secs) if secs > MAX_EXPLICIT_RETRY_AFTER_SECS => None,
                    Some(secs) => Some(secs.max(1)),
                    None => Some((1u64 << attempt.min(10)).clamp(1, MAX_RETRY_AFTER_SECS)),
                };
                match wait {
                    Some(secs) if hourly && attempt < MAX_RETRIES => {
                        std::thread::sleep(Duration::from_secs(secs));
                        attempt += 1;
                        continue;
                    }
                    _ => return Err(ThreatError::RateLimitExceeded(message)),
                }
            }

            if status.as_u16() == 413 {
                // Not retried: the caller resizes (match/batch) or reports the cap.
                let cap = response.json::<Value>().ok().and_then(|b| advertised_cap(&b));
                return Err(ThreatError::BatchTooLarge(cap));
            }

            // A handler 500 has already been counted against the quota; only
            // gateway/availability errors are worth retrying.
            if matches!(status.as_u16(), 502..=504) && attempt < MAX_RETRIES {
                // 503 carries Retry-After while Radar is briefly unavailable.
                match parse_header(response.headers(), "Retry-After") {
                    Some(secs) => std::thread::sleep(Duration::from_secs(secs.clamp(1, MAX_RETRY_AFTER_SECS))),
                    None => self.backoff_sleep(attempt),
                }
                attempt += 1;
                continue;
            }

            if !status.is_success() {
                let code = status.as_u16();
                let text = response.text().unwrap_or_default();
                let body = serde_json::from_str::<Value>(&text).unwrap_or(Value::Null);
                let mut msg = error_message(&body).unwrap_or_else(|| {
                    if text.is_empty() {
                        format!("HTTP {code}")
                    } else {
                        format!("HTTP {code}: {}", text.chars().take(200).collect::<String>())
                    }
                });
                if code == 401 {
                    msg = format!("{msg} (check your API key — re-run with --reset to re-enter it)");
                }
                if code == 403 {
                    if let Some(denied) = access_denied(&body, &msg) {
                        return Err(ThreatError::AccessDenied(denied));
                    }
                }
                return Err(ThreatError::Other(msg));
            }

            return Ok(response);
        }
    }

    fn execute(&self, build: impl Fn() -> reqwest::blocking::RequestBuilder) -> Result<Value, ThreatError> {
        self.send("application/json", build)?.json().map_err(ThreatError::Http)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn get_json(&self, path: &str, params: &[(&str, String)]) -> Result<Value, ThreatError> {
        self.execute(|| self.client.get(self.url(path)).query(params))
    }

    fn post_json<T: Serialize>(&self, path: &str, body: &T) -> Result<Value, ThreatError> {
        self.execute(|| self.client.post(self.url(path)).json(body))
    }

    /// The raw body of a GET whose 2xx response is a document, not the JSON envelope.
    fn get_raw(&self, path: &str, params: &[(&str, &str)]) -> Result<Vec<u8>, ThreatError> {
        let resp = self.send("*/*", || self.client.get(self.url(path)).query(params))?;
        Ok(resp.bytes()?.to_vec())
    }

    /// Match a whole inventory by exact coordinate in one POST per tier-sized
    /// chunk. Results are positionally aligned to `queries` (guarded per chunk).
    pub fn match_batch(
        &self,
        queries: &[MatchQuery],
        strict: bool,
    ) -> Result<Vec<MatchResult>, ThreatError> {
        let mut out: Vec<MatchResult> = Vec::with_capacity(queries.len());
        let mut cursor = 0usize;
        // The working cap can only shrink within a run (a 413 tells us the real
        // server limit); we never grow it back past what the server accepted.
        let mut cap_ceiling = usize::MAX;
        while cursor < queries.len() {
            // Recompute every iteration: the first chunk uses the smallest plan cap
            // until a response's rate-limit headers reveal the real tier.
            let cap = tier_batch_cap(self.last_rate_limit().limit_hourly).min(cap_ceiling);
            let end = (cursor + cap).min(queries.len());
            let chunk = &queries[cursor..end];

            let body = MatchBatchRequest { queries: chunk, strict };
            match self.post_json("/match/batch", &body) {
                Ok(json) => {
                    let parsed: MatchBatchResponse = serde_json::from_value(json)
                        .map_err(|e| ThreatError::Other(format!("match/batch decode error: {e}")))?;
                    if parsed.data.results.len() != chunk.len() {
                        return Err(ThreatError::Other(format!(
                            "match/batch alignment error: sent {} queries, got {} results",
                            chunk.len(), parsed.data.results.len()
                        )));
                    }
                    out.extend(parsed.data.results);
                    cursor = end;
                }
                Err(ThreatError::BatchTooLarge(max_batch)) => {
                    // A single item can't be split further; a 413 on it is a hard
                    // error rather than something we can retry-shrink out of.
                    if chunk.len() <= 1 {
                        return Err(ThreatError::BatchTooLarge(max_batch));
                    }
                    // Server rejected this chunk as too large. Shrink the working
                    // cap to the advertised max (or halve it) and retry the SAME
                    // slice — do not advance the cursor or abort the run. Always
                    // make strict progress (< chunk.len()) to avoid an infinite loop.
                    let new_cap = match max_batch {
                        Some(n) if n >= 1 && n < chunk.len() => n,
                        _ => chunk.len() / 2,
                    };
                    cap_ceiling = new_cap.max(1);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Register (or refresh) this host's asset inventory for continuous
    /// monitoring. Hits `POST /inventory/register` over the same authenticated,
    /// retrying request path as `/match/batch`. A 403 (host-limit / no API
    /// access) or 413 (too many assets) surfaces the server `message`/`maxAssets`
    /// via [`ThreatError`]. The caller treats any error as non-fatal.
    #[allow(clippy::too_many_arguments)]
    pub fn register_inventory(
        &self,
        host_id: &str,
        hostname: Option<&str>,
        os: Option<InventoryOs>,
        agent_version: &str,
        monitor: bool,
        assets: &[InventoryAsset],
    ) -> Result<RegisterResponse, ThreatError> {
        let body = RegisterRequest {
            host_id,
            hostname,
            os,
            agent_version,
            monitor,
            assets,
        };
        // 413 here means "too many assets"; reuse BatchTooLarge to carry the
        // advertised cap (data.maxAssets) so the caller can report it.
        let json = self.post_json("/inventory/register", &body)?;
        let resp: RegisterResponse = json
            .get("data")
            .cloned()
            .map(serde_json::from_value)
            .unwrap_or_else(|| serde_json::from_value(json))
            .map_err(|e| ThreatError::Other(format!("inventory/register decode error: {e}")))?;
        Ok(resp)
    }

    /// Delete this host's inventory (`DELETE /inventory/{hostId}`). Used by
    /// `--unregister`. Returns Ok on any 2xx.
    pub fn unregister(&self, host_id: &str) -> Result<(), ThreatError> {
        let path = self.url(&format!("/inventory/{host_id}"));
        self.execute(|| self.client.delete(&path))?;
        Ok(())
    }

    /// The host's current findings with their `recordedDecision` (`GET /inventory/{hostId}`).
    pub fn host_findings(&self, host_id: &str) -> Result<Vec<HostFinding>, ThreatError> {
        let json = self.get_json(&format!("/inventory/{host_id}"), &[])?;
        serde_json::from_value(json.pointer("/data/findings").cloned().unwrap_or(Value::Null))
            .map_err(|e| ThreatError::Other(format!("inventory detail decode error: {e}")))
    }

    /// The host's decisions as a VEX document (`openvex` | `cyclonedx`), verbatim.
    pub fn host_vex(&self, host_id: &str, format: &str) -> Result<Vec<u8>, ThreatError> {
        self.get_raw(&format!("/inventory/{host_id}/vex"), &[("format", format)])
    }

    /// Scan an SBOM or lockfile in one request; `body` comes from [`scan_body`].
    pub fn scan(&self, body: Vec<u8>) -> Result<ScanReport, ThreatError> {
        let json = self.execute(|| {
            self.client.post(self.url("/scan"))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.clone())
        })?;
        serde_json::from_value(json.get("data").cloned().unwrap_or(Value::Null))
            .map_err(|e| ThreatError::Other(format!("scan decode error: {e}")))
    }

    /// GET ?search= fallback for assets with no buildable coordinate. Returns
    /// raw threat objects (no client-side version comparison — they are surfaced
    /// as unconfirmed/triage).
    pub fn search_threats(&self, service: &str) -> Result<Vec<Value>, ThreatError> {
        let mut all_threats: Vec<Value> = Vec::new();
        let mut seen_ids: HashSet<String> = HashSet::new();
        let mut page = 1u32;
        loop {
            let params = vec![
                ("search", service.to_string()),
                // Clamped server-side to the plan's maxResultsPerRequest.
                ("limit", "100".to_string()),
                ("page", page.to_string()),
            ];
            let data = self.get_json("/threats", &params)?;
            let Some(threats) = data.pointer("/data/threats").and_then(Value::as_array) else { break };
            let mut added = 0usize;
            for threat in threats {
                if seen_ids.insert(threat_id(threat)) {
                    all_threats.push(threat.clone());
                    added += 1;
                }
            }
            // The server clamps `limit` to the plan's page size, so only `hasNext` is reliable.
            let has_next = data.pointer("/data/pagination/hasNext").and_then(Value::as_bool).unwrap_or(false);
            if !has_next || added == 0 || page >= MAX_PAGES {
                break;
            }
            page += 1;
        }
        Ok(all_threats)
    }
}

/// The cap a 413 advertises: `maxBatch` (match/batch), `maxAssets` (register), `maxPackages` (scan).
fn advertised_cap(body: &Value) -> Option<usize> {
    let d = body.get("data")?;
    ["maxBatch", "maxAssets", "maxPackages"].iter()
        .find_map(|k| d.get(*k).and_then(Value::as_u64))
        .map(|n| n as usize)
}

fn error_message(body: &Value) -> Option<String> {
    body.get("message")
        .or_else(|| body.get("error"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// The user-facing message for a 403 the account can fix (plan gate or an
/// incomplete profile), or `None` for a generic forbidden-resource 403.
fn access_denied(body: &Value, msg: &str) -> Option<String> {
    match body.get("error").and_then(Value::as_str) {
        Some("Profile incomplete") => Some(format!("{msg} ({SITE_URL}/console)")),
        Some("API access required" | "pro_access_required") => Some(msg.to_string()),
        _ => {
            let m = msg.to_ascii_lowercase();
            (m.contains("api access") || m.contains("subscription")).then(|| msg.to_string())
        }
    }
}

// ── Inventory / monitoring API ───────────────────────────────────────────────

/// Optional OS descriptor sent with a registration; every field is optional and
/// omitted from the wire when absent.
#[derive(Debug, Clone, Default, Serialize)]
pub struct InventoryOs {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub os_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distro: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// One asset in a registration payload. Built only from assets with a real purl,
/// so no malformed coordinate is ever sent.
#[derive(Debug, Clone, Serialize)]
pub struct InventoryAsset {
    /// purl coordinate, when the asset has one (Linux/macOS/BSD pkgs, npm/pip/…).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub purl: String,
    /// CPE coordinate, for Windows apps / the OS that have no canonical purl.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpe: Option<String>,
    pub version: String,
    pub ecosystem: String,
    pub name: String,
    /// Reachability: `public` | `private` | `loopback` | `none`.
    pub exposure: String,
    pub exposed: bool,
    pub runtime: bool,
}

impl InventoryAsset {
    /// The `coordinate` the server reports on this asset's findings.
    pub fn coordinate(&self) -> String {
        if self.purl.is_empty() { format!("{}/{}", self.ecosystem, self.name) } else { self.purl.clone() }
    }
}

#[derive(Serialize)]
struct RegisterRequest<'a> {
    #[serde(rename = "hostId")]
    host_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os: Option<InventoryOs>,
    #[serde(rename = "agentVersion")]
    agent_version: &'a str,
    monitor: bool,
    assets: &'a [InventoryAsset],
}

/// Drift since the host's previous scan.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RegisterDrift {
    #[serde(default)]
    pub added: u64,
    #[serde(default)]
    pub removed: u64,
    #[serde(default)]
    pub changed: u64,
}

/// Server-side severity breakdown.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RegisterSummary {
    #[serde(default)]
    pub total: u64,
    #[serde(default)]
    pub confirmed: u64,
    #[serde(default)]
    pub kev: u64,
    #[serde(default)]
    pub exposed: u64,
    #[serde(rename = "actNow", default)]
    pub act_now: u64,
    #[serde(rename = "bySeverity", default, skip_serializing_if = "BTreeMap::is_empty")]
    pub by_severity: BTreeMap<String, u64>,
    #[serde(rename = "byDecision", default, skip_serializing_if = "BTreeMap::is_empty")]
    pub by_decision: BTreeMap<String, u64>,
}

/// A finding in the registration's `newSinceLast`, as far as the CLI prints it.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RegisterFinding {
    #[serde(rename = "cveId", default)]
    pub cve_id: Option<String>,
    #[serde(default)]
    pub coordinate: Option<String>,
    #[serde(rename = "radarUrl", default)]
    pub radar_url: Option<String>,
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub kev: bool,
    #[serde(rename = "kevOverdue", default)]
    pub kev_overdue: bool,
    #[serde(rename = "fixedVersions", default)]
    pub fixed_versions: Vec<String>,
}

/// One finding of `GET /inventory/{hostId}`, as far as decision matching needs it.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HostFinding {
    #[serde(rename = "cveId", default)]
    pub cve_id: Option<String>,
    /// The registered purl, or `ecosystem/name` for a CPE-only asset.
    #[serde(default)]
    pub coordinate: Option<String>,
    #[serde(rename = "recordedDecision", default)]
    pub recorded_decision: Option<RecordedDecision>,
}

/// The decision-ledger entry covering a finding (most specific: asset, host, then account).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RecordedDecision {
    #[serde(default)]
    pub verdict: String,
    #[serde(default)]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
    #[serde(rename = "staleReasons", default, skip_serializing_if = "Vec::is_empty")]
    pub stale_reasons: Vec<String>,
    /// Whether it silences this finding, and so keeps it out of --fail-on.
    #[serde(default)]
    pub suppressing: bool,
}

impl RecordedDecision {
    /// `suppresses` in server/utils/alertDecision.js; the server already matched the subject.
    fn suppresses(&self, now: i64) -> bool {
        matches!(self.verdict.as_str(), "accept" | "not_affected" | "mitigated" | "defer")
            && matches!(self.status.as_str(), "active" | "review_due")
            && self.until.as_deref().and_then(iso_secs).is_none_or(|until| until > now)
    }
}

/// Decoded `data` from `POST /inventory/register`. All fields `#[serde(default)]`
/// so a partial / evolving server response never fails the decode.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RegisterResponse {
    #[serde(rename = "hostId", default)]
    pub host_id: String,
    #[serde(default)]
    pub monitoring: bool,
    #[serde(default)]
    pub new: bool,
    #[serde(rename = "assetCount", default)]
    pub asset_count: u64,
    #[serde(default)]
    pub drift: RegisterDrift,
    #[serde(default)]
    pub summary: RegisterSummary,
    #[serde(rename = "newSinceLast", default)]
    pub new_since_last: Vec<RegisterFinding>,
    #[serde(rename = "newSinceLastCount", default)]
    pub new_since_last_count: u64,
    #[serde(rename = "resolvedCount", default)]
    pub resolved_count: u64,
}

// ── Match API (exact coordinate) ─────────────────────────────────────────────

/// Per-request `maxBatchQueries` by plan, keyed by its unique hourly quota
/// (utils/planLimits.js); the smallest cap until a header is seen. A 413 still
/// shrinks it to the server-advertised `maxBatch`.
fn tier_batch_cap(limit_hourly: u64) -> usize {
    match limit_hourly {
        1500 => 4000,          // enterprise
        375 => 1000,           // pro
        25 | 45 | 75 => 200,   // individual / lifetime / base
        _ => 50,               // free / unknown
    }
}

#[derive(Debug, Clone)]
enum MatchQueryKind {
    Purl(String),
    Package { name: String, ecosystem: String, version: String },
    Cpe(String),
}

/// A single coordinate query. Constructors guarantee exactly one of
/// purl / (package+version) / cpe is sent, so "version in two places" (a 400) is
/// structurally unrepresentable.
#[derive(Debug, Clone, Serialize)]
#[serde(into = "MatchQueryWire")]
pub struct MatchQuery(MatchQueryKind);

impl MatchQuery {
    pub fn purl(p: impl Into<String>) -> Self {
        MatchQuery(MatchQueryKind::Purl(p.into()))
    }
    pub fn package(name: impl Into<String>, ecosystem: impl Into<String>, version: impl Into<String>) -> Self {
        MatchQuery(MatchQueryKind::Package {
            name: name.into(),
            ecosystem: ecosystem.into(),
            version: version.into(),
        })
    }
    pub fn cpe(c: impl Into<String>) -> Self {
        MatchQuery(MatchQueryKind::Cpe(c.into()))
    }
}

#[derive(Serialize, Clone)]
struct PackageRef {
    name: String,
    ecosystem: String,
}

#[derive(Serialize)]
struct MatchQueryWire {
    #[serde(skip_serializing_if = "Option::is_none")] purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] package: Option<PackageRef>,
    #[serde(skip_serializing_if = "Option::is_none")] version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] cpe: Option<String>,
}

impl From<MatchQuery> for MatchQueryWire {
    fn from(q: MatchQuery) -> Self {
        let mut w = MatchQueryWire { purl: None, package: None, version: None, cpe: None };
        match q.0 {
            MatchQueryKind::Purl(p) => w.purl = Some(p),
            MatchQueryKind::Cpe(c) => w.cpe = Some(c),
            MatchQueryKind::Package { name, ecosystem, version } => {
                w.package = Some(PackageRef { name, ecosystem });
                w.version = Some(version);
            }
        }
        w
    }
}

#[derive(Serialize)]
struct MatchBatchRequest<'a> {
    queries: &'a [MatchQuery],
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    strict: bool,
}

#[derive(Debug, Deserialize)]
struct MatchBatchResponse {
    data: MatchData,
}
#[derive(Debug, Deserialize)]
struct MatchData {
    results: Vec<MatchResult>,
}

/// One result, positionally aligned to its submitted query.
#[derive(Debug, Default, Deserialize)]
pub struct MatchResult {
    #[serde(default)]
    pub matches: Vec<MatchHit>,
    /// Smallest known version that fixes every match on this package.
    #[serde(rename = "upgradeTo", default)]
    pub upgrade_to: Option<String>,
    /// The candidate or per-plan result cap cut `matches` short.
    #[serde(default)]
    pub truncated: bool,
    /// The query was rejected or could not be evaluated.
    #[serde(default)]
    pub error: Option<String>,
}

/// Tolerant EPSS model: the server sends `epss` as an object `{score, percentile}`
/// (the common case), but defensively we also accept a bare number or null/absent.
/// A wrong-typed *present* value here would otherwise fail the whole-chunk decode.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum EpssField {
    Object {
        #[serde(default)]
        score: Option<f64>,
        #[serde(default)]
        percentile: Option<f64>,
    },
    Score(f64),
    Null,
}

impl EpssField {
    fn score(&self) -> Option<f64> {
        match self {
            EpssField::Object { score, .. } => *score,
            EpssField::Score(s) => Some(*s),
            EpssField::Null => None,
        }
    }
    fn percentile(&self) -> Option<f64> {
        match self {
            EpssField::Object { percentile, .. } => *percentile,
            _ => None,
        }
    }
}

/// One CVE match, as `formatHit` in server/services/packageMatchService.js.
/// Nested signal objects stay raw `Value`s so an evolving shape never fails the
/// whole-chunk decode.
#[derive(Debug, Deserialize)]
pub struct MatchHit {
    #[serde(default)] id: Option<Value>,
    #[serde(rename = "cveId")] pub cve_id: Option<String>,
    pub title: Option<String>,
    pub severity: Option<String>,
    #[serde(rename = "cvssScore")] pub cvss_score: Option<Value>,
    #[serde(rename = "cvssVector", default)] pub cvss_vector: Option<String>,
    #[serde(default)] epss: Option<EpssField>,
    #[serde(default)] kev: Option<Value>,
    #[serde(default)] exploit: Option<Value>,
    /// `{euvd, mirage}`: exploitation reported outside CISA KEV.
    #[serde(default)] exploitation: Option<Value>,
    #[serde(rename = "knownExploitsInWild", default)] known_exploits_in_wild: Option<Value>,
    #[serde(rename = "matchBasis")] pub match_basis: Option<String>,
    #[serde(rename = "matchedRange")] pub matched_range: Option<String>,
    #[serde(rename = "publishedDate", default)] pub published_date: Option<String>,
    #[serde(rename = "patchAvailable", default)] pub patch_available: Option<Value>,
    #[serde(default)] pub confirmed: bool,
    #[serde(default)] pub references: Vec<Value>,
    /// Radar slug — drives the per-finding detail URL.
    #[serde(default)] pub slug: Option<String>,
    /// The advisory's canonical affected-range list.
    #[serde(rename = "affectedVersions", default)] pub affected_versions: Vec<String>,
    #[serde(rename = "fixedVersions", default)] pub fixed_versions: Vec<String>,
    #[serde(rename = "patchLinks", default)] pub patch_links: Vec<String>,
    #[serde(default)] pub remediation: Option<String>,
    #[serde(default)] pub cwes: Vec<String>,
}

impl MatchHit {
    /// Numeric EPSS score (`epss.score`), or `None` when null/absent.
    pub fn epss(&self) -> Option<f64> {
        self.epss.as_ref().and_then(EpssField::score)
    }
    /// EPSS percentile, present only in the object shape.
    pub fn epss_percentile(&self) -> Option<f64> {
        self.epss.as_ref().and_then(EpssField::percentile)
    }
}

// ── Scan API (SBOM / lockfile) ───────────────────────────────────────────────

/// The server's `express.json` body limit (10 MB).
pub const MAX_SCAN_BODY: usize = 10 * 1024 * 1024;
/// `MAX_LINE` in server/utils/sbom: longer lines are rejected unless the file is JSON.
pub const MAX_SCAN_LINE: usize = 4096;

#[derive(Serialize)]
struct ScanRequest<'a> {
    content: &'a str,
    filename: &'a str,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    strict: bool,
}

/// The `/scan` request body, or why the server would reject it.
pub fn scan_body(content: &str, filename: &str, strict: bool) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(&ScanRequest { content, filename, strict }).map_err(|e| e.to_string())?;
    if body.len() > MAX_SCAN_BODY {
        return Err(format!(
            "{filename} is too large to scan: {:.1} MB to send, the server accepts up to {} MB.",
            body.len() as f64 / 1_048_576.0, MAX_SCAN_BODY / 1_048_576
        ));
    }
    let json = content.trim_start().starts_with(['{', '['])
        && serde_json::from_str::<serde::de::IgnoredAny>(content).is_ok();
    // The server measures JavaScript string length, i.e. UTF-16 units.
    if !json && content.split('\n').any(|l| l.encode_utf16().count() > MAX_SCAN_LINE) {
        return Err(format!("{filename} has lines longer than {MAX_SCAN_LINE} characters, which the server rejects."));
    }
    Ok(body)
}

/// Decoded `data` of `POST /scan` (server/utils/sbom/report.js).
#[derive(Debug, Default, Deserialize)]
pub struct ScanReport {
    /// Detected file format, e.g. `cyclonedx-json` or `package-lock`.
    #[serde(default)]
    pub format: String,
    /// Unique packages in the file.
    #[serde(default)]
    pub packages: u64,
    #[serde(default)]
    findings: Vec<ScanFinding>,
    #[serde(default)]
    remediation: Vec<ScanRemediation>,
    #[serde(rename = "notChecked", default)]
    not_checked: Vec<NotChecked>,
}

#[derive(Debug, Default, Deserialize)]
struct ScanFinding {
    #[serde(default)] purl: String,
    #[serde(default)] id: Option<String>,
    #[serde(rename = "cveId", default)] cve_id: Option<String>,
    #[serde(default)] title: Option<String>,
    #[serde(default)] severity: Option<String>,
    #[serde(rename = "cvssScore", default)] cvss_score: Option<Value>,
    #[serde(default)] epss: Option<f64>,
    #[serde(default)] kev: bool,
    #[serde(rename = "kevDueDate", default)] kev_due_date: Option<String>,
    #[serde(default)] ransomware: bool,
    #[serde(default)] exploited: bool,
    #[serde(rename = "exploitMaturity", default)] exploit_maturity: Option<String>,
    #[serde(rename = "riskScore", default)] risk_score: Option<u32>,
    #[serde(default)] decision: Option<String>,
    #[serde(default)] confirmed: bool,
    #[serde(rename = "matchBasis", default)] match_basis: Option<String>,
    #[serde(rename = "matchedRange", default)] matched_range: Option<String>,
    #[serde(rename = "fixedVersions", default)] fixed_versions: Vec<String>,
    #[serde(default)] url: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ScanRemediation {
    #[serde(default)] purl: String,
    #[serde(default)] version: Option<String>,
    #[serde(rename = "upgradeTo", default)] upgrade_to: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct NotChecked {
    #[serde(default)] purl: String,
    #[serde(default)] reason: String,
}

impl ScanFinding {
    fn into_entry(self) -> ThreatEntry {
        let kev_due_date = self.kev_due_date.map(|d| d.split('T').next().unwrap_or_default().to_string());
        let mut e = ThreatEntry {
            id: self.id,
            cve_id: self.cve_id,
            title: self.title,
            severity: self.severity,
            cvss_score: self.cvss_score,
            epss: self.epss,
            kev: self.kev,
            kev_overdue: self.kev && kev_due_date.as_deref().is_some_and(is_past),
            kev_due_date,
            ransomware: self.ransomware,
            exploited: self.exploited,
            exploit_maturity: self.exploit_maturity,
            confirmed: self.confirmed,
            matched_range: self.matched_range,
            match_basis: self.match_basis.unwrap_or_else(|| "coordinate".to_string()),
            radar_url: self.url,
            fixed_versions: self.fixed_versions,
            // The server's score (no exposure) also counts EUVD/Mirage, which this body omits.
            risk_score: self.risk_score,
            decision: self.decision,
            ..Default::default()
        };
        if e.risk_score.is_none() || e.decision.is_none() {
            e.apply_risk("none");
        }
        e
    }
}

impl ScanReport {
    /// The report in host-scan shape, keyed by purl, with `source` as each asset's location.
    pub fn into_results(self, source: &str, severity_floor: u8) -> BatchResults {
        let mut services: BTreeMap<String, Vec<ThreatEntry>> = BTreeMap::new();
        let mut unconfirmed: BTreeMap<String, Vec<ThreatEntry>> = BTreeMap::new();
        for f in self.findings {
            let key = f.purl.clone();
            let e = f.into_entry();
            // KEV is never dropped by the severity floor, as in scan::run_scan.
            if !e.kev && severity_rank(e.severity.as_deref()) < severity_floor {
                continue;
            }
            let bucket = if e.confirmed { &mut services } else { &mut unconfirmed };
            bucket.entry(key).or_default().push(e);
        }
        let assets = self.remediation.into_iter()
            .map(|r| (r.purl, AssetInfo {
                exe: source.to_string(),
                version: r.version.unwrap_or_default(),
                version_source: self.format.clone(),
                exposed: false,
                reachability: "none".to_string(),
                listeners: Vec::new(),
                upgrade_to: r.upgrade_to,
            }))
            .collect();
        BatchResults {
            meta: Meta::default(),
            services,
            by_cve: BTreeMap::new(),
            unconfirmed,
            assets,
            errors: BTreeMap::new(),
            rejected: self.not_checked.into_iter().map(|n| (n.purl, n.reason)).collect(),
            truncated: Vec::new(),
            registration: None,
        }
    }
}

fn truthy(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bool(true))) || v.and_then(|x| x.as_str()) == Some("true")
}

fn str_of(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
}

/// Read the numeric EPSS score from a raw JSON value that may be the object
/// `{score, percentile, ...}` (the `/threats` and `/match` shape) or a bare
/// number. Returns `None` for null/absent/other shapes.
fn epss_score_from_value(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Object(o)) => o.get("score").and_then(Value::as_f64),
        other => other.and_then(Value::as_f64),
    }
}

/// Days since 1970-01-01 of an ISO `YYYY-MM-DD…` date (Hinnant's days_from_civil).
fn iso_days(s: &str) -> Option<i64> {
    let mut parts = s.get(..10)?.splitn(3, '-').map(|p| p.parse::<i64>().ok());
    let (y, m, d) = (parts.next()??, parts.next()??, parts.next()??);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    Some(era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468)
}

/// Seconds since the epoch of an ISO UTC date or `YYYY-MM-DDTHH:MM:SS…` timestamp.
fn iso_secs(s: &str) -> Option<i64> {
    let time = s.get(11..19).map_or(0, |t| t.split(':').filter_map(|p| p.parse::<i64>().ok()).fold(0, |acc, p| acc * 60 + p));
    Some(iso_days(s)? * 86_400 + time)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Whether a KEV due date (midnight UTC) has passed, as `isKevOverdue` on the server.
fn is_past(date: &str) -> bool {
    iso_secs(date).is_some_and(|t| t < now_secs())
}

impl ThreatEntry {
    /// Fold the exploitation signals in. `kev` is `{addedDate,dueDate,ransomwareUse,…}`
    /// on a KEV-listed threat (a bare `true` is accepted defensively); anything
    /// else, including an object without `addedDate`, means not listed.
    fn with_signals(mut self, kev: Option<&Value>, in_wild: Option<&Value>, exploit: Option<&Value>, outside_kev: bool) -> Self {
        let kev_obj = kev.and_then(Value::as_object)
            .filter(|o| o.get("addedDate").is_some_and(|d| !d.is_null()));
        self.kev = kev_obj.is_some() || matches!(kev, Some(Value::Bool(true)));
        self.kev_due_date = kev_obj
            .and_then(|o| str_of(o.get("dueDate")))
            .map(|d| d.split('T').next().unwrap_or_default().to_string());
        self.kev_overdue = self.kev && self.kev_due_date.as_deref().is_some_and(is_past);
        self.ransomware = kev_obj
            .and_then(|o| o.get("ransomwareUse"))
            .and_then(Value::as_str)
            .is_some_and(|s| s.eq_ignore_ascii_case("known"));
        self.exploited_outside_kev = outside_kev;
        self.exploited = self.kev || outside_kev || truthy(in_wild);
        self.exploit_maturity = str_of(exploit.and_then(|e| e.get("maturity")));
        self
    }
}

fn refs_to_strings(refs: &[Value]) -> Vec<String> {
    refs.iter()
        .filter_map(|r| {
            r.as_str().map(|s| s.to_string())
                .or_else(|| r.get("url").and_then(|u| u.as_str()).map(|s| s.to_string()))
        })
        .collect()
}

/// Convert an API match into a ThreatEntry.
pub fn match_to_entry(m: MatchHit) -> ThreatEntry {
    let outside_kev = m.exploitation.as_ref()
        .is_some_and(|x| truthy(x.get("euvd")) || truthy(x.get("mirage")));
    ThreatEntry {
        id: str_of(m.id.as_ref()),
        epss: m.epss(),
        cve_id: m.cve_id,
        title: m.title,
        severity: m.severity,
        cvss_score: m.cvss_score,
        cvss_vector: m.cvss_vector,
        // Date-only, the same shape the search path emits.
        published_date: m.published_date.as_deref().map(|s| clean_date(Some(&Value::String(s.to_string())))),
        affected_versions: (!m.affected_versions.is_empty()).then(|| Value::from(m.affected_versions)),
        patch_available: m.patch_available,
        references: refs_to_strings(&m.references),
        patch_links: m.patch_links,
        confirmed: m.confirmed,
        matched_range: m.matched_range,
        match_basis: m.match_basis.unwrap_or_else(|| "coordinate".to_string()),
        radar_url: m.slug.map(|s| format!("{SITE_URL}/threat/{s}")),
        fixed_versions: m.fixed_versions,
        remediation: m.remediation,
        cwes: m.cwes,
        ..Default::default()
    }
    .with_signals(m.kev.as_ref(), m.known_exploits_in_wild.as_ref(), m.exploit.as_ref(), outside_kev)
}

/// Convert a raw ?search= threat into an (unconfirmed) ThreatEntry.
pub fn search_to_entry(t: &Value) -> ThreatEntry {
    let outside_kev = truthy(t.pointer("/euvd/exploited")) || truthy(t.pointer("/mirageIntel/exploited"));
    ThreatEntry {
        id: str_of(t.get("_id")).or_else(|| str_of(t.get("id"))),
        cve_id: str_of(t.get("cveId")).or_else(|| str_of(t.get("externalId"))),
        title: str_of(t.get("title")),
        severity: str_of(t.get("severity")),
        cvss_score: t.get("cvssScore").cloned(),
        cvss_vector: str_of(t.get("cvssVector")),
        epss: epss_score_from_value(t.get("epss")),
        published_date: Some(clean_date(t.get("publishedDate"))),
        affected_versions: t.get("affectedVersions").cloned(),
        patch_available: t.get("patchAvailable").cloned(),
        references: t.get("references").and_then(Value::as_array).map(|a| refs_to_strings(a)).unwrap_or_default(),
        patch_links: str_vec_from_value(t.get("patchLinks")),
        match_basis: "search-fallback".to_string(),
        radar_url: str_of(t.get("slug")).map(|s| format!("{SITE_URL}/threat/{s}")),
        fixed_versions: str_vec_from_value(t.get("fixedVersions")),
        remediation: str_of(t.get("remediation")),
        cwes: str_vec_from_value(t.get("cwes")),
        ..Default::default()
    }
    .with_signals(t.get("kev"), t.get("knownExploitsInWild"), t.get("exploit"), outside_kev)
}

/// Collect a JSON array of strings into a `Vec<String>`, ignoring non-string
/// elements; returns empty for null/absent/non-array.
fn str_vec_from_value(v: Option<&Value>) -> Vec<String> {
    v.and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default()
}

fn threat_id(threat: &Value) -> String {
    for key in &["_id", "externalId", "cveId", "slug", "title"] {
        if let Some(v) = threat.get(key).and_then(|v| v.as_str()) {
            if !v.is_empty() {
                return v.to_string();
            }
        }
    }
    threat.to_string()
}

fn clean_date(value: Option<&Value>) -> String {
    match value.and_then(|v| v.as_str()) {
        Some(s) => s.split('T').next().unwrap_or("N/A").to_string(),
        None    => "N/A".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn access_denied_classifies_fixable_403s_only() {
        let denied = |error: &str, message: &str| access_denied(&json!({ "error": error, "message": message }), message);
        assert!(denied("API access required", "API access requires an active Individual, Base, Pro or Enterprise plan.").is_some());
        assert!(denied("pro_access_required", "The decision ledger needs a paid plan.").is_some());
        assert_eq!(
            denied("Profile incomplete", "Please complete your profile.").as_deref(),
            Some("Please complete your profile. (https://radar.offseq.com/console)")
        );
        assert!(denied("Forbidden", "You do not own this host").is_none());
    }

    #[test]
    fn batch_cap_by_tier() {
        assert_eq!(tier_batch_cap(0), 50);
        assert_eq!(tier_batch_cap(20), 50);
        assert_eq!(tier_batch_cap(25), 200);
        assert_eq!(tier_batch_cap(45), 200);
        assert_eq!(tier_batch_cap(75), 200);
        assert_eq!(tier_batch_cap(375), 1000);
        assert_eq!(tier_batch_cap(1500), 4000);
    }

    #[test]
    fn match_query_serializes_exactly_one_shape() {
        // purl: only {purl}, never a version field
        let v = serde_json::to_value(MatchQuery::purl("pkg:npm/lodash@4.17.20")).unwrap();
        assert_eq!(v, json!({ "purl": "pkg:npm/lodash@4.17.20" }));
        // package: {package:{name,ecosystem}, version}
        let v = serde_json::to_value(MatchQuery::package("django", "PyPI", "4.2.0")).unwrap();
        assert_eq!(v, json!({ "package": { "name": "django", "ecosystem": "PyPI" }, "version": "4.2.0" }));
        // cpe
        let v = serde_json::to_value(MatchQuery::cpe("cpe:2.3:a:apache:http_server:2.4.48:*:*:*:*:*:*:*")).unwrap();
        assert_eq!(v, json!({ "cpe": "cpe:2.3:a:apache:http_server:2.4.48:*:*:*:*:*:*:*" }));
    }

    #[test]
    fn batch_request_omits_strict_when_false() {
        let q = [MatchQuery::purl("pkg:deb/debian/nginx@1.0")];
        let body = MatchBatchRequest { queries: &q, strict: false };
        let v = serde_json::to_value(&body).unwrap();
        assert!(v.get("strict").is_none());
        let body = MatchBatchRequest { queries: &q, strict: true };
        assert_eq!(serde_json::to_value(&body).unwrap()["strict"], json!(true));
    }

    #[test]
    fn batch_response_deserializes() {
        let raw = json!({ "data": { "results": [
            { "query": {"purl":"x"}, "mode":"purl", "ecosystem":"Debian", "version":"1.0",
              "totalCandidates": 2, "matches": [
                { "cveId":"CVE-2024-1","title":"t","severity":"high","cvssScore":7.5,
                  "kev":true,"epss":0.42,"matchBasis":"coordinate","matchedRange":"<2.0","confirmed":true }
            ] },
            { "matches": [] }
        ] } });
        let resp: MatchBatchResponse = serde_json::from_value(raw).unwrap();
        assert_eq!(resp.data.results.len(), 2);
        let e = match_to_entry(resp.data.results.into_iter().next().unwrap().matches.into_iter().next().unwrap());
        assert_eq!(e.cve_id.as_deref(), Some("CVE-2024-1"));
        assert!(e.confirmed && e.kev);
        assert_eq!(e.matched_range.as_deref(), Some("<2.0"));
        assert_eq!(e.match_basis, "coordinate");
    }

    #[test]
    fn search_entry_is_unconfirmed() {
        let t = json!({ "cveId":"CVE-9","severity":"low","knownExploitsInWild":true });
        let e = search_to_entry(&t);
        assert!(!e.confirmed);
        assert_eq!(e.match_basis, "search-fallback");
        assert!(e.exploited && !e.kev, "in-the-wild is exploited, not KEV");
    }

    /// A realistic server hit where `epss` and `kev` are OBJECTS (the common live
    /// shape). Before the fix this failed the WHOLE-chunk decode.
    fn realistic_hit() -> Value {
        json!({
            "id": "abc", "cveId": "CVE-2024-1", "title": "t", "slug": "cve-2024-1",
            "severity": "high", "cvssScore": 7.2, "type": "vulnerability", "source": "nvd",
            "publishedDate": "2024-01-01T00:00:00.000Z",
            "kev": { "addedDate": "2024-02-01", "dueDate": "2024-02-22", "ransomwareUse": "Known" },
            "epss": { "score": 0.42, "percentile": 0.97 },
            "knownExploitsInWild": false,
            "patchAvailable": true,
            "matchBasis": "coordinate",
            "matchedRange": "<4.17.21",
            "matchedCoordinate": "pkg:npm/lodash",
            "confirmed": true
        })
    }

    #[test]
    fn object_shaped_epss_and_kev_decode() {
        // Whole envelope: one result, one object-shaped hit, must decode cleanly.
        let raw = json!({ "data": { "results": [ { "matches": [ realistic_hit() ] } ] } });
        let resp: MatchBatchResponse = serde_json::from_value(raw)
            .expect("object-shaped epss/kev must not fail the chunk decode");
        assert_eq!(resp.data.results.len(), 1);

        let hit = resp.data.results.into_iter().next().unwrap()
            .matches.into_iter().next().unwrap();
        assert_eq!(hit.epss(), Some(0.42));
        assert_eq!(hit.epss_percentile(), Some(0.97));
        assert!(hit.kev.is_some(), "object kev present");
        assert!(hit.confirmed);
        assert_eq!(hit.match_basis.as_deref(), Some("coordinate"));
        assert_eq!(hit.matched_range.as_deref(), Some("<4.17.21"));

        // And the conversion surfaces publishedDate / patchAvailable. The match
        // path now normalizes the date the same way the search path does, so the
        // JSON `publishedDate` has ONE shape ("YYYY-MM-DD", not the raw ISO ts).
        let e = match_to_entry(hit);
        assert_eq!(e.epss, Some(0.42));
        assert!(e.kev);
        assert_eq!(e.published_date.as_deref(), Some("2024-01-01"));
        assert_eq!(e.patch_available, Some(json!(true)));
    }

    #[test]
    fn null_epss_and_kev_decode_to_none_and_false() {
        let raw = json!({
            "cveId": "CVE-2024-2", "severity": "low",
            "epss": null, "kev": null, "matchBasis": "cpe", "matchedRange": "*"
        });
        let hit: MatchHit = serde_json::from_value(raw).unwrap();
        assert_eq!(hit.epss(), None);
        assert_eq!(hit.epss_percentile(), None);
        assert!(hit.kev.is_none(), "null kev => not listed");
        let e = match_to_entry(hit);
        assert_eq!(e.epss, None);
        assert!(!e.kev);
    }

    #[test]
    fn absent_epss_and_kev_default() {
        // Neither field present at all.
        let raw = json!({ "cveId": "CVE-2024-3", "matchBasis": "coordinate" });
        let hit: MatchHit = serde_json::from_value(raw).unwrap();
        assert_eq!(hit.epss(), None);
        assert!(hit.kev.is_none());
    }

    #[test]
    fn bare_number_epss_and_bool_kev_defensive() {
        // Defensive: a bare numeric epss and a bare bool kev are still accepted.
        let raw = json!({ "cveId": "CVE-2024-4", "epss": 0.5, "kev": true });
        let hit: MatchHit = serde_json::from_value(raw).unwrap();
        assert_eq!(hit.epss(), Some(0.5));
        assert_eq!(hit.epss_percentile(), None);
        assert!(match_to_entry(hit).kev, "bool kev => as-is");
    }

    #[test]
    fn search_fallback_reads_object_epss_and_kev() {
        // GET /threats also returns epss + kev as objects; both paths must agree.
        let t = json!({
            "cveId": "CVE-2024-5", "severity": "high",
            "epss": { "score": 0.33, "percentile": 0.9 },
            "kev": { "addedDate": "2024-03-01" }
        });
        let e = search_to_entry(&t);
        assert_eq!(e.epss, Some(0.33));
        assert!(e.kev, "object kev in /threats => true");

        // null kev / null epss => false / None.
        let t2 = json!({ "cveId": "CVE-2024-6", "epss": null, "kev": null });
        let e2 = search_to_entry(&t2);
        assert_eq!(e2.epss, None);
        assert!(!e2.kev);
    }

    #[test]
    fn slug_becomes_radar_url_on_match_path() {
        // SITE_URL must equal BASE_URL with the "/api/v1" API path trimmed off.
        assert_eq!(SITE_URL, "https://radar.offseq.com");
        assert_eq!(
            BASE_URL.strip_suffix("/api/v1").unwrap_or(BASE_URL),
            SITE_URL,
            "SITE_URL must track BASE_URL"
        );
        let raw = json!({
            "cveId": "CVE-2021-23337", "slug": "lodash-command-injection-abc123",
            "matchBasis": "coordinate", "confirmed": true
        });
        let hit: MatchHit = serde_json::from_value(raw).unwrap();
        assert_eq!(hit.slug.as_deref(), Some("lodash-command-injection-abc123"));
        let e = match_to_entry(hit);
        assert_eq!(
            e.radar_url.as_deref(),
            Some("https://radar.offseq.com/threat/lodash-command-injection-abc123")
        );
        // Serializes under the `radarUrl` key.
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["radarUrl"], json!("https://radar.offseq.com/threat/lodash-command-injection-abc123"));
    }

    #[test]
    fn absent_slug_yields_no_radar_url() {
        let raw = json!({ "cveId": "CVE-2024-7", "matchBasis": "coordinate" });
        let hit: MatchHit = serde_json::from_value(raw).unwrap();
        let e = match_to_entry(hit);
        assert!(e.radar_url.is_none());
        // Skipped from JSON when None.
        let v = serde_json::to_value(&e).unwrap();
        assert!(v.get("radarUrl").is_none());
    }

    #[test]
    fn remediation_fields_decode_and_surface() {
        let raw = json!({
            "cveId": "CVE-2021-23337", "severity": "high", "matchBasis": "coordinate",
            "slug": "lodash-x", "confirmed": true,
            "fixedVersions": ["4.17.21"],
            "remediation": "Upgrade to lodash 4.17.21 or later.",
            "cwes": ["CWE-77"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"]
        });
        let hit: MatchHit = serde_json::from_value(raw).unwrap();
        assert_eq!(hit.fixed_versions, vec!["4.17.21".to_string()]);
        assert_eq!(hit.cwes, vec!["CWE-77".to_string()]);
        let e = match_to_entry(hit);
        assert_eq!(e.fixed_versions, vec!["4.17.21".to_string()]);
        assert_eq!(e.remediation.as_deref(), Some("Upgrade to lodash 4.17.21 or later."));
        assert_eq!(e.cwes, vec!["CWE-77".to_string()]);
        // `references` is now populated (server projects it).
        assert_eq!(e.references, vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23337".to_string()]);
        // Empty / absent remediation fields stay out of the JSON.
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["fixedVersions"], json!(["4.17.21"]));
        assert_eq!(v["cwes"], json!(["CWE-77"]));
    }

    fn risk(sev: Option<&str>, cvss: f64, epss: Option<f64>, kev: bool, exposure: &str, confirmed: bool) -> (u32, String) {
        let t = ThreatEntry {
            severity: sev.map(str::to_string), cvss_score: Some(json!(cvss)), epss, kev, confirmed,
            ..Default::default()
        };
        compute_risk(&t, exposure)
    }

    #[test]
    fn risk_score_matches_documented_bands() {
        // critical + KEV + public + confirmed: 40+20+12 = 72 → but KEV&exposed&
        // confirmed forces act-now regardless of score.
        let (score, dec) = risk(Some("critical"), 9.8, Some(0.9), true, "public", true);
        // sev 40, epss round(0.9*25)=23 (0.9*25=22.5 → 23), kev 20, exp 12 = 95
        assert_eq!(score, 95);
        assert_eq!(dec, "act-now");

        // high, no kev, public, confirmed, low epss: 30 + round(0.1*25=2.5→3) + 0
        // + 12 = 45 → schedule (>=32, <58).
        let (score, dec) = risk(Some("high"), 7.5, Some(0.1), false, "public", true);
        assert_eq!(score, 45);
        assert_eq!(dec, "schedule");

        // medium, no kev, loopback (exp 0), confirmed, no epss: 18 → track (<32).
        let (score, dec) = risk(Some("medium"), 5.0, None, false, "loopback", true);
        assert_eq!(score, 18);
        assert_eq!(dec, "track");

        // Unconfirmed halves the score: high+public, confirmed=false:
        // (30 + 0 + 0 + 12) * 0.6 = 25.2 → 25 → track.
        let (score, dec) = risk(Some("high"), 7.0, None, false, "public", false);
        assert_eq!(score, 25);
        assert_eq!(dec, "track");

        // KEV + confirmed but NOT exposed (loopback) → not act-now via the
        // kev&exposed rule, but `kev && confirmed` lands it in soon.
        let (_score, dec) = risk(Some("low"), 3.0, None, true, "loopback", true);
        assert_eq!(dec, "soon");

        // epss>=0.5 && exposed (private) with no kev, medium → soon via the epss rule.
        // sev 18, epss round(0.6*25)=15, exp 7 = 40 (schedule by score) but the
        // epss>=0.5 && exposed branch promotes it to soon.
        let (score, dec) = risk(Some("medium"), 5.0, Some(0.6), false, "private", true);
        assert_eq!(score, 40);
        assert_eq!(dec, "soon");

        // Without KEV: critical + max epss + public = 77, past the act-now threshold (74).
        let (score, dec) = risk(Some("critical"), 10.0, Some(1.0), false, "public", true);
        assert_eq!(score, 77);
        assert_eq!(dec, "act-now");
        let (score, dec) = risk(Some("critical"), 10.0, Some(0.8), false, "public", true);
        assert_eq!(score, 72);
        assert_eq!(dec, "soon");
    }

    #[test]
    fn risk_score_counts_exploit_overdue_and_outside_kev_like_the_server() {
        let base = ThreatEntry { severity: Some("high".into()), confirmed: true, ..Default::default() };
        // 30 + WEAPONIZED 10 = 40
        let t = ThreatEntry { exploit_maturity: Some("WEAPONIZED".into()), ..base.clone() };
        assert_eq!(compute_risk(&t, "none").0, 40);
        // 30 + PoC 3 = 33
        let t = ThreatEntry { exploit_maturity: Some("POC_LOW".into()), ..base.clone() };
        assert_eq!(compute_risk(&t, "none").0, 33);
        // EUVD/Mirage only: 30 + 15 = 45
        let t = ThreatEntry { exploited_outside_kev: true, ..base.clone() };
        assert_eq!(compute_risk(&t, "none").0, 45);
        // KEV + overdue: 30 + 20 + 5 = 55, and the outside-KEV bonus never stacks on KEV.
        let t = ThreatEntry { kev: true, kev_overdue: true, exploited_outside_kev: true, ..base };
        assert_eq!(compute_risk(&t, "none").0, 55);
    }

    #[test]
    fn match_hit_decodes_exploitation_signals() {
        let e = match_to_entry(serde_json::from_value(json!({
            "id": "65f0c0ffee", "cveId": null, "severity": "high", "matchBasis": "coordinate", "confirmed": true,
            "kev": { "addedDate": "2024-02-01", "dueDate": "2024-02-22T00:00:00.000Z", "ransomwareUse": "Known" },
            "exploit": { "maturity": "WEAPONIZED" },
            "exploitation": { "euvd": true, "mirage": false },
            "cvssVector": "CVSS:3.1/AV:N", "patchLinks": ["https://x/fix"]
        })).unwrap());
        assert_eq!(e.id.as_deref(), Some("65f0c0ffee"));
        assert!(e.kev && e.ransomware && e.kev_overdue && e.exploited && e.exploited_outside_kev);
        assert_eq!(e.kev_due_date.as_deref(), Some("2024-02-22"));
        assert_eq!(e.exploit_maturity.as_deref(), Some("WEAPONIZED"));
        assert_eq!(e.cvss_vector.as_deref(), Some("CVSS:3.1/AV:N"));
        assert_eq!(e.patch_links, vec!["https://x/fix".to_string()]);

        // An empty kev object (raw /threats docs) is not a KEV listing.
        let e = search_to_entry(&json!({ "kev": {}, "euvd": { "exploited": true } }));
        assert!(!e.kev && e.exploited && e.exploited_outside_kev);
    }

    #[test]
    fn iso_days_matches_civil_calendar() {
        assert_eq!(iso_days("1970-01-01"), Some(0));
        assert_eq!(iso_days("2000-03-01"), Some(11_017));
        assert_eq!(iso_days("2024-02-29T12:00:00Z"), Some(19_782));
        assert_eq!(iso_days("2024-13-01"), None);
        assert_eq!(iso_days("bad"), None);
        assert!(is_past("2000-01-01") && !is_past("9999-01-01"));
    }

    #[test]
    fn match_result_reads_upgrade_truncation_and_error() {
        let r: MatchResult = serde_json::from_value(json!({
            "matches": [], "upgradeTo": "1.2.4", "truncated": true, "totalMatches": 40
        })).unwrap();
        assert_eq!(r.upgrade_to.as_deref(), Some("1.2.4"));
        assert!(r.truncated && r.error.is_none());
        let r: MatchResult = serde_json::from_value(json!({ "error": "invalid purl", "matches": [] })).unwrap();
        assert_eq!(r.error.as_deref(), Some("invalid purl"));
    }

    #[test]
    fn plan_names_follow_hourly_quota() {
        assert_eq!(plan_name(20), "Free");
        assert_eq!(plan_name(75), "Base");
        assert_eq!(plan_name(1500), "Enterprise");
        assert_eq!(plan_name(7), "Custom (7/hr)");
    }

    #[test]
    fn risk_score_falls_back_to_cvss_when_severity_missing() {
        // No severity string → bucket by CVSS. cvss 9.1 → sev 40.
        let (score, _) = risk(None, 9.1, None, false, "none", true);
        assert_eq!(score, 40);
        // cvss 0 → floor 8.
        let (score, _) = risk(None, 0.0, None, false, "none", true);
        assert_eq!(score, 8);
    }

    #[test]
    fn risk_score_clamps_epss_and_total() {
        // Out-of-range epss is clamped to [0,1]; total clamped to 100.
        let (score, _) = risk(Some("critical"), 10.0, Some(5.0), true, "public", true);
        // 40 + 25 + 20 + 12 = 97 (epss clamp keeps it at 25), still <=100.
        assert_eq!(score, 97);
        let (score, _) = risk(Some("critical"), 10.0, Some(-1.0), true, "public", true);
        // negative epss clamps to 0 → 40 + 0 + 20 + 12 = 72.
        assert_eq!(score, 72);
    }

    #[test]
    fn risk_score_exposure_is_case_and_whitespace_insensitive() {
        // The exposure is normalised (trim + lowercase) before matching, mirroring
        // the server. Mixed-case / padded variants must yield the SAME result as
        // the canonical lowercase the client emits today.
        let canonical = risk(Some("high"), 7.5, Some(0.1), false, "public", true);
        for variant in ["PUBLIC", "Public", " public ", "pUbLiC\n"] {
            assert_eq!(
                risk(Some("high"), 7.5, Some(0.1), false, variant, true),
                canonical,
                "exposure {variant:?} must match the lowercase result",
            );
        }
        // And a private variant matches its lowercase counterpart too.
        assert_eq!(
            risk(Some("medium"), 5.0, Some(0.6), false, "PRIVATE", true),
            risk(Some("medium"), 5.0, Some(0.6), false, "private", true),
        );
    }

    #[test]
    fn apply_risk_sets_fields_and_serializes() {
        let mut e: ThreatEntry = serde_json::from_value(json!({
            "cveId": "CVE-2024-1", "severity": "critical", "cvssScore": 9.8,
            "kev": true, "epss": 0.9, "matchBasis": "coordinate", "confirmed": true,
            "references": []
        })).unwrap();
        assert!(e.risk_score.is_none() && e.decision.is_none());
        e.apply_risk("public");
        assert_eq!(e.risk_score, Some(95));
        assert_eq!(e.decision.as_deref(), Some("act-now"));
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["riskScore"], json!(95));
        assert_eq!(v["decision"], json!("act-now"));
        // Before scoring the fields are skipped entirely.
        let e2: ThreatEntry = serde_json::from_value(json!({
            "cveId": "CVE-2024-2", "matchBasis": "coordinate", "references": [], "kev": false
        })).unwrap();
        let v2 = serde_json::to_value(&e2).unwrap();
        assert!(v2.get("riskScore").is_none() && v2.get("decision").is_none());
    }

    #[test]
    fn register_response_decodes_from_sample() {
        // The documented server `data` payload must decode with all fields.
        let data = json!({
            "hostId": "11111111-2222-3333-4444-555555555555",
            "monitoring": true, "new": true, "assetCount": 1840,
            "drift": { "added": 5, "removed": 2, "changed": 3 },
            "summary": {
                "total": 12, "confirmed": 9, "kev": 2, "exposed": 3,
                "bySeverity": {"critical":1,"high":4,"medium":5,"low":2},
                "byDecision": {"act-now":2,"soon":3,"schedule":4,"track":3}, "actNow": 2
            },
            "top": [ { "cveId": "CVE-2024-9", "decision": "act-now", "coordinate": "openssl@1.1" } ],
            "newSinceLast": [ { "cveId": "CVE-2024-10", "decision": "soon", "coordinate": "nginx@1.0" } ],
            "newSinceLastCount": 3
        });
        let resp: RegisterResponse = serde_json::from_value(data).unwrap();
        assert_eq!(resp.host_id, "11111111-2222-3333-4444-555555555555");
        assert!(resp.monitoring && resp.new);
        assert_eq!(resp.asset_count, 1840);
        assert_eq!((resp.drift.added, resp.drift.removed, resp.drift.changed), (5, 2, 3));
        assert_eq!(resp.summary.act_now, 2);
        assert_eq!(resp.summary.kev, 2);
        assert_eq!(resp.summary.by_severity.get("critical"), Some(&1));
        assert_eq!(resp.summary.by_decision.get("schedule"), Some(&4));
        assert_eq!(resp.new_since_last_count, 3);
        assert_eq!(resp.new_since_last.len(), 1);
        assert_eq!(resp.new_since_last[0].cve_id.as_deref(), Some("CVE-2024-10"));

        // A sparse / partial response must still decode (all fields default).
        let sparse: RegisterResponse =
            serde_json::from_value(json!({ "monitoring": false })).unwrap();
        assert!(!sparse.monitoring && !sparse.new);
        assert_eq!(sparse.asset_count, 0);
    }

    #[test]
    fn registration_report_serializes_expected_shape() {
        let resp = RegisterResponse {
            host_id: "abc".into(), monitoring: true, asset_count: 10,
            new_since_last_count: 2, ..Default::default()
        };
        let report = RegistrationReport::from(&resp);
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["hostId"], json!("abc"));
        assert_eq!(v["monitoring"], json!(true));
        assert_eq!(v["assetCount"], json!(10));
        assert_eq!(v["newSinceLastCount"], json!(2));
        assert!(v.get("drift").is_some() && v.get("summary").is_some());
    }

    #[test]
    fn inventory_payload_serializes_camel_case() {
        let body = RegisterRequest {
            host_id: "h1",
            hostname: Some("web-01"),
            os: Some(InventoryOs { os_type: Some("linux".into()), distro: Some("ubuntu".into()), version: None }),
            agent_version: "0.1.4",
            monitor: true,
            assets: &[InventoryAsset {
                purl: "pkg:deb/ubuntu/openssl@1.1.1f".into(), cpe: None,
                version: "1.1.1f".into(), ecosystem: "deb".into(), name: "openssl".into(),
                exposure: "public".into(), exposed: true, runtime: true,
            }],
        };
        let v = serde_json::to_value(&body).unwrap();
        assert_eq!(v["hostId"], json!("h1"));
        assert_eq!(v["hostname"], json!("web-01"));
        assert_eq!(v["agentVersion"], json!("0.1.4"));
        assert_eq!(v["monitor"], json!(true));
        // os.version is None → omitted; os.type kept under the wire key "type".
        assert_eq!(v["os"]["type"], json!("linux"));
        assert!(v["os"].get("version").is_none());
        assert_eq!(v["assets"][0]["purl"], json!("pkg:deb/ubuntu/openssl@1.1.1f"));
        assert_eq!(v["assets"][0]["exposure"], json!("public"));
        assert_eq!(v["assets"][0]["runtime"], json!(true));
    }

    #[test]
    fn scan_report_maps_into_host_report_shape() {
        let data = json!({
            "format": "package-lock", "packages": 3,
            "findings": [
                { "purl": "pkg:npm/lodash@4.17.20", "id": "t1", "cveId": "CVE-2021-23337", "severity": "high",
                  "cvssScore": 7.2, "epss": 0.4, "kev": true, "kevDueDate": "2024-02-22T00:00:00.000Z",
                  "ransomware": false, "exploited": true, "exploitMaturity": null, "riskScore": 61,
                  "decision": "soon", "confirmed": true, "matchBasis": "coordinate", "matchedRange": "<4.17.21",
                  "fixedVersions": ["4.17.21"], "upgradeTo": "4.17.21", "url": "https://radar.offseq.com/threat/x" },
                { "purl": "pkg:npm/lodash@4.17.20", "id": "t2", "cveId": null, "severity": "low",
                  "cvssScore": null, "epss": null, "kev": false, "confirmed": true, "matchBasis": "coordinate" },
                { "purl": "pkg:npm/qs@6.0.0", "id": "t3", "cveId": "CVE-2022-1", "severity": "medium",
                  "kev": false, "confirmed": false, "riskScore": 11, "decision": "track", "matchBasis": "coordinate-unconfirmed" }
            ],
            "remediation": [
                { "purl": "pkg:npm/lodash@4.17.20", "version": "4.17.20", "findings": 2, "upgradeTo": "4.17.21" },
                { "purl": "pkg:npm/qs@6.0.0", "version": "6.0.0", "findings": 1, "upgradeTo": null }
            ],
            "notChecked": [ { "purl": "pkg:foo/bar", "reason": "unsupported ecosystem" } ],
            "summary": { "total": 3 }
        });
        let report: ScanReport = serde_json::from_value(data).unwrap();
        assert_eq!((report.format.as_str(), report.packages), ("package-lock", 3));
        let r = report.into_results("deps/package-lock.json", 0);

        let lodash = &r.services["pkg:npm/lodash@4.17.20"];
        assert_eq!(lodash.len(), 2);
        let e = &lodash[0];
        assert_eq!((e.id.as_deref(), e.cve_id.as_deref()), (Some("t1"), Some("CVE-2021-23337")));
        assert!(e.kev && e.kev_overdue && e.exploited && e.confirmed);
        assert_eq!(e.kev_due_date.as_deref(), Some("2024-02-22"));
        assert_eq!((e.risk_score, e.decision.as_deref()), (Some(61), Some("soon")), "server score kept");
        assert_eq!(e.radar_url.as_deref(), Some("https://radar.offseq.com/threat/x"));
        assert_eq!(e.fixed_versions, vec!["4.17.21".to_string()]);
        assert_eq!(lodash[1].risk_score, Some(compute_risk(&lodash[1], "none").0), "local fallback");

        assert_eq!(r.unconfirmed["pkg:npm/qs@6.0.0"][0].cve_id.as_deref(), Some("CVE-2022-1"));
        assert_eq!(r.assets["pkg:npm/lodash@4.17.20"].upgrade_to.as_deref(), Some("4.17.21"));
        assert_eq!(r.assets["pkg:npm/qs@6.0.0"].version_source, "package-lock");
        assert_eq!(r.assets["pkg:npm/qs@6.0.0"].exe, "deps/package-lock.json");
        assert_eq!(r.rejected["pkg:foo/bar"], "unsupported ecosystem");
        assert!(r.errors.is_empty());
    }

    #[test]
    fn scan_severity_floor_keeps_kev() {
        let report: ScanReport = serde_json::from_value(json!({ "findings": [
            { "purl": "pkg:npm/a@1", "severity": "low", "kev": true, "confirmed": true },
            { "purl": "pkg:npm/b@1", "severity": "low", "kev": false, "confirmed": true },
        ] })).unwrap();
        let r = report.into_results("f", severity_rank(Some("high")));
        assert_eq!(r.services.keys().collect::<Vec<_>>(), ["pkg:npm/a@1"]);
    }

    #[test]
    fn scan_body_enforces_server_limits() {
        let v: Value = serde_json::from_slice(&scan_body("pkg:npm/a@1\n", "purls.txt", true).unwrap()).unwrap();
        assert_eq!(v, json!({ "content": "pkg:npm/a@1\n", "filename": "purls.txt", "strict": true }));
        let v: Value = serde_json::from_slice(&scan_body("x", "f", false).unwrap()).unwrap();
        assert!(v.get("strict").is_none());

        let long = "a".repeat(MAX_SCAN_LINE + 1);
        assert!(scan_body(&long, "yarn.lock", false).unwrap_err().contains("longer than 4096"));
        assert!(scan_body(&"a".repeat(MAX_SCAN_LINE), "yarn.lock", false).is_ok());
        assert!(scan_body(&format!("{{\"k\":\"{long}\"}}"), "bom.json", false).is_ok(), "JSON is exempt");

        // Escaping counts: quotes double in the body.
        let quotes = "\"".repeat(MAX_SCAN_BODY / 2 + 1);
        assert!(scan_body(&quotes, "f", false).unwrap_err().contains("too large"));
    }

    #[test]
    fn advertised_cap_reads_every_413_shape() {
        assert_eq!(advertised_cap(&json!({ "data": { "maxBatch": 50 } })), Some(50));
        assert_eq!(advertised_cap(&json!({ "data": { "maxAssets": 100 } })), Some(100));
        assert_eq!(advertised_cap(&json!({ "data": { "maxPackages": 200, "packages": 900 } })), Some(200));
        assert_eq!(advertised_cap(&json!({ "error": "Payload too large" })), None);
    }

    #[test]
    fn recorded_decision_suppression_mirrors_alert_decision() {
        let now = iso_secs("2026-06-01T12:00:00.000Z").unwrap();
        let d = |verdict: &str, status: &str, until: Option<&str>| RecordedDecision {
            verdict: verdict.into(), status: status.into(), until: until.map(str::to_string), ..Default::default()
        };
        for v in ["accept", "not_affected", "mitigated", "defer"] {
            assert!(d(v, "active", None).suppresses(now), "{v}");
            assert!(d(v, "review_due", None).suppresses(now), "{v}");
        }
        assert!(!d("patch_now", "active", None).suppresses(now));
        assert!(!d("accept", "stale", None).suppresses(now));
        assert!(!d("accept", "expired", None).suppresses(now));
        assert!(d("defer", "active", Some("2026-06-01T12:00:01.000Z")).suppresses(now));
        assert!(!d("defer", "active", Some("2026-06-01T12:00:00.000Z")).suppresses(now), "until <= now");
        assert!(!d("defer", "active", Some("2026-05-01")).suppresses(now));
    }

    #[test]
    fn decisions_attach_by_cve_and_coordinate() {
        let entry = |cve: &str| ThreatEntry { cve_id: Some(cve.into()), confirmed: true, ..Default::default() };
        let mut results = BatchResults {
            meta: Meta::default(),
            services: BTreeMap::from([
                ("nginx@1.24.0".to_string(), vec![entry("CVE-2024-1"), entry("CVE-2024-2")]),
                ("openssl@3.0.2".to_string(), vec![entry("CVE-2024-1")]),
            ]),
            by_cve: BTreeMap::new(), assets: BTreeMap::new(), unconfirmed: BTreeMap::new(),
            errors: BTreeMap::new(), rejected: BTreeMap::new(), truncated: vec![], registration: None,
        };
        let coords = BTreeMap::from([
            ("nginx@1.24.0".to_string(), "pkg:deb/ubuntu/nginx@1.24.0".to_string()),
            ("openssl@3.0.2".to_string(), "pkg:deb/ubuntu/openssl@3.0.2".to_string()),
        ]);
        let findings: Vec<HostFinding> = serde_json::from_value(json!([
            { "cveId": "cve-2024-1", "coordinate": "pkg:deb/ubuntu/nginx@1.24.0", "assetKey": "deb/nginx",
              "recordedDecision": { "id": "d1", "scope": "host", "verdict": "accept", "status": "active",
                                    "staleReasons": [], "until": null } },
            { "cveId": "CVE-2024-2", "coordinate": "pkg:deb/ubuntu/nginx@1.24.0",
              "recordedDecision": { "verdict": "accept", "status": "stale", "staleReasons": ["EPSS rose"] } },
            { "cveId": "CVE-2024-1", "coordinate": "pkg:deb/ubuntu/openssl@3.0.2", "recordedDecision": null }
        ])).unwrap();
        assert_eq!(results.apply_decisions_at(&coords, findings, 0), 2);

        let nginx = &results.services["nginx@1.24.0"];
        assert!(nginx[0].suppressed());
        assert!(nginx[1].recorded_decision.is_some() && !nginx[1].suppressed());
        assert!(results.services["openssl@3.0.2"][0].recorded_decision.is_none());

        let v = serde_json::to_value(&nginx[1]).unwrap();
        assert_eq!(v["recordedDecision"], json!({ "verdict": "accept", "status": "stale", "staleReasons": ["EPSS rose"], "suppressing": false }));
    }

    #[test]
    fn register_finding_decodes_print_fields() {
        let f: RegisterFinding = serde_json::from_value(json!({
            "cveId": "CVE-2024-1", "kev": true, "kevOverdue": true, "fixedVersions": ["1.2.3"],
            "radarUrl": "https://radar.offseq.com/threat/x", "coordinate": "pkg:npm/a@1"
        })).unwrap();
        assert!(f.kev && f.kev_overdue);
        assert_eq!(f.fixed_versions, vec!["1.2.3".to_string()]);
        assert_eq!(f.radar_url.as_deref(), Some("https://radar.offseq.com/threat/x"));
    }

    /// Serve one canned HTTP response on loopback; the handle yields the raw request.
    fn serve_once(response: String) -> (ThreatClient, std::thread::JoinHandle<String>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = ThreatClient::with_base("k", &format!("http://{}", listener.local_addr().unwrap()));
        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let (mut req, mut buf) = (Vec::new(), [0u8; 4096]);
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = sock.read(&mut buf).unwrap();
                if n == 0 { break; }
                req.extend_from_slice(&buf[..n]);
            }
            sock.write_all(response.as_bytes()).unwrap();
            String::from_utf8_lossy(&req).into_owned()
        });
        (client, handle)
    }

    #[test]
    fn host_vex_returns_the_raw_document() {
        let (client, server) = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 27\r\n\
             X-RateLimit-Limit-Hourly: 375\r\nConnection: close\r\n\r\n{\n  \"@context\": \"openvex\"\n}".to_string(),
        );
        let doc = client.host_vex("h-1", "cyclonedx").unwrap();
        assert_eq!(doc, b"{\n  \"@context\": \"openvex\"\n}");
        let req = server.join().unwrap();
        assert!(req.starts_with("GET /inventory/h-1/vex?format=cyclonedx "), "{req}");
        assert!(req.to_ascii_lowercase().contains("accept: */*"), "{req}");
        assert_eq!(client.last_rate_limit().limit_hourly, 375);
    }

    #[test]
    fn host_vex_on_free_plan_is_access_denied() {
        let body = r#"{"success":false,"error":"pro_access_required","message":"The decision ledger needs a paid plan (Individual and up)."}"#;
        let (client, server) = serve_once(format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ));
        match client.host_vex("h-1", "openvex") {
            Err(ThreatError::AccessDenied(msg)) => assert!(msg.contains("paid plan"), "{msg}"),
            other => panic!("expected AccessDenied, got {other:?}"),
        }
        server.join().unwrap();
    }

    #[test]
    fn search_path_reads_slug_and_remediation() {
        let t = json!({
            "cveId": "CVE-2024-8", "slug": "openssl-heartbleed",
            "fixedVersions": ["1.0.1g"], "cwes": ["CWE-125"],
            "remediation": "Upgrade OpenSSL."
        });
        let e = search_to_entry(&t);
        assert_eq!(e.radar_url.as_deref(), Some("https://radar.offseq.com/threat/openssl-heartbleed"));
        assert_eq!(e.fixed_versions, vec!["1.0.1g".to_string()]);
        assert_eq!(e.cwes, vec!["CWE-125".to_string()]);
        assert_eq!(e.remediation.as_deref(), Some("Upgrade OpenSSL."));
    }
}
