use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const BASE_URL: &str = "https://radar.offseq.com/api/v1";

const MAX_RETRIES: u32 = 4;
const BASE_BACKOFF_MS: u64 = 300;
const MAX_RETRY_AFTER_SECS: u64 = 30;
const MAX_PAGES: u32 = 50;
const USER_AGENT: &str = concat!("threat-finder/", env!("CARGO_PKG_VERSION"));

fn plan_name(limit_hourly: u64) -> String {
    match limit_hourly {
        15   => "Free".to_string(),
        50   => "Basic".to_string(),
        200  => "Pro".to_string(),
        1000 => "Enterprise".to_string(),
        n    => format!("Unknown ({n}/hr)"),
    }
}

#[derive(Debug, Clone, Default)]
pub struct RateLimitInfo {
    pub limit_hourly:      u64,
    pub remaining_hourly:  u64,
    pub limit_monthly:     u64,
    pub remaining_monthly: u64,
}

fn parse_header(headers: &reqwest::header::HeaderMap, name: &str) -> Option<u64> {
    headers.get(name)?.to_str().ok()?.parse().ok()
}

impl RateLimitInfo {
    /// Merge whatever rate-limit headers are present into `self`. Each header is
    /// parsed independently (a single missing one no longer discards the rest),
    /// and `remaining_*` counters only ever move DOWN, so a stale response that
    /// races in after a fresher one can't bump the remaining count back up.
    fn merge_from_headers(&mut self, headers: &reqwest::header::HeaderMap) {
        if let Some(v) = parse_header(headers, "X-RateLimit-Limit-Hourly") {
            self.limit_hourly = v;
        }
        if let Some(v) = parse_header(headers, "X-RateLimit-Limit-Monthly") {
            self.limit_monthly = v;
        }
        if let Some(v) = parse_header(headers, "X-RateLimit-Remaining-Hourly") {
            self.remaining_hourly = if self.remaining_hourly == 0 {
                v
            } else {
                self.remaining_hourly.min(v)
            };
        }
        if let Some(v) = parse_header(headers, "X-RateLimit-Remaining-Monthly") {
            self.remaining_monthly = if self.remaining_monthly == 0 {
                v
            } else {
                self.remaining_monthly.min(v)
            };
        }
    }
}

pub fn print_plan_info(info: &RateLimitInfo) {
    if info.limit_hourly == 0 {
        return;
    }
    println!("Plan:     {}", plan_name(info.limit_hourly));
    println!(
        "Hourly:   {:>6} / {:>6} remaining",
        format_num(info.remaining_hourly),
        format_num(info.limit_hourly)
    );
    println!(
        "Monthly:  {:>6} / {:>6} remaining",
        format_num(info.remaining_monthly),
        format_num(info.limit_monthly)
    );
    println!();
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
    Http(reqwest::Error),
    Other(String),
}

impl std::fmt::Display for ThreatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatError::RateLimitExceeded(msg) => write!(f, "Rate limit exceeded: {msg}"),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEntry {
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
    /// CISA Known-Exploited / exploited-in-the-wild flag.
    pub kev:                   bool,
    #[serde(rename = "publishedDate")]
    pub published_date:        Option<String>,
    #[serde(rename = "affectedVersions")]
    pub affected_versions:     Option<Value>,
    #[serde(rename = "patchAvailable")]
    pub patch_available:       Option<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references:            Vec<String>,
    /// Whether the target version is inside an affected range (report) vs a
    /// coordinate match whose version is unconfirmed (triage).
    #[serde(default)]
    pub confirmed:             bool,
    #[serde(rename = "matchedRange", skip_serializing_if = "Option::is_none")]
    pub matched_range:         Option<String>,
    /// How the API matched: coordinate | cpe | coordinate-unconfirmed | search-fallback.
    #[serde(rename = "matchBasis")]
    pub match_basis:           String,
}

impl ThreatEntry {
    fn severity_rank(&self) -> u8 {
        severity_rank(self.severity.as_deref())
    }

    fn cvss_num(&self) -> f64 {
        self.cvss_score.as_ref().and_then(|v| v.as_f64()).unwrap_or(0.0)
    }

    /// Highest-risk first: exploited-in-wild, then severity, EPSS, CVSS, CVE id.
    pub(crate) fn risk_key(&self) -> (bool, u8, i64, i64, String) {
        (
            self.kev,
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
        Meta { tool: "threat-finder", version: env!("CARGO_PKG_VERSION"), schema_version: 1 }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system:   Option<BTreeMap<String, Vec<ThreatEntry>>>,
    /// Per-service lookup failures (name -> error). Distinguishes "lookup failed"
    /// from "no CVEs found".
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub errors:   BTreeMap<String, String>,
}

impl BatchResults {
    pub fn total_vulns(&self) -> usize {
        let svc: usize = self.services.values().map(|v| v.len()).sum();
        let sys: usize = self.system.as_ref()
            .map(|m| m.values().map(|v| v.len()).sum())
            .unwrap_or(0);
        svc + sys
    }

    /// Roll findings up by CVE id across all services + system entries.
    pub fn compute_cve_groups(&mut self) {
        let mut groups: BTreeMap<String, CveGroup> = BTreeMap::new();
        let sources = self.services.iter().chain(self.system.iter().flatten());
        for (key, entries) in sources {
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
}

pub struct BatchOutcome {
    pub results: BTreeMap<String, Vec<ThreatEntry>>,
    pub unconfirmed: BTreeMap<String, Vec<ThreatEntry>>,
    pub errors:  BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct ServiceEntry {
    pub name:    String,
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub struct SystemInfo {
    pub kernel_name:    String,
    pub kernel_version: String,
    pub distro_name:    String,
    pub distro_version: String,
}

pub struct ThreatClient {
    client:         Client,
    api_key:        String,
    rate_limit:     Arc<Mutex<RateLimitInfo>>,
}

impl ThreatClient {
    pub fn new(api_key: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(8))
            .user_agent(USER_AGENT)
            .use_rustls_tls()
            .build()
            .expect("Failed to build HTTP client");

        ThreatClient {
            client,
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

    /// Execute a request (built fresh each attempt) with retry/backoff, lenient
    /// rate-limit header capture, Retry-After handling, and descriptive errors.
    /// Returns the parsed JSON body on 2xx.
    fn execute(
        &self,
        build: impl Fn() -> reqwest::blocking::RequestBuilder,
    ) -> Result<Value, ThreatError> {
        let mut attempt = 0u32;
        loop {
            let send_result = build()
                .header("X-API-Key", &self.api_key)
                .header("Accept", "application/json")
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
                let monthly_exhausted = self.rate_limit.lock()
                    .map(|i| i.limit_monthly > 0 && i.remaining_monthly == 0)
                    .unwrap_or(false);
                let retry_after = parse_header(response.headers(), "Retry-After");
                if !monthly_exhausted && attempt < MAX_RETRIES {
                    let wait = retry_after
                        .unwrap_or(1u64 << attempt.min(10))
                        .clamp(1, MAX_RETRY_AFTER_SECS);
                    std::thread::sleep(Duration::from_secs(wait));
                    attempt += 1;
                    continue;
                }
                let message = response.json::<Value>().ok()
                    .and_then(|b| error_message(&b))
                    .unwrap_or_else(|| "Rate limit exceeded.".to_string());
                return Err(ThreatError::RateLimitExceeded(message));
            }

            if status.is_server_error() && attempt < MAX_RETRIES {
                self.backoff_sleep(attempt);
                attempt += 1;
                continue;
            }

            if !status.is_success() {
                let code = status.as_u16();
                let body = response.text().unwrap_or_default();
                let mut msg = serde_json::from_str::<Value>(&body).ok()
                    .and_then(|b| error_message(&b))
                    .unwrap_or_else(|| {
                        if body.is_empty() {
                            format!("HTTP {code}")
                        } else {
                            format!("HTTP {code}: {}", body.chars().take(200).collect::<String>())
                        }
                    });
                if code == 401 || code == 403 {
                    msg = format!("{msg} (check your API key — re-run with --reset to re-enter it)");
                }
                return Err(ThreatError::Other(msg));
            }

            return response.json::<Value>().map_err(ThreatError::Http);
        }
    }

    fn get_json(&self, path: &str, params: &[(&str, String)]) -> Result<Value, ThreatError> {
        self.execute(|| self.client.get(format!("{BASE_URL}{path}")).query(params))
    }

    fn post_json<T: Serialize>(&self, path: &str, body: &T) -> Result<Value, ThreatError> {
        self.execute(|| self.client.post(format!("{BASE_URL}{path}")).json(body))
    }

    /// Match a whole inventory by exact coordinate in one POST per tier-sized
    /// chunk. Results are positionally aligned to `queries` (guarded per chunk).
    pub fn match_batch(
        &self,
        queries: &[MatchQuery],
        strict: bool,
    ) -> Result<Vec<MatchResult>, ThreatError> {
        let cap = tier_batch_cap(self.last_rate_limit().limit_hourly);
        let mut out: Vec<MatchResult> = Vec::with_capacity(queries.len());
        for chunk in queries.chunks(cap) {
            let body = MatchBatchRequest { queries: chunk, strict };
            let json = self.post_json("/match/batch", &body)?;
            let parsed: MatchBatchResponse = serde_json::from_value(json)
                .map_err(|e| ThreatError::Other(format!("match/batch decode error: {e}")))?;
            if parsed.data.results.len() != chunk.len() {
                return Err(ThreatError::Other(format!(
                    "match/batch alignment error: sent {} queries, got {} results",
                    chunk.len(), parsed.data.results.len()
                )));
            }
            out.extend(parsed.data.results);
        }
        Ok(out)
    }

    /// GET ?search= fallback for assets with no buildable coordinate. Returns
    /// raw threat objects (no client-side version comparison — they are surfaced
    /// as unconfirmed/triage).
    pub fn search_threats(&self, service: &str, limit: usize) -> Result<Vec<Value>, ThreatError> {
        let mut all_threats: Vec<Value> = Vec::new();
        let mut seen_ids: HashSet<String> = HashSet::new();
        let mut page = 1u32;
        loop {
            let params = vec![
                ("search", service.to_string()),
                ("limit", limit.to_string()),
                ("page", page.to_string()),
            ];
            let data = self.get_json("/threats", &params)?;
            let threats = match data.get("data").and_then(|d| d.get("threats")).and_then(|t| t.as_array()) {
                Some(t) => t.clone(),
                None => break,
            };
            if threats.is_empty() {
                break;
            }
            let page_len = threats.len();
            let mut added = 0usize;
            for threat in threats {
                if seen_ids.insert(threat_id(&threat)) {
                    all_threats.push(threat);
                    added += 1;
                }
            }
            if page_len < limit || added == 0 || page >= MAX_PAGES {
                break;
            }
            page += 1;
        }
        Ok(all_threats)
    }
}

fn error_message(body: &Value) -> Option<String> {
    body.get("message")
        .or_else(|| body.get("error"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

// ── Match API (exact coordinate) ─────────────────────────────────────────────

/// Per-request batch-size cap by tier, derived from the hourly rate-limit.
/// Distinct from the hourly quota; defaults to the smallest until a header seen.
fn tier_batch_cap(limit_hourly: u64) -> usize {
    match limit_hourly {
        1000 => 4000, // enterprise
        200 => 1000,  // pro
        50 => 200,    // basic
        _ => 25,      // free / unknown
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
#[derive(Debug, Deserialize)]
pub struct MatchResult {
    #[serde(default)]
    pub matches: Vec<MatchHit>,
}

/// One CVE match. Field names follow the maintainer-provided contract; if the
/// live /match/help differs, only these `rename`s need adjusting.
#[derive(Debug, Deserialize)]
pub struct MatchHit {
    #[serde(rename = "cveId")] pub cve_id: Option<String>,
    pub title: Option<String>,
    pub severity: Option<String>,
    #[serde(rename = "cvssScore")] pub cvss_score: Option<Value>,
    #[serde(default)] pub epss: Option<f64>,
    #[serde(default)] pub kev: bool,
    #[serde(rename = "knownExploitsInWild", default)] pub known_exploits_in_wild: Option<Value>,
    #[serde(rename = "matchBasis")] pub match_basis: Option<String>,
    #[serde(rename = "matchedRange")] pub matched_range: Option<String>,
    #[serde(default)] pub confirmed: bool,
    #[serde(default)] pub references: Vec<Value>,
}

fn truthy(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bool(true))) || v.and_then(|x| x.as_str()) == Some("true")
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
    let kev = m.kev || truthy(m.known_exploits_in_wild.as_ref());
    ThreatEntry {
        cve_id: m.cve_id,
        title: m.title,
        severity: m.severity,
        cvss_score: m.cvss_score,
        cvss_vector: None,
        epss: m.epss,
        kev,
        published_date: None,
        affected_versions: None,
        patch_available: None,
        references: refs_to_strings(&m.references),
        confirmed: m.confirmed,
        matched_range: m.matched_range,
        match_basis: m.match_basis.unwrap_or_else(|| "coordinate".to_string()),
    }
}

/// Convert a raw ?search= threat into an (unconfirmed) ThreatEntry.
pub fn search_to_entry(t: &Value) -> ThreatEntry {
    let cve_id = t.get("cveId").or_else(|| t.get("externalId"))
        .and_then(|v| v.as_str()).map(|s| s.to_string());
    let references = t.get("references").and_then(|r| r.as_array())
        .map(|arr| refs_to_strings(arr)).unwrap_or_default();
    ThreatEntry {
        cve_id,
        title: t.get("title").and_then(|v| v.as_str()).map(|s| s.to_string()),
        severity: t.get("severity").and_then(|v| v.as_str()).map(|s| s.to_string()),
        cvss_score: t.get("cvssScore").cloned(),
        cvss_vector: t.get("cvssVector").and_then(|v| v.as_str()).map(|s| s.to_string()),
        epss: t.get("epss").and_then(|v| v.as_f64()),
        kev: truthy(t.get("knownExploitsInWild")),
        published_date: Some(clean_date(t.get("publishedDate"))),
        affected_versions: t.get("affectedVersions").cloned(),
        patch_available: t.get("patchAvailable").cloned(),
        references,
        confirmed: false,
        matched_range: None,
        match_basis: "search-fallback".to_string(),
    }
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
    fn batch_cap_by_tier() {
        assert_eq!(tier_batch_cap(0), 25);
        assert_eq!(tier_batch_cap(15), 25);
        assert_eq!(tier_batch_cap(50), 200);
        assert_eq!(tier_batch_cap(200), 1000);
        assert_eq!(tier_batch_cap(1000), 4000);
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
        assert!(e.kev);
    }
}
