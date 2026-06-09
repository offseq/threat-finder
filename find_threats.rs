use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use once_cell::sync::Lazy;
use rayon::prelude::*;
use regex::Regex;
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

#[derive(Debug, Serialize, Deserialize)]
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
    /// Whether the match came from a structured constraint or the free-text fallback.
    #[serde(rename = "matchBasis")]
    pub match_basis:           MatchBasis,
}

impl ThreatEntry {
    fn severity_rank(&self) -> u8 {
        match self.severity.as_deref().map(str::to_lowercase).as_deref() {
            Some("critical") => 4,
            Some("high")     => 3,
            Some("medium")   => 2,
            Some("low")      => 1,
            _                => 0,
        }
    }

    fn cvss_num(&self) -> f64 {
        self.cvss_score.as_ref().and_then(|v| v.as_f64()).unwrap_or(0.0)
    }

    /// Highest-risk first: exploited-in-wild, then severity, EPSS, CVSS, CVE id.
    fn risk_key(&self) -> (bool, u8, i64, i64, String) {
        (
            self.kev,
            self.severity_rank(),
            (self.epss.unwrap_or(0.0) * 1000.0) as i64,
            (self.cvss_num() * 100.0) as i64,
            self.cve_id.clone().unwrap_or_default(),
        )
    }
}

/// How a threat was matched to the target version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchBasis {
    Constraint,
    FreeText,
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub listeners: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct BatchResults {
    pub services: BTreeMap<String, Vec<ThreatEntry>>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub assets:   BTreeMap<String, AssetInfo>,
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
}

pub struct BatchOutcome {
    pub results: BTreeMap<String, Vec<ThreatEntry>>,
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

    // Single paginated GET, with retry/backoff for transient failures and
    // Retry-After handling for rate-limit bursts.
    fn fetch_page(
        &self,
        params: &[(&str, String)],
    ) -> Result<Value, ThreatError> {
        let mut attempt = 0u32;
        loop {
            let send_result = self.client
                .get(format!("{BASE_URL}/threats"))
                .header("X-API-Key", &self.api_key)
                .header("Accept", "application/json")
                .query(params)
                .send();

            let response = match send_result {
                Ok(r) => r,
                Err(e) => {
                    // Retry transient connect/timeout errors.
                    if attempt < MAX_RETRIES && (e.is_timeout() || e.is_connect() || e.is_request()) {
                        self.backoff_sleep(attempt);
                        attempt += 1;
                        continue;
                    }
                    return Err(ThreatError::Http(e));
                }
            };

            let status = response.status();

            // Record whatever rate-limit headers came back (leniently).
            if let Ok(mut info) = self.rate_limit.lock() {
                info.merge_from_headers(response.headers());
            }

            if status.as_u16() == 429 {
                // Burst vs. exhaustion: if the monthly quota is truly spent,
                // give up immediately; otherwise honor Retry-After and retry.
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
                    .and_then(|b| {
                        b.get("message")
                            .or_else(|| b.get("error"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_else(|| "Rate limit exceeded.".to_string());
                return Err(ThreatError::RateLimitExceeded(message));
            }

            // Retry transient server errors.
            if status.is_server_error() && attempt < MAX_RETRIES {
                self.backoff_sleep(attempt);
                attempt += 1;
                continue;
            }

            // Other non-2xx: read the body so the error is descriptive.
            if !status.is_success() {
                let code = status.as_u16();
                let body = response.text().unwrap_or_default();
                let mut msg = serde_json::from_str::<Value>(&body).ok()
                    .and_then(|b| {
                        b.get("message")
                            .or_else(|| b.get("error"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    })
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

    pub fn fetch_all_service_threats(
        &self,
        service: &str,
        limit:   usize,
        severity:     Option<&str>,
        threat_type:  Option<&str>,
        days:         Option<u32>,
    ) -> Result<Vec<Value>, ThreatError> {
        let mut all_threats: Vec<Value> = Vec::new();
        let mut seen_ids: HashSet<String> = HashSet::new();
        let mut page = 1u32;

        loop {
            let mut params: Vec<(&str, String)> = vec![
                ("search", service.to_string()),
                ("limit",  limit.to_string()),
                ("page",   page.to_string()),
            ];

            if let Some(s) = severity    { params.push(("severity", s.to_string())); }
            if let Some(t) = threat_type { params.push(("type",     t.to_string())); }
            if let Some(d) = days        { params.push(("days",     d.to_string())); }

            let data = self.fetch_page(&params)?;
            let threats = match data
                .get("data")
                .and_then(|d| d.get("threats"))
                .and_then(|t| t.as_array())
            {
                Some(t) => t.clone(),
                None    => break,
            };

            if threats.is_empty() {
                break;
            }

            let page_len = threats.len();

            let mut added = 0usize;
            for threat in threats {
                let id = threat_id(&threat);
                if seen_ids.insert(id) {
                    all_threats.push(threat);
                    added += 1;
                }
            }

            // Stop on a short page (last page) or when a full page contributed
            // nothing new — the latter catches a server that ignores `page` and
            // re-serves the same data, which would otherwise loop forever.
            if page_len < limit || added == 0 || page >= MAX_PAGES {
                break;
            }

            page += 1;
        }

        // Extra safety, confirm each result actually matches the service
        let matched: Vec<Value> = all_threats
            .into_iter()
            .filter(|t| threat_matches_service(t, service))
            .collect();

        Ok(matched)
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

// Version parsing
//
// `Version` keeps every numeric component (not just major.minor.patch) and
// compares them numerically with implicit trailing zeros, so 1.2 == 1.2.0 and
// 1.20 > 1.2 — the old (u64,u64,u64) tuple silently dropped a 4th component and
// mis-ordered everything past patch. A Debian/RPM epoch prefix ("1:2.3.4") is
// stripped before parsing so it doesn't get read as a major version of 1.

static VERSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\d+(?:\.\d+)*").unwrap());

// A leading "<digits>:" epoch, e.g. the "1:" in "1:2.3.4-1".
static EPOCH_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*\d+:").unwrap());

#[derive(Debug, Clone)]
pub struct Version(Vec<u64>);

impl Version {
    /// Parse the first dotted numeric run in `text` (after stripping any epoch).
    fn parse(text: &str) -> Option<Version> {
        let stripped = EPOCH_RE.replace(text, "");
        let m = VERSION_RE.find(&stripped)?;
        // VERSION_RE only yields digit runs, so the only parse failure is u64
        // overflow — saturate rather than drop, since dropping a component would
        // corrupt ordering (e.g. "1.<huge>.3" must not collapse to [1, 3]).
        let parts: Vec<u64> = m.as_str()
            .split('.')
            .map(|p| p.parse::<u64>().unwrap_or(u64::MAX))
            .collect();
        if parts.is_empty() { None } else { Some(Version(parts)) }
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let n = self.0.len().max(other.0.len());
        for i in 0..n {
            let a = self.0.get(i).copied().unwrap_or(0);
            let b = other.0.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                std::cmp::Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// Eq is defined in terms of Ord so that 1.2 == 1.2.0 (zero-padded), keeping the
// two consistent — a derived element-wise PartialEq would disagree with Ord.
impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for Version {}

fn parse_version(text: &str) -> Option<Version> {
    Version::parse(text)
}

/// True if `needle` appears in `haystack` as a standalone version token, i.e.
/// not glued to surrounding digits or dots. Prevents "1.2" from matching inside
/// "1.20" or "11.2.3".
fn contains_version_token(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let bytes = haystack.as_bytes();
    let nlen = needle.len();
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(needle) {
        let i = start + pos;
        let before_ok = i == 0 || !matches!(bytes[i - 1], b'0'..=b'9' | b'.');
        let after = i + nlen;
        let after_ok = after >= bytes.len() || !matches!(bytes[after], b'0'..=b'9' | b'.');
        if before_ok && after_ok {
            return true;
        }
        // Advance past the whole match (a guaranteed char boundary) — i+1 could
        // land mid-codepoint and panic the next slice on a multibyte needle.
        start = i + nlen;
    }
    false
}

fn clean_date(value: Option<&Value>) -> String {
    match value.and_then(|v| v.as_str()) {
        Some(s) => s.split('T').next().unwrap_or("N/A").to_string(),
        None    => "N/A".to_string(),
    }
}

fn normalize_name(s: &str) -> String {
    s.to_lowercase().trim().to_string()
}

fn collect_text_values(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => vec![s.clone()],
        Value::Array(arr) => arr.iter().flat_map(collect_text_values).collect(),
        Value::Object(map) => map.values().flat_map(collect_text_values).collect(),
        _ => vec![],
    }
}

fn get_enrichment_text(threat: &Value) -> String {
    let enrichment = threat.get("enrichment").cloned().unwrap_or(Value::Object(Default::default()));
    collect_text_values(&enrichment).join("\n")
}

// Standalone word boundary check

// NOTE: the Rust `regex` crate does not support look-around, so the previous
// `(?<![a-z0-9_-])…(?![a-z0-9_-])` pattern failed to compile at runtime and this
// function always returned false — silently disabling all word-boundary product
// and title matching. This manual scan restores it with no regex at all.
fn contains_standalone_service(text: &str, service: &str) -> bool {
    let text = text.to_lowercase();
    let service = service.to_lowercase();
    if service.is_empty() {
        return false;
    }
    let bytes = text.as_bytes();
    let slen = service.len();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    let mut start = 0;
    while let Some(pos) = text[start..].find(&service) {
        let i = start + pos;
        let before_ok = i == 0 || !is_word(bytes[i - 1]);
        let after = i + slen;
        let after_ok = after >= bytes.len() || !is_word(bytes[after]);
        if before_ok && after_ok {
            return true;
        }
        // Advance past the whole match (char boundary) to stay UTF-8-safe.
        start = i + slen;
    }
    false
}

fn threat_matches_service(threat: &Value, service: &str) -> bool {
    let service = normalize_name(service);

    let vendor  = str_field(threat, "vendorProject");
    let product = str_field(threat, "product");
    let title   = str_field(threat, "title");
    let desc    = str_field(threat, "description");
    let enrich  = get_enrichment_text(threat).to_lowercase();

    if product == service { return true; }
    if vendor == service && product.is_empty() { return true; }
    if contains_standalone_service(&product, &service) { return true; }

    // nginx false-positive guard
    if service == "nginx" {
        let blocked = [
            "nginx-ui", "nginx ui", "nginx plus",
            "nginx javascript", "nginx proxy manager",
        ];
        let combined = format!("{vendor} {product} {title}");
        if blocked.iter().any(|b| combined.contains(b))
            && !enrich.contains("nginx open source")
            && !desc.contains("nginx open source")
        {
            return false;
        }
    }

    // Fallback for records with missing product field
    let product_missing = matches!(product.as_str(), "" | "n/a" | "unknown" | "none");

    if product_missing {
        let strong_text = format!("{title}\n{desc}\n{enrich}");
        let phrases = [
            format!("{service} versions"),
            format!("{service} open source"),
            format!("affects {service}"),
            format!("affecting {service}"),
            format!("in {service}"),
            format!("{service}'s"),
        ];
        if phrases.iter().any(|p| strong_text.contains(p.as_str())) {
            return true;
        }
        if contains_standalone_service(&title, &service) {
            return true;
        }
    }

    false
}

fn str_field(threat: &Value, key: &str) -> String {
    threat.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase()
        .trim()
        .to_string()
}

// Free-text version-range fallback
//
// Used ONLY when affectedVersions has no usable structured constraints. Scans
// description/enrichment prose for version ranges. Lower confidence than the
// structured matcher, but better than nothing for sparse records. Patterns are
// compiled once into Lazy statics instead of on every call across rayon threads.

static RANGE_RES: Lazy<Vec<Regex>> = Lazy::new(|| {
    [
        r"versions?\s+(\d+(?:\.\d+){1,3})\s+through\s+(\d+(?:\.\d+){1,3})",
        r"versions?\s+(\d+(?:\.\d+){1,3})\s+to\s+(\d+(?:\.\d+){1,3})",
        r"versions?\s+(\d+(?:\.\d+){1,3})\s*-\s*(\d+(?:\.\d+){1,3})",
        r"from\s+(\d+(?:\.\d+){1,3})\s+through\s+(\d+(?:\.\d+){1,3})",
        r"from\s+(\d+(?:\.\d+){1,3})\s+to\s+(\d+(?:\.\d+){1,3})",
    ].iter().map(|p| Regex::new(p).unwrap()).collect()
});

static UPPER_EXCL_RES: Lazy<Vec<Regex>> = Lazy::new(|| {
    [
        r"prior to version\s+(\d+(?:\.\d+){1,3})",
        r"prior to\s+(\d+(?:\.\d+){1,3})",
        r"before\s+(\d+(?:\.\d+){1,3})",
        r"<\s*(\d+(?:\.\d+){1,3})",
    ].iter().map(|p| Regex::new(p).unwrap()).collect()
});

static UPPER_INCL_RES: Lazy<Vec<Regex>> = Lazy::new(|| {
    [
        r"up to\s+(\d+(?:\.\d+){1,3})",
        r"through\s+(\d+(?:\.\d+){1,3})",
        r"<=\s*(\d+(?:\.\d+){1,3})",
    ].iter().map(|p| Regex::new(p).unwrap()).collect()
});

fn text_mentions_affected_version_range(text: &str, target: &Version, target_raw: &str) -> bool {
    let text = text.to_lowercase();

    // Direct, boundary-anchored mention (so 1.2 does not match inside 1.20).
    if contains_version_token(&text, target_raw.to_lowercase().trim()) {
        return true;
    }

    for re in RANGE_RES.iter() {
        if let Some(caps) = re.captures(&text) {
            if let (Some(lo), Some(hi)) = (parse_version(&caps[1]), parse_version(&caps[2])) {
                if &lo <= target && target <= &hi {
                    return true;
                }
            }
        }
    }
    for re in UPPER_EXCL_RES.iter() {
        if let Some(caps) = re.captures(&text) {
            if let Some(hi) = parse_version(&caps[1]) {
                if target < &hi {
                    return true;
                }
            }
        }
    }
    for re in UPPER_INCL_RES.iter() {
        if let Some(caps) = re.captures(&text) {
            if let Some(hi) = parse_version(&caps[1]) {
                if target <= &hi {
                    return true;
                }
            }
        }
    }
    false
}

// Structured affectedVersions constraint matching
//
// The API returns affectedVersions as an array of constraint strings:
//   "*"               all versions affected (always matches)
//   "=1.2.3"          exactly this version
//   "<2.4.49"         strictly before (encodes "fixed in 2.4.49")
//   "<=2.4.48"        up to and including
//   ">=2.0.0"         this version and later
//   ">2.0.0"          strictly after
//   ">=2.0.0 <2.5.2"  compound: AND of all space-separated comparators
// Each array element is the AND of its comparators; the array is the OR of its
// elements (a version is affected if it satisfies ANY element).

#[derive(Debug, Clone)]
enum Comparator {
    Wildcard,
    Eq(Version),
    Lt(Version),
    Le(Version),
    Gt(Version),
    Ge(Version),
}

impl Comparator {
    fn matches(&self, target: &Version) -> bool {
        match self {
            Comparator::Wildcard => true,
            Comparator::Eq(v) => target == v,
            Comparator::Lt(v) => target < v,
            Comparator::Le(v) => target <= v,
            Comparator::Gt(v) => target > v,
            Comparator::Ge(v) => target >= v,
        }
    }
}

/// Parse a single comparator token like "<=2.4.48" or "*". Two-char operators
/// are tested before single-char ones. A bare version (no operator) is treated
/// as an exact match. Returns None when no version parses out of the token.
fn parse_comparator(token: &str) -> Option<Comparator> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    if token == "*" {
        return Some(Comparator::Wildcard);
    }
    let (build, rest): (fn(Version) -> Comparator, &str) =
        if let Some(r) = token.strip_prefix(">=") {
            (Comparator::Ge, r)
        } else if let Some(r) = token.strip_prefix("<=") {
            (Comparator::Le, r)
        } else if let Some(r) = token.strip_prefix('>') {
            (Comparator::Gt, r)
        } else if let Some(r) = token.strip_prefix('<') {
            (Comparator::Lt, r)
        } else if let Some(r) = token.strip_prefix('=') {
            (Comparator::Eq, r)
        } else {
            (Comparator::Eq, token)
        };
    Version::parse(rest).map(build)
}

/// Parse one affectedVersions element into its AND-ed comparators. Fail-closed:
/// if ANY whitespace-separated token fails to parse, the whole element is
/// rejected (None) rather than silently evaluating the survivors — that avoids
/// ">=2.0.0 garbage" over-matching as just ">=2.0.0".
fn parse_element(element: &str) -> Option<Vec<Comparator>> {
    let tokens: Vec<&str> = element.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }
    let mut comparators = Vec::with_capacity(tokens.len());
    for tok in tokens {
        comparators.push(parse_comparator(tok)?);
    }
    Some(comparators)
}

/// Evaluate one affectedVersions element (the AND of its comparators). Returns
/// None when the element is not a valid structured constraint.
fn element_matches(element: &str, target: &Version) -> Option<bool> {
    let comparators = parse_element(element)?;
    Some(comparators.iter().all(|c| c.matches(target)))
}

/// True if any element of an affectedVersions array is a usable structured
/// constraint (used to decide policy when the target version can't be parsed).
fn has_structured_constraint(arr: &[Value]) -> bool {
    arr.iter()
        .filter_map(|el| el.as_str())
        .any(|s| parse_element(s.trim()).is_some())
}

/// True if any element is the wildcard "*".
fn has_wildcard(arr: &[Value]) -> bool {
    arr.iter()
        .filter_map(|el| el.as_str())
        .any(|s| s.trim() == "*")
}

/// Decide whether a threat applies to `target_version`, returning HOW it matched
/// (structured constraint vs free-text fallback) or None for no match.
fn match_version(threat: &Value, target_version: &str) -> Option<MatchBasis> {
    let affected_arr = threat.get("affectedVersions").and_then(|v| v.as_array());

    let freetext_match = |t: &Value, raw: &str, parsed: Option<&Version>| -> Option<MatchBasis> {
        let desc = str_field(t, "description");
        let enrich = get_enrichment_text(t);
        let combined = format!("{desc}\n{enrich}");
        let hit = match parsed {
            Some(v) => text_mentions_affected_version_range(&combined, v, raw),
            None => !combined.trim().is_empty()
                && contains_version_token(&combined.to_lowercase(), raw.to_lowercase().trim()),
        };
        hit.then_some(MatchBasis::FreeText)
    };

    let target = match parse_version(target_version) {
        Some(v) => v,
        None => {
            if let Some(arr) = affected_arr {
                if has_wildcard(arr) {
                    return Some(MatchBasis::Constraint);
                }
                if has_structured_constraint(arr) {
                    return None;
                }
            }
            return freetext_match(threat, target_version, None);
        }
    };

    if let Some(arr) = affected_arr {
        let mut saw_parseable = false;
        for el in arr {
            let Some(s) = el.as_str() else { continue };
            let s = s.trim();
            if s.is_empty()
                || matches!(s.to_lowercase().as_str(), "unspecified" | "n/a" | "unknown")
            {
                continue;
            }
            match element_matches(s, &target) {
                Some(true) => return Some(MatchBasis::Constraint),
                Some(false) => saw_parseable = true,
                None => {}
            }
        }
        if saw_parseable {
            return None;
        }
    }

    freetext_match(threat, target_version, Some(&target))
}

fn to_entry(t: &Value, basis: MatchBasis) -> ThreatEntry {
    let cve_id = t.get("cveId")
        .or_else(|| t.get("externalId"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let references: Vec<String> = t.get("references")
        .and_then(|r| r.as_array())
        .map(|arr| arr.iter()
            .filter_map(|r| {
                r.get("url").and_then(|u| u.as_str())
                    .or_else(|| r.as_str())
                    .map(|s| s.to_string())
            })
            .collect())
        .unwrap_or_default();

    let kev = t.get("knownExploitsInWild")
        .map(|v| matches!(v, Value::Bool(true)) || v.as_str() == Some("true"))
        .unwrap_or(false);

    let epss = t.get("epss").and_then(|v| {
        v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    });

    ThreatEntry {
        cve_id,
        title:             t.get("title").and_then(|v| v.as_str()).map(|s| s.to_string()),
        severity:          t.get("severity").and_then(|v| v.as_str()).map(|s| s.to_string()),
        cvss_score:        t.get("cvssScore").cloned(),
        cvss_vector:       t.get("cvssVector").and_then(|v| v.as_str()).map(|s| s.to_string()),
        epss,
        kev,
        published_date:    Some(clean_date(t.get("publishedDate"))),
        affected_versions: t.get("affectedVersions").cloned(),
        patch_available:   t.get("patchAvailable").cloned(),
        references,
        match_basis:       basis,
    }
}

/// Run a batch lookup for a list of services concurrently.
///
/// Network fetches are deduplicated by service name (so apache2 and httpd, which
/// both normalize to "apache", cost one request not two — important against a
/// 15/hr free-tier quota), then version filtering is applied per entry locally.
/// Per-service failures are collected instead of being silently turned into an
/// empty (and falsely reassuring) "no CVEs" result.
pub fn run_batch(
    client:      &Arc<ThreatClient>,
    services:    &[ServiceEntry],
    limit:       usize,
    severity:    Option<&str>,
    threat_type: Option<&str>,
    days:        Option<u32>,
) -> Result<BatchOutcome, ThreatError> {
    // Unique service names, preserving first-seen order.
    let mut unique_names: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for entry in services {
        if seen.insert(entry.name.clone()) {
            unique_names.push(entry.name.clone());
        }
    }

    let rate_limit_err: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let errors: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

    // Size the pool to the work (I/O-bound), capped to avoid hammering the API.
    let threads = unique_names.len().clamp(1, 8);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|e| ThreatError::Other(e.to_string()))?;

    // One fetch per unique name.
    let fetched: HashMap<String, Vec<Value>> = pool.install(|| {
        unique_names.par_iter().filter_map(|name| {
            if rate_limit_err.lock().unwrap().is_some() {
                return None;
            }
            match client.fetch_all_service_threats(name, limit, severity, threat_type, days) {
                Ok(threats) => Some((name.clone(), threats)),
                Err(ThreatError::RateLimitExceeded(msg)) => {
                    *rate_limit_err.lock().unwrap() = Some(msg);
                    None
                }
                Err(e) => {
                    eprintln!("[!] lookup failed for '{name}': {e}");
                    errors.lock().unwrap().insert(name.clone(), e.to_string());
                    None
                }
            }
        }).collect()
    });

    if let Some(msg) = rate_limit_err.lock().unwrap().take() {
        return Err(ThreatError::RateLimitExceeded(msg));
    }

    // Apply per-entry version filtering against the deduped fetch cache.
    let mut results: BTreeMap<String, Vec<ThreatEntry>> = BTreeMap::new();
    for entry in services {
        let key = format!("{}@{}", entry.name, entry.version);
        let filtered = match fetched.get(&entry.name) {
            Some(threats) => matched_entries(threats, &entry.version),
            None => vec![],
        };
        results.insert(key, filtered);
    }

    let errors: BTreeMap<String, String> = Arc::try_unwrap(errors)
        .map(|m| m.into_inner().unwrap_or_default())
        .unwrap_or_default()
        .into_iter()
        .collect();

    Ok(BatchOutcome { results, errors })
}

/// Filter a service's threats to those matching `version`, convert to entries,
/// and sort highest-risk first (deterministic and diff-stable).
fn matched_entries(threats: &[Value], version: &str) -> Vec<ThreatEntry> {
    let mut entries: Vec<ThreatEntry> = threats.iter()
        .filter_map(|t| match_version(t, version).map(|basis| to_entry(t, basis)))
        .collect();
    entries.sort_by_key(|e| std::cmp::Reverse(e.risk_key()));
    entries
}

pub fn run_system_lookup(
    client:      &Arc<ThreatClient>,
    system_info: &SystemInfo,
    limit:       usize,
    severity:    Option<&str>,
    threat_type: Option<&str>,
    days:        Option<u32>,
) -> Result<BTreeMap<String, Vec<ThreatEntry>>, ThreatError> {
    let mut results = BTreeMap::new();

    let lookups = [
        (&system_info.kernel_name, &system_info.kernel_version),
        (&system_info.distro_name, &system_info.distro_version),
    ];

    let mut seen: HashSet<&str> = HashSet::new();
    let unique: Vec<_> = lookups.iter()
        .filter(|(name, version)| {
            !name.is_empty() && !version.is_empty() && seen.insert(name.as_str())
        })
        .collect();

    for (name, version) in unique {
        let threats = client.fetch_all_service_threats(
            name, limit, severity, threat_type, days,
        )?;
        results.insert(format!("{name}@{version}"), matched_entries(&threats, version));
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ver(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn version_zero_pads_and_orders() {
        assert_eq!(ver("1.2"), ver("1.2.0"));
        assert!(ver("1.20") > ver("1.2"));
        assert!(ver("1.2.3") < ver("1.2.10"));
        assert!(ver("2.0") > ver("1.999.999"));
        // distro epoch is stripped, not read as a major component
        assert_eq!(ver("1:2.3.4"), ver("2.3.4"));
        // distro revision suffix is dropped to the upstream version
        assert_eq!(ver("1.2.3-4ubuntu5"), ver("1.2.3"));
    }

    // One affectedVersions element vs a target -> Some(matched)/None(malformed).
    fn el(constraint: &str, target: &str) -> Option<bool> {
        element_matches(constraint, &ver(target))
    }

    #[test]
    fn constraint_grammar() {
        // wildcard
        assert_eq!(el("*", "9.9.9"), Some(true));
        // exact
        assert_eq!(el("=1.2.3", "1.2.3"), Some(true));
        assert_eq!(el("=1.2.3", "1.2.4"), Some(false));
        // strictly before (fixed-in semantics): boundary excluded
        assert_eq!(el("<2.4.49", "2.4.48"), Some(true));
        assert_eq!(el("<2.4.49", "2.4.49"), Some(false));
        assert_eq!(el("<2.4.49", "2.4.50"), Some(false));
        // up to and including: boundary included
        assert_eq!(el("<=2.4.48", "2.4.48"), Some(true));
        assert_eq!(el("<=2.4.48", "2.4.49"), Some(false));
        // at-or-after / after
        assert_eq!(el(">=2.0.0", "2.0.0"), Some(true));
        assert_eq!(el(">=2.0.0", "1.9.9"), Some(false));
        assert_eq!(el(">2.0.0", "2.0.0"), Some(false));
        assert_eq!(el(">2.0.0", "2.0.1"), Some(true));
        // compound range: [2.0.0, 2.5.2)
        assert_eq!(el(">=2.0.0 <2.5.2", "2.0.0"), Some(true));
        assert_eq!(el(">=2.0.0 <2.5.2", "2.5.1"), Some(true));
        assert_eq!(el(">=2.0.0 <2.5.2", "2.5.2"), Some(false));
        assert_eq!(el(">=2.0.0 <2.5.2", "1.9.9"), Some(false));
        // compound inclusive range: [3.0.0, 3.4.2]
        assert_eq!(el(">=3.0.0 <=3.4.2", "3.4.2"), Some(true));
        assert_eq!(el(">=3.0.0 <=3.4.2", "3.4.3"), Some(false));
        // component-count mismatch (zero-padded compare)
        assert_eq!(el("<2.5", "2.4.9"), Some(true));
        assert_eq!(el("<2.5", "2.5.0"), Some(false));
        // distro-style target compared against a numeric constraint
        assert_eq!(el("<2.4.49", "2.4.48-1ubuntu0.1"), Some(true));
        // malformed element -> None
        assert_eq!(el("not-a-version", "1.0.0"), None);
        assert_eq!(el("", "1.0.0"), None);
    }

    fn matches(t: &Value, v: &str) -> bool {
        match_version(t, v).is_some()
    }

    #[test]
    fn threat_matches_version_or_across_array() {
        let t = json!({ "affectedVersions": [">=2.0.0 <2.5.2", "=3.1.0"] });
        assert_eq!(match_version(&t, "2.3.0"), Some(MatchBasis::Constraint));
        assert!(matches(&t, "3.1.0"));
        assert!(!matches(&t, "2.5.2"));
        assert!(!matches(&t, "4.0.0"));

        let all = json!({ "affectedVersions": ["*"] });
        assert!(matches(&all, "0.0.1"));

        // fail-closed: a malformed token poisons the whole element
        let poisoned = json!({ "affectedVersions": [">=2.0.0 garbage"] });
        assert!(!matches(&poisoned, "2.1.0"));
    }

    #[test]
    fn unparseable_target_policy() {
        let wild = json!({ "affectedVersions": ["*"] });
        assert!(matches(&wild, "not-a-version"));
        let structured = json!({ "affectedVersions": ["=1.2.3"] });
        assert!(!matches(&structured, "not-a-version"));
        let structured2 = json!({ "affectedVersions": ["<1.0.0"] });
        assert!(!matches(&structured2, "not-a-version"));
    }

    #[test]
    fn freetext_fallback_basis() {
        // No structured affectedVersions, but the description names the version.
        let t = json!({ "description": "Affects Foo before 2.0.0 only." });
        assert_eq!(match_version(&t, "1.5.0"), Some(MatchBasis::FreeText));
    }

    #[test]
    fn data_driven_vectors() {
        // (constraint element, target, expected)
        let cases: &[(&str, &str, bool)] = &[
            ("*", "1.2.3", true),
            ("*", "9.9.9-2ubuntu1", true),
            ("=1.2.3", "1.2.3", true),
            ("=1.2.3", "1.2.4", false),
            ("=1.2.3", "1.2.30", false),
            ("=1.2", "1.2.0", true),
            ("=1.2.0", "1.2", true),
            ("<2.4.49", "2.4.48", true),
            ("<2.4.49", "2.4.49", false),
            ("<2.4.49", "2.4.50", false),
            ("<2.4.49", "1.0.0", true),
            ("<=2.4.48", "2.4.48", true),
            ("<=2.4.48", "2.4.49", false),
            ("<=2.4.48", "2.4.47", true),
            (">=2.0.0", "2.0.0", true),
            (">=2.0.0", "1.9.9", false),
            (">=2.0.0", "2.0.1", true),
            (">2.0.0", "2.0.0", false),
            (">2.0.0", "2.0.1", true),
            (">2.0.0", "1.5.0", false),
            (">=2.0.0 <2.5.2", "2.0.0", true),
            (">=2.0.0 <2.5.2", "2.5.1", true),
            (">=2.0.0 <2.5.2", "2.5.2", false),
            (">=2.0.0 <2.5.2", "1.9.9", false),
            (">=3.0.0 <=3.4.2", "3.4.2", true),
            (">=3.0.0 <=3.4.2", "3.4.3", false),
            ("<2.5", "2.4.9", true),
            ("<2.5", "2.5.0", false),
            ("<2.4.49", "2.4.48-1ubuntu0.1", true),
            ("not-a-version", "1.0.0", false), // malformed -> no match
        ];
        for (constraint, version, expected) in cases {
            let got = element_matches(constraint, &ver(version)).unwrap_or(false);
            assert_eq!(got, *expected, "constraint {constraint:?} vs {version:?}");
        }
    }

    #[test]
    fn standalone_service_boundary() {
        // the lookaround-regex bug used to make this always false
        assert!(contains_standalone_service("openssh server", "openssh"));
        assert!(contains_standalone_service("affects nginx today", "nginx"));
        assert!(!contains_standalone_service("nginx-ui dashboard", "nginx"));
        assert!(!contains_standalone_service("opensshd", "openssh"));
    }

    #[test]
    fn version_token_anchoring() {
        assert!(contains_version_token("affected 1.2 only", "1.2"));
        assert!(!contains_version_token("affected 1.20 only", "1.2"));
        assert!(!contains_version_token("affected 11.2 only", "1.2"));
        assert!(contains_version_token("ends with 1.2", "1.2"));
    }
}
