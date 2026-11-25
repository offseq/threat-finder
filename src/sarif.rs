//! SARIF 2.1.0 serialization, so findings surface in code-scanning UIs
//! (GitHub Advanced Security, Azure DevOps, etc.).

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::api::{severity_rank, BatchResults, Eol, ThreatEntry};

fn level(sev: Option<&str>) -> &'static str {
    match severity_rank(sev) {
        4 | 3 => "error",
        2 => "warning",
        _ => "note",
    }
}

/// GitHub code scanning drops results without a physical location and resolves
/// URIs against the repository root, so the asset's path is made relative and
/// percent-encoded into a valid uri-reference.
fn artifact_uri(exe: &str) -> String {
    let path = exe.replace('\\', "/");
    let path = match path.as_bytes() {
        [d, b':', ..] if d.is_ascii_alphabetic() => &path[2..],
        _ => &path,
    };
    let mut uri = String::with_capacity(path.len());
    for b in path.trim_start_matches('/').bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => uri.push(b as char),
            _ => uri.push_str(&format!("%{b:02X}")),
        }
    }
    uri
}

fn push_entry(rules: &mut BTreeMap<String, Value>, results: &mut Vec<Value>, asset: &str, exe: Option<&str>, t: &ThreatEntry) {
    let id = t.cve_id.clone().or_else(|| t.id.clone()).unwrap_or_else(|| "UNKNOWN".to_string());

    let rule = rules.entry(id.clone()).or_insert_with(|| {
        let mut rule = json!({
            "id": id,
            "name": id,
            "shortDescription": { "text": t.title.clone().unwrap_or_else(|| id.clone()) },
        });
        // Prefer the Radar detail page (curated, with remediation) over a raw
        // reference URL for the rule's helpUri.
        if let Some(url) = t.radar_url.as_ref().or_else(|| t.references.first()) {
            rule["helpUri"] = json!(url);
        }
        rule
    });
    // security-severity: take the highest CVSS seen across duplicate entries for
    // this CVE (a later entry may carry a score the first one lacked).
    if let Some(score) = t.cvss_score.as_ref().and_then(|v| v.as_f64()) {
        let prev = rule["properties"]["security-severity"]
            .as_str()
            .and_then(|s| s.parse::<f64>().ok());
        if prev.is_none_or(|p| score > p) {
            rule["properties"]["security-severity"] = json!(score.to_string());
        }
    }

    // Fold remediation into the result message so SARIF consumers see how to fix,
    // not just that something is wrong.
    let mut text = format!(
        "{asset} is affected by {id} ({})",
        t.severity.clone().unwrap_or_else(|| "unknown".to_string())
    );
    if !t.fixed_versions.is_empty() {
        text.push_str(&format!(". Fixed in {}", t.fixed_versions.join(", ")));
    }
    if let Some(rem) = &t.remediation {
        text.push_str(&format!(". {rem}"));
    }

    let mut props = json!({
        "kev": t.kev,
        "exploited": t.exploited,
        "epss": t.epss,
        "confirmed": t.confirmed,
        "matchBasis": t.match_basis,
    });
    if let Some(decision) = &t.decision {
        props["decision"] = json!(decision);
    }
    if let Some(reason) = &t.decision_reason {
        props["decisionReason"] = json!(reason);
    }
    if let Some(score) = t.risk_score {
        props["riskScore"] = json!(score);
    }
    if let Some(m) = &t.exploit_maturity {
        props["exploitMaturity"] = json!(m);
    }
    if !t.patch_links.is_empty() {
        props["patchLinks"] = json!(t.patch_links);
    }
    if !t.cwes.is_empty() {
        props["cwe"] = json!(t.cwes);
    }
    if !t.fixed_versions.is_empty() {
        props["fixedVersions"] = json!(t.fixed_versions);
    }
    if let Some(rem) = &t.remediation {
        props["remediation"] = json!(rem);
    }

    let mut location = json!({ "logicalLocations": [{ "fullyQualifiedName": asset, "kind": "module" }] });
    if let Some(exe) = exe {
        location["physicalLocation"] = json!({
            "artifactLocation": { "uri": artifact_uri(exe) },
            "region": { "startLine": 1 },
        });
    }
    let mut result = json!({
        "ruleId": id,
        "level": level(t.severity.as_deref()),
        "message": { "text": text },
        "locations": [location],
        "properties": props,
    });
    if let Some(d) = t.recorded_decision.as_ref().filter(|d| d.suppressing) {
        result["suppressions"] = json!([{ "kind": "external", "status": "accepted", "justification": d.verdict }]);
    }
    results.push(result);
}

const EOL_RULE: &str = "EOL";

/// A result for an asset (or the OS, with no `exe`) at or near its end of life.
fn push_eol(rules: &mut BTreeMap<String, Value>, results: &mut Vec<Value>, asset: &str, exe: Option<&str>, e: &Eol) {
    rules.entry(EOL_RULE.to_string()).or_insert_with(|| json!({
        "id": EOL_RULE,
        "name": "EndOfLife",
        "shortDescription": { "text": "Component at or near its end of life" },
        "helpUri": "https://endoflife.date",
    }));
    let mut location = json!({ "logicalLocations": [{ "fullyQualifiedName": asset, "kind": "module" }] });
    if let Some(exe) = exe {
        location["physicalLocation"] = json!({
            "artifactLocation": { "uri": artifact_uri(exe) },
            "region": { "startLine": 1 },
        });
    }
    results.push(json!({
        "ruleId": EOL_RULE,
        "level": if e.is_eol() { "warning" } else { "note" },
        "message": { "text": format!("{asset}: {}", e.describe()) },
        "locations": [location],
        "properties": { "eol": e },
    }));
}

/// Render a full SARIF 2.1.0 document for the report.
pub fn to_sarif(results: &BatchResults) -> String {
    let mut rules: BTreeMap<String, Value> = BTreeMap::new();
    let mut out: Vec<Value> = Vec::new();

    for (asset, entries) in &results.services {
        let exe = results.assets.get(asset).map(|a| a.exe.as_str()).filter(|e| !e.is_empty());
        for t in entries {
            push_entry(&mut rules, &mut out, asset, exe, t);
        }
    }
    if let Some(e) = results.os_eol.as_ref().filter(|e| e.flagged()) {
        push_eol(&mut rules, &mut out, "os", None, e);
    }
    for (asset, info) in &results.assets {
        if let Some(e) = info.eol.as_ref().filter(|e| e.flagged()) {
            push_eol(&mut rules, &mut out, asset, Some(info.exe.as_str()).filter(|x| !x.is_empty()), e);
        }
    }

    let doc = json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": { "driver": {
                "name": "threat-finder",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://radar.offseq.com",
                "rules": rules.into_values().collect::<Vec<_>>(),
            }},
            "results": out,
        }]
    });

    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::artifact_uri;

    #[test]
    fn artifact_uri_is_a_relative_uri_reference() {
        assert_eq!(artifact_uri("/usr/sbin/nginx"), "usr/sbin/nginx");
        assert_eq!(artifact_uri("C:\\Program Files\\App (x86)\\a#b.exe"), "Program%20Files/App%20%28x86%29/a%23b.exe");
        assert_eq!(artifact_uri("deps/pkg:lock?.json"), "deps/pkg%3Alock%3F.json");
        assert_eq!(artifact_uri("/opt/caf\u{e9}/x"), "opt/caf%C3%A9/x");
    }
}
