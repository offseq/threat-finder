//! SARIF 2.1.0 serialization, so findings surface in code-scanning UIs
//! (GitHub Advanced Security, Azure DevOps, etc.).

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::api::{severity_rank, BatchResults, ThreatEntry};

fn level(sev: Option<&str>) -> &'static str {
    match severity_rank(sev) {
        4 | 3 => "error",
        2 => "warning",
        _ => "note",
    }
}


/// GitHub code scanning drops results without a physical location and resolves
/// URIs against the repository root, so the asset's path is made relative.
fn artifact_uri(exe: &str) -> String {
    let path = exe.replace('\\', "/");
    let path = match path.as_bytes() {
        [d, b':', ..] if d.is_ascii_alphabetic() => &path[2..],
        _ => &path,
    };
    path.trim_start_matches('/').to_string()
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
    if let Some(rem) = &t.remediation {
        // A `fixes`-adjacent hint that SARIF viewers can surface as guidance.
        result["fixes"] = json!([{ "description": { "text": rem } }]);
    }
    if let Some(d) = t.recorded_decision.as_ref().filter(|d| d.suppressing) {
        result["suppressions"] = json!([{ "kind": "external", "status": "accepted", "justification": d.verdict }]);
    }
    results.push(result);
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
