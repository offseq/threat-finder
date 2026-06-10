//! SARIF 2.1.0 serialization, so findings surface in code-scanning UIs
//! (GitHub Advanced Security, Azure DevOps, etc.).

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::find_threats::{severity_rank, BatchResults, ThreatEntry};

fn level(sev: Option<&str>) -> &'static str {
    match severity_rank(sev) {
        4 | 3 => "error",
        2 => "warning",
        _ => "note",
    }
}

fn security_severity(t: &ThreatEntry) -> Option<String> {
    t.cvss_score.as_ref().and_then(|v| v.as_f64()).map(|f| f.to_string())
}

fn push_entry(rules: &mut BTreeMap<String, Value>, results: &mut Vec<Value>, asset: &str, t: &ThreatEntry) {
    let id = t.cve_id.clone().unwrap_or_else(|| "UNKNOWN".to_string());

    rules.entry(id.clone()).or_insert_with(|| {
        let mut rule = json!({
            "id": id,
            "name": id,
            "shortDescription": { "text": t.title.clone().unwrap_or_else(|| id.clone()) },
        });
        if let Some(url) = t.references.first() {
            rule["helpUri"] = json!(url);
        }
        if let Some(ss) = security_severity(t) {
            rule["properties"] = json!({ "security-severity": ss });
        }
        rule
    });

    results.push(json!({
        "ruleId": id,
        "level": level(t.severity.as_deref()),
        "message": {
            "text": format!(
                "{asset} is affected by {id} ({})",
                t.severity.clone().unwrap_or_else(|| "unknown".to_string())
            )
        },
        "locations": [{
            "logicalLocations": [{ "fullyQualifiedName": asset, "kind": "module" }]
        }],
        "properties": {
            "kev": t.kev,
            "epss": t.epss,
            "matchBasis": t.match_basis,
        }
    }));
}

/// Render a full SARIF 2.1.0 document for the report.
pub fn to_sarif(results: &BatchResults) -> String {
    let mut rules: BTreeMap<String, Value> = BTreeMap::new();
    let mut out: Vec<Value> = Vec::new();

    for (asset, entries) in &results.services {
        for t in entries {
            push_entry(&mut rules, &mut out, asset, t);
        }
    }
    if let Some(sys) = &results.system {
        for (asset, entries) in sys {
            for t in entries {
                push_entry(&mut rules, &mut out, asset, t);
            }
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
