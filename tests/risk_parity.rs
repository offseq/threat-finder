//! compute_risk against vectors scored by Radar's server/utils/riskScore.js (see gen_risk_vectors.js).

use find_threats::{compute_risk, ThreatEntry};
use serde_json::Value;

#[test]
fn compute_risk_matches_the_server_on_shared_vectors() {
    let vectors: Vec<Value> = serde_json::from_str(include_str!("risk_vectors.json")).unwrap();
    assert!(vectors.len() > 100);
    for v in &vectors {
        let str_of = |k: &str| v[k].as_str().map(str::to_string);
        let t = ThreatEntry {
            severity: str_of("severity"),
            cvss_score: Some(v["cvssScore"].clone()),
            epss: v["epss"].as_f64(),
            kev: v["kev"] == true,
            kev_overdue: v["kevOverdue"] == true,
            exploit_maturity: str_of("exploitMaturity"),
            exploited_outside_kev: v["exploitedOutsideKev"] == true,
            confirmed: v["confirmed"] == true,
            ..Default::default()
        };
        let risk = compute_risk(&t, v["exposure"].as_str().unwrap(), v["eol"] == true);
        assert_eq!(risk.score as u64, v["score"].as_u64().unwrap(), "score of {v}");
        assert_eq!(risk.decision, v["decision"].as_str().unwrap(), "decision of {v}");
        assert_eq!(risk.reason, v["reason"].as_str(), "reason of {v}");
    }
}
