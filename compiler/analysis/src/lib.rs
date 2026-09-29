use serde_json::{json, Value};

/// Triage indicators, not malware verdicts. Confidence is a heuristic, not a probability.
pub fn analyze(capability: &str, evidence: &Value) -> Vec<Value> {
    let mut findings = Vec::new();
    let rows = evidence.as_array().or_else(|| ["processes", "connections", "events", "lines", "modules", "drivers"]
        .iter().find_map(|key| evidence.get(key).and_then(Value::as_array)));
    let single = vec![evidence.clone()];
    for (index, row) in rows.unwrap_or(&single).iter().enumerate() {
        let mut emit = |rule: &str, category: &str, severity: &str, title: &str, confidence: f64| {
            findings.push(json!({"rule_id":rule, "category":category, "severity":severity,
                "title":title, "description":"Suspicious indicator; validate context and corroborate with independent evidence before drawing conclusions.",
                "confidence":confidence, "row_index":index, "capability":capability}));
        };
        if capability == "process.list" {
            if row["name"].as_str().unwrap_or("").to_lowercase().contains("miner") {
                emit("process.miner", "process", "HIGH", "Possible mining process", 0.75);
            }
            let path = row["path"].as_str().or_else(|| row["exe"].as_str()).or_else(|| row["name"].as_str()).unwrap_or("").replace('\\', "/").to_lowercase();
            if path.split('/').any(|part| part == "temp" || part == "tmp") {
                emit("process.temp", "process", "MEDIUM", "Suspicious indicator: process in temporary directory", 0.45);
            }
        }
        if capability == "process.modules" {
            let path = row["path"].as_str().or_else(|| row["name"].as_str()).unwrap_or("").replace('\\', "/").to_lowercase();
            if path.split('/').any(|part| part == "temp" || part == "tmp") {
                emit("module.temp", "process", "HIGH", "Module loaded from temporary directory", 0.65);
            }
        }
        if capability == "network.connections" {
            let port = row["remote_port"].as_u64().or_else(|| row["remote_port"].as_str().and_then(|s| s.parse().ok()));
            if matches!(port, Some(3333 | 4444)) {
                emit(if port == Some(3333) {"network.mining"} else {"network.4444"}, "network", "HIGH",
                     if port == Some(3333) {"Possible mining-pool connection"} else {"Possible remote-shell indicator on port 4444"}, 0.55);
            }
        }
        if capability.starts_with("logs.") {
            let message = row["message"].as_str().or_else(|| row["text"].as_str()).or_else(|| row.as_str()).unwrap_or("").to_lowercase();
            if message.contains("failed password") || message.contains("failed login") || row["event_id"] == 4625 || row["event_id"] == "4625" {
                emit("logs.failed_login", "logs", "MEDIUM", "Suspicious indicator: failed login", 0.4);
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn miner() { assert_eq!(analyze("process.list", &json!([{"name":"suspicious_miner.exe"}]))[0]["severity"], "HIGH"); }
    #[test] fn temp() { assert_eq!(analyze("process.list", &json!([{"path":"C:\\Temp\\x.exe"}]))[0]["severity"], "MEDIUM"); }
    #[test] fn mining_port() { assert_eq!(analyze("network.connections", &json!([{"remote_port":3333}]))[0]["rule_id"], "network.mining"); }
    #[test] fn shell_indicator() { assert_eq!(analyze("network.connections", &json!([{"remote_port":4444}]))[0]["severity"], "HIGH"); }
    #[test] fn failed_login() { assert_eq!(analyze("logs.journal", &json!({"events":[{"message":"Failed login"}]}))[0]["severity"], "MEDIUM"); }
    #[test] fn benign() { assert!(analyze("process.list", &json!([{"name":"notepad.exe", "path":"C:\\Templates\\notepad.exe"}])).is_empty()); }
}
