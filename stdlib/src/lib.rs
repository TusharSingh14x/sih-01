use anyhow::{bail, Result};
use serde_json::Value;

pub mod filesystem;
pub mod hashing;
pub mod logs;
pub mod network;
pub mod process;
pub mod reporting;
pub mod system;
pub mod timeline;

pub fn invoke(capability: &str, args: &[Value]) -> Result<Value> {
    if std::env::var("JOCKY_MOCK_MODE").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true")) {
        return invoke_mock(capability, args);
    }
    match (capability, args) {
        ("system.info", []) => system::info(),
        ("system.drivers", []) => system::drivers(),
        ("process.list", []) => process::list(),
        ("process.modules", [Value::Number(pid)]) => {
            let pid = pid.as_u64().filter(|pid| *pid > 0 && *pid <= u32::MAX as u64)
                .ok_or_else(|| anyhow::anyhow!("process.modules requires a positive process ID"))?;
            process::modules(pid as u32)
        }
        ("network.connections", []) => network::connections(),
        ("filesystem.metadata", [Value::String(path)]) => filesystem::metadata(path),
        ("filesystem.hash", [Value::String(path)]) => filesystem::hash(path),
        ("logs.read", [Value::String(path)]) => logs::read(path),
        ("logs.syslog", [Value::String(path)]) => logs::syslog(path),
        ("logs.journal", []) => logs::journal(),
        ("logs.windows_events", [Value::String(channel)]) => logs::windows_events(channel),
        ("hashing.sha256", [Value::String(value)]) => Ok(hashing::sha256(value)),
        ("timeline.build", [value]) => timeline::build(value),
        ("reporting.summary", [value]) => reporting::summary(value),
        _ => bail!("unsupported capability or arguments: {capability}"),
    }
}

/// Mock mode never falls back to reading the host, including file/log/module calls.
pub fn invoke_mock(capability: &str, args: &[Value]) -> Result<Value> {
    match (capability, args) {
        ("system.info", []) => Ok(jocky_agent_mock::system_info()),
        ("system.drivers", []) => Ok(serde_json::json!({"drivers": [], "source": "mock", "truncated": false})),
        ("process.list", []) => Ok(jocky_agent_mock::processes()),
        ("network.connections", []) => Ok(jocky_agent_mock::connections()),
        ("logs.journal", []) | ("logs.windows_events", [Value::String(_)]) |
        ("logs.read", [Value::String(_)]) | ("logs.syslog", [Value::String(_)]) => Ok(jocky_agent_mock::logs()),
        ("hashing.sha256", [Value::String(value)]) => Ok(hashing::sha256(value)),
        ("timeline.build", [value]) => timeline::build(value),
        ("reporting.summary", [value]) => reporting::summary(value),
        _ => bail!("capability unavailable in isolated mock mode: {capability}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_mode_cannot_read_real_files_or_process_modules() {
        assert!(invoke_mock("filesystem.hash", &[Value::String("Cargo.toml".into())]).is_err());
        assert!(invoke_mock("process.modules", &[serde_json::json!(1)]).is_err());
        assert_eq!(invoke_mock("process.list", &[]).unwrap().as_array().unwrap().len(), 15);
    }

    #[test]
    fn authorized_file_and_log_collection() {
        let root = std::env::current_dir().unwrap();
        std::env::set_var("JOCKY_READ_ROOTS", &root);
        let path = root.join("Cargo.toml").to_string_lossy().into_owned();
        let arg = [Value::String(path)];
        let metadata = invoke("filesystem.metadata", &arg).unwrap();
        assert!(metadata["size"].as_u64().unwrap() > 0);
        let digest = invoke("filesystem.hash", &arg).unwrap();
        assert_eq!(digest["digest"].as_str().unwrap().len(), 64);
        let log = invoke("logs.read", &arg).unwrap();
        assert!(!log["lines"].as_array().unwrap().is_empty());
        std::env::remove_var("JOCKY_READ_ROOTS");
    }
}
