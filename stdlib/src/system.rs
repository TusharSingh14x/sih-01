use anyhow::Result;
use serde_json::Value;

#[cfg(target_os = "linux")]
pub fn info() -> Result<Value> {
    Ok(jocky_agent_linux::collect_system_info())
}

#[cfg(target_os = "linux")]
pub fn drivers() -> Result<Value> {
    jocky_agent_linux::collect_drivers()
}

#[cfg(target_os = "windows")]
pub fn info() -> Result<Value> {
    Ok(jocky_agent_windows::collect_system_info())
}

#[cfg(target_os = "windows")]
pub fn drivers() -> Result<Value> {
    jocky_agent_windows::collect_drivers()
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn info() -> Result<Value> {
    anyhow::bail!("unsupported platform")
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn drivers() -> Result<Value> {
    anyhow::bail!("unsupported platform")
}
