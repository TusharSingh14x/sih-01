use std::env;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct Job {
    id: String,
    capability: String,
}

fn main() -> Result<()> {
    let api = env::var("JOCKY_API_URL").unwrap_or_else(|_| "http://localhost:8000".into());
    let key = env::var("JOCKY_AGENT_KEY").context("JOCKY_AGENT_KEY is required")?;
    let id = env::var("JOCKY_AGENT_ID").unwrap_or_else(|_| "local-agent".into());
    let client = Client::builder().timeout(Duration::from_secs(15)).build()?;
    loop {
        if let Err(error) = tick(&client, &api, &key, &id) {
            eprintln!("agent check-in failed: {error:#}");
        }
        thread::sleep(Duration::from_secs(5));
    }
}

fn tick(client: &Client, api: &str, key: &str, id: &str) -> Result<()> {
    client.post(format!("{api}/api/agent/register"))
        .bearer_auth(key)
        .json(&json!({
            "id": id,
            "hostname": env::var("HOSTNAME").or_else(|_| env::var("COMPUTERNAME")).unwrap_or_else(|_| "localhost".into()),
            "platform": env::consts::OS,
            "version": env!("CARGO_PKG_VERSION")
        }))
        .send()?.error_for_status()?;
    let job: Option<Job> = client.get(format!("{api}/api/agent/{id}/next"))
        .bearer_auth(key).send()?.error_for_status()?.json()?;
    if let Some(job) = job {
        let result = collect(&job.capability);
        let completion = match result {
            Ok(payload) => json!({"payload": payload}),
            Err(error) => json!({"error": error.to_string()}),
        };
        client.post(format!("{api}/api/agent/{id}/jobs/{}/complete", job.id))
            .bearer_auth(key).json(&completion).send()?.error_for_status()?;
    }
    Ok(())
}

fn collect(capability: &str) -> Result<Value> {
    if let Some(pid) = capability.strip_prefix("process.modules:") {
        let pid = pid.parse::<u32>().ok().filter(|pid| *pid > 0)
            .context("process.modules requires a positive PID")?;
        return jocky_stdlib::invoke("process.modules", &[json!(pid)]);
    }
    match capability {
        "system.info" => system_info(),
        "system.drivers" => system_drivers(),
        "process.list" => process_list(),
        "network.connections" => network_connections(),
        "logs.system" if cfg!(target_os = "linux") => jocky_stdlib::invoke("logs.journal", &[]),
        "logs.system" if cfg!(target_os = "windows") => jocky_stdlib::invoke("logs.windows_events", &[json!("System")]),
        _ => anyhow::bail!("unsupported collection capability"),
    }
}

#[cfg(target_os = "linux")]
fn system_info() -> Result<Value> { Ok(jocky_agent_linux::collect_system_info()) }
#[cfg(target_os = "windows")]
fn system_info() -> Result<Value> { Ok(jocky_agent_windows::collect_system_info()) }

#[cfg(target_os = "linux")]
fn process_list() -> Result<Value> { Ok(serde_json::to_value(jocky_agent_linux::collect_processes()?)?) }
#[cfg(target_os = "windows")]
fn process_list() -> Result<Value> { Ok(serde_json::to_value(jocky_agent_windows::collect_processes()?)?) }

#[cfg(target_os = "linux")]
fn network_connections() -> Result<Value> {
    jocky_agent_linux::collect_network_connections()
}

#[cfg(target_os = "windows")]
fn network_connections() -> Result<Value> {
    jocky_agent_windows::collect_network_connections()
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn system_info() -> Result<Value> { anyhow::bail!("unsupported platform") }
#[cfg(target_os = "linux")]
fn system_drivers() -> Result<Value> { jocky_agent_linux::collect_drivers() }
#[cfg(target_os = "windows")]
fn system_drivers() -> Result<Value> { jocky_agent_windows::collect_drivers() }
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn system_drivers() -> Result<Value> { anyhow::bail!("unsupported platform") }
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn process_list() -> Result<Value> { anyhow::bail!("unsupported platform") }
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn network_connections() -> Result<Value> { anyhow::bail!("unsupported platform") }
