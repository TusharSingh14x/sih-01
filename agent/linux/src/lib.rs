use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Context;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct LinuxProcess {
    pub pid: u32,
    pub name: String,
    pub parent_pid: Option<u32>,
    pub exe: Option<String>,
    pub command_line: Vec<String>,
}

pub fn collect_processes() -> anyhow::Result<Vec<LinuxProcess>> {
    let mut processes = Vec::new();
    for entry in fs::read_dir("/proc").context("read /proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(pid) = name.to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        let name = fs::read_to_string(entry.path().join("comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let status = fs::read_to_string(entry.path().join("status")).unwrap_or_default();
        let parent_pid = status.lines().find_map(|line| line.strip_prefix("PPid:").and_then(|s| s.trim().parse().ok()));
        let exe = fs::read_link(entry.path().join("exe")).ok().map(|p| p.to_string_lossy().into_owned());
        let command_line = fs::read(entry.path().join("cmdline")).unwrap_or_default()
            .split(|b| *b == 0).filter(|s| !s.is_empty()).take(128)
            .map(|s| String::from_utf8_lossy(&s[..s.len().min(4096)]).into_owned()).collect();
        processes.push(LinuxProcess { pid, name, parent_pid, exe, command_line });
    }
    processes.sort_by_key(|process| process.pid);
    Ok(processes)
}

pub fn collect_system_info() -> serde_json::Value {
    serde_json::json!({
        "os": "linux",
        "arch": std::env::consts::ARCH,
        "hostname": fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default().trim(),
        "kernel": fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim()
    })
}

pub fn collect_network_connections() -> anyhow::Result<serde_json::Value> {
    let mut rows = Vec::new();
    let mut truncated = false;
    for (protocol, file) in [
        ("tcp", "/proc/net/tcp"),
        ("tcp6", "/proc/net/tcp6"),
        ("udp", "/proc/net/udp"),
        ("udp6", "/proc/net/udp6"),
    ] {
        let contents = match fs::read_to_string(file) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).with_context(|| format!("read {file}")),
        };
        let mut lines = contents.lines().skip(1);
        for line in lines.by_ref().take(2000) {
            let columns: Vec<_> = line.split_whitespace().collect();
            if columns.len() > 3 {
                rows.push(serde_json::json!({
                    "protocol": protocol,
                    "local_address": decode_endpoint(columns[1]),
                    "remote_address": decode_endpoint(columns[2]),
                    "state": state_name(columns[3]),
                    "remote_port": columns[2].rsplit_once(':').and_then(|(_, p)| u16::from_str_radix(p, 16).ok()),
                    "local_port": columns[1].rsplit_once(':').and_then(|(_, p)| u16::from_str_radix(p, 16).ok()),
                    "local_address_raw": columns[1],
                    "remote_address_raw": columns[2],
                    "state_raw": columns[3]
                }));
            }
        }
        truncated |= lines.next().is_some();
    }
    Ok(serde_json::json!({"connections": rows, "source": "/proc/net", "truncated": truncated}))
}

pub fn collect_drivers() -> anyhow::Result<serde_json::Value> {
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open("/proc/modules")?.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 { anyhow::bail!("driver inventory exceeds 1 MiB"); }
    let drivers = String::from_utf8_lossy(&bytes).lines().take(4096).filter_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        (fields.len() >= 6).then(|| serde_json::json!({
            "name": fields[0], "size_bytes": fields[1].parse::<u64>().ok(),
            "references": fields[2].parse::<u64>().ok(), "used_by": fields[3],
            "state": fields[4], "source": "/proc/modules"
        }))
    }).collect::<Vec<_>>();
    let truncated = drivers.len() >= 4096;
    Ok(serde_json::json!({"drivers": drivers, "source": "/proc/modules", "truncated": truncated}))
}

fn decode_endpoint(raw: &str) -> Option<String> {
    let (address, port) = raw.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let bytes = address.as_bytes().chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect::<Option<Vec<_>>>()?;
    match bytes.len() {
        4 => Some(format!("{}:{port}", Ipv4Addr::new(bytes[3], bytes[2], bytes[1], bytes[0]))),
        16 => {
            let mut address = [0_u8; 16];
            for (index, word) in bytes.chunks_exact(4).enumerate() {
                address[index * 4..index * 4 + 4].copy_from_slice(&[word[3], word[2], word[1], word[0]]);
            }
            Some(format!("[{}]:{port}", Ipv6Addr::from(address)))
        }
        _ => None,
    }
}

fn state_name(raw: &str) -> &'static str {
    match raw {
        "01" => "established", "02" => "syn_sent", "03" => "syn_received",
        "04" => "fin_wait_1", "05" => "fin_wait_2", "06" => "time_wait",
        "07" => "closed", "08" => "close_wait", "09" => "last_ack",
        "0A" => "listen", "0B" => "closing", _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn decodes_proc_ipv4_and_ipv6() {
        assert_eq!(super::decode_endpoint("0100007F:0016"), Some("127.0.0.1:22".into()));
        assert_eq!(super::decode_endpoint("00000000000000000000000001000000:1F90"), Some("[::1]:8080".into()));
    }
}
