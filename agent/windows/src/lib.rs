use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct WindowsProcess {
    pub pid: u32,
    pub name: String,
    pub parent_pid: Option<u32>,
    pub exe: Option<String>,
    pub command_line: Vec<String>,
}

pub fn collect_system_info() -> serde_json::Value {
    serde_json::json!({
        "os": "windows",
        "hostname": std::env::var("COMPUTERNAME").unwrap_or_default(),
        "arch": std::env::consts::ARCH
    })
}

pub fn collect_drivers() -> anyhow::Result<serde_json::Value> {
    let output = std::process::Command::new("driverquery").args(["/fo", "csv", "/nh"]).output()?;
    if !output.status.success() { anyhow::bail!("read-only driver inventory failed"); }
    if output.stdout.len() > 1024 * 1024 { anyhow::bail!("driver inventory exceeds 1 MiB"); }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut truncated = false;
    let mut drivers = Vec::new();
    for line in text.lines() {
        if drivers.len() == 4096 { truncated = true; break; }
        let fields = parse_csv(line);
        if fields.len() >= 4 {
            drivers.push(serde_json::json!({"name": fields[0], "display_name": fields[1],
                "type": fields[2], "state": fields[3], "source": "driverquery"}));
        }
    }
    Ok(serde_json::json!({"drivers": drivers, "source": "driverquery", "truncated": truncated}))
}

fn parse_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut value = String::new();
    let mut chars = line.chars().peekable();
    let mut quoted = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted && chars.peek() == Some(&'"') => { value.push('"'); chars.next(); }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut value)),
            _ => value.push(ch),
        }
    }
    fields.push(value);
    fields
}

pub fn collect_processes() -> anyhow::Result<Vec<WindowsProcess>> {
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, false);
    let mut processes: Vec<_> = system.processes().iter().map(|(pid, process)| WindowsProcess {
        pid: pid.as_u32(),
        name: process.name().to_string_lossy().into_owned(),
        parent_pid: process.parent().map(|p| p.as_u32()),
        exe: process.exe().map(|p| p.to_string_lossy().into_owned()),
        command_line: process.cmd().iter().take(128).map(|s| s.to_string_lossy().chars().take(4096).collect()).collect(),
    }).collect();
    processes.sort_by_key(|process| process.pid);
    Ok(processes)
}

pub fn collect_network_connections() -> anyhow::Result<serde_json::Value> {
    let output = std::process::Command::new("netstat").arg("-ano").output()?;
    if !output.status.success() {
        anyhow::bail!("netstat collection failed");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut rows = text.lines().filter_map(parse_netstat_row).take(2001).collect::<Vec<_>>();
    let truncated = rows.len() > 2000;
    rows.truncate(2000);
    Ok(serde_json::json!({"connections": rows, "source": "netstat -ano", "truncated": truncated}))
}

fn parse_netstat_row(line: &str) -> Option<serde_json::Value> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    match fields.as_slice() {
        [protocol, local, remote, state, pid] if protocol.eq_ignore_ascii_case("TCP") => Some(serde_json::json!({
            "protocol": "tcp", "local_address": local, "remote_address": remote,
            "remote_port": remote.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()),
            "local_port": local.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()),
            "state": state.to_ascii_lowercase(), "pid": pid.parse::<u32>().ok()?
        })),
        [protocol, local, remote, pid] if protocol.eq_ignore_ascii_case("UDP") => Some(serde_json::json!({
            "protocol": "udp", "local_address": local, "remote_address": remote,
            "remote_port": remote.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()),
            "local_port": local.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()),
            "state": "unconnected", "pid": pid.parse::<u32>().ok()?
        })),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_netstat_lines() {
        let row = super::parse_netstat_row("TCP    127.0.0.1:80    0.0.0.0:0    LISTENING    123").unwrap();
        assert_eq!(row["pid"], 123);
        assert_eq!(row["state"], "listening");
    }
}
