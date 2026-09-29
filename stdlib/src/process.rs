use anyhow::Result;
use serde_json::{json, Value};

fn observed_at() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("UTC timestamp formatting")
}

#[cfg(target_os = "linux")]
pub fn list() -> Result<Value> {
    let timestamp = observed_at();
    Ok(json!(jocky_agent_linux::collect_processes()?.into_iter()
        .map(|process| json!({"pid": process.pid, "name": process.name, "parent_pid": process.parent_pid, "exe": process.exe, "command_line": process.command_line, "timestamp": timestamp}))
        .collect::<Vec<_>>()))
}

#[cfg(target_os = "windows")]
pub fn list() -> Result<Value> {
    let timestamp = observed_at();
    Ok(json!(jocky_agent_windows::collect_processes()?.into_iter()
        .map(|process| json!({"pid": process.pid, "name": process.name, "parent_pid": process.parent_pid, "exe": process.exe, "command_line": process.command_line, "timestamp": timestamp}))
        .collect::<Vec<_>>()))
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn list() -> Result<Value> { anyhow::bail!("unsupported platform") }

#[cfg(target_os = "linux")]
pub fn modules(pid: u32) -> Result<Value> { linux_modules(pid) }

#[cfg(target_os = "windows")]
pub fn modules(pid: u32) -> Result<Value> { windows_modules(pid) }

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn modules(pid: u32) -> Result<Value> {
    anyhow::bail!("unsupported platform for process {pid}")
}

#[cfg(target_os = "linux")]
fn linux_modules(pid: u32) -> Result<Value> {
    use std::collections::BTreeSet;
    use std::io::Read;

    let path = format!("/proc/{pid}/maps");
    let file = std::fs::File::open(&path)?;
    let mut bytes = Vec::new();
    file.take(4 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    let byte_truncated = bytes.len() > 4 * 1024 * 1024;
    if byte_truncated {
        bytes.truncate(4 * 1024 * 1024);
        if let Some(last_newline) = bytes.iter().rposition(|byte| *byte == b'\n') {
            bytes.truncate(last_newline + 1);
        } else { bytes.clear(); }
    }
    let content = String::from_utf8_lossy(&bytes);
    let mut paths = BTreeSet::new();
    let mut lines = content.lines();
    let mut count_truncated = false;
    for line in lines.by_ref().take(20_000) {
        let mut fields = line.split_whitespace();
        let _range = fields.next();
        let executable = fields.next().is_some_and(|permissions| permissions.contains('x'));
        let pathname = line.find('/').map(|index| &line[index..]);
        if executable {
            if let Some(pathname) = pathname.filter(|value| value.starts_with('/')) {
                paths.insert(pathname.to_string());
            }
        }
        if paths.len() >= 4096 { break; }
    }
    count_truncated |= lines.next().is_some();
    let timestamp = observed_at();
    Ok(json!({"pid": pid, "modules": paths.into_iter().map(|path| json!({"path": path, "timestamp": timestamp})).collect::<Vec<_>>(), "source": path, "truncated": byte_truncated || count_truncated}))
}

#[cfg(target_os = "windows")]
fn windows_modules(pid: u32) -> Result<Value> {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
        TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
    };

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    if snapshot == INVALID_HANDLE_VALUE { return Err(std::io::Error::last_os_error().into()); }
    let result = (|| -> Result<Value> {
        let mut entry: MODULEENTRY32W = unsafe { zeroed() };
        entry.dwSize = size_of::<MODULEENTRY32W>() as u32;
        if unsafe { Module32FirstW(snapshot, &mut entry) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut modules = Vec::new();
        let mut truncated = false;
        let timestamp = observed_at();
        loop {
            let end = entry.szExePath.iter().position(|unit| *unit == 0).unwrap_or(entry.szExePath.len());
            let path = String::from_utf16_lossy(&entry.szExePath[..end]);
            modules.push(json!({"path": path, "size": entry.modBaseSize, "timestamp": timestamp}));
            let more = unsafe { Module32NextW(snapshot, &mut entry) } != 0;
            if modules.len() >= 4096 { truncated = more; break; }
            if !more { break; }
        }
        Ok(json!({"pid": pid, "modules": modules, "source": "toolhelp32", "truncated": truncated}))
    })();
    unsafe { CloseHandle(snapshot) };
    result
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn lists_current_process_modules() {
        let value = super::modules(std::process::id()).unwrap();
        assert!(!value["modules"].as_array().unwrap().is_empty());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn lists_current_process_modules() {
        let value = super::modules(std::process::id()).unwrap();
        assert!(!value["modules"].as_array().unwrap().is_empty());
    }
}
