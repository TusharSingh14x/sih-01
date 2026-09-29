use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use anyhow::{bail, Context, Result};
use jocky_ast::{Argument, Literal, Predicate, Target};
use jocky_ir::{IrOp, IrProgram};
use serde_json::{json, Value};
use time::OffsetDateTime;

#[derive(Debug, Default)]
pub struct Runtime {
    bindings: BTreeMap<String, Value>,
    reports: Vec<Value>,
    findings: Vec<Value>,
}

impl Runtime {
    pub fn execute(&mut self, ir: &IrProgram) -> Result<Value> {
        self.reports.clear();
        self.findings.clear();
        for investigation in &ir.investigations {
            self.begin(&investigation.target)?;
            for op in &investigation.ops {
                self.execute_op(op).with_context(|| format!("investigation {}", investigation.title))?;
            }
        }
        Ok(self.output())
    }

    pub fn begin(&mut self, target: &Target) -> Result<()> {
        let hostname = jocky_stdlib::invoke("system.info", &[])?
            .get("hostname").and_then(Value::as_str).unwrap_or("").to_string();
        match target {
            Target::Host(id) if id.eq_ignore_ascii_case("localhost")
                || id == "127.0.0.1" || id.eq_ignore_ascii_case(&hostname) => {}
            Target::Host(id) => bail!("host {id} is not local; use an authorized agent job"),
            Target::Agent(id) => bail!("agent {id} cannot run through the local CLI"),
        }
        self.bindings.clear();
        Ok(())
    }

    pub fn execute_op(&mut self, op: &IrOp) -> Result<()> {
        match op {
            IrOp::Collect { binding, capability, args } => {
                let resolved = args.iter().map(|arg| match arg {
                    Argument::Literal(Literal::String(s)) => Ok(json!(s)),
                    Argument::Literal(Literal::Integer(i)) => Ok(json!(i)),
                    Argument::Literal(Literal::Boolean(b)) => Ok(json!(b)),
                    Argument::Binding(name) => self.bindings.get(name).cloned()
                        .with_context(|| format!("unknown binding {name}")),
                }).collect::<Result<Vec<_>>>()?;
                let value = jocky_stdlib::invoke(capability, &resolved)
                    .with_context(|| format!("collect {capability} as {binding}"))?;
                for mut finding in jocky_analysis::analyze(capability, &value) {
                    finding["binding"] = json!(binding);
                    self.findings.push(finding);
                }
                self.bindings.insert(binding.clone(), value);
            }
            IrOp::Filter { source, destination, predicate } => {
                let value = self.bindings.get(source)
                    .with_context(|| format!("unknown binding {source}"))?;
                self.bindings.insert(destination.clone(), filter_rows(value, predicate));
            }
            IrOp::Report { name, includes } => {
                let mut evidence = BTreeMap::new();
                let mut evidence_sha256 = BTreeMap::new();
                for include in includes {
                    let value = self.bindings.get(include)
                        .with_context(|| format!("unknown binding {include}"))?;
                    let digest = jocky_stdlib::reporting::summary(value)?["sha256"]
                        .as_str().expect("summary returns SHA-256").to_string();
                    evidence_sha256.insert(include.clone(), digest);
                    evidence.insert(include.clone(), value.clone());
                }
                self.reports.push(json!({
                    "name": name,
                    "generated_at": OffsetDateTime::now_utc().to_string(),
                    "evidence": evidence,
                    "evidence_sha256": evidence_sha256
                }));
            }
        }
        Ok(())
    }

    pub fn output(&self) -> Value {
        json!({ "reports": self.reports, "findings": self.findings,
            "mock": std::env::var("JOCKY_MOCK_MODE").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true")) })
    }
}

fn filter_rows(value: &Value, predicate: &Predicate) -> Value {
    let matches = |row: &Value| {
        let (field, expected, contains) = match predicate {
            Predicate::Contains { field, value } => (field, value, true),
            Predicate::Equals { field, value } => (field, value, false),
        };
        let actual = match row.get(field) {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Number(n)) => n.to_string(),
            Some(Value::Bool(b)) => b.to_string(),
            _ => return false,
        };
        if contains {
            actual.to_lowercase().contains(&expected.to_lowercase())
        } else {
            actual.eq_ignore_ascii_case(expected)
        }
    };
    match value {
        Value::Array(rows) => Value::Array(rows.iter().filter(|row| matches(row)).cloned().collect()),
        Value::Object(map) => {
            let mut result = map.clone();
            for key in ["processes", "connections", "events", "lines", "modules", "drivers"] {
                if let Some(Value::Array(rows)) = map.get(key) {
                    result.insert(key.to_string(), Value::Array(rows.iter().filter(|row| matches(row)).cloned().collect()));
                    return Value::Object(result);
                }
            }
            Value::Array(if matches(value) { vec![value.clone()] } else { vec![] })
        }
        _ => Value::Array(Vec::new()),
    }
}

fn ffi_step<F>(session: *mut Runtime, data: *const u8, len: usize, step: F) -> i32
where F: FnOnce(&mut Runtime, &[u8]) -> Result<()> {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if session.is_null() || data.is_null() || len > 1024 * 1024 {
            bail!("invalid JOCKY runtime input");
        }
        let runtime = unsafe { &mut *session };
        let bytes = unsafe { std::slice::from_raw_parts(data, len) };
        step(runtime, bytes)
    }));
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => { eprintln!("jocky runtime: {error:#}"); 1 },
        Err(_) => { eprintln!("jocky runtime panic"); 2 },
    }
}

#[no_mangle]
pub extern "C" fn jocky_runtime_new() -> *mut Runtime {
    Box::into_raw(Box::new(Runtime::default()))
}

#[no_mangle]
pub extern "C" fn jocky_runtime_begin(session: *mut Runtime, data: *const u8, len: usize) -> i32 {
    ffi_step(session, data, len, |runtime, bytes| runtime.begin(&serde_json::from_slice::<Target>(bytes)?))
}

#[no_mangle]
pub extern "C" fn jocky_runtime_op(session: *mut Runtime, data: *const u8, len: usize) -> i32 {
    ffi_step(session, data, len, |runtime, bytes| runtime.execute_op(&serde_json::from_slice::<IrOp>(bytes)?))
}

#[no_mangle]
pub extern "C" fn jocky_runtime_finish(session: *mut Runtime) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if session.is_null() { bail!("null JOCKY runtime session"); }
        let runtime = unsafe { &*session };
        println!("{}", serde_json::to_string_pretty(&runtime.output())?);
        Ok::<(), anyhow::Error>(())
    }));
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => { eprintln!("jocky runtime: {error:#}"); 1 },
        Err(_) => { eprintln!("jocky runtime panic"); 2 },
    }
}

#[no_mangle]
pub extern "C" fn jocky_runtime_free(session: *mut Runtime) {
    if !session.is_null() {
        drop(unsafe { Box::from_raw(session) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_matching_process_names() {
        let input = json!([{"pid":1,"name":"powershell.exe"},{"pid":2,"name":"explorer.exe"}]);
        let predicate = Predicate::Contains { field: "name".into(), value: "PowerShell".into() };
        assert_eq!(filter_rows(&input, &predicate), json!([{"pid":1,"name":"powershell.exe"}]));
    }

    #[test]
    fn rejects_nonlocal_target() {
        assert!(Runtime::default().begin(&Target::Agent("remote".into())).is_err());
    }

    #[test]
    fn collection_errors_fail_execution() {
        let mut runtime = Runtime::default();
        runtime.begin(&Target::Host("localhost".into())).unwrap();
        let op = IrOp::Collect {
            binding: "file".into(), capability: "filesystem.hash".into(),
            args: vec![Argument::Literal(Literal::String("missing-file".into()))],
        };
        assert!(runtime.execute_op(&op).is_err());
    }

    #[test]
    fn reports_hash_included_evidence() {
        let mut runtime = Runtime::default();
        runtime.begin(&Target::Host("localhost".into())).unwrap();
        runtime.execute_op(&IrOp::Collect {
            binding: "digest".into(), capability: "hashing.sha256".into(),
            args: vec![Argument::Literal(Literal::String("abc".into()))],
        }).unwrap();
        runtime.execute_op(&IrOp::Report { name: "r".into(), includes: vec!["digest".into()] }).unwrap();
        assert_eq!(runtime.output()["reports"][0]["evidence_sha256"]["digest"].as_str().unwrap().len(), 64);
    }
}
