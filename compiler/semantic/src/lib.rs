use std::collections::HashSet;

use jocky_ast::{Argument, ForensicCall, Literal, Program, Statement};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SemanticError {
    #[error("unsafe or unsupported forensic call {0}.{1}")]
    UnsafeCall(String, String),
    #[error("duplicate binding {0}")]
    DuplicateBinding(String),
    #[error("unknown binding {0}")]
    UnknownBinding(String),
    #[error("invalid arguments for {0}.{1}: {2}")]
    InvalidArguments(String, String, &'static str),
    #[error("a JOCKY program must contain at least one investigation")]
    EmptyProgram,
}

pub fn analyze(program: &Program) -> Result<(), SemanticError> {
    if program.investigations.is_empty() {
        return Err(SemanticError::EmptyProgram);
    }
    for investigation in &program.investigations {
        let mut bindings = HashSet::new();
        for statement in &investigation.statements {
            match statement {
                Statement::Collect { call, alias } => {
                    validate_call(call, &bindings)?;
                    if !bindings.insert(alias.clone()) {
                        return Err(SemanticError::DuplicateBinding(alias.clone()));
                    }
                }
                Statement::Analyze { source, predicate: _ } => {
                    if !bindings.contains(source) {
                        return Err(SemanticError::UnknownBinding(source.clone()));
                    }
                    let destination = format!("{source}_analysis");
                    if !bindings.insert(destination.clone()) {
                        return Err(SemanticError::DuplicateBinding(destination));
                    }
                }
                Statement::Report { name: _, includes } => {
                    for include in includes {
                        if !bindings.contains(include) {
                            return Err(SemanticError::UnknownBinding(include.clone()));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_call(call: &ForensicCall, bindings: &HashSet<String>) -> Result<(), SemanticError> {
    let expected = match (call.namespace.as_str(), call.function.as_str()) {
        ("system", "info") | ("system", "drivers") | ("process", "list") | ("network", "connections")
        | ("logs", "journal") => 0,
        ("process", "modules") => 1,
        ("filesystem", "metadata") | ("filesystem", "hash") | ("logs", "read")
        | ("logs", "syslog") | ("logs", "windows_events")
        | ("hashing", "sha256") | ("timeline", "build") | ("reporting", "summary") => 1,
        _ => return Err(SemanticError::UnsafeCall(
            call.namespace.clone(),
            call.function.clone(),
        )),
    };
    if call.args.len() != expected {
        return Err(SemanticError::InvalidArguments(call.namespace.clone(), call.function.clone(), "wrong argument count"));
    }
    match (call.namespace.as_str(), call.function.as_str(), call.args.first()) {
        ("process", "modules", Some(Argument::Literal(Literal::Integer(pid))))
            if *pid > 0 && *pid <= u32::MAX as i64 => Ok(()),
        ("filesystem" | "logs" | "hashing", _, Some(Argument::Literal(Literal::String(_)))) => Ok(()),
        ("timeline" | "reporting", _, Some(Argument::Binding(name))) => {
            if bindings.contains(name) { Ok(()) } else { Err(SemanticError::UnknownBinding(name.clone())) }
        }
        ("system" | "process" | "network" | "logs", _, None) => Ok(()),
        _ => Err(SemanticError::InvalidArguments(call.namespace.clone(), call.function.clone(), "expected a string literal or prior binding")),
    }
}

#[cfg(test)]
mod tests {
    use jocky_ast::{ForensicCall, Investigation, Program, Statement, Target};

    use super::*;

    #[test]
    fn rejects_unsafe_calls() {
        let program = Program {
            investigations: vec![Investigation {
                title: "x".into(),
                target: Target::Host("h".into()),
                statements: vec![Statement::Collect {
                    call: ForensicCall {
                        namespace: "process".into(),
                        function: "inject".into(),
                        args: vec![],
                    },
                    alias: "x".into(),
                }],
            }],
        };
        assert!(analyze(&program).is_err());
    }

    #[test]
    fn allows_incident_terms_in_investigation_metadata() {
        let program = Program {
            investigations: vec![Investigation {
                title: "Credential theft investigation".into(),
                target: Target::Host("h".into()),
                statements: vec![Statement::Collect {
                    call: ForensicCall {
                        namespace: "process".into(),
                        function: "list".into(),
                        args: vec![],
                    },
                    alias: "credential_incident".into(),
                }],
            }],
        };
        assert!(analyze(&program).is_ok());
    }

    #[test]
    fn validates_argument_types_and_binding_order() {
        let program = jocky_parser::parse_program(r#"investigation "x" { target host("h") collect reporting.summary(missing) as summary }"#).unwrap();
        assert_eq!(analyze(&program), Err(SemanticError::UnknownBinding("missing".into())));
        let program = jocky_parser::parse_program(r#"investigation "x" { target host("h") collect filesystem.hash(1) as digest }"#).unwrap();
        assert!(matches!(analyze(&program), Err(SemanticError::InvalidArguments(..))));
        let program = jocky_parser::parse_program(r#"investigation "x" { target host("localhost") collect process.modules(0) as modules }"#).unwrap();
        assert!(matches!(analyze(&program), Err(SemanticError::InvalidArguments(..))));
        let program = jocky_parser::parse_program(r#"investigation "x" { target host("localhost") collect process.modules(123) as modules collect logs.journal() as journal }"#).unwrap();
        assert!(analyze(&program).is_ok());
    }

    #[test]
    fn rejects_empty_program() {
        assert_eq!(analyze(&Program { investigations: vec![] }), Err(SemanticError::EmptyProgram));
    }
}
