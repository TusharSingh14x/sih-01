"""Bounded, explainable triage rules for collected evidence. Never malware verdicts."""
import hashlib
import json
import os
from pathlib import Path
from uuid import uuid5, NAMESPACE_URL
from . import models as m

RULESET = "jocky-triage-1"


def rows(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("processes", "connections", "events", "lines", "files", "modules", "drivers"):
            if isinstance(payload.get(key), list):
                return payload[key]
        return [payload]
    return []


def indicators():
    """Operator-maintained offline indicators; no external evidence uploads."""
    path = os.getenv("JOCKY_IOC_PATH")
    if not path:
        return {}
    with Path(path).open("rb") as source:
        content = source.read(1_000_001)
    if len(content) > 1_000_000:
        raise ValueError("IOC file exceeds 1 MB")
    data = json.loads(content)
    if not isinstance(data, dict):
        raise ValueError("IOC file must be an object")
    for key in ("ips", "sha256", "drivers"):
        values = data.get(key, [])
        if not isinstance(values, list) or len(values) > 10000 or any(not isinstance(value, str) or len(value) > 512 for value in values):
            raise ValueError(f"IOC field {key} must be a bounded list of strings")
    return data


def analyze(capability, payload, iocs=None):
    iocs = iocs or {}
    findings = []
    for index, raw in enumerate(rows(payload)[:10000]):
        row = raw if isinstance(raw, dict) else {"message": str(raw)}
        def emit(rule, category, title, severity="MEDIUM", confidence=0.45):
            findings.append(dict(rule=rule, index=index, category=category, title=title,
                severity=severity, confidence=confidence,
                description=f"Ruleset {RULESET}; rule {rule}; evidence row {index}; PID {row.get('pid', 'unknown')}. Indicator requires analyst review; confidence is a heuristic, not a probability."))
        if capability == "process.list":
            name = str(row.get("name", "")).lower()
            path = str(row.get("exe") or row.get("path") or "").replace("\\", "/").lower()
            command = row.get("command_line") or []
            command = " ".join(map(str, command)) if isinstance(command, list) else str(command)
            if "miner" in name:
                emit("process.miner", "process", "Possible mining process", "HIGH", 0.75)
            if any(part in {"tmp", "temp"} for part in path.split("/")):
                emit("process.temp", "process", "Process executable in temporary directory")
            if name in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"} and any(arg in command.lower().split() for arg in ("-enc", "-encodedcommand", "-e")):
                emit("process.encoded_powershell", "process", "Encoded PowerShell command requires review")
        if capability == "system.drivers":
            name = str(row.get("name", "")).lower()
            driver_iocs = {str(value).lower().removesuffix(".sys").removesuffix(".ko") for value in iocs.get("drivers", [])}
            if name and name.removesuffix(".sys").removesuffix(".ko") in driver_iocs:
                emit("driver.local_ioc", "system", "Driver matches local review list", "HIGH", 0.85)
        if capability.startswith("process.modules:"):
            path = str(row.get("path", row.get("name", ""))).replace("\\", "/").lower()
            if any(part in {"tmp", "temp"} for part in path.split("/")):
                emit("module.temp", "process", "Module loaded from temporary directory", "HIGH", 0.65)
        if capability == "network.connections":
            endpoint = str(row.get("remote_address", ""))
            ip = endpoint.rsplit(":", 1)[0].strip("[]")
            try:
                port = int(row.get("remote_port") or endpoint.rsplit(":", 1)[-1])
            except (ValueError, TypeError):
                port = 0
            if port in (3333, 4444):
                emit("network.unusual_port", "network", f"Connection to review: remote port {port}")
            if ip in iocs.get("ips", []):
                emit("network.ioc", "network", "Remote address matches local IOC list", "HIGH", 0.85)
        digest = str(row.get("sha256", "")).lower()
        if digest and digest in iocs.get("sha256", []):
            emit("file.ioc", "filesystem", "File hash matches local IOC list", "HIGH", 0.95)
        if capability.startswith("logs."):
            message = str(row.get("message", row.get("text", ""))).lower()
            if "failed password" in message or "failed login" in message or str(row.get("event_id")) == "4625":
                emit("logs.failed_login", "logs", "Failed authentication event")
    return findings[:500]


def persist(db, evidence, payload):
    generated = analyze(evidence.capability, payload, indicators())
    count = 0
    for item in generated:
        key = str(uuid5(NAMESPACE_URL, f"{RULESET}:{evidence.id}:{item['rule']}:{item['index']}"))
        if db.get(m.Finding, key) is None:
            values = {k:v for k,v in item.items() if k not in {"rule", "index"}}
            db.add(m.Finding(id=key, investigation_id=evidence.investigation_id, evidence_ids=[evidence.id], **values))
            count += 1
    db.flush()
    evidence.details = {**evidence.details, "ruleset": RULESET, "analysis_status": "complete", "finding_count": len(generated)}
    return count
