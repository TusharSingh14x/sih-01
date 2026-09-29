"""Isolated synthetic demo. Never connects to or tampers with a live workspace."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


def scenario(client, tamper):
    def call(method, path, headers=None, **kwargs):
        result = client.request(method, path, headers=headers, **kwargs)
        assert result.is_success, (path, result.status_code, result.text)
        return result.json()
    token = call("POST", "/api/auth/login", json={"email":"analyst@jocky.local", "password":"jocky-demo"})["access_token"]
    analyst = {"Authorization": "Bearer " + token}
    agent = {"Authorization":"Bearer dev-agent-key"}
    machines = ["PC-001", "PC-002", "UBUNTU-001"]
    for name in machines:
        call("POST", "/api/agent/register", agent, json={"id":name,"hostname":name,"platform":"linux" if name.startswith("UBUNTU") else "windows"})
    case = call("POST", "/api/investigations", analyst, json={"title":"CASE-001", "description":"Synthetic demonstration only", "agent_ids":machines})
    for name in machines:
        job = call("GET", f"/api/agent/{name}/next", agent)
        call("POST", f"/api/agent/{name}/jobs/{job['id']}/complete", agent, json={"payload":{"hostname":name,"mock":True,"os":"synthetic"}})
        for capability, payload in [("process.list", [{"name":"suspicious_miner.exe" if name == "PC-001" else "notepad.exe", "pid":1013, "mock":True}]),
                                    ("network.connections", [{"remote_address":"198.51.100.33", "remote_port":3333 if name == "PC-001" else 443, "mock":True}])]:
            call("POST", "/api/jobs", analyst, json={"investigation_id":case["id"],"agent_id":name,"capability":capability})
            job = call("GET", f"/api/agent/{name}/next", agent)
            call("POST", f"/api/agent/{name}/jobs/{job['id']}/complete", agent, json={"payload":payload})
    evidence = call("GET", "/api/evidence?investigation_id=" + case["id"], analyst)
    for item in evidence:
        call("POST", "/api/blockchain/register", analyst, json={"evidence_id":item["id"]})
    findings = call("GET", "/api/findings", analyst)
    assert any(f["title"] == "Possible mining process" for f in findings)
    assert any(f["title"] == "Connection to review: remote port 3333" for f in findings)
    batch = call("POST", "/api/blockchain/batches", analyst, json={"investigation_id":case["id"], "evidence_ids":[e["id"] for e in evidence]})
    batch_check = call("GET", "/api/blockchain/batches/" + batch["id"] + "/verify", analyst)
    assert batch_check["status"] == "VERIFIED" and all(p["valid"] for p in batch_check["proofs"])
    first = next(e for e in evidence if e["details"]["agent_id"] == "PC-001" and e["capability"] == "system.info")
    second = next(e for e in evidence if e["details"]["agent_id"] == "PC-002" and e["capability"] == "system.info")
    tamper(first)
    results = {"PC-001":call("GET", "/api/blockchain/verify/" + first["id"], analyst)["status"],
               "PC-002":call("GET", "/api/blockchain/verify/" + second["id"], analyst)["status"]}
    assert results == {"PC-001":"MISMATCH", "PC-002":"VERIFIED"}
    tampered_batch = call("GET", "/api/blockchain/batches/" + batch["id"] + "/verify", analyst)
    assert tampered_batch["status"] == "MISMATCH"
    report = call("POST", "/api/reports", analyst, json={"investigation_id":case["id"],"title":"CASE-001 synthetic report"})
    pdf = client.get(f"/api/reports/{report['id']}/pdf", headers=analyst)
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    return {"case_id":case["id"], "verification":results, "batch_before_tamper":"VERIFIED",
            "batch_after_tamper":tampered_batch["status"], "automatic_findings":len(findings),
            "report_id":report["id"], "evidence_count":len(evidence)}, pdf.content


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("output/pdf/demo-report.pdf"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "backend"))
    with tempfile.TemporaryDirectory(prefix="jocky-demo-") as directory:
        temp = Path(directory)
        iocs = temp / "iocs.json"
        iocs.write_text(json.dumps({"ips": [], "sha256": [], "drivers": []}), encoding="utf-8")
        os.environ.update(DATABASE_URL="sqlite:///" + (temp / "demo.db").as_posix(), EVIDENCE_DIR=str(temp / "evidence"),
            STORAGE_BACKEND="local", BLOCKCHAIN_MOCK="true", BLOCKCHAIN_MOCK_DB=str(temp / "chain.db"),
            DEMO_EMAIL="analyst@jocky.local", DEMO_PASSWORD="jocky-demo", AGENT_API_KEY="dev-agent-key",
            JOCKY_IOC_PATH=str(iocs))
        from fastapi.testclient import TestClient
        from app.main import app
        from app import storage
        def tamper(item):
            storage.put_object(f"{item['investigation_id']}/{item['job_id']}.json", b'{"mock":true,"tampered":true}')
        with TestClient(app) as client:
            result, pdf = scenario(client, tamper)
        from app.registry import get_blockchain
        from app.database import engine
        get_blockchain().db.close()
        get_blockchain.cache_clear()
        engine.dispose()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(pdf)
        print(json.dumps({**result, "pdf":str(args.output.resolve()), "mode":"isolated mock"}, indent=2))


if __name__ == "__main__":
    main()
