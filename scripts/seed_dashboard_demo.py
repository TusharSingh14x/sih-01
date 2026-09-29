"""Create a clearly synthetic negative-case investigation in a local JOCKY dashboard."""
import argparse
import json
import os
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def request(base_url, path, *, method="GET", data=None, token=None, agent=False):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if agent:
        headers["Authorization"] = f"Bearer {os.getenv('JOCKY_AGENT_KEY', 'dev-agent-key')}"
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    call = Request(base_url.rstrip("/") + path, data=body, headers=headers, method=method)
    try:
        with urlopen(call, timeout=10) as response:
            return json.loads(response.read())
    except HTTPError as exc:
        raise RuntimeError(f"{method} {path}: HTTP {exc.code}: {exc.read().decode(errors='replace')}") from exc
    except URLError as exc:
        raise RuntimeError(f"Cannot reach {base_url}: {exc.reason}") from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:8000", help="Local JOCKY backend URL")
    parser.add_argument("--allow-remote", action="store_true", help="Permit sending synthetic records to a non-local URL")
    args = parser.parse_args()
    parsed = urlparse(args.url)
    if parsed.hostname not in {"localhost", "127.0.0.1", "::1"} and not args.allow_remote:
        parser.error("Refusing non-local URL; use --allow-remote only if you intentionally want persistent demo records there")

    email = os.getenv("DEMO_EMAIL", "analyst@jocky.local")
    password = os.getenv("DEMO_PASSWORD", "jocky-demo")
    run_tag = time.strftime("%H%M%S", time.gmtime())
    token = request(args.url, "/api/auth/login", method="POST", data={"email": email, "password": password})["access_token"]
    machines = [
        {"id": f"synthetic-win-{run_tag}", "hostname": f"SYNTHETIC-WIN-{run_tag}", "platform": "windows"},
        {"id": f"synthetic-ubuntu-{run_tag}", "hostname": f"SYNTHETIC-UBUNTU-{run_tag}", "platform": "linux"},
    ]
    for machine in machines:
        request(args.url, "/api/agent/register", method="POST", agent=True,
                data={**machine, "version": "0.1.0-demo"})
    stamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    case = request(args.url, "/api/investigations", method="POST", token=token,
                   data={"title": "DEMO ONLY — Synthetic cross-platform case " + stamp,
                         "description": "Two fabricated Windows/Linux endpoint fixtures for SIH video testing. No real hosts or malware; review indicators, not a malware verdict.",
                         "agent_ids": [machine["id"] for machine in machines]})
    for machine in machines:
        for capability in ("process.list", "network.connections"):
            request(args.url, "/api/jobs", method="POST", token=token,
                    data={"investigation_id": case["id"], "agent_id": machine["id"], "capability": capability})

    completed = []
    for machine in machines:
        for _ in range(3):
            agent_id = machine["id"]
            job = request(args.url, f"/api/agent/{agent_id}/next", agent=True)
            if not job:
                raise RuntimeError(f"Expected a queued synthetic job for {agent_id} but none was available")
            if job["capability"] == "process.list" and machine["platform"] == "windows":
                payload = [{"name": "suspicious_miner.exe", "pid": 4242, "path": "C:/Users/Public/suspicious_miner.exe", "mock": True}]
            elif job["capability"] == "process.list":
                payload = [{"name": "systemd", "pid": 1, "path": "/usr/lib/systemd/systemd", "mock": True}]
            elif job["capability"] == "network.connections" and machine["platform"] == "windows":
                payload = [{"remote_address": "198.51.100.33", "remote_port": 3333, "mock": True}]
            elif job["capability"] == "network.connections":
                payload = [{"remote_address": "198.51.100.44", "remote_port": 443, "mock": True}]
            else:
                payload = {"hostname": machine["hostname"], "os": machine["platform"], "mock": True}
            request(args.url, f"/api/agent/{agent_id}/jobs/{job['id']}/complete", method="POST", agent=True,
                    data={"payload": payload})
            completed.append(f"{machine['hostname']}:{job['capability']}")

    findings = request(args.url, f"/api/findings?investigation_id={case['id']}", token=token)
    print(json.dumps({"investigation": case["title"], "investigation_id": case["id"],
                      "synthetic_endpoints": machines,
                      "completed_jobs": completed, "findings": [
                          {"title": f["title"], "severity": f["severity"], "confidence": f["confidence"]}
                          for f in findings], "note": "Synthetic demo data is now saved in the local dashboard."}, indent=2))


if __name__ == "__main__":
    main()
