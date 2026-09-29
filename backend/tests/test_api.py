import hashlib
import json
import os

from fastapi.testclient import TestClient


def test_investigation_collection_and_report(tmp_path):
    os.environ["DATABASE_URL"] = f"sqlite:///{(tmp_path / 'test.db').as_posix()}"
    os.environ["EVIDENCE_DIR"] = str(tmp_path / "evidence")
    os.environ["STORAGE_BACKEND"] = "local"

    from app.main import app
    from app import models
    from app.database import SessionLocal
    from app.security import create_token, hash_password

    with TestClient(app) as client:
        assert client.get("/health").json() == {"status": "ok"}
        assert client.get("/api/jobs").status_code in (401, 403)
        assert client.post("/api/auth/login", json={"email": "analyst@jocky.local", "password": "wrong"}).status_code == 401
        token = client.post("/api/auth/login", json={"email": "analyst@jocky.local", "password": "jocky-demo"}).json()["access_token"]
        analyst = {"Authorization": f"Bearer {token}"}
        agent = {"Authorization": "Bearer dev-agent-key"}

        case = client.post("/api/investigations", headers=analyst, json={"title": "Endpoint triage", "description": "Authorized host review"})
        assert case.status_code == 201
        case_id = case.json()["id"]
        assert len(client.get("/api/investigations", headers=analyst).json()) == 1

        with SessionLocal() as db:
            viewer = models.User(email="viewer@jocky.local", password_hash=hash_password("viewer-password"), role="viewer")
            db.add(viewer)
            db.commit()
            viewer_token = create_token(viewer)
        viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
        assert client.get("/api/investigations", headers=viewer_headers).status_code == 200
        assert client.post("/api/investigations", headers=viewer_headers, json={"title": "Denied case"}).status_code == 403

        assert client.post("/api/agent/register", headers=analyst, json={"id": "host-1", "hostname": "host-1", "platform": "linux"}).status_code == 401
        registration = client.post("/api/agent/register", headers=agent, json={"id": "host-1", "hostname": "host-1", "platform": "linux"})
        assert registration.status_code == 200
        assert client.post("/api/jobs", headers=analyst, json={"investigation_id": case_id, "agent_id": "host-1", "capability": "process.inject"}).status_code == 422

        job = client.post("/api/jobs", headers=analyst, json={"investigation_id": case_id, "agent_id": "host-1", "capability": "system.info"})
        assert job.status_code == 201
        claimed = client.get("/api/agent/host-1/next", headers=agent).json()
        assert claimed["id"] == job.json()["id"]
        assert claimed["status"] == "running"
        assert client.get("/api/agent/host-1/next", headers=agent).json() is None
        completed = client.post(f"/api/agent/host-1/jobs/{claimed['id']}/complete", headers=agent, json={"payload": {"hostname": "host-1", "os": "linux"}})
        assert completed.json()["status"] == "completed"

        items = client.get("/api/evidence", headers=analyst).json()
        assert len(items) == 1
        assert len(items[0]["sha256"]) == 64
        manifest = items[0]["details"]
        assert manifest["schema"] == "jocky-collection-manifest-v1"
        assert manifest["agent_platform"] == "linux"
        assert manifest["agent_version"] == "0.1.0"
        assert manifest["evidence_sha256"] == items[0]["sha256"]
        assert len(manifest["collection_manifest_sha256"]) == 64
        manifest_fields = {key: manifest[key] for key in (
            "schema", "evidence_id", "investigation_id", "job_id", "agent_id",
            "agent_hostname", "agent_platform", "agent_version", "capability",
            "collected_at_utc", "evidence_sha256",
        )}
        canonical_manifest = json.dumps(manifest_fields, sort_keys=True, separators=(",", ":")).encode()
        assert hashlib.sha256(canonical_manifest).hexdigest() == manifest["collection_manifest_sha256"]
        assert client.get(f"/api/evidence/{items[0]['id']}/content", headers=analyst).json()["hostname"] == "host-1"
        report = client.post("/api/reports", headers=analyst, json={"investigation_id": case_id, "title": "Triage report"})
        assert report.status_code == 201
        assert report.json()["content"]["evidence_count"] == 1

        closed = client.patch(f"/api/investigations/{case_id}", headers=analyst, json={"status": "closed"})
        assert closed.json()["status"] == "closed"
        assert client.post("/api/jobs", headers=analyst, json={"investigation_id": case_id, "agent_id": "host-1", "capability": "system.info"}).status_code == 409
        assert client.patch(f"/api/investigations/{case_id}", headers=viewer_headers, json={"status": "open"}).status_code == 403

        evidence_file = tmp_path / "evidence" / case_id / f"{claimed['id']}.json"
        evidence_file.write_text('{"hostname":"tampered"}')
        assert client.get(f"/api/evidence/{items[0]['id']}/content", headers=analyst).status_code == 409
