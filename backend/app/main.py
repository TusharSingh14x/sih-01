import hashlib
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config, models, storage
from .database import Base, SessionLocal, engine, get_db
from .security import create_token, current_user, hash_password, require_agent, require_analyst, verify_password
from .audit import audit
from .extensions import router as extension_router
from .editor import router as editor_router
from .rate_limit import RateLimitMiddleware


SAFE_CAPABILITIES = {"system.info", "system.drivers", "process.list", "network.connections", "logs.system"}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(bind=engine)
    # Compatibility with pre-registry local databases. Deployment uses Alembic.
    from sqlalchemy import inspect, text
    if "blockchain_tx_id" not in {c["name"] for c in inspect(engine).get_columns("evidence")}:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE evidence ADD COLUMN blockchain_tx_id VARCHAR(100)"))
    with SessionLocal() as db:
        user = db.scalar(select(models.User).where(models.User.email == config.DEMO_EMAIL))
        if user is None:
            db.add(models.User(email=config.DEMO_EMAIL, password_hash=hash_password(config.DEMO_PASSWORD)))
            db.commit()
    yield


app = FastAPI(title="JOCKY Investigation API", version="0.1.0", lifespan=lifespan)
app.include_router(extension_router)
app.include_router(editor_router)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(","),
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


class Login(BaseModel):
    email: str
    password: str


class InvestigationCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=5000)
    agent_ids: list[str] = Field(default_factory=list, max_length=100)


class InvestigationUpdate(BaseModel):
    status: Literal["open", "closed"]


class JobCreate(BaseModel):
    investigation_id: str
    agent_id: str
    capability: str = Field(max_length=100)


class AgentRegistration(BaseModel):
    id: str = Field(min_length=1, max_length=100)
    hostname: str = Field(min_length=1, max_length=255)
    platform: str = Field(min_length=1, max_length=50)
    version: str = Field(default="0.1.0", max_length=50)


class Completion(BaseModel):
    payload: dict | list | None = None
    error: str | None = Field(default=None, max_length=2000)


class ReportCreate(BaseModel):
    investigation_id: str
    title: str = Field(min_length=3, max_length=200)


class PublicModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class InvestigationOut(PublicModel):
    id: str
    title: str
    description: str
    status: str
    created_at: datetime
    owner_id: str


class AgentOut(PublicModel):
    id: str
    hostname: str
    platform: str
    version: str
    last_seen: datetime


class JobOut(PublicModel):
    id: str
    investigation_id: str
    agent_id: str
    capability: str
    status: str
    created_at: datetime
    completed_at: datetime | None
    error: str | None


class EvidenceOut(PublicModel):
    id: str
    investigation_id: str
    job_id: str
    capability: str
    sha256: str
    size_bytes: int
    collected_at: datetime
    details: dict
    blockchain_tx_id: str | None


class ReportOut(PublicModel):
    id: str
    investigation_id: str
    title: str
    created_at: datetime
    content: dict


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/auth/login")
def login(body: Login, db: Session = Depends(get_db)):
    user = db.scalar(select(models.User).where(models.User.email == body.email))
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    audit(db, user.id, "auth.login", user.id)
    db.commit()
    return {"access_token": create_token(user), "token_type": "bearer", "role": user.role}


@app.get("/api/investigations", response_model=list[InvestigationOut])
def investigations(db: Session = Depends(get_db), _user: models.User = Depends(current_user)):
    return db.scalars(select(models.Investigation).order_by(models.Investigation.created_at.desc())).all()


@app.post("/api/investigations", response_model=InvestigationOut, status_code=201)
def create_investigation(body: InvestigationCreate, db: Session = Depends(get_db), user: models.User = Depends(require_analyst)):
    for agent_id in set(body.agent_ids):
        if db.get(models.Agent, agent_id) is None:
            raise HTTPException(404, "Agent not found")
    row = models.Investigation(title=body.title, description=body.description, owner_id=user.id)
    db.add(row)
    db.flush()
    for agent_id in sorted(set(body.agent_ids)):
        db.add(models.Job(investigation_id=row.id, agent_id=agent_id, capability="system.info"))
    audit(db, user.id, "investigation.create", row.id, agents=body.agent_ids)
    db.commit()
    db.refresh(row)
    return row


@app.patch("/api/investigations/{investigation_id}", response_model=InvestigationOut)
def update_investigation(investigation_id: str, body: InvestigationUpdate, db: Session = Depends(get_db), _user: models.User = Depends(require_analyst)):
    row = db.get(models.Investigation, investigation_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    row.status = body.status
    audit(db, _user.id, "investigation.update", row.id, status=body.status)
    db.commit()
    db.refresh(row)
    return row


@app.get("/api/agents", response_model=list[AgentOut])
def agents(db: Session = Depends(get_db), _user: models.User = Depends(current_user)):
    return db.scalars(select(models.Agent).order_by(models.Agent.hostname)).all()


@app.post("/api/agent/register", response_model=AgentOut)
def register_agent(body: AgentRegistration, db: Session = Depends(get_db), _agent: None = Depends(require_agent)):
    row = db.get(models.Agent, body.id)
    if row is None:
        row = models.Agent(id=body.id, hostname=body.hostname, platform=body.platform, version=body.version)
        db.add(row)
    else:
        row.hostname, row.platform, row.version = body.hostname, body.platform, body.version
        row.last_seen = models.now()
    db.commit()
    db.refresh(row)
    return row


@app.get("/api/jobs", response_model=list[JobOut])
def jobs(db: Session = Depends(get_db), _user: models.User = Depends(current_user)):
    return db.scalars(select(models.Job).order_by(models.Job.created_at.desc())).all()


@app.post("/api/jobs", response_model=JobOut, status_code=201)
def create_job(body: JobCreate, db: Session = Depends(get_db), _user: models.User = Depends(require_analyst)):
    module_request = body.capability.startswith("process.modules:") and body.capability.removeprefix("process.modules:").isdigit()
    if body.capability not in SAFE_CAPABILITIES and not module_request:
        raise HTTPException(status_code=422, detail="Unsupported collection capability")
    if module_request and not 1 <= int(body.capability.removeprefix("process.modules:")) <= 2**32 - 1:
        raise HTTPException(status_code=422, detail="Process ID must be between 1 and 4294967295")
    investigation = db.get(models.Investigation, body.investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if investigation.status != "open":
        raise HTTPException(status_code=409, detail="Investigation is closed")
    if db.get(models.Agent, body.agent_id) is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    row = models.Job(**body.model_dump())
    db.add(row)
    db.flush()
    audit(db, _user.id, "job.create", row.id)
    db.commit()
    db.refresh(row)
    return row


@app.get("/api/agent/{agent_id}/next", response_model=JobOut | None)
def next_job(agent_id: str, db: Session = Depends(get_db), _agent: None = Depends(require_agent)):
    if db.get(models.Agent, agent_id) is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    row = db.scalar(select(models.Job).where(models.Job.agent_id == agent_id, models.Job.status == "queued").order_by(models.Job.created_at).with_for_update(skip_locked=True))
    if row:
        row.status = "running"
        db.commit()
        db.refresh(row)
    return row


@app.post("/api/agent/{agent_id}/jobs/{job_id}/complete", response_model=JobOut)
def complete_job(agent_id: str, job_id: str, body: Completion, db: Session = Depends(get_db), _agent: None = Depends(require_agent)):
    row = db.get(models.Job, job_id)
    if row is None or row.agent_id != agent_id or row.status != "running":
        raise HTTPException(status_code=404, detail="Running job not found")
    if body.error:
        row.status, row.error = "failed", body.error
    else:
        if body.payload is None:
            raise HTTPException(status_code=422, detail="Payload required")
        data = json.dumps(body.payload, sort_keys=True, separators=(",", ":")).encode()
        if len(data) > 1_000_000:
            raise HTTPException(status_code=413, detail="Evidence too large")
        evidence = models.Evidence(
            investigation_id=row.investigation_id,
            job_id=row.id,
            capability=row.capability,
            object_key=f"{row.investigation_id}/{row.id}.json",
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
            collected_at=models.now(),
            details={},
        )
        storage.put_object(evidence.object_key, data)
        db.add(evidence)
        db.flush()
        agent_record = db.get(models.Agent, agent_id)
        provenance = {
            "schema": "jocky-collection-manifest-v1",
            "evidence_id": evidence.id,
            "investigation_id": row.investigation_id,
            "job_id": row.id,
            "agent_id": agent_id,
            "agent_hostname": agent_record.hostname if agent_record else agent_id,
            "agent_platform": agent_record.platform if agent_record else "unknown",
            "agent_version": agent_record.version if agent_record else "unknown",
            "capability": row.capability,
            "collected_at_utc": evidence.collected_at.isoformat(),
            "evidence_sha256": evidence.sha256,
        }
        canonical_manifest = json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode()
        evidence.details = {**provenance, "collection_manifest_sha256": hashlib.sha256(canonical_manifest).hexdigest()}
        from .detection import persist as analyze_evidence
        try:
            analyze_evidence(db, evidence, body.payload)
        except (OSError, ValueError, TypeError):
            evidence.details = {**evidence.details, "analysis_status": "failed", "finding_count": 0}
        owner = db.get(models.Investigation, row.investigation_id).owner_id
        db.add(models.CustodyEvent(evidence_id=evidence.id, event_type="collection", from_entity=agent_id, to_entity=owner))
        audit(db, agent_id, "evidence.collect", evidence.id, sha256=evidence.sha256)
        row.status = "completed"
    row.completed_at = models.now()
    audit(db, agent_id, "job.complete", row.id, status=row.status)
    db.commit()
    db.refresh(row)
    return row


@app.get("/api/evidence", response_model=list[EvidenceOut])
def evidence(investigation_id: str | None = None, db: Session = Depends(get_db), _user: models.User = Depends(current_user)):
    query = select(models.Evidence).order_by(models.Evidence.collected_at.desc())
    if investigation_id:
        query = query.where(models.Evidence.investigation_id == investigation_id)
    return db.scalars(query).all()


@app.get("/api/evidence/{evidence_id}/content")
def evidence_content(evidence_id: str, db: Session = Depends(get_db), _user: models.User = Depends(current_user)):
    row = db.get(models.Evidence, evidence_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    data = storage.get_object(row.object_key)
    if hashlib.sha256(data).hexdigest() != row.sha256:
        raise HTTPException(status_code=409, detail="Evidence hash mismatch")
    return json.loads(data)


@app.get("/api/reports", response_model=list[ReportOut])
def reports(db: Session = Depends(get_db), _user: models.User = Depends(current_user)):
    return db.scalars(select(models.Report).order_by(models.Report.created_at.desc())).all()


@app.post("/api/reports", response_model=ReportOut, status_code=201)
def create_report(body: ReportCreate, db: Session = Depends(get_db), _user: models.User = Depends(require_analyst)):
    investigation = db.get(models.Investigation, body.investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    entries = db.scalars(select(models.Evidence).where(models.Evidence.investigation_id == body.investigation_id)).all()
    content = {
        "investigation": investigation.title,
        "generated_at": models.now().isoformat(),
        "evidence": [{"id": e.id, "capability": e.capability, "sha256": e.sha256, "collected_at": e.collected_at.isoformat()} for e in entries],
        "evidence_count": len(entries),
    }
    row = models.Report(investigation_id=body.investigation_id, title=body.title, content=content)
    db.add(row)
    db.flush()
    audit(db, _user.id, "report.create", row.id)
    db.commit()
    db.refresh(row)
    return row
