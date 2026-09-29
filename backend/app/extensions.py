import hashlib
from threading import RLock
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models as m, storage
from .audit import audit
from .database import get_db
from .registry import get_blockchain
from .security import current_user, require_analyst
from .merkle import ALGORITHM as MERKLE_ALGORITHM, tree as merkle_tree

router = APIRouter(prefix="/api")
registry_lock = RLock()


def public(row):
    return jsonable_encoder({c.name: getattr(row, c.name) for c in row.__table__.columns})


def require_row(db, model, key):
    row = db.get(model, key)
    if row is None:
        raise HTTPException(404, "Record not found")
    return row


class FindingBody(BaseModel):
    investigation_id: str
    category: Literal["process", "network", "logs", "filesystem", "system", "other"]
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=1, max_length=10000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=100)
    confidence: float = Field(ge=0, le=1)


def validate_finding(db, body):
    require_row(db, m.Investigation, body.investigation_id)
    for key in body.evidence_ids:
        if require_row(db, m.Evidence, key).investigation_id != body.investigation_id:
            raise HTTPException(422, "Evidence belongs to another investigation")


@router.get("/findings")
def findings(investigation_id: str | None = None, severity: str | None = None, category: str | None = None,
             search: str = "", db: Session = Depends(get_db), user=Depends(current_user)):
    query = select(m.Finding).order_by(m.Finding.created_at.desc())
    for name, value in (("investigation_id", investigation_id), ("severity", severity), ("category", category)):
        if value:
            query = query.where(getattr(m.Finding, name) == value)
    if search:
        query = query.where(m.Finding.title.icontains(search, autoescape=True))
    return [public(row) for row in db.scalars(query).all()]


@router.post("/findings", status_code=201)
def create_finding(body: FindingBody, db: Session = Depends(get_db), user=Depends(require_analyst)):
    validate_finding(db, body)
    row = m.Finding(**body.model_dump())
    db.add(row)
    db.flush()
    audit(db, user.id, "finding.create", row.id)
    db.commit()
    return public(row)


@router.get("/findings/{key}")
def get_finding(key: str, db: Session = Depends(get_db), user=Depends(current_user)):
    return public(require_row(db, m.Finding, key))


@router.patch("/findings/{key}")
def update_finding(key: str, body: FindingBody, db: Session = Depends(get_db), user=Depends(require_analyst)):
    row = require_row(db, m.Finding, key)
    if row.investigation_id != body.investigation_id:
        raise HTTPException(422, "Cannot move a finding between investigations")
    validate_finding(db, body)
    for name, value in body.model_dump().items():
        setattr(row, name, value)
    audit(db, user.id, "finding.update", key)
    db.commit()
    return public(row)


@router.delete("/findings/{key}")
def delete_finding(key: str, db: Session = Depends(get_db), user=Depends(require_analyst)):
    row = require_row(db, m.Finding, key)
    audit(db, user.id, "finding.delete", key, previous=public(row))
    db.delete(row)
    db.commit()
    return {"deleted": key}


class RegisterBody(BaseModel):
    evidence_id: str


@router.post("/blockchain/register", status_code=201)
def register(body: RegisterBody, db: Session = Depends(get_db), user=Depends(require_analyst), chain=Depends(get_blockchain)):
    with registry_lock:
        evidence = db.scalar(select(m.Evidence).where(m.Evidence.id == body.evidence_id).with_for_update())
        if evidence is None:
            raise HTTPException(404, "Evidence not found")
        existing = db.scalar(select(m.BlockchainRecord).where(m.BlockchainRecord.evidence_id == evidence.id))
        if existing:
            return public(existing)
        case = require_row(db, m.Investigation, evidence.investigation_id)
        if user.id != case.owner_id and user.role != "admin":
            raise HTTPException(403, "Case owner or admin required to register custody")
        try:
            actual = hashlib.sha256(storage.get_object(evidence.object_key)).hexdigest()
        except (OSError, KeyError) as exc:
            raise HTTPException(409, "Evidence unavailable") from exc
        if actual != evidence.sha256:
            raise HTTPException(409, "Evidence hash mismatch; registration refused")
        try:
            tx = chain.register_evidence(evidence.id, evidence.sha256, case.owner_id)
        except Exception as exc:
            raise HTTPException(503, "Registry registration failed; reconcile chain state before retrying") from exc
        record = m.BlockchainRecord(evidence_id=evidence.id, sha256=evidence.sha256, blockchain_tx_id=tx,
                                    mode=chain.mode, custodian=case.owner_id, verification_status="UNVERIFIED")
        evidence.blockchain_tx_id = tx
        db.add(record)
        db.add(m.CustodyEvent(evidence_id=evidence.id, event_type="blockchain", from_entity=case.owner_id,
                             to_entity=case.owner_id, blockchain_tx_id=tx))
        audit(db, user.id, "blockchain.register", evidence.id, mode=chain.mode, transaction=tx)
        db.commit()
        return public(record)


@router.get("/blockchain/records")
def records(db: Session = Depends(get_db), user=Depends(current_user)):
    return [public(row) for row in db.scalars(select(m.BlockchainRecord).order_by(m.BlockchainRecord.created_at.desc()))]


@router.get("/blockchain/verify/{evidence_id}")
def verify(evidence_id: str, db: Session = Depends(get_db), user=Depends(current_user), chain=Depends(get_blockchain)):
    evidence = require_row(db, m.Evidence, evidence_id)
    row = db.scalar(select(m.BlockchainRecord).where(m.BlockchainRecord.evidence_id == evidence_id))
    if row is None:
        raise HTTPException(404, "Evidence is not registered")
    if row.mode != chain.mode:
        raise HTTPException(409, "Registry mode differs from original registration")
    try:
        on_chain = chain.get_evidence(evidence_id)["sha256"]
        actual = hashlib.sha256(storage.get_object(evidence.object_key)).hexdigest()
    except Exception as exc:
        raise HTTPException(503, "Evidence or registry unavailable; verification not performed") from exc
    row.verification_status = "VERIFIED" if actual == on_chain == row.sha256 == evidence.sha256 else "MISMATCH"
    row.verified_at = m.now()
    audit(db, user.id, "blockchain.verify", evidence_id, status=row.verification_status)
    db.commit()
    return {"evidence_id": evidence_id, "status": row.verification_status, "actual_sha256": actual,
            "registered_sha256": on_chain, "metadata_sha256": evidence.sha256, "mode": row.mode, "verified_at": row.verified_at}


class BatchCreate(BaseModel):
    investigation_id: str
    evidence_ids: list[str] = Field(min_length=1, max_length=256)


@router.post("/blockchain/batches", status_code=201)
def register_batch(body: BatchCreate, db: Session = Depends(get_db), user=Depends(require_analyst), chain=Depends(get_blockchain)):
    case = require_row(db, m.Investigation, body.investigation_id)
    if user.id != case.owner_id and user.role != "admin":
        raise HTTPException(403, "Case owner or admin required to commit evidence")
    ids = sorted(set(body.evidence_ids))
    if len(ids) != len(body.evidence_ids):
        raise HTTPException(422, "Evidence IDs must be unique")
    rows = db.scalars(select(m.Evidence).where(m.Evidence.id.in_(ids), m.Evidence.investigation_id == case.id)).all()
    if len(rows) != len(ids):
        raise HTTPException(422, "Every evidence item must belong to this investigation")
    if sum(row.size_bytes for row in rows) > 64 * 1024 * 1024:
        raise HTTPException(413, "Evidence batch exceeds 64 MiB")
    manifest = []
    for evidence in sorted(rows, key=lambda row: row.id):
        try:
            actual = hashlib.sha256(storage.get_object(evidence.object_key)).hexdigest()
        except (OSError, KeyError) as exc:
            raise HTTPException(409, f"Evidence {evidence.id} is unavailable") from exc
        if actual != evidence.sha256:
            raise HTTPException(409, f"Evidence {evidence.id} failed its collection hash check")
        manifest.append({"evidence_id": evidence.id, "sha256": evidence.sha256, "capability": evidence.capability,
                         "size_bytes": evidence.size_bytes, "agent_id": evidence.details.get("agent_id"),
                         "collected_at": evidence.collected_at.isoformat()})
    root, proofs = merkle_tree(manifest)
    batch = m.EvidenceBatch(investigation_id=case.id, root=root, manifest=manifest, mode=chain.mode, blockchain_tx_id="pending")
    db.add(batch)
    db.flush()
    try:
        tx = chain.register_evidence("batch:" + batch.id, root, case.owner_id)
    except Exception as exc:
        db.rollback()
        raise HTTPException(503, "Merkle root registration failed") from exc
    batch.blockchain_tx_id = tx
    audit(db, user.id, "blockchain.batch.register", batch.id,
          algorithm=MERKLE_ALGORITHM, root=root, evidence_count=len(manifest), mode=chain.mode, transaction=tx)
    db.commit()
    return {"id": batch.id, "investigation_id": batch.investigation_id, "algorithm": MERKLE_ALGORITHM,
            "root": root, "mode": batch.mode, "blockchain_tx_id": tx, "created_at": batch.created_at,
            "evidence": [{**item, "proof": proofs[index]} for index, item in enumerate(manifest)]}


@router.get("/blockchain/batches")
def evidence_batches(db: Session = Depends(get_db), _user=Depends(current_user)):
    return [{"id": batch.id, "investigation_id": batch.investigation_id, "root": batch.root,
             "algorithm": MERKLE_ALGORITHM, "mode": batch.mode, "blockchain_tx_id": batch.blockchain_tx_id,
             "created_at": batch.created_at, "evidence_count": len(batch.manifest)}
            for batch in db.scalars(select(m.EvidenceBatch).order_by(m.EvidenceBatch.created_at.desc())).all()]


@router.get("/blockchain/batches/{batch_id}")
def evidence_batch_manifest(batch_id: str, db: Session = Depends(get_db), _user=Depends(current_user)):
    batch = require_row(db, m.EvidenceBatch, batch_id)
    _, proofs = merkle_tree(batch.manifest)
    return {"id": batch.id, "investigation_id": batch.investigation_id, "root": batch.root,
            "algorithm": MERKLE_ALGORITHM, "mode": batch.mode, "blockchain_tx_id": batch.blockchain_tx_id,
            "created_at": batch.created_at, "evidence_count": len(batch.manifest),
            "evidence": [{**item, "proof": proofs[index]} for index, item in enumerate(batch.manifest)]}


@router.get("/blockchain/batches/{batch_id}/verify")
def verify_batch(batch_id: str, db: Session = Depends(get_db), user=Depends(current_user), chain=Depends(get_blockchain)):
    batch = require_row(db, m.EvidenceBatch, batch_id)
    if batch.mode != chain.mode:
        raise HTTPException(409, "Registry mode differs from original commitment")
    current = []
    intact = True
    try:
        for item in batch.manifest:
            evidence = require_row(db, m.Evidence, item["evidence_id"])
            actual = hashlib.sha256(storage.get_object(evidence.object_key)).hexdigest()
            intact &= actual == item["sha256"] == evidence.sha256
            current.append({**item, "sha256": actual})
        root, proofs = merkle_tree(current)
        registered = chain.get_evidence("batch:" + batch.id)["sha256"]
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, "Evidence or registry unavailable; batch verification not performed") from exc
    proof_results = []
    for index, item in enumerate(current):
        from .merkle import verify as verify_proof
        proof_results.append({"evidence_id": item["evidence_id"], "valid": verify_proof(item, proofs[index], registered)})
    intact &= root == batch.root == registered and all(result["valid"] for result in proof_results)
    audit(db, user.id, "blockchain.batch.verify", batch.id, status="VERIFIED" if intact else "MISMATCH", root=root)
    db.commit()
    return {"id": batch.id, "status": "VERIFIED" if intact else "MISMATCH", "algorithm": MERKLE_ALGORITHM,
            "stored_root": batch.root, "current_root": root, "registered_root": registered,
            "mode": batch.mode, "proofs": proof_results}


@router.get("/custody/history")
def history(evidence_id: str, db: Session = Depends(get_db), user=Depends(current_user)):
    require_row(db, m.Evidence, evidence_id)
    return [public(row) for row in db.scalars(select(m.CustodyEvent).where(m.CustodyEvent.evidence_id == evidence_id)
                                              .order_by(m.CustodyEvent.created_at, m.CustodyEvent.id))]


class TransferBody(BaseModel):
    evidence_id: str
    from_entity: str
    to_entity: str


@router.post("/custody/transfer")
def transfer(body: TransferBody, db: Session = Depends(get_db), user=Depends(require_analyst), chain=Depends(get_blockchain)):
    with registry_lock:
        row = db.scalar(select(m.BlockchainRecord).where(m.BlockchainRecord.evidence_id == body.evidence_id).with_for_update())
        if row is None:
            raise HTTPException(409, "Register evidence before transferring custody")
        if row.mode != chain.mode:
            raise HTTPException(409, "Registry mode mismatch")
        if row.custodian != body.from_entity:
            raise HTTPException(409, "Stale custodian")
        if user.id != row.custodian:
            raise HTTPException(403, "Only the current custodian can transfer evidence")
        recipient = require_row(db, m.User, body.to_entity)
        if recipient.role not in {"analyst", "admin"} or recipient.id == row.custodian:
            raise HTTPException(422, "Choose another analyst or admin")
        try:
            tx = chain.transfer_custody(body.evidence_id, body.from_entity, body.to_entity)
        except Exception as exc:
            raise HTTPException(503, "Custody transaction failed; reconcile chain state before retrying") from exc
        row.custodian = recipient.id
        event = m.CustodyEvent(**body.model_dump(), event_type="transfer", blockchain_tx_id=tx)
        db.add(event)
        audit(db, user.id, "custody.transfer", body.evidence_id, recipient=recipient.id, transaction=tx)
        db.commit()
        return public(event)


@router.get("/custody/recipients")
def recipients(db: Session = Depends(get_db), user=Depends(require_analyst)):
    return [{"id": row.id, "email": row.email} for row in db.scalars(select(m.User).where(m.User.role.in_(["analyst", "admin"])))]


@router.get("/audit")
def audit_log(limit: int = Query(200, ge=1, le=1000), db: Session = Depends(get_db), user=Depends(current_user)):
    if user.role != "admin":
        raise HTTPException(403, "Admin role required")
    return [public(row) for row in db.scalars(select(m.AuditLog).order_by(m.AuditLog.created_at.desc()).limit(limit))]


@router.get("/investigations/{key}")
def investigation_detail(key: str, db: Session = Depends(get_db), user=Depends(current_user)):
    case = require_row(db, m.Investigation, key)
    jobs = db.scalars(select(m.Job).where(m.Job.investigation_id == key)).all()
    agents = db.scalars(select(m.Agent).where(m.Agent.id.in_({job.agent_id for job in jobs}))).all()
    return {"investigation": public(case), "agents": [public(a) for a in agents], "jobs": [public(j) for j in jobs],
            "evidence": [public(e) for e in db.scalars(select(m.Evidence).where(m.Evidence.investigation_id == key))],
            "findings": [public(f) for f in db.scalars(select(m.Finding).where(m.Finding.investigation_id == key))]}


@router.get("/reports/{key}/pdf")
def pdf_report(key: str, db: Session = Depends(get_db), user=Depends(current_user)):
    from .report_generator import generate_report
    report = require_row(db, m.Report, key)
    data = generate_report(db, report)
    audit(db, user.id, "report.pdf", key)
    db.commit()
    return Response(data, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="jocky-{report.id}.pdf"'})
