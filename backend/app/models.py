from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text, Float, CheckConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def now() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid4())


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(32), default="analyst")


class Investigation(Base):
    __tablename__ = "investigations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    owner: Mapped[User] = relationship()


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255))
    platform: Mapped[str] = mapped_column(String(50))
    version: Mapped[str] = mapped_column(String(50), default="0.1.0")
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), index=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    capability: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(32), default="queued")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), index=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"))
    capability: Mapped[str] = mapped_column(String(100))
    object_key: Mapped[str] = mapped_column(String(255), unique=True)
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    blockchain_tx_id: Mapped[str | None] = mapped_column(String(100), nullable=True)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), index=True)
    title: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    content: Mapped[dict] = mapped_column(JSON)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (CheckConstraint("confidence >= 0 AND confidence <= 1"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), index=True)
    category: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    confidence: Mapped[float] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class CustodyEvent(Base):
    __tablename__ = "custody_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(30))
    from_entity: Mapped[str | None] = mapped_column(String(100), nullable=True)
    to_entity: Mapped[str] = mapped_column(String(100))
    blockchain_tx_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class BlockchainRecord(Base):
    __tablename__ = "blockchain_records"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"), unique=True)
    sha256: Mapped[str] = mapped_column(String(64))
    blockchain_tx_id: Mapped[str] = mapped_column(String(100))
    verification_status: Mapped[str] = mapped_column(String(30), default="UNVERIFIED")
    mode: Mapped[str] = mapped_column(String(10))
    custodian: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    actor_id: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(80))
    resource_id: Mapped[str] = mapped_column(String(100))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class EvidenceBatch(Base):
    __tablename__ = "evidence_batches"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), index=True)
    root: Mapped[str] = mapped_column(String(64))
    manifest: Mapped[list] = mapped_column(JSON)
    mode: Mapped[str] = mapped_column(String(10))
    blockchain_tx_id: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
