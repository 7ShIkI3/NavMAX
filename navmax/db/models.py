"""
Modèles SQLAlchemy : Target, Scan, Service, Vulnerability.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Workspace — un projet/contexte d'investigation
# ---------------------------------------------------------------------------
class Workspace(Base):
    __tablename__ = "workspaces"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    targets: Mapped[list["Target"]] = relationship(back_populates="workspace", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Workspace {self.name}>"


# ---------------------------------------------------------------------------
# Target — une cible (IP, domaine, réseau)
# ---------------------------------------------------------------------------
class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    workspace_id: Mapped[str | None] = mapped_column(ForeignKey("workspaces.id", ondelete="SET NULL"))
    workspace: Mapped[Workspace | None] = relationship(back_populates="targets")
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True, comment="Nom affiché")
    address: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, comment="IP, domaine ou CIDR")
    kind: Mapped[str] = mapped_column(
        String(16), nullable=False, default="host", comment="host | subnet | domain"
    )
    tags: Mapped[str | None] = mapped_column(Text, comment="Tags séparés par virgule")
    notes: Mapped[str | None] = mapped_column(Text)
    alive: Mapped[bool | None] = mapped_column(Boolean, default=None, comment="None=inconnu")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    scans: Mapped[list["Scan"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    services: Mapped[list["Service"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    vulns: Mapped[list["Vulnerability"]] = relationship(back_populates="target", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Target {self.name} ({self.address})>"


# ---------------------------------------------------------------------------
# Scan — un scan réseau (Nmap-like)
# ---------------------------------------------------------------------------
class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    target: Mapped[Target] = relationship(back_populates="scans")

    scan_type: Mapped[str] = mapped_column(
        String(32), default="tcp_connect", comment="tcp_connect | tcp_syn | udp | service_detect | os_detect"
    )
    ports: Mapped[str] = mapped_column(Text, comment="Ports scannés (ex: 1-1000,22,80,443)")
    status: Mapped[str] = mapped_column(
        String(16), default="pending", comment="pending | running | completed | failed"
    )
    progress: Mapped[float] = mapped_column(Float, default=0.0, comment="0.0 → 100.0")
    result_summary: Mapped[str | None] = mapped_column(Text)
    raw_result: Mapped[str | None] = mapped_column(Text, comment="Sortie brute JSON")
    error_message: Mapped[str | None] = mapped_column(Text)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    def __repr__(self) -> str:
        return f"<Scan {self.scan_type} sur {self.target_id}>"


# ---------------------------------------------------------------------------
# Service — un service découvert sur un port
# ---------------------------------------------------------------------------
class Service(Base):
    __tablename__ = "services"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    target: Mapped[Target] = relationship(back_populates="services")
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))

    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp", comment="tcp | udp")
    state: Mapped[str] = mapped_column(String(16), default="open", comment="open | closed | filtered")
    service_name: Mapped[str | None] = mapped_column(String(64), comment="http, ssh, ftp, …")
    banner: Mapped[str | None] = mapped_column(Text, comment="Bannière brute du service")
    version: Mapped[str | None] = mapped_column(String(128))
    extra_data: Mapped[str | None] = mapped_column(Text, comment="Données additionnelles JSON")

    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    def __repr__(self) -> str:
        return f"<Service {self.port}/{self.protocol} {self.service_name}>"


# ---------------------------------------------------------------------------
# Vulnerability — une vulnérabilité détectée
# ---------------------------------------------------------------------------
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    target: Mapped[Target] = relationship(back_populates="vulns")
    service_id: Mapped[str | None] = mapped_column(ForeignKey("services.id", ondelete="SET NULL"))

    cve_id: Mapped[str | None] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(String(16), comment="info | low | medium | high | critical")
    cvss_score: Mapped[float | None] = mapped_column(Float)
    evidence: Mapped[str | None] = mapped_column(Text, comment="Preuve JSON de la détection")
    remediation: Mapped[str | None] = mapped_column(Text)
    exploited: Mapped[bool] = mapped_column(Boolean, default=False)

    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    def __repr__(self) -> str:
        return f"<Vuln {self.cve_id or self.title}>"
