"""PostgreSQL persistence for uploaded analysis metadata and findings."""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, Integer, JSON, String, create_engine, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker


class DatabaseConfigurationError(RuntimeError):
    pass


class DatabaseStorageError(RuntimeError):
    pass


class Base(DeclarativeBase):
    pass


class AnalysisRecord(Base):
    __tablename__ = "analyses"

    analysis_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    packet_count: Mapped[int] = mapped_column(Integer, nullable=False)
    window_count: Mapped[int] = mapped_column(Integer, nullable=False)
    duration_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    protocols: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="uploaded_pcap")
    result: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(String(1000))
    findings: Mapped[list["FindingRecord"]] = relationship(back_populates="analysis", cascade="all, delete-orphan")


class FindingRecord(Base):
    __tablename__ = "findings"

    finding_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.analysis_id", ondelete="CASCADE"), primary_key=True)
    rule_id: Mapped[str | None] = mapped_column(String(128))
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    observed_metric: Mapped[Any | None] = mapped_column(JSON)
    threshold: Mapped[Any | None] = mapped_column(JSON)
    explanation: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    recommendation: Mapped[str] = mapped_column(String(2000), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    analysis: Mapped[AnalysisRecord] = relationship(back_populates="findings")


Index("ix_findings_analysis_id", FindingRecord.analysis_id)
Index("ix_findings_severity", FindingRecord.severity)


def _engine():
    url = os.getenv("DATABASE_URL")
    if not url:
        raise DatabaseConfigurationError("DATABASE_URL is required for uploaded analysis storage.")
    if url.startswith("postgres://"):
        url = "postgresql+psycopg://" + url.removeprefix("postgres://")
    elif url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url.removeprefix("postgresql://")
    options: dict[str, Any] = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        options["connect_args"] = {"check_same_thread": False}
    else:
        options.update(pool_size=5, max_overflow=5)
    return create_engine(url, **options)


def _session_factory():
    return sessionmaker(bind=_engine(), expire_on_commit=False)


def _finding_values(finding: dict[str, Any]) -> dict[str, Any]:
    evidence = finding.get("evidence", [])
    first = evidence[0] if evidence else {}
    return {
        "finding_id": str(finding["finding_id"]),
        "rule_id": first.get("rule_id"),
        "title": finding.get("attack_category", finding.get("prediction", "Detection finding")),
        "severity": finding.get("severity", "low"),
        "evidence": evidence,
        "observed_metric": first.get("value"),
        "threshold": first.get("threshold"),
        "explanation": finding.get("explanation", []),
        "recommendation": finding.get("recommendation", "Review the associated traffic evidence."),
    }


def persist_analysis(result: dict[str, Any]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    try:
        with _session_factory().begin() as session:
            record = AnalysisRecord(
                analysis_id=result["analysis_id"],
                filename=result["source"]["name"],
                file_size=result["source"]["size_bytes"],
                packet_count=result["packet_count"],
                window_count=result["window_count"],
                duration_seconds=result["duration_seconds"],
                protocols=result["protocol_summary"],
                status=result["status"],
                source=result["source"]["kind"],
                result=result,
                created_at=now,
                completed_at=now,
            )
            record.findings = [FindingRecord(analysis_id=result["analysis_id"], created_at=now, **_finding_values(finding)) for finding in result["findings"]]
            session.add(record)
    except SQLAlchemyError as error:
        raise DatabaseStorageError("Analysis storage is temporarily unavailable. Please try again.") from error
    return result


def get_analysis(analysis_id: str) -> dict[str, Any] | None:
    try:
        with _session_factory()() as session:
            record = session.scalar(select(AnalysisRecord).where(AnalysisRecord.analysis_id == analysis_id))
            return None if record is None else record.result
    except SQLAlchemyError as error:
        raise DatabaseStorageError("Analysis storage is temporarily unavailable. Please try again.") from error


def delete_analysis(analysis_id: str) -> None:
    try:
        with _session_factory().begin() as session:
            record = session.get(AnalysisRecord, analysis_id)
            if record is not None:
                session.delete(record)
    except SQLAlchemyError as error:
        raise DatabaseStorageError("Analysis storage is temporarily unavailable. Please try again.") from error