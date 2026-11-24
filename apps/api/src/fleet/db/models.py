"""PostgreSQL persistence model for tenant-scoped telemetry."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Identity,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenant"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    company_id: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Employee(Base):
    __tablename__ = "employee"

    tenant_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("tenant.id", ondelete="CASCADE"), primary_key=True
    )
    employee_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Device(Base):
    __tablename__ = "device"

    tenant_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("tenant.id", ondelete="CASCADE"), primary_key=True
    )
    device_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class TelemetrySnapshot(Base):
    __tablename__ = "telemetry_snapshot"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "device_id", "collected_at", name="uq_snapshot_tenant_device_collected"
        ),
        UniqueConstraint("tenant_id", "id", name="uq_snapshot_tenant_id"),
        ForeignKeyConstraint(
            ["tenant_id", "device_id"],
            ["device.tenant_id", "device.device_id"],
            name="fk_snapshot_device_tenant",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "employee_id"],
            ["employee.tenant_id", "employee.employee_id"],
            name="fk_snapshot_employee_tenant",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    tenant_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    device_id: Mapped[str] = mapped_column(String(255), nullable=False)
    employee_id: Mapped[str] = mapped_column(String(255), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(255), nullable=False)
    os_platform: Mapped[str] = mapped_column(String(128), nullable=False)
    os_product_name: Mapped[str] = mapped_column(String(255), nullable=False)
    os_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    device_identity_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    memory_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    battery_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True))
    network_json: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB(none_as_null=True))
    raw_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    source_path: Mapped[str] = mapped_column(Text, nullable=False)
    source_line_number: Mapped[int] = mapped_column(Integer, nullable=False)
    source_row_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    data_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DiskVolume(Base):
    __tablename__ = "disk_volume"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "snapshot_id"],
            ["telemetry_snapshot.tenant_id", "telemetry_snapshot.id"],
            name="fk_disk_volume_snapshot_tenant",
            ondelete="CASCADE",
        ),
        CheckConstraint("size_bytes > 0", name="ck_disk_volume_size_positive"),
        CheckConstraint(
            "available_bytes >= 0 AND available_bytes <= size_bytes",
            name="ck_disk_volume_available_in_range",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    tenant_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    snapshot_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    volume_name: Mapped[str] = mapped_column(String(512), nullable=False)
    file_system: Mapped[str] = mapped_column(String(255), nullable=False)
    mount_point: Mapped[str] = mapped_column(String(1024), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    available_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    encrypted: Mapped[bool] = mapped_column(Boolean, nullable=False)


class ComplianceResult(Base):
    __tablename__ = "compliance_result"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "snapshot_id"],
            ["telemetry_snapshot.tenant_id", "telemetry_snapshot.id"],
            name="fk_compliance_result_snapshot_tenant",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    tenant_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    snapshot_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    check_id: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(128), nullable=False)


class InstalledSoftware(Base):
    __tablename__ = "installed_software"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "snapshot_id"],
            ["telemetry_snapshot.tenant_id", "telemetry_snapshot.id"],
            name="fk_installed_software_snapshot_tenant",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    tenant_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    snapshot_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    version: Mapped[str] = mapped_column(String(255), nullable=False)
    publisher: Mapped[str] = mapped_column(String(512), nullable=False)


class GraphRun(Base):
    """Tenant-owned run envelope; payloads and telemetry text remain untrusted data."""

    __tablename__ = "graph_run"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenant.id"], ondelete="CASCADE"),
        UniqueConstraint("tenant_id", "id", name="uq_graph_run_tenant_id"),
        UniqueConstraint("tenant_id", "thread_id", name="uq_graph_run_tenant_thread"),
        UniqueConstraint("tenant_id", "trace_id", name="uq_graph_run_tenant_trace"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    tenant_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    thread_id: Mapped[str] = mapped_column(String(255), nullable=False)
    trace_id: Mapped[str | None] = mapped_column(String(255))
    user_id: Mapped[str] = mapped_column(String(255), nullable=False)
    data_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(128), nullable=False)
    graph_version: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(128), nullable=False)
    model_version: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AgentStepEvent(Base):
    """Tenant-owned, privacy-filtered event for an observable graph step."""

    __tablename__ = "agent_step_event"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "run_id"],
            ["graph_run.tenant_id", "graph_run.id"],
            name="fk_agent_step_run_tenant",
            ondelete="CASCADE",
        ),
        UniqueConstraint("tenant_id", "run_id", "step_index", name="uq_agent_step_order"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    tenant_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    run_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    trace_id: Mapped[str] = mapped_column(String(255), nullable=False)
    step_index: Mapped[int] = mapped_column(Integer, nullable=False)
    node: Mapped[str] = mapped_column(String(64), nullable=False)
    event_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    elapsed_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "run_id"],
            ["graph_run.tenant_id", "graph_run.id"],
            name="fk_evidence_run_tenant",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "snapshot_id"],
            ["telemetry_snapshot.tenant_id", "telemetry_snapshot.id"],
            name="fk_evidence_snapshot_tenant",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_evidence_tenant_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    tenant_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    run_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    snapshot_id: Mapped[int | None] = mapped_column(BigInteger)
    data_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class EvidencePointerRecord(Base):
    __tablename__ = "evidence_pointer"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "snapshot_id"],
            ["telemetry_snapshot.tenant_id", "telemetry_snapshot.id"],
            name="fk_evidence_pointer_snapshot_tenant",
        ),
        UniqueConstraint("tenant_id", "evidence_id", name="uq_evidence_pointer_tenant_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    tenant_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    snapshot_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    evidence_id: Mapped[str] = mapped_column(String(67), nullable=False)
    dataset_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    device_id: Mapped[str] = mapped_column(String(255), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    field_path: Mapped[str] = mapped_column(Text, nullable=False)
    field_value_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    pointer_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AggregateManifestRecord(Base):
    __tablename__ = "aggregate_manifest"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenant.id"], ondelete="CASCADE"),
        UniqueConstraint("tenant_id", "manifest_id", name="uq_manifest_tenant_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    tenant_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    manifest_id: Mapped[str] = mapped_column(String(68), nullable=False)
    manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Proposal(Base):
    __tablename__ = "proposal"
    __table_args__ = (
        CheckConstraint(
            "status IN ('DRAFT','PENDING_APPROVAL','APPROVED','EXECUTING','EXECUTED',"
            "'REJECTED','EXPIRED','BLOCKED','FAILED')",
            name="ck_proposal_status",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "run_id"],
            ["graph_run.tenant_id", "graph_run.id"],
            name="fk_proposal_run_tenant",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_proposal_tenant_id"),
        UniqueConstraint("workflow_thread_id", name="uq_proposal_workflow_thread"),
        UniqueConstraint(
            "tenant_id", "requested_by", "idempotency_key", name="uq_proposal_idempotency"
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    tenant_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    run_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    proposal_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="DRAFT")
    data_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(128), nullable=False)
    graph_version: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(128), nullable=False)
    model_version: Mapped[str] = mapped_column(String(255), nullable=False)
    proposal_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    workflow_thread_id: Mapped[str] = mapped_column(String(255), nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Approval(Base):
    __tablename__ = "approval"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "proposal_id"],
            ["proposal.tenant_id", "proposal.id"],
            name="fk_approval_proposal_tenant",
            ondelete="CASCADE",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_approval_tenant_id"),
        UniqueConstraint("tenant_id", "proposal_id", name="uq_approval_once"),
        CheckConstraint("decision IN ('approve','reject')", name="ck_approval_decision"),
        CheckConstraint("approver_role IN ('approver','admin','legacy')", name="ck_approval_role"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    tenant_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    proposal_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    approver_id: Mapped[str] = mapped_column(String(255), nullable=False)
    approver_role: Mapped[str] = mapped_column(String(32), nullable=False, default="legacy")
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    proposal_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ActionExecution(Base):
    __tablename__ = "action_execution"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "proposal_id"],
            ["proposal.tenant_id", "proposal.id"],
            name="fk_action_execution_proposal_tenant",
        ),
        UniqueConstraint("tenant_id", "execution_id", name="uq_action_execution_tenant_id"),
        UniqueConstraint("tenant_id", "id", name="uq_action_execution_tenant_pk"),
        UniqueConstraint(
            "tenant_id", "proposal_id", "action_version", name="uq_action_execution_version"
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    tenant_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    proposal_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    execution_id: Mapped[str] = mapped_column(String(255), nullable=False)
    proposal_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    action_version: Mapped[str] = mapped_column(String(64), nullable=False, default="sandbox-v1")
    result_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditEvent(Base):
    __tablename__ = "audit_event"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "run_id"],
            ["graph_run.tenant_id", "graph_run.id"],
            name="fk_audit_run_tenant",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_audit_event_tenant_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    tenant_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    run_id: Mapped[int | None] = mapped_column(BigInteger)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(128), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(255), nullable=False)
    details_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    previous_hash: Mapped[str | None] = mapped_column(String(64))
    event_hash: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditChainHead(Base):
    __tablename__ = "audit_chain_head"

    tenant_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("tenant.id", ondelete="CASCADE"), primary_key=True
    )
    last_event_id: Mapped[int | None] = mapped_column(BigInteger)
    last_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class GraphCheckpoint(Base):
    """Tenant-keyed LangGraph checkpoint payload; values are serialized by LangGraph serde."""

    __tablename__ = "graph_checkpoint"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenant.id"], ondelete="CASCADE"),
        UniqueConstraint(
            "tenant_id",
            "thread_id",
            "checkpoint_ns",
            "checkpoint_id",
            name="uq_checkpoint_tenant_thread_id",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    tenant_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    thread_id: Mapped[str] = mapped_column(String(255), nullable=False)
    checkpoint_ns: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    checkpoint_id: Mapped[str] = mapped_column(String(255), nullable=False)
    parent_checkpoint_id: Mapped[str | None] = mapped_column(String(255))
    checkpoint_data: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    metadata_data: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    pending_writes: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ActionOutbox(Base):
    """Idempotent staging record for a future real connector; sandbox never writes it."""

    __tablename__ = "action_outbox"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING','SENT','RECONCILED','FAILED')", name="ck_action_outbox_status"
        ),
        ForeignKeyConstraint(
            ["tenant_id", "proposal_id"],
            ["proposal.tenant_id", "proposal.id"],
            name="fk_action_outbox_proposal_tenant",
        ),
        UniqueConstraint(
            "tenant_id", "proposal_id", "action_version", name="uq_action_outbox_version"
        ),
        UniqueConstraint(
            "tenant_id", "provider_idempotency_key", name="uq_action_outbox_idempotency"
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    tenant_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    proposal_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    action_version: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    provider_reference: Mapped[str | None] = mapped_column(String(255))
    reconciliation_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DatasetImport(Base):
    __tablename__ = "dataset_import"
    __table_args__ = (Index("ix_dataset_import_data_sha256", "data_sha256"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    data_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    dataset_version: Mapped[str] = mapped_column(String(128), nullable=False)
    source_path: Mapped[str] = mapped_column(Text, nullable=False)
    source_line_count: Mapped[int] = mapped_column(Integer, nullable=False)
    records_validated: Mapped[int] = mapped_column(Integer, nullable=False)
    snapshots_inserted: Mapped[int] = mapped_column(Integer, nullable=False)
    snapshots_noop: Mapped[int] = mapped_column(Integer, nullable=False)
    error_count: Mapped[int] = mapped_column(Integer, nullable=False)
    policy_version: Mapped[str] = mapped_column(String(128), nullable=False)
    graph_version: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(128), nullable=False)
    model_version: Mapped[str] = mapped_column(String(255), nullable=False)
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
