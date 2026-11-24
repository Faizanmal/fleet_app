"""Atomic, provenance-preserving NDJSON telemetry import."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from fleet.db.models import (
    ComplianceResult,
    DatasetImport,
    Device,
    DiskVolume,
    Employee,
    InstalledSoftware,
    TelemetrySnapshot,
    Tenant,
)
from fleet.ingest.errors import (
    ConflictingObservation,
    DatabaseIntegrityFailure,
    InvalidDataset,
    RowDiagnostic,
    SourceChecksumMismatch,
)
from fleet.ingest.schemas import (
    TelemetryInput,
    normalize_device_id,
    normalize_os_platform,
    normalize_tenant_or_employee_id,
)

EXPECTED_DATASET_SHA256 = "fb0ee31ffeeb731b919fc4d5124098c9c5b68cf3fba35eed5092a9f73655c4de"
INGEST_VERSION = "ingest-v1"
NOT_APPLICABLE = "not_applicable"


@dataclass
class ImportReport:
    status: str
    source_path: str
    data_sha256: str
    checksum_matches_expected: bool | None
    expected_sha256: str | None
    total_lines: int = 0
    records_validated: int = 0
    snapshots_inserted: int = 0
    snapshots_noop: int = 0
    errors: list[RowDiagnostic] = field(default_factory=list)
    policy_version: str = "policy-v1"
    graph_version: str = NOT_APPLICABLE
    prompt_version: str = NOT_APPLICABLE
    model_version: str = NOT_APPLICABLE
    dataset_version: str = ""
    database_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["errors"] = [item.to_dict() for item in self.errors]
        result["error_count"] = len(self.errors)
        return result


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sanitize_validation_errors(error: ValidationError, line_number: int) -> list[RowDiagnostic]:
    diagnostics = []
    for item in error.errors(include_input=False, include_context=False, include_url=False):
        location = ".".join(str(part) for part in item["loc"])
        diagnostics.append(
            RowDiagnostic(
                line_number=line_number,
                code=str(item["type"]),
                field=location or None,
                message=str(item["msg"]),
            )
        )
    return diagnostics


def _source_row_hash(line: bytes) -> str:
    return hashlib.sha256(line.rstrip(b"\r\n")).hexdigest()


def _get_counts(session: Session) -> dict[str, int]:
    tables = {
        "tenants": Tenant,
        "employees": Employee,
        "devices": Device,
        "snapshots": TelemetrySnapshot,
        "disk_volumes": DiskVolume,
        "compliance_results": ComplianceResult,
        "installed_software": InstalledSoftware,
        "dataset_imports": DatasetImport,
    }
    return {
        name: int(session.scalar(select(func.count()).select_from(model)) or 0)
        for name, model in tables.items()
    }


class TelemetryImporter:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        policy_version: str = "policy-v1",
        expected_sha256: str | None = EXPECTED_DATASET_SHA256,
        allow_checksum_mismatch: bool = False,
    ) -> None:
        self.session_factory = session_factory
        self.policy_version = policy_version
        self.expected_sha256 = expected_sha256
        self.allow_checksum_mismatch = allow_checksum_mismatch

    def import_file(self, source_path: str | Path) -> ImportReport:
        path = Path(source_path)
        data_sha = file_sha256(path)
        try:
            source_label = path.as_posix()
        except OSError:
            source_label = path.name
        checksum_matches = (
            data_sha == self.expected_sha256 if self.expected_sha256 is not None else None
        )
        report = ImportReport(
            status="running",
            source_path=source_label,
            data_sha256=data_sha,
            checksum_matches_expected=checksum_matches,
            expected_sha256=self.expected_sha256,
            policy_version=self.policy_version,
            graph_version=NOT_APPLICABLE,
            prompt_version=NOT_APPLICABLE,
            model_version=NOT_APPLICABLE,
            dataset_version=f"sha256:{data_sha}",
        )
        if checksum_matches is False and not self.allow_checksum_mismatch:
            report.status = "failed"
            report.errors.append(
                RowDiagnostic(
                    line_number=0,
                    code="checksum_mismatch",
                    field="source_sha256",
                    message="Source checksum does not match the pinned dataset checksum",
                )
            )
            raise SourceChecksumMismatch(
                "Source checksum mismatch; no database rows were changed", report
            )

        duplicate_keys: dict[tuple[str, str, datetime], tuple[dict[str, Any], int]] = {}
        current_line = 0
        streamed_hash = hashlib.sha256()
        try:
            with self.session_factory() as session, session.begin():
                with path.open("rb") as source:
                    for current_line, raw_line in enumerate(source, start=1):
                        streamed_hash.update(raw_line)
                        report.total_lines += 1
                        line = raw_line.rstrip(b"\r\n")
                        try:
                            source_row = json.loads(line)
                        except (json.JSONDecodeError, UnicodeDecodeError) as error:
                            message = (
                                error.msg
                                if isinstance(error, json.JSONDecodeError)
                                else "invalid UTF-8"
                            )
                            report.errors.append(
                                RowDiagnostic(
                                    current_line,
                                    "malformed_json",
                                    f"Invalid JSON: {message}",
                                )
                            )
                            continue
                        if not isinstance(source_row, dict):
                            report.errors.append(
                                RowDiagnostic(
                                    current_line,
                                    "invalid_structure",
                                    "NDJSON row must be a JSON object",
                                )
                            )
                            continue
                        try:
                            record = TelemetryInput.model_validate(source_row)
                        except ValidationError as error:
                            report.errors.extend(_sanitize_validation_errors(error, current_line))
                            continue
                        report.records_validated += 1
                        tenant_key = normalize_tenant_or_employee_id(record.company_id)
                        device_key = normalize_device_id(record.device_id)
                        employee_key = normalize_tenant_or_employee_id(record.employee_id)
                        duplicate_key = (tenant_key, device_key, record.collected_at)
                        prior = duplicate_keys.get(duplicate_key)
                        if prior is not None:
                            if prior[0] == source_row:
                                report.snapshots_noop += 1
                            else:
                                report.errors.append(
                                    RowDiagnostic(
                                        current_line,
                                        "conflicting_duplicate",
                                        f"Timestamp key conflicts with source line {prior[1]}",
                                        "device_id/collected_at",
                                    )
                                )
                            continue
                        duplicate_keys[duplicate_key] = (source_row, current_line)

                        tenant = session.scalar(
                            select(Tenant).where(Tenant.company_id == tenant_key)
                        )
                        if tenant is None:
                            tenant = Tenant(company_id=tenant_key)
                            session.add(tenant)
                            session.flush()
                        device = session.get(Device, (tenant.id, device_key))
                        if device is None:
                            device = Device(
                                tenant_id=tenant.id,
                                device_id=device_key,
                                first_seen_at=record.collected_at,
                                last_seen_at=record.collected_at,
                            )
                            session.add(device)
                        else:
                            device.first_seen_at = min(device.first_seen_at, record.collected_at)
                            device.last_seen_at = max(device.last_seen_at, record.collected_at)
                        employee = session.get(Employee, (tenant.id, employee_key))
                        if employee is None:
                            session.add(Employee(tenant_id=tenant.id, employee_id=employee_key))
                        session.flush()

                        existing = session.scalar(
                            select(TelemetrySnapshot).where(
                                TelemetrySnapshot.tenant_id == tenant.id,
                                TelemetrySnapshot.device_id == device_key,
                                TelemetrySnapshot.collected_at == record.collected_at,
                            )
                        )
                        if existing is not None:
                            if existing.raw_json == source_row:
                                report.snapshots_noop += 1
                            else:
                                report.errors.append(
                                    RowDiagnostic(
                                        current_line,
                                        "conflicting_duplicate",
                                        "Timestamp key already exists with different source values",
                                        "device_id/collected_at",
                                    )
                                )
                            continue

                        snapshot = TelemetrySnapshot(
                            tenant_id=tenant.id,
                            device_id=device_key,
                            employee_id=employee_key,
                            collected_at=record.collected_at,
                            agent_version=record.agent_version,
                            os_platform=normalize_os_platform(record.os.platform),
                            os_product_name=normalize_os_platform(record.os.product_name),
                            os_json=source_row["os"],
                            device_identity_json=source_row["device_identity"],
                            memory_json=source_row["memory"],
                            battery_json=source_row.get("battery"),
                            network_json=source_row.get("network"),
                            raw_json=source_row,
                            source_path=source_label,
                            source_line_number=current_line,
                            source_row_sha256=_source_row_hash(raw_line),
                            data_sha256=data_sha,
                        )
                        session.add(snapshot)
                        session.flush()
                        for volume in record.disk_volumes:
                            session.add(
                                DiskVolume(
                                    tenant_id=tenant.id,
                                    snapshot_id=snapshot.id,
                                    **volume.model_dump(),
                                )
                            )
                        for compliance in record.compliance_results:
                            session.add(
                                ComplianceResult(
                                    tenant_id=tenant.id,
                                    snapshot_id=snapshot.id,
                                    **compliance.model_dump(),
                                )
                            )
                        for software in record.installed_software:
                            session.add(
                                InstalledSoftware(
                                    tenant_id=tenant.id,
                                    snapshot_id=snapshot.id,
                                    **software.model_dump(),
                                )
                            )
                        session.flush()
                        report.snapshots_inserted += 1

                if streamed_hash.hexdigest() != data_sha:
                    report.status = "failed"
                    report.snapshots_inserted = 0
                    report.errors.append(
                        RowDiagnostic(
                            0,
                            "source_changed_during_import",
                            "Source bytes changed between checksum and import passes",
                        )
                    )
                    raise SourceChecksumMismatch(
                        "Source changed during import; transaction rolled back", report
                    )

                if report.errors:
                    report.status = "failed"
                    report.snapshots_inserted = 0
                    if any(item.code == "conflicting_duplicate" for item in report.errors):
                        raise ConflictingObservation(
                            "Conflicting duplicate timestamp; full file transaction rolled back",
                            report,
                        )
                    raise InvalidDataset(
                        "One or more source rows were rejected; transaction rolled back", report
                    )

                session.add(
                    DatasetImport(
                        data_sha256=data_sha,
                        dataset_version=report.dataset_version,
                        source_path=source_label,
                        source_line_count=report.total_lines,
                        records_validated=report.records_validated,
                        snapshots_inserted=report.snapshots_inserted,
                        snapshots_noop=report.snapshots_noop,
                        error_count=0,
                        policy_version=self.policy_version,
                        graph_version=NOT_APPLICABLE,
                        prompt_version=NOT_APPLICABLE,
                        model_version=NOT_APPLICABLE,
                    )
                )
            with self.session_factory() as session:
                report.database_counts = _get_counts(session)
        except (InvalidDataset, SourceChecksumMismatch, ConflictingObservation):
            raise
        except IntegrityError as error:
            report.status = "failed"
            report.snapshots_inserted = 0
            report.errors.append(
                RowDiagnostic(
                    current_line,
                    "database_integrity_error",
                    "Database rejected a tenant-scoped key or integrity constraint; "
                    "full file rolled back",
                )
            )
            constraint = getattr(getattr(error.orig, "diag", None), "constraint_name", None)
            if constraint in {"fk_snapshot_device_tenant", "fk_snapshot_employee_tenant"}:
                raise DatabaseIntegrityFailure(
                    "Cross-tenant key reference rejected", report
                ) from error
            raise DatabaseIntegrityFailure(
                "Database integrity check failed; full file rolled back", report
            ) from error
        except SQLAlchemyError as error:
            report.status = "failed"
            report.snapshots_inserted = 0
            report.errors.append(
                RowDiagnostic(
                    current_line,
                    "database_error",
                    "Database operation failed; full file rolled back",
                )
            )
            raise DatabaseIntegrityFailure(
                "Database operation failed; full file rolled back", report
            ) from error
        report.status = "success"
        return report
