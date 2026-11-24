"""Strict Pydantic schemas for telemetry source rows."""

from __future__ import annotations

import unicodedata
from datetime import UTC, datetime
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

MAX_BIGINT = 2**63 - 1
ByteCount = Annotated[StrictInt, Field(ge=0, le=MAX_BIGINT)]
PositiveByteCount = Annotated[StrictInt, Field(gt=0, le=MAX_BIGINT)]


class SourceModel(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)

    @field_validator("*", mode="before")
    @classmethod
    def reject_null_bytes(cls, value: Any) -> Any:
        if isinstance(value, str) and "\x00" in value:
            raise ValueError("string fields must not contain NUL bytes")
        return value


class OperatingSystemInput(SourceModel):
    platform: StrictStr
    product_name: StrictStr
    product_version: StrictStr
    build_version: StrictStr
    architecture: StrictStr
    kernel_name: StrictStr
    kernel_release: StrictStr
    hostname: StrictStr


class DeviceIdentityInput(SourceModel):
    serial_number: StrictStr
    model_name: StrictStr
    model_identifier: StrictStr
    processor: StrictStr
    hardware_uuid: StrictStr
    total_memory: StrictStr


class MemoryInput(SourceModel):
    ram_bytes: ByteCount
    total_memory_bytes: ByteCount
    used_memory_bytes: ByteCount
    free_memory_bytes: ByteCount
    page_size_bytes: ByteCount


class DiskVolumeInput(SourceModel):
    volume_name: StrictStr
    file_system: StrictStr
    mount_point: StrictStr
    size_bytes: PositiveByteCount
    available_bytes: ByteCount
    encrypted: StrictBool

    @model_validator(mode="after")
    def validate_capacity(self) -> DiskVolumeInput:
        if self.available_bytes > self.size_bytes:
            raise ValueError("available_bytes cannot exceed size_bytes")
        return self


class BatteryInput(SourceModel):
    battery_present: StrictBool
    charging_status: StrictStr
    percentage: Annotated[StrictInt, Field(ge=0, le=100)]
    condition: StrictStr
    cycle_count: Annotated[StrictInt, Field(ge=0, le=MAX_BIGINT)]
    full_charge_capacity: ByteCount


class NetworkInterfaceInput(SourceModel):
    address: StrictStr
    family: StrictStr
    interface_name: StrictStr
    internal: StrictBool
    mac: StrictStr


class ComplianceResultInput(SourceModel):
    check_id: StrictStr
    status: StrictStr
    severity: StrictStr


class InstalledSoftwareInput(SourceModel):
    name: StrictStr
    version: StrictStr
    publisher: StrictStr


class TelemetryInput(SourceModel):
    device_id: StrictStr
    company_id: StrictStr
    employee_id: StrictStr
    collected_at: datetime
    agent_version: StrictStr
    os: OperatingSystemInput
    device_identity: DeviceIdentityInput
    memory: MemoryInput
    disk_volumes: list[DiskVolumeInput]
    installed_software: list[InstalledSoftwareInput]
    compliance_results: list[ComplianceResultInput]
    battery: BatteryInput | None = None
    network: list[NetworkInterfaceInput] | None = None

    @field_validator("collected_at", mode="before")
    @classmethod
    def parse_offset_datetime(cls, value: Any) -> datetime:
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as error:
                raise ValueError("collected_at must be an ISO 8601 timestamp") from error
        if not isinstance(value, datetime):
            raise ValueError("collected_at must be an ISO 8601 timestamp")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("collected_at must include a UTC offset")
        return value.astimezone(UTC)

    @field_validator("device_id", "company_id", "employee_id")
    @classmethod
    def require_nonblank_identifier(cls, value: str) -> str:
        if not unicodedata.normalize("NFKC", value).strip():
            raise ValueError("identifier must not be blank")
        return value


def normalize_device_id(value: str) -> str:
    return unicodedata.normalize("NFKC", value).strip().upper()


def normalize_tenant_or_employee_id(value: str) -> str:
    return unicodedata.normalize("NFKC", value).strip().casefold()


def normalize_os_platform(value: str) -> str:
    return unicodedata.normalize("NFKC", value).strip().casefold()
