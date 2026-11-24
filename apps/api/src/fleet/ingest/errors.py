"""Typed ingest failures and row-level diagnostics."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RowDiagnostic:
    line_number: int
    code: str
    message: str
    field: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "line_number": self.line_number,
            "code": self.code,
            "field": self.field,
            "message": self.message,
        }


class IngestError(Exception):
    """Base exception carrying a safe machine-readable report."""

    def __init__(self, message: str, report: Any):
        super().__init__(message)
        self.report = report


class SourceChecksumMismatch(IngestError):
    """The source file did not match the configured checksum."""


class InvalidDataset(IngestError):
    """At least one source row failed JSON/schema validation."""


class ConflictingObservation(IngestError):
    """A tenant/device/timestamp key already has different source values."""


class DatabaseIntegrityFailure(IngestError):
    """A database constraint rejected a row; the complete file is rolled back."""
