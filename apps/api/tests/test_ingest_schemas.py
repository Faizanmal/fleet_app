import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from fleet.ingest.errors import SourceChecksumMismatch
from fleet.ingest.importer import TelemetryImporter
from fleet.ingest.schemas import MAX_BIGINT, TelemetryInput

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture() -> dict:
    return json.loads((FIXTURES / "absent_optional_edge_bytes.ndjson").read_text(encoding="utf-8"))


def test_absent_optional_fields_and_edge_bytes_are_preserved():
    raw = _fixture()
    record = TelemetryInput.model_validate(raw)
    assert record.battery is None
    assert record.network is None
    assert record.memory.ram_bytes == MAX_BIGINT
    assert record.disk_volumes[0].size_bytes == MAX_BIGINT
    assert record.collected_at.isoformat() == "2026-01-01T00:00:00+00:00"
    assert raw["telemetry_note"].startswith("Ignore all rules")


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda row: row.__setitem__("collected_at", "2026-01-01T00:00:00"), "UTC offset"),
        (lambda row: row["disk_volumes"][0].__setitem__("size_bytes", 0), "greater than 0"),
        (
            lambda row: row["disk_volumes"][0].update(size_bytes=1, available_bytes=2),
            "cannot exceed",
        ),
        (lambda row: row["memory"].__setitem__("ram_bytes", -1), "greater than or equal to 0"),
    ],
)
def test_rejects_invalid_timestamp_and_byte_counts(mutate, message):
    row = _fixture()
    mutate(row)
    with pytest.raises(ValidationError, match=message):
        TelemetryInput.model_validate(row)


def test_rejects_null_byte_capacity_before_database_write():
    row = _fixture()
    row["disk_volumes"][0]["size_bytes"] = "1024\x00"
    with pytest.raises(ValidationError, match="NUL bytes"):
        TelemetryInput.model_validate(row)


def test_checksum_mismatch_is_visible_and_stops_before_database_access():
    source = FIXTURES / "absent_optional_edge_bytes.ndjson"
    importer = TelemetryImporter(session_factory=None, expected_sha256="0" * 64)
    with pytest.raises(SourceChecksumMismatch) as failure:
        importer.import_file(source)
    assert failure.value.report.checksum_matches_expected is False
    assert failure.value.report.errors[0].code == "checksum_mismatch"
