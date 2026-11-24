"""Command-line entry point for safe, transactional NDJSON ingestion."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from fleet.db.connection import sqlalchemy_url
from fleet.ingest.errors import IngestError, SourceChecksumMismatch
from fleet.ingest.importer import EXPECTED_DATASET_SHA256, TelemetryImporter
from fleet.settings import get_settings


class IngestSettings(BaseSettings):
    ingest_database_url: str = Field(validation_alias="INGEST_DATABASE_URL")
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)


def _write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m fleet.ingest.cli")
    subparsers = parser.add_subparsers(dest="command", required=True)
    import_parser = subparsers.add_parser("import", help="transactionally import telemetry NDJSON")
    import_parser.add_argument("source", type=Path)
    import_parser.add_argument("--json-report", type=Path, required=True)
    import_parser.add_argument("--expected-sha256", default=EXPECTED_DATASET_SHA256)
    import_parser.add_argument(
        "--allow-hash-mismatch",
        action="store_true",
        help="explicitly allow a source different from the pinned dataset",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    ingest_settings = IngestSettings()
    database_url = os.getenv("INGEST_DATABASE_URL") or ingest_settings.ingest_database_url
    engine = create_engine(sqlalchemy_url(database_url), pool_pre_ping=True)
    session_factory = sessionmaker(engine, expire_on_commit=False)
    importer = TelemetryImporter(
        session_factory,
        policy_version=settings.policy_version,
        expected_sha256=args.expected_sha256,
        allow_checksum_mismatch=args.allow_hash_mismatch,
    )
    try:
        report = importer.import_file(args.source)
    except IngestError as error:
        report = error.report
        report_data = report.to_dict()
        _write_report(args.json_report, report_data)
        print(json.dumps(report_data, indent=2))
        engine.dispose()
        return 2 if isinstance(error, SourceChecksumMismatch) else 1
    except OSError as error:
        error_report = {
            "status": "failed",
            "source_path": args.source.as_posix(),
            "data_sha256": None,
            "policy_version": settings.policy_version,
            "graph_version": "not_applicable",
            "prompt_version": "not_applicable",
            "model_version": "not_applicable",
            "errors": [{"code": "source_io_error", "message": str(error)}],
        }
        _write_report(args.json_report, error_report)
        print(json.dumps(error_report, indent=2), file=sys.stderr)
        engine.dispose()
        return 2
    report_data = report.to_dict()
    _write_report(args.json_report, report_data)
    print(json.dumps(report_data, indent=2))
    engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
