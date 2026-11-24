"""Small structured JSON logging setup."""

import json
import logging
from datetime import UTC, datetime


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            # Exception messages can include SQL text, credentials, or private values.
            payload["error_type"] = record.exc_info[0].__name__
        for field in (
            "request_id",
            "run_id",
            "trace_id",
            "tenant_ref",
            "tenant_run_ref",
            "tool",
            "duration_ms",
            "success",
            "evidence_ids",
            "error_type",
            "build_version",
        ):
            if hasattr(record, field):
                payload[field] = getattr(record, field)
        return json.dumps(payload)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())
