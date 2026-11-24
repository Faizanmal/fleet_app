from __future__ import annotations

import json
import logging

from fleet.logging_config import JsonFormatter


def test_json_logs_keep_trace_metadata_and_omit_free_text_and_exception_message():
    formatter = JsonFormatter()
    record = logging.LogRecord(
        "fleet.test",
        logging.ERROR,
        __file__,
        10,
        "request_failed_safely",
        (),
        (ValueError, ValueError("private@example.invalid secret-token"), None),
    )
    record.request_id = "trace-safe-id"
    record.authorization = "Bearer secret-token"
    record.prompt = "private@example.invalid"
    payload = json.loads(formatter.format(record))
    assert payload["request_id"] == "trace-safe-id"
    assert payload["error_type"] == "ValueError"
    assert "authorization" not in payload
    assert "prompt" not in payload
    assert "private@example.invalid" not in str(payload)
    assert "secret-token" not in str(payload)
