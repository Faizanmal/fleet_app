from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from fleet.agent.graph import build_test_agent
from fleet.core.identity import Membership, Principal, RequestContext
from fleet.observability import span
from fleet.tools.gateway import QueryResult


def test_graph_spans_export_safe_attributes_when_otel_extra_is_installed():
    trace = pytest.importorskip("opentelemetry.trace")
    sdk = pytest.importorskip("opentelemetry.sdk.trace")
    exporter_module = pytest.importorskip("opentelemetry.sdk.trace.export.in_memory_span_exporter")
    exporter = exporter_module.InMemorySpanExporter()
    processor = sdk.export.SimpleSpanProcessor(exporter)

    current_provider = trace.get_tracer_provider()
    if isinstance(current_provider, sdk.TracerProvider):
        provider = current_provider
        provider.add_span_processor(processor)
    else:
        provider = sdk.TracerProvider()
        provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)

    context = RequestContext(
        Session(),
        Principal(
            "test-user",
            (Membership("acme-001", frozenset({"viewer"})),),
            "acme-001",
            "test",
        ),
        1,
        "acme-001",
        clock=lambda: datetime(2026, 11, 23, tzinfo=UTC),
    )

    def executor(_name, _context, _args):
        return QueryResult(total_count=0)

    marker = "private-prompt-marker"
    result = build_test_agent(context, tool_executor=executor).invoke(
        f"Which devices have low disk below 20 percent? {marker}"
    )
    finished = exporter.get_finished_spans()
    names = [item.name for item in finished]
    assert "agent.plan" in names
    assert "agent.tool" in names
    assert result["trace_id"] == result["run_id"]
    attributes = [dict(item.attributes) for item in finished]
    assert any(len(item.get("fleet.tenant_ref", "")) == 16 for item in attributes)
    assert marker not in str(finished)
    processor.shutdown()


def test_span_helper_is_safe_when_sdk_provider_is_not_configured():
    with span("test.noop", {"fleet.outcome": "ok"}) as current:
        current.set_attribute("fleet.error.type", "none")
