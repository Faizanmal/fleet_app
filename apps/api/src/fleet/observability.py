"""Optional OpenTelemetry helpers; missing/broken exporters never affect policy decisions."""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger(__name__)


def configure_telemetry() -> None:
    """Install SDK and optional OTLP HTTP export when the observability extra is available."""
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        endpoint = os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        provider = TracerProvider(
            resource=Resource.create(
                {"service.name": os.getenv("OTEL_SERVICE_NAME", "rayda-fleet-api")}
            )
        )
        if endpoint:
            try:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

                provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
            except Exception as exc:
                # A collector/exporter failure is diagnostic only. Local spans still work.
                logger.warning(
                    "otel_exporter_unavailable", extra={"error_type": type(exc).__name__}
                )
        trace.set_tracer_provider(provider)
    except Exception as exc:
        logger.info("otel_sdk_unavailable", extra={"error_type": type(exc).__name__})


@contextmanager
def span(name: str, attributes: dict[str, Any] | None = None):
    """Create a span if OTel is installed; keep failure isolated from application logic."""
    try:
        from opentelemetry import trace
    except ImportError:
        yield _NoopSpan()
        return
    try:
        tracer = trace.get_tracer("fleet")
        span_context = tracer.start_as_current_span(
            name,
            attributes=attributes,
            record_exception=False,
            set_status_on_exception=False,
        )
    except Exception as exc:
        logger.debug("otel_span_unavailable", extra={"error_type": type(exc).__name__})
        yield _NoopSpan()
        return
    with span_context as current:
        yield current


class _NoopSpan:
    def set_attribute(self, *_args, **_kwargs) -> None:
        return None

    def set_status(self, *_args, **_kwargs) -> None:
        return None


def opaque_tenant_id(tenant_key: str) -> str:
    import hashlib

    return hashlib.sha256(tenant_key.encode("utf-8")).hexdigest()[:16]
