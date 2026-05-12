"""
Layer: infrastructure
Ports: none (cross-cutting).
MCP integration: tracer is propagated through MCP tool calls via the
    propagation context injected at the MCP server boundary.
Stack: canonical (Python + OpenTelemetry).

Architectural Rules §6:
- OpenTelemetry tracing
- RED metrics per endpoint / per MCP tool
- Structured JSON logs with correlation IDs, zero PII
- Per-AI-call structured log: model_id, version, prompt_hash, tokens, latency, cost

OpenTelemetry packages are optional at runtime. When absent, this module
falls back to no-op spans / metrics so tests and minimal deploys keep working.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

try:  # pragma: no cover - import guard
    from opentelemetry import metrics, trace
    from opentelemetry.trace import SpanKind, Status, StatusCode

    _OTEL_AVAILABLE = True
except ImportError:  # pragma: no cover
    _OTEL_AVAILABLE = False
    trace = None  # type: ignore
    metrics = None  # type: ignore

_SERVICE_NAME = os.environ.get("OTEL_SERVICE_NAME", "synaptic-bridge")
_logger = logging.getLogger("synaptic_bridge")


def _get_tracer():
    if not _OTEL_AVAILABLE:
        return None
    return trace.get_tracer(_SERVICE_NAME)


def _get_meter():
    if not _OTEL_AVAILABLE:
        return None
    return metrics.get_meter(_SERVICE_NAME)


_red_request_counter = None
_red_error_counter = None
_red_duration_histogram = None


def _ensure_red_instruments() -> None:
    global _red_request_counter, _red_error_counter, _red_duration_histogram
    meter = _get_meter()
    if meter is None or _red_request_counter is not None:
        return
    _red_request_counter = meter.create_counter(
        "synaptic.requests", unit="1", description="Request rate"
    )
    _red_error_counter = meter.create_counter(
        "synaptic.errors", unit="1", description="Error rate"
    )
    _red_duration_histogram = meter.create_histogram(
        "synaptic.duration_ms", unit="ms", description="Request duration"
    )


@dataclass(frozen=True)
class CorrelationContext:
    correlation_id: str

    @classmethod
    def new(cls) -> CorrelationContext:
        return cls(correlation_id=uuid.uuid4().hex)


@contextlib.contextmanager
def traced(
    name: str,
    *,
    attributes: dict[str, Any] | None = None,
    kind: str = "internal",
) -> Iterator[dict[str, Any]]:
    """
    Open a span for `name` and record RED metrics for it. The yielded dict
    can be mutated to attach extra attributes; values added land on the span
    and the structured log.
    """
    _ensure_red_instruments()
    started = time.perf_counter()
    extra: dict[str, Any] = dict(attributes or {})
    tracer = _get_tracer()
    cm: Any
    if tracer is not None:
        otel_kind = getattr(SpanKind, kind.upper(), SpanKind.INTERNAL)
        cm = tracer.start_as_current_span(name, kind=otel_kind, attributes=extra)
    else:
        cm = contextlib.nullcontext()

    error = False
    with cm as span:
        try:
            yield extra
        except Exception as exc:
            error = True
            if span is not None and _OTEL_AVAILABLE:
                span.set_status(Status(StatusCode.ERROR, str(exc)))
                span.record_exception(exc)
            raise
        finally:
            duration_ms = (time.perf_counter() - started) * 1000.0
            tags = {"op": name}
            if _red_request_counter is not None:
                _red_request_counter.add(1, tags)
            if error and _red_error_counter is not None:
                _red_error_counter.add(1, tags)
            if _red_duration_histogram is not None:
                _red_duration_histogram.record(duration_ms, tags)
            if span is not None and _OTEL_AVAILABLE:
                for k, v in extra.items():
                    span.set_attribute(k, v)


def hash_prompt(prompt: str) -> str:
    """Stable hash for prompts (PII-safe identifier)."""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def log_ai_call(
    *,
    model_id: str,
    model_version: str,
    prompt: str,
    tokens_in: int,
    tokens_out: int,
    latency_ms: float,
    cost_usd: float,
    correlation_id: str | None = None,
) -> None:
    """Structured JSON log for every AI call (§6)."""
    record = {
        "event": "ai_call",
        "model_id": model_id,
        "model_version": model_version,
        "prompt_hash": hash_prompt(prompt),
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "latency_ms": round(latency_ms, 3),
        "cost_usd": round(cost_usd, 6),
        "correlation_id": correlation_id,
    }
    _logger.info(json.dumps(record, sort_keys=True))
