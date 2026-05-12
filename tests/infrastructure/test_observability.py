"""Smoke tests for observability module (§6)."""

import json
import logging

import pytest

from synaptic_bridge.infrastructure.observability import (
    CorrelationContext,
    hash_prompt,
    log_ai_call,
    traced,
)


def test_correlation_context_unique():
    a = CorrelationContext.new()
    b = CorrelationContext.new()
    assert a.correlation_id != b.correlation_id
    assert len(a.correlation_id) == 32


def test_hash_prompt_stable():
    assert hash_prompt("hello") == hash_prompt("hello")
    assert hash_prompt("hello") != hash_prompt("Hello")
    assert len(hash_prompt("x")) == 64


def test_traced_records_success():
    with traced("test.op", attributes={"k": "v"}) as attrs:
        attrs["extra"] = "value"
    # No assertion on metrics — exporter is no-op when OTel SDK isn't configured.


def test_traced_records_failure():
    with pytest.raises(RuntimeError), traced("test.op.fail"):
        raise RuntimeError("boom")


def test_log_ai_call_emits_json(caplog):
    with caplog.at_level(logging.INFO, logger="synaptic_bridge"):
        log_ai_call(
            model_id="claude-opus-4-7",
            model_version="20260101",
            prompt="explain X",
            tokens_in=10,
            tokens_out=42,
            latency_ms=123.456,
            cost_usd=0.0012,
            correlation_id="abc",
        )
    records = [r for r in caplog.records if r.name == "synaptic_bridge"]
    assert records, "expected at least one log record"
    payload = json.loads(records[-1].message)
    assert payload["event"] == "ai_call"
    assert payload["model_id"] == "claude-opus-4-7"
    assert payload["prompt_hash"] == hash_prompt("explain X")
    assert payload["tokens_in"] == 10
    assert "explain X" not in records[-1].message  # PII safety
