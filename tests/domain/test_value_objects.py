"""Coverage for domain value objects."""

from datetime import UTC, datetime, timedelta

import pytest

from synaptic_bridge.domain.entities.correction import CorrectionPattern
from synaptic_bridge.domain.value_objects import (
    CorrectionScore,
    ExecutionToken,
    IntentEmbedding,
    PolicyRule,
    ToolResult,
)


def test_execution_token_expiry():
    past = datetime.now(UTC) - timedelta(seconds=1)
    future = datetime.now(UTC) + timedelta(hours=1)
    expired = ExecutionToken(token="t", session_id="s", issued_at=past, expires_at=past)
    fresh = ExecutionToken(token="t", session_id="s", issued_at=past, expires_at=future)
    assert expired.is_expired() is True
    assert fresh.is_expired() is False


def test_tool_result_is_error():
    ok = ToolResult(success=True, data={"x": 1}, error=None, execution_time_ms=1.0)
    fail = ToolResult(success=False, data=None, error="nope", execution_time_ms=1.0)
    assert ok.is_error is False
    assert fail.is_error is True


def test_correction_score_improvement():
    s = CorrectionScore(confidence_before=0.5, confidence_after=0.8, trust_score=0.9)
    assert s.improvement == pytest.approx(0.3)
    assert s.is_improvement is True
    bad = CorrectionScore(confidence_before=0.8, confidence_after=0.5, trust_score=0.9)
    assert bad.is_improvement is False


def test_intent_embedding_cosine_similarity():
    a = IntentEmbedding(text="x", vector=(1.0, 0.0))
    b = IntentEmbedding(text="y", vector=(1.0, 0.0))
    orth = IntentEmbedding(text="z", vector=(0.0, 1.0))
    zero = IntentEmbedding(text="0", vector=(0.0, 0.0))
    short = IntentEmbedding(text="s", vector=(1.0,))
    assert a.cosine_similarity(b) == pytest.approx(1.0)
    assert a.cosine_similarity(orth) == pytest.approx(0.0)
    assert a.cosine_similarity(zero) == 0.0
    assert a.cosine_similarity(short) == 0.0


def test_policy_rule_validates_effect():
    PolicyRule(policy_id="p1", name="n", rego_code="x", effect="allow")
    PolicyRule(policy_id="p1", name="n", rego_code="x", effect="deny")
    with pytest.raises(ValueError, match="Effect must"):
        PolicyRule(policy_id="p1", name="n", rego_code="x", effect="maybe")


def test_correction_pattern_undo_and_decay():
    pattern = CorrectionPattern(
        pattern_id="p",
        intent_vector=(1.0, 0.0),
        original_tools=("a",),
        corrected_tools=("b",),
        occurrence_count=10,
        avg_confidence_improvement=0.5,
        last_updated=datetime.now(UTC),
        total_undo_count=0,
    )
    undone = pattern.with_undo()
    assert undone.total_undo_count == 1

    # matches_intent dimension-mismatch path
    assert pattern.matches_intent((1.0, 0.0, 0.0)) == 0.0
    # matches_intent zero-magnitude path
    zero_pattern = CorrectionPattern(
        pattern_id="z",
        intent_vector=(0.0, 0.0),
        original_tools=("a",),
        corrected_tools=("b",),
        occurrence_count=1,
        avg_confidence_improvement=0.0,
        last_updated=datetime.now(UTC),
        total_undo_count=0,
    )
    assert zero_pattern.matches_intent((0.0, 0.0)) == 0.0

    # effective_confidence end-to-end
    score = pattern.effective_confidence((1.0, 0.0))
    assert 0.0 <= score <= 1.0


def test_correction_pattern_undo_penalty_zero_occurrences():
    pattern = CorrectionPattern(
        pattern_id="p",
        intent_vector=(1.0,),
        original_tools=("a",),
        corrected_tools=("b",),
        occurrence_count=0,
        avg_confidence_improvement=0.0,
        last_updated=datetime.now(UTC),
        total_undo_count=0,
    )
    # internal helper: zero occurrences => no penalty
    assert pattern._calculate_undo_penalty() == 1.0
