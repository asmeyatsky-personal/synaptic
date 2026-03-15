"""
Additional Unit Tests

Extended test coverage for SynapticBridge domain entities and infrastructure.
"""

import pytest
import asyncio
from datetime import datetime, UTC


class TestToolCallEntity:
    """Tests for ToolCall domain entity."""

    def test_create_tool_call(self):
        from synaptic_bridge.domain.entities import ToolCall, ToolCallStatus

        call = ToolCall(
            call_id="call_123",
            session_id="session_1",
            agent_id="agent_1",
            tool_name="filesystem.read",
            corrected_tool=None,
            parameters={"path": "/tmp/test"},
            status=ToolCallStatus.PENDING,
            started_at=datetime.now(UTC),
            completed_at=None,
            result=None,
            error=None,
            was_corrected=False,
            correction_confidence=None,
        )

        assert call.call_id == "call_123"
        assert call.tool_name == "filesystem.read"
        assert call.status == ToolCallStatus.PENDING
        assert not call.was_corrected

    def test_mark_in_progress(self):
        from synaptic_bridge.domain.entities import ToolCall, ToolCallStatus

        call = ToolCall(
            call_id="call_123",
            session_id="session_1",
            agent_id="agent_1",
            tool_name="filesystem.read",
            corrected_tool=None,
            parameters={},
            status=ToolCallStatus.PENDING,
            started_at=datetime.now(UTC),
            completed_at=None,
            result=None,
            error=None,
            was_corrected=False,
            correction_confidence=None,
        )

        in_progress = call.mark_in_progress()
        assert in_progress.status == ToolCallStatus.IN_PROGRESS

    def test_complete_success(self):
        from synaptic_bridge.domain.entities import ToolCall, ToolCallStatus

        call = ToolCall(
            call_id="call_123",
            session_id="session_1",
            agent_id="agent_1",
            tool_name="filesystem.read",
            corrected_tool=None,
            parameters={},
            status=ToolCallStatus.IN_PROGRESS,
            started_at=datetime.now(UTC),
            completed_at=None,
            result=None,
            error=None,
            was_corrected=False,
            correction_confidence=None,
        )

        completed = call.complete_success({"data": "result"})
        assert completed.status == ToolCallStatus.SUCCESS
        assert completed.result == {"data": "result"}
        assert completed.completed_at is not None

    def test_complete_failure(self):
        from synaptic_bridge.domain.entities import ToolCall, ToolCallStatus

        call = ToolCall(
            call_id="call_123",
            session_id="session_1",
            agent_id="agent_1",
            tool_name="filesystem.read",
            corrected_tool=None,
            parameters={},
            status=ToolCallStatus.IN_PROGRESS,
            started_at=datetime.now(UTC),
            completed_at=None,
            result=None,
            error=None,
            was_corrected=False,
            correction_confidence=None,
        )

        failed = call.complete_failure("File not found")
        assert failed.status == ToolCallStatus.FAILED
        assert failed.error == "File not found"

    def test_to_audit_dict(self):
        from synaptic_bridge.domain.entities import ToolCall, ToolCallStatus

        started = datetime.now(UTC)
        call = ToolCall(
            call_id="call_123",
            session_id="session_1",
            agent_id="agent_1",
            tool_name="filesystem.read",
            corrected_tool=None,
            parameters={},
            status=ToolCallStatus.SUCCESS,
            started_at=started,
            completed_at=started,
            result={"data": "test"},
            error=None,
            was_corrected=False,
            correction_confidence=None,
        )

        audit_dict = call.to_audit_dict()
        assert audit_dict["call_id"] == "call_123"
        assert audit_dict["status"] == "success"
        assert audit_dict["was_corrected"] is False


class TestAuditEventEntity:
    """Tests for AuditEvent domain entity."""

    def test_create_audit_event(self):
        from synaptic_bridge.domain.entities import AuditEvent

        event = AuditEvent(
            event_id="evt_123",
            event_type="tool_call",
            session_id="session_1",
            agent_id="agent_1",
            tool_name="filesystem.read",
            action="execute",
            actor="system",
            resource="/tmp/file",
            outcome="success",
            metadata={"size": 1024},
            timestamp=datetime.now(UTC),
            signature="sig123",
        )

        assert event.event_id == "evt_123"
        assert event.event_type == "tool_call"

    def test_is_critical(self):
        from synaptic_bridge.domain.entities import AuditEvent

        critical_event = AuditEvent(
            event_id="evt_1",
            event_type="policy_violation",
            session_id=None,
            agent_id=None,
            tool_name=None,
            action="deny",
            actor="system",
            resource="",
            outcome="denied",
            metadata={},
            timestamp=datetime.now(UTC),
            signature="sig",
        )

        non_critical = AuditEvent(
            event_id="evt_2",
            event_type="tool_call",
            session_id="session_1",
            agent_id="agent_1",
            tool_name="test.tool",
            action="execute",
            actor="system",
            resource="",
            outcome="success",
            metadata={},
            timestamp=datetime.now(UTC),
            signature="sig",
        )

        assert critical_event.is_critical() is True
        assert non_critical.is_critical() is False


class TestCorrectionPatternEntity:
    """Tests for CorrectionPattern domain entity."""

    def test_create_correction_pattern(self):
        from synaptic_bridge.domain.entities import CorrectionPattern

        pattern = CorrectionPattern(
            pattern_id="pattern_1",
            intent_vector=tuple([0.1] * 128),
            original_tools=("bad.tool",),
            corrected_tools=("good.tool",),
            occurrence_count=5,
            avg_confidence_improvement=0.3,
            last_updated=datetime.now(UTC),
        )

        assert pattern.pattern_id == "pattern_1"
        assert pattern.occurrence_count == 5
        assert pattern.avg_confidence_improvement == 0.3

    def test_with_increment(self):
        from synaptic_bridge.domain.entities import CorrectionPattern

        pattern = CorrectionPattern(
            pattern_id="pattern_1",
            intent_vector=tuple([0.1] * 128),
            original_tools=("bad.tool",),
            corrected_tools=("good.tool",),
            occurrence_count=5,
            avg_confidence_improvement=0.3,
            last_updated=datetime.now(UTC),
        )

        updated = pattern.with_increment(0.5)
        assert updated.occurrence_count == 6
        assert updated.avg_confidence_improvement == pytest.approx(0.3333333333333333)

    def test_matches_intent(self):
        from synaptic_bridge.domain.entities import CorrectionPattern

        pattern = CorrectionPattern(
            pattern_id="pattern_1",
            intent_vector=(1.0, 0.0, 0.0),
            original_tools=("bad.tool",),
            corrected_tools=("good.tool",),
            occurrence_count=1,
            avg_confidence_improvement=0.3,
            last_updated=datetime.now(UTC),
        )

        similar_intent = pattern.matches_intent((1.0, 0.0, 0.0))
        assert similar_intent == 1.0

        different_intent = pattern.matches_intent((0.0, 1.0, 0.0))
        assert different_intent == 0.0


class TestOPAPolicyEngine:
    """Tests for OPA policy engine."""

    @pytest.mark.asyncio
    async def test_add_and_list_policies(self):
        from synaptic_bridge.infrastructure.adapters.opa_engine import OPAPolicyEngine
        from synaptic_bridge.domain.entities import Policy, PolicyEffect, PolicyScope

        engine = OPAPolicyEngine()

        policy = Policy(
            policy_id="policy_1",
            name="Test Policy",
            description="Test",
            rego_code='package test\ndeny { input.tool == "bad" }',
            effect=PolicyEffect.DENY,
            scope=PolicyScope.TOOL,
            tags=frozenset(["test"]),
            version="1.0.0",
            enabled=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        await engine.add_policy(policy)
        policies = await engine.list_policies()

        assert len(policies) == 1
        assert policies[0].policy_id == "policy_1"

    @pytest.mark.asyncio
    async def test_evaluate_allow_policy(self):
        from synaptic_bridge.infrastructure.adapters.opa_engine import OPAPolicyEngine
        from synaptic_bridge.domain.entities import Policy, PolicyEffect, PolicyScope

        engine = OPAPolicyEngine()

        policy = Policy(
            policy_id="policy_allow",
            name="Allow Policy",
            description="Allow all",
            rego_code="package test\nallow { true }",
            effect=PolicyEffect.ALLOW,
            scope=PolicyScope.TOOL,
            tags=frozenset([]),
            version="1.0.0",
            enabled=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        await engine.add_policy(policy)
        result = await engine.evaluate(policy, {"tool": "anything"})

        assert result is True

    @pytest.mark.asyncio
    async def test_evaluate_disabled_policy(self):
        from synaptic_bridge.infrastructure.adapters.opa_engine import OPAPolicyEngine
        from synaptic_bridge.domain.entities import Policy, PolicyEffect, PolicyScope

        engine = OPAPolicyEngine()

        policy = Policy(
            policy_id="policy_disabled",
            name="Disabled Policy",
            description="Should not evaluate",
            rego_code='package test\ndeny { input.tool == "bad_tool" }',
            effect=PolicyEffect.DENY,
            scope=PolicyScope.TOOL,
            tags=frozenset([]),
            version="1.0.0",
            enabled=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        await engine.add_policy(policy)
        result = await engine.evaluate(policy, {"tool": "bad_tool"})

        assert result is True

    @pytest.mark.asyncio
    async def test_remove_policy(self):
        from synaptic_bridge.infrastructure.adapters.opa_engine import OPAPolicyEngine
        from synaptic_bridge.domain.entities import Policy, PolicyEffect, PolicyScope

        engine = OPAPolicyEngine()

        policy = Policy(
            policy_id="policy_1",
            name="Test Policy",
            description="Test",
            rego_code="package test\nallow { true }",
            effect=PolicyEffect.ALLOW,
            scope=PolicyScope.TOOL,
            tags=frozenset([]),
            version="1.0.0",
            enabled=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        await engine.add_policy(policy)
        assert len(await engine.list_policies()) == 1

        await engine.remove_policy("policy_1")
        assert len(await engine.list_policies()) == 0


class TestIntentClassifier:
    """Tests for intent classifier."""

    @pytest.mark.asyncio
    async def test_get_embedding(self):
        from synaptic_bridge.infrastructure.adapters.intent_classifier import (
            IntentClassifier,
        )

        classifier = IntentClassifier()

        vector = await classifier.get_embedding("read a file from disk")
        assert len(vector) == 128
        assert isinstance(vector[0], float)

    @pytest.mark.asyncio
    async def test_classify_intent(self):
        from synaptic_bridge.infrastructure.adapters.intent_classifier import (
            IntentClassifier,
        )

        classifier = IntentClassifier()

        tool_name, confidence = await classifier.classify_intent("read a file")
        assert isinstance(tool_name, str)
        assert 0.0 <= confidence <= 1.0


class TestDriftDetector:
    """Tests for drift detector."""

    @pytest.mark.asyncio
    async def test_check_drift(self):
        from synaptic_bridge.infrastructure.adapters.drift_detector import DriftDetector

        detector = DriftDetector(window_size=10, drift_threshold=0.3)

        drift_score = await detector.check_drift(
            "test_tool", {"execution_time_ms": 100}
        )
        assert isinstance(drift_score, float)

    @pytest.mark.asyncio
    async def test_drift_report(self):
        from synaptic_bridge.infrastructure.adapters.drift_detector import DriftDetector

        detector = DriftDetector()

        report = detector.get_drift_report()
        assert isinstance(report, dict)
