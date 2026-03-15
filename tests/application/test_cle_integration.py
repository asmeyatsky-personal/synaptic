"""
Tests for CLE Feedback Loop Integration

Verifies that the Correction Learning Engine properly intercepts tool calls,
consults learned patterns, and applies or logs corrections.
"""

import os

os.environ["TESTING"] = "1"

import pytest
from datetime import datetime, UTC

from synaptic_bridge.application.commands import (
    ExecuteToolCommand,
    CaptureCorrectionCommand,
)
from synaptic_bridge.infrastructure.adapters import (
    InMemoryExecutionAdapter,
    InMemoryToolRegistry,
    InMemoryCorrectionStore,
    InMemoryPolicyEngine,
    InMemoryAuditLog,
    MockIntentClassifier,
)
from synaptic_bridge.domain.entities import (
    CapabilityType,
    AuditLevel,
    ToolManifest,
    CorrectionPattern,
)
from synaptic_bridge.domain.constants import EMBEDDING_DIM


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_execution_adapter():
    return InMemoryExecutionAdapter()


def _make_tool_registry(*tool_names):
    """Return an InMemoryToolRegistry pre-loaded with the given tools."""
    registry = InMemoryToolRegistry()
    for name in tool_names:
        manifest = ToolManifest(
            tool_name=name,
            version="1.0.0",
            capabilities=frozenset([CapabilityType.READ]),
            scope="workspace:current",
            ttl_seconds=900,
            network_egress=False,
            audit_level=AuditLevel.FULL,
            signature="sig_abc",
            created_at=datetime.now(UTC),
        )
        registry._tools[name] = manifest
    return registry


async def _create_active_session(adapter):
    return await adapter.create_session("agent_1", "admin")


# ---------------------------------------------------------------------------
# CLE no-op when no patterns exist
# ---------------------------------------------------------------------------

class TestCLENoPatterns:

    @pytest.mark.asyncio
    async def test_no_patterns_executes_original_tool(self):
        adapter = _make_execution_adapter()
        registry = _make_tool_registry("fs.read")
        policy_engine = InMemoryPolicyEngine()
        audit = InMemoryAuditLog()
        classifier = MockIntentClassifier()
        store = InMemoryCorrectionStore()

        session = await _create_active_session(adapter)

        cmd = ExecuteToolCommand(
            session_id=session.session_id,
            tool_name="fs.read",
            parameters={"path": "/tmp"},
            intent="read a file",
        )
        result = await cmd.execute(
            adapter, registry, policy_engine, audit,
            intent_classifier=classifier,
            correction_store=store,
        )

        assert result["success"] is True
        assert result["tool"] == "fs.read"

        # No CLEInterceptionEvent should be emitted
        cle_events = [e for e in audit._events if e.event_type == "CLEInterceptionEvent"]
        assert len(cle_events) == 0


# ---------------------------------------------------------------------------
# Shadow mode: logs but doesn't redirect
# ---------------------------------------------------------------------------

class TestCLEShadowMode:

    @pytest.mark.asyncio
    async def test_shadow_mode_logs_but_does_not_redirect(self):
        adapter = _make_execution_adapter()
        registry = _make_tool_registry("fs.read", "db.query")
        policy_engine = InMemoryPolicyEngine()
        audit = InMemoryAuditLog()
        classifier = MockIntentClassifier()
        store = InMemoryCorrectionStore()

        # Inject a pattern with a real embedding that will match
        embedding = await classifier.get_embedding("read a file")
        store._patterns[("db.query",)] = CorrectionPattern(
            pattern_id="pattern_test1",
            intent_vector=embedding,
            original_tools=("fs.read",),
            corrected_tools=("db.query",),
            occurrence_count=5,
            avg_confidence_improvement=0.3,
            last_updated=datetime.now(UTC),
        )

        session = await _create_active_session(adapter)

        cmd = ExecuteToolCommand(
            session_id=session.session_id,
            tool_name="fs.read",
            parameters={},
            intent="read a file",
        )
        result = await cmd.execute(
            adapter, registry, policy_engine, audit,
            intent_classifier=classifier,
            correction_store=store,
            shadow_mode=True,
        )

        # Original tool should still be executed
        assert result["tool"] == "fs.read"

        # CLEInterceptionEvent should be emitted with shadow_mode=True, applied=False
        cle_events = [e for e in audit._events if e.event_type == "CLEInterceptionEvent"]
        assert len(cle_events) == 1
        cle_meta = cle_events[0].metadata
        assert cle_meta.get("shadow_mode") is True
        assert cle_meta.get("applied") is False

        # ToolCalledEvent should show was_corrected=False
        tool_events = [e for e in audit._events if e.event_type == "ToolCalledEvent"]
        assert len(tool_events) == 1


# ---------------------------------------------------------------------------
# Active mode: redirects when confidence >= threshold
# ---------------------------------------------------------------------------

class TestCLEActiveMode:

    @pytest.mark.asyncio
    async def test_active_mode_redirects_high_confidence(self):
        adapter = _make_execution_adapter()
        registry = _make_tool_registry("fs.read", "db.query")
        policy_engine = InMemoryPolicyEngine()
        audit = InMemoryAuditLog()
        classifier = MockIntentClassifier()
        store = InMemoryCorrectionStore()

        embedding = await classifier.get_embedding("read a file")
        store._patterns[("db.query",)] = CorrectionPattern(
            pattern_id="pattern_active1",
            intent_vector=embedding,
            original_tools=("fs.read",),
            corrected_tools=("db.query",),
            occurrence_count=10,
            avg_confidence_improvement=0.4,
            last_updated=datetime.now(UTC),
        )

        session = await _create_active_session(adapter)

        cmd = ExecuteToolCommand(
            session_id=session.session_id,
            tool_name="fs.read",
            parameters={},
            intent="read a file",
        )
        result = await cmd.execute(
            adapter, registry, policy_engine, audit,
            intent_classifier=classifier,
            correction_store=store,
            shadow_mode=False,
        )

        # Tool should be redirected to db.query
        assert result["tool"] == "db.query"

    @pytest.mark.asyncio
    async def test_below_threshold_does_not_redirect(self):
        adapter = _make_execution_adapter()
        registry = _make_tool_registry("fs.read", "db.query")
        policy_engine = InMemoryPolicyEngine()
        audit = InMemoryAuditLog()
        classifier = MockIntentClassifier()
        store = InMemoryCorrectionStore()

        # Use a very different embedding to produce low similarity
        mismatched_embedding = tuple([0.0] * (EMBEDDING_DIM - 1) + [1.0])
        store._patterns[("db.query",)] = CorrectionPattern(
            pattern_id="pattern_low",
            intent_vector=mismatched_embedding,
            original_tools=("fs.read",),
            corrected_tools=("db.query",),
            occurrence_count=1,
            avg_confidence_improvement=0.1,
            last_updated=datetime.now(UTC),
        )

        session = await _create_active_session(adapter)

        cmd = ExecuteToolCommand(
            session_id=session.session_id,
            tool_name="fs.read",
            parameters={},
            intent="read a file",
        )
        result = await cmd.execute(
            adapter, registry, policy_engine, audit,
            intent_classifier=classifier,
            correction_store=store,
            shadow_mode=False,
        )

        # Should NOT redirect
        assert result["tool"] == "fs.read"


# ---------------------------------------------------------------------------
# Corrected tool not in registry falls back to original
# ---------------------------------------------------------------------------

class TestCLEFallback:

    @pytest.mark.asyncio
    async def test_corrected_tool_not_in_registry_falls_back(self):
        adapter = _make_execution_adapter()
        registry = _make_tool_registry("fs.read")  # db.query NOT registered
        policy_engine = InMemoryPolicyEngine()
        audit = InMemoryAuditLog()
        classifier = MockIntentClassifier()
        store = InMemoryCorrectionStore()

        embedding = await classifier.get_embedding("read a file")
        store._patterns[("db.query",)] = CorrectionPattern(
            pattern_id="pattern_missing",
            intent_vector=embedding,
            original_tools=("fs.read",),
            corrected_tools=("db.query",),
            occurrence_count=5,
            avg_confidence_improvement=0.3,
            last_updated=datetime.now(UTC),
        )

        session = await _create_active_session(adapter)

        cmd = ExecuteToolCommand(
            session_id=session.session_id,
            tool_name="fs.read",
            parameters={},
            intent="read a file",
        )
        result = await cmd.execute(
            adapter, registry, policy_engine, audit,
            intent_classifier=classifier,
            correction_store=store,
            shadow_mode=False,
        )

        # Falls back to original tool
        assert result["tool"] == "fs.read"

        # CLEInterceptionEvent should show applied=False
        cle_events = [e for e in audit._events if e.event_type == "CLEInterceptionEvent"]
        assert len(cle_events) == 1
        assert cle_events[0].metadata.get("applied") is False


# ---------------------------------------------------------------------------
# CLE exception doesn't block execution
# ---------------------------------------------------------------------------

class TestCLEExceptionHandling:

    @pytest.mark.asyncio
    async def test_cle_exception_does_not_block(self):
        adapter = _make_execution_adapter()
        registry = _make_tool_registry("fs.read")
        policy_engine = InMemoryPolicyEngine()
        audit = InMemoryAuditLog()

        # Use a broken classifier that raises
        class BrokenClassifier:
            async def get_embedding(self, text):
                raise RuntimeError("Classifier is down")

            async def classify_intent(self, text):
                raise RuntimeError("Classifier is down")

            async def match_tool(self, embedding):
                raise RuntimeError("Classifier is down")

        store = InMemoryCorrectionStore()
        broken = BrokenClassifier()

        session = await _create_active_session(adapter)

        cmd = ExecuteToolCommand(
            session_id=session.session_id,
            tool_name="fs.read",
            parameters={},
            intent="read a file",
        )
        # Should NOT raise
        result = await cmd.execute(
            adapter, registry, policy_engine, audit,
            intent_classifier=broken,
            correction_store=store,
        )

        assert result["success"] is True
        assert result["tool"] == "fs.read"


# ---------------------------------------------------------------------------
# ToolCalledEvent reflects correction data
# ---------------------------------------------------------------------------

class TestToolCalledEventCorrection:

    @pytest.mark.asyncio
    async def test_tool_called_event_reflects_correction(self):
        adapter = _make_execution_adapter()
        registry = _make_tool_registry("fs.read", "db.query")
        policy_engine = InMemoryPolicyEngine()
        audit = InMemoryAuditLog()
        classifier = MockIntentClassifier()
        store = InMemoryCorrectionStore()

        embedding = await classifier.get_embedding("read a file")
        store._patterns[("db.query",)] = CorrectionPattern(
            pattern_id="pattern_evt",
            intent_vector=embedding,
            original_tools=("fs.read",),
            corrected_tools=("db.query",),
            occurrence_count=3,
            avg_confidence_improvement=0.2,
            last_updated=datetime.now(UTC),
        )

        session = await _create_active_session(adapter)

        cmd = ExecuteToolCommand(
            session_id=session.session_id,
            tool_name="fs.read",
            parameters={},
            intent="read a file",
        )
        await cmd.execute(
            adapter, registry, policy_engine, audit,
            intent_classifier=classifier,
            correction_store=store,
            shadow_mode=False,
        )

        tool_events = [e for e in audit._events if e.event_type == "ToolCalledEvent"]
        assert len(tool_events) == 1
        meta = tool_events[0].metadata
        assert meta.get("was_corrected") is True
        assert meta.get("correction_confidence", 0) > 0


# ---------------------------------------------------------------------------
# CLEInterceptionEvent emitted
# ---------------------------------------------------------------------------

class TestCLEInterceptionEventEmitted:

    @pytest.mark.asyncio
    async def test_cle_interception_event_emitted(self):
        adapter = _make_execution_adapter()
        registry = _make_tool_registry("fs.read", "db.query")
        policy_engine = InMemoryPolicyEngine()
        audit = InMemoryAuditLog()
        classifier = MockIntentClassifier()
        store = InMemoryCorrectionStore()

        embedding = await classifier.get_embedding("read a file")
        store._patterns[("db.query",)] = CorrectionPattern(
            pattern_id="pattern_emit",
            intent_vector=embedding,
            original_tools=("fs.read",),
            corrected_tools=("db.query",),
            occurrence_count=5,
            avg_confidence_improvement=0.3,
            last_updated=datetime.now(UTC),
        )

        session = await _create_active_session(adapter)

        cmd = ExecuteToolCommand(
            session_id=session.session_id,
            tool_name="fs.read",
            parameters={},
            intent="read a file",
        )
        await cmd.execute(
            adapter, registry, policy_engine, audit,
            intent_classifier=classifier,
            correction_store=store,
            shadow_mode=False,
        )

        cle_events = [e for e in audit._events if e.event_type == "CLEInterceptionEvent"]
        assert len(cle_events) == 1
        meta = cle_events[0].metadata
        assert meta["original_tool"] == "fs.read"
        assert meta["suggested_tool"] == "db.query"
        assert meta["pattern_id"] == "pattern_emit"
        assert meta["applied"] is True


# ---------------------------------------------------------------------------
# Correction with embedding stores real vector
# ---------------------------------------------------------------------------

class TestCorrectionEmbeddingStorage:

    @pytest.mark.asyncio
    async def test_correction_stores_real_embedding(self):
        store = InMemoryCorrectionStore()
        classifier = MockIntentClassifier()

        cmd = CaptureCorrectionCommand(
            session_id="session_1",
            agent_id="agent_1",
            original_intent="read a file",
            inferred_context="user wants data",
            original_tool="fs.read",
            corrected_tool="db.query",
            correction_metadata={"reason": "wrong tool"},
            operator_identity="admin",
            confidence_before=0.4,
            confidence_after=0.9,
        )
        await cmd.execute(store, intent_classifier=classifier)

        # The pattern should have a non-zero vector
        patterns = list(store._patterns.values())
        assert len(patterns) == 1
        pattern = patterns[0]
        assert any(v != 0.0 for v in pattern.intent_vector)
        assert len(pattern.intent_vector) == EMBEDDING_DIM


# ---------------------------------------------------------------------------
# End-to-end: capture correction then verify CLE intercepts
# ---------------------------------------------------------------------------

class TestCLEEndToEnd:

    @pytest.mark.asyncio
    async def test_capture_then_intercept(self):
        adapter = _make_execution_adapter()
        registry = _make_tool_registry("fs.read", "db.query")
        policy_engine = InMemoryPolicyEngine()
        audit = InMemoryAuditLog()
        classifier = MockIntentClassifier()
        store = InMemoryCorrectionStore()

        # Step 1: Capture a correction with real embedding
        capture_cmd = CaptureCorrectionCommand(
            session_id="session_1",
            agent_id="agent_1",
            original_intent="read a file",
            inferred_context="user wants database data",
            original_tool="fs.read",
            corrected_tool="db.query",
            correction_metadata={"reason": "should query db"},
            operator_identity="admin",
            confidence_before=0.4,
            confidence_after=0.9,
        )
        await capture_cmd.execute(store, intent_classifier=classifier)

        # Step 2: Execute the same intent — CLE should intercept in active mode
        session = await _create_active_session(adapter)

        exec_cmd = ExecuteToolCommand(
            session_id=session.session_id,
            tool_name="fs.read",
            parameters={},
            intent="read a file",
        )
        result = await exec_cmd.execute(
            adapter, registry, policy_engine, audit,
            intent_classifier=classifier,
            correction_store=store,
            shadow_mode=False,
        )

        # The tool should have been redirected based on the learned pattern
        assert result["tool"] == "db.query"
