"""
Test Package

Following skill2026.md Rule 4 - Mandatory Testing Coverage.
Tests for all layers with appropriate mocking.
"""

import pytest
import asyncio
from datetime import datetime, UTC


class TestToolManifest:
    """Tests for ToolManifest domain entity."""

    def test_create_tool_manifest(self):
        from synaptic_bridge.domain.entities import (
            ToolManifest,
            CapabilityType,
            AuditLevel,
        )

        manifest = ToolManifest(
            tool_name="filesystem.read",
            version="1.0.0",
            capabilities=frozenset([CapabilityType.READ]),
            scope="workspace:current",
            ttl_seconds=900,
            network_egress=False,
            audit_level=AuditLevel.FULL,
            signature="abc123",
            created_at=datetime.now(UTC),
        )

        assert manifest.tool_name == "filesystem.read"
        assert manifest.has_capability(CapabilityType.READ)
        assert not manifest.has_capability(CapabilityType.WRITE)
        assert not manifest.allows_network()

    def test_to_toml(self):
        from synaptic_bridge.domain.entities import (
            ToolManifest,
            CapabilityType,
            AuditLevel,
        )

        manifest = ToolManifest(
            tool_name="test.tool",
            version="1.0.0",
            capabilities=frozenset([CapabilityType.READ, CapabilityType.EXECUTE]),
            scope="workspace:current",
            ttl_seconds=900,
            network_egress=False,
            audit_level=AuditLevel.SUMMARY,
            signature="sig123",
            created_at=datetime.now(UTC),
        )

        toml = manifest.to_toml()
        assert "[test.tool]" in toml
        assert "capabilities = [" in toml
        assert 'scope = "workspace:current"' in toml


class TestExecutionSession:
    """Tests for ExecutionSession domain entity."""

    def test_create_session(self):
        from synaptic_bridge.domain.entities import ExecutionSession, SessionStatus

        session = ExecutionSession(
            session_id="test_session",
            agent_id="agent_1",
            execution_token="token123",
            status=SessionStatus.ACTIVE,
            started_at=datetime.now(UTC),
            expires_at=datetime.now(UTC).timestamp() + 900,
            tool_calls=(),
            created_by="system",
        )

        assert session.session_id == "test_session"
        assert session.is_active()

    def test_session_expiration(self):
        from synaptic_bridge.domain.entities import ExecutionSession, SessionStatus

        session = ExecutionSession(
            session_id="expired_session",
            agent_id="agent_1",
            execution_token="token123",
            status=SessionStatus.ACTIVE,
            started_at=datetime.now(UTC),
            expires_at=datetime.now(UTC).timestamp() - 100,
            tool_calls=(),
            created_by="system",
        )

        assert session.is_expired()
        assert not session.is_active()


class TestCorrection:
    """Tests for Correction domain entity."""

    def test_create_correction(self):
        from synaptic_bridge.domain.entities import Correction

        correction = Correction(
            correction_id="corr_123",
            session_id="session_1",
            agent_id="agent_1",
            original_intent="read file",
            inferred_context="user wants to read",
            original_tool="filesystem.read",
            corrected_tool="database.query",
            correction_metadata={"reason": "wrong tool"},
            operator_identity="admin",
            confidence_before=0.5,
            confidence_after=0.9,
            captured_at=datetime.now(UTC),
        )

        assert correction.correction_id == "corr_123"
        assert correction.was_improvement()
        assert correction.trust_score() > 0.5


class TestPolicy:
    """Tests for Policy domain entity."""

    def test_create_policy(self):
        from synaptic_bridge.domain.entities import Policy, PolicyEffect, PolicyScope

        policy = Policy(
            policy_id="policy_1",
            name="Deny Network",
            description="Deny all network calls",
            rego_code='package test\ndeny { input.tool == "network" }',
            effect=PolicyEffect.DENY,
            scope=PolicyScope.NETWORK,
            tags=frozenset(["security", "network"]),
            version="1.0.0",
            enabled=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        assert policy.policy_id == "policy_1"
        assert policy.matches_tag("security")
        assert not policy.matches_tag("wrong")


class TestDAGOrchestrator:
    """Tests for DAG-based workflow orchestration."""

    @pytest.mark.asyncio
    async def test_sequential_execution(self):
        from synaptic_bridge.application.orchestration import (
            DAGOrchestrator,
            WorkflowStep,
        )

        execution_order = []

        async def step_a(ctx, completed):
            execution_order.append("a")
            return "result_a"

        async def step_b(ctx, completed):
            execution_order.append("b")
            return "result_b"

        orchestrator = DAGOrchestrator(
            [
                WorkflowStep("a", step_a),
                WorkflowStep("b", step_b, depends_on=["a"]),
            ]
        )

        result = await orchestrator.execute({})

        assert execution_order == ["a", "b"]
        assert result["a"] == "result_a"
        assert result["b"] == "result_b"

    @pytest.mark.asyncio
    async def test_parallel_execution(self):
        from synaptic_bridge.application.orchestration import (
            DAGOrchestrator,
            WorkflowStep,
        )

        execution_times = {}

        async def step_a(ctx, completed):
            execution_times["a_start"] = len(execution_times)
            await asyncio.sleep(0.01)
            execution_times["a_end"] = len(execution_times)
            return "result_a"

        async def step_b(ctx, completed):
            execution_times["b_start"] = len(execution_times)
            await asyncio.sleep(0.01)
            execution_times["b_end"] = len(execution_times)
            return "result_b"

        orchestrator = DAGOrchestrator(
            [
                WorkflowStep("a", step_a),
                WorkflowStep("b", step_b),
            ]
        )

        result = await orchestrator.execute({})

        assert "a_start" in execution_times
        assert "b_start" in execution_times


class TestInMemoryAdapters:
    """Tests for infrastructure adapters."""

    @pytest.mark.asyncio
    async def test_execution_session_creation(self):
        from synaptic_bridge.infrastructure.adapters import InMemoryExecutionAdapter

        adapter = InMemoryExecutionAdapter()
        session = await adapter.create_session("agent_1", "admin")

        assert session.agent_id == "agent_1"
        assert session.execution_token is not None
        assert session.is_active()

    @pytest.mark.asyncio
    async def test_tool_registry(self):
        from synaptic_bridge.infrastructure.adapters import InMemoryToolRegistry
        from synaptic_bridge.domain.entities import (
            ToolManifest,
            CapabilityType,
            AuditLevel,
        )

        registry = InMemoryToolRegistry()

        manifest = ToolManifest(
            tool_name="test.tool",
            version="1.0.0",
            capabilities=frozenset([CapabilityType.READ]),
            scope="test",
            ttl_seconds=900,
            network_egress=False,
            audit_level=AuditLevel.NONE,
            signature="sig",
            created_at=datetime.now(UTC),
        )

        await registry.register(manifest)

        retrieved = await registry.get("test.tool")
        assert retrieved is not None
        assert retrieved.tool_name == "test.tool"

    @pytest.mark.asyncio
    async def test_audit_log(self):
        from synaptic_bridge.infrastructure.adapters import InMemoryAuditLog
        from synaptic_bridge.domain.events import ToolCalledEvent

        log = InMemoryAuditLog()

        event = ToolCalledEvent(
            aggregate_id="test",
            session_id="session_1",
            agent_id="agent_1",
            tool_name="test.tool",
        )

        await log.write(event)

        events = await log.get_by_session("session_1")
        assert len(events) == 1
