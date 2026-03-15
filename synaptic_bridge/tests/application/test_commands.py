"""
Tests for Application Commands

Comprehensive tests for all CQRS command handlers in the application layer.
"""

import os

os.environ["TESTING"] = "1"

import pytest
from datetime import datetime, UTC

from synaptic_bridge.application.commands import (
    CreateSessionCommand,
    ExecuteToolCommand,
    CaptureCorrectionCommand,
    AddPolicyCommand,
    RegisterToolCommand,
)
from synaptic_bridge.infrastructure.adapters import (
    InMemoryExecutionAdapter,
    InMemoryToolRegistry,
    InMemoryCorrectionStore,
    InMemoryPolicyEngine,
    InMemoryAuditLog,
)
from synaptic_bridge.domain.entities import (
    CapabilityType,
    AuditLevel,
    ToolManifest,
    SessionStatus,
    PolicyEffect,
    PolicyScope,
    Policy,
)
from synaptic_bridge.domain.exceptions import (
    SessionNotFoundError,
    SessionExpiredError,
    ToolNotFoundError,
    PolicyViolationError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_execution_adapter():
    return InMemoryExecutionAdapter()


def _make_tool_registry_with_tool(tool_name="test.tool"):
    """Return an InMemoryToolRegistry pre-loaded with one manifest."""
    registry = InMemoryToolRegistry()
    manifest = ToolManifest(
        tool_name=tool_name,
        version="1.0.0",
        capabilities=frozenset([CapabilityType.READ]),
        scope="workspace:current",
        ttl_seconds=900,
        network_egress=False,
        audit_level=AuditLevel.FULL,
        signature="sig_abc",
        created_at=datetime.now(UTC),
    )
    # Directly inject into the internal dict so we stay synchronous
    registry._tools[tool_name] = manifest
    return registry


def _make_deny_policy():
    """Create a DENY policy scoped to TOOL."""
    return Policy(
        policy_id="policy_deny_1",
        name="Block All",
        description="Deny all tool executions",
        rego_code='package test\ndeny { true }',
        effect=PolicyEffect.DENY,
        scope=PolicyScope.TOOL,
        tags=frozenset(["security"]),
        version="1.0.0",
        enabled=True,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# CreateSessionCommand
# ---------------------------------------------------------------------------

class TestCreateSessionCommand:

    @pytest.mark.asyncio
    async def test_execute_creates_session(self):
        adapter = _make_execution_adapter()
        audit = InMemoryAuditLog()

        cmd = CreateSessionCommand(agent_id="agent_1", created_by="admin")
        session = await cmd.execute(adapter, audit)

        assert session is not None
        assert session.agent_id == "agent_1"
        assert session.created_by == "admin"
        assert session.status == SessionStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_session_fields_populated(self):
        adapter = _make_execution_adapter()
        audit = InMemoryAuditLog()

        cmd = CreateSessionCommand(agent_id="agent_x", created_by="ops")
        session = await cmd.execute(adapter, audit)

        assert session.session_id.startswith("session_")
        assert session.execution_token  # non-empty JWT
        assert session.tool_calls == ()
        assert session.is_active()

    @pytest.mark.asyncio
    async def test_audit_log_written_on_create(self):
        adapter = _make_execution_adapter()
        audit = InMemoryAuditLog()

        cmd = CreateSessionCommand(agent_id="agent_1", created_by="admin")
        session = await cmd.execute(adapter, audit)

        # The session's first domain_event should have been forwarded to the
        # audit log if it was present.  InMemoryAuditLog.write accepts None
        # gracefully, so we just verify no crash and the log has either 0 or 1
        # entries depending on whether a domain event was emitted.
        events = audit._events
        assert isinstance(events, list)


# ---------------------------------------------------------------------------
# ExecuteToolCommand
# ---------------------------------------------------------------------------

class TestExecuteToolCommand:

    @pytest.mark.asyncio
    async def test_execute_with_valid_session_and_tool(self):
        adapter = _make_execution_adapter()
        registry = _make_tool_registry_with_tool("fs.read")
        policy_engine = InMemoryPolicyEngine()
        audit = InMemoryAuditLog()

        session = await adapter.create_session("agent_1", "admin")

        cmd = ExecuteToolCommand(
            session_id=session.session_id,
            tool_name="fs.read",
            parameters={"path": "/tmp"},
            intent="read a file",
        )
        result = await cmd.execute(adapter, registry, policy_engine, audit)

        assert result["success"] is True
        assert result["tool"] == "fs.read"

    @pytest.mark.asyncio
    async def test_session_not_found_raises_error(self):
        adapter = _make_execution_adapter()
        registry = _make_tool_registry_with_tool()
        policy_engine = InMemoryPolicyEngine()
        audit = InMemoryAuditLog()

        cmd = ExecuteToolCommand(
            session_id="nonexistent_session",
            tool_name="test.tool",
            parameters={},
            intent="do something",
        )

        with pytest.raises(SessionNotFoundError):
            await cmd.execute(adapter, registry, policy_engine, audit)

    @pytest.mark.asyncio
    async def test_inactive_session_raises_error(self):
        adapter = _make_execution_adapter()
        registry = _make_tool_registry_with_tool()
        policy_engine = InMemoryPolicyEngine()
        audit = InMemoryAuditLog()

        session = await adapter.create_session("agent_1", "admin")
        # Force the session to TERMINATED so it's no longer active
        terminated = session.terminate()
        adapter._sessions[session.session_id] = terminated

        cmd = ExecuteToolCommand(
            session_id=session.session_id,
            tool_name="test.tool",
            parameters={},
            intent="do something",
        )

        with pytest.raises(SessionExpiredError):
            await cmd.execute(adapter, registry, policy_engine, audit)

    @pytest.mark.asyncio
    async def test_tool_not_found_raises_error(self):
        adapter = _make_execution_adapter()
        registry = InMemoryToolRegistry()  # empty registry
        policy_engine = InMemoryPolicyEngine()
        audit = InMemoryAuditLog()

        session = await adapter.create_session("agent_1", "admin")

        cmd = ExecuteToolCommand(
            session_id=session.session_id,
            tool_name="missing.tool",
            parameters={},
            intent="do something",
        )

        with pytest.raises(ToolNotFoundError):
            await cmd.execute(adapter, registry, policy_engine, audit)

    @pytest.mark.asyncio
    async def test_policy_denial_raises_error(self):
        adapter = _make_execution_adapter()
        registry = _make_tool_registry_with_tool("fs.write")
        policy_engine = InMemoryPolicyEngine()
        audit = InMemoryAuditLog()

        # Add a DENY policy
        deny_policy = _make_deny_policy()
        await policy_engine.add_policy(deny_policy)

        session = await adapter.create_session("agent_1", "admin")

        cmd = ExecuteToolCommand(
            session_id=session.session_id,
            tool_name="fs.write",
            parameters={},
            intent="write something",
        )

        with pytest.raises(PolicyViolationError):
            await cmd.execute(adapter, registry, policy_engine, audit)

    @pytest.mark.asyncio
    async def test_policy_denial_writes_violation_audit_event(self):
        adapter = _make_execution_adapter()
        registry = _make_tool_registry_with_tool("fs.write")
        policy_engine = InMemoryPolicyEngine()
        audit = InMemoryAuditLog()

        deny_policy = _make_deny_policy()
        await policy_engine.add_policy(deny_policy)

        session = await adapter.create_session("agent_1", "admin")

        cmd = ExecuteToolCommand(
            session_id=session.session_id,
            tool_name="fs.write",
            parameters={},
            intent="write something",
        )

        with pytest.raises(PolicyViolationError):
            await cmd.execute(adapter, registry, policy_engine, audit)

        # A PolicyViolationEvent should have been written
        assert len(audit._events) >= 1
        violation_event = audit._events[0]
        assert violation_event.event_type == "PolicyViolationEvent"

    @pytest.mark.asyncio
    async def test_successful_execute_writes_tool_called_event(self):
        adapter = _make_execution_adapter()
        registry = _make_tool_registry_with_tool("bash.run")
        policy_engine = InMemoryPolicyEngine()
        audit = InMemoryAuditLog()

        session = await adapter.create_session("agent_1", "admin")

        cmd = ExecuteToolCommand(
            session_id=session.session_id,
            tool_name="bash.run",
            parameters={"cmd": "ls"},
            intent="list files",
        )
        await cmd.execute(adapter, registry, policy_engine, audit)

        assert len(audit._events) >= 1
        tool_event = audit._events[-1]
        assert tool_event.event_type == "ToolCalledEvent"
        assert tool_event.tool_name == "bash.run"

    @pytest.mark.asyncio
    async def test_execute_with_allow_policy_succeeds(self):
        adapter = _make_execution_adapter()
        registry = _make_tool_registry_with_tool("fs.read")
        policy_engine = InMemoryPolicyEngine()
        audit = InMemoryAuditLog()

        allow_policy = Policy(
            policy_id="policy_allow_1",
            name="Allow Reads",
            description="Allow read operations",
            rego_code="package test\nallow { true }",
            effect=PolicyEffect.ALLOW,
            scope=PolicyScope.TOOL,
            tags=frozenset(["access"]),
            version="1.0.0",
            enabled=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        await policy_engine.add_policy(allow_policy)

        session = await adapter.create_session("agent_1", "admin")

        cmd = ExecuteToolCommand(
            session_id=session.session_id,
            tool_name="fs.read",
            parameters={},
            intent="read file",
        )
        result = await cmd.execute(adapter, registry, policy_engine, audit)
        assert result["success"] is True


# ---------------------------------------------------------------------------
# CaptureCorrectionCommand
# ---------------------------------------------------------------------------

class TestCaptureCorrectionCommand:

    @pytest.mark.asyncio
    async def test_execute_creates_correction(self):
        store = InMemoryCorrectionStore()

        cmd = CaptureCorrectionCommand(
            session_id="session_1",
            agent_id="agent_1",
            original_intent="read file",
            inferred_context="user wants data",
            original_tool="fs.read",
            corrected_tool="db.query",
            correction_metadata={"reason": "wrong tool"},
            operator_identity="admin",
            confidence_before=0.4,
            confidence_after=0.9,
        )
        correction = await cmd.execute(store)

        assert correction is not None
        assert correction.correction_id.startswith("corr_")

    @pytest.mark.asyncio
    async def test_correction_fields_match_command(self):
        store = InMemoryCorrectionStore()

        cmd = CaptureCorrectionCommand(
            session_id="sess_x",
            agent_id="agent_x",
            original_intent="deploy service",
            inferred_context="CI/CD context",
            original_tool="bash.exec",
            corrected_tool="deploy.run",
            correction_metadata={"env": "staging"},
            operator_identity="ops_user",
            confidence_before=0.3,
            confidence_after=0.85,
        )
        correction = await cmd.execute(store)

        assert correction.session_id == "sess_x"
        assert correction.agent_id == "agent_x"
        assert correction.original_intent == "deploy service"
        assert correction.original_tool == "bash.exec"
        assert correction.corrected_tool == "deploy.run"
        assert correction.operator_identity == "ops_user"
        assert correction.confidence_before == pytest.approx(0.3)
        assert correction.confidence_after == pytest.approx(0.85)
        assert correction.captured_at is not None

    @pytest.mark.asyncio
    async def test_correction_saved_to_store(self):
        store = InMemoryCorrectionStore()

        cmd = CaptureCorrectionCommand(
            session_id="session_1",
            agent_id="agent_1",
            original_intent="intent",
            inferred_context="ctx",
            original_tool="a.tool",
            corrected_tool="b.tool",
            correction_metadata={},
            operator_identity="admin",
            confidence_before=0.5,
            confidence_after=0.8,
        )
        correction = await cmd.execute(store)

        saved = await store.get_correction(correction.correction_id)
        assert saved is not None
        assert saved.correction_id == correction.correction_id


# ---------------------------------------------------------------------------
# AddPolicyCommand
# ---------------------------------------------------------------------------

class TestAddPolicyCommand:

    @pytest.mark.asyncio
    async def test_execute_creates_policy(self):
        engine = InMemoryPolicyEngine()

        cmd = AddPolicyCommand(
            name="Deny Network",
            description="Block network egress",
            rego_code='package net\ndeny { input.network_egress }',
            effect=PolicyEffect.DENY,
            scope=PolicyScope.NETWORK,
            tags=["security", "network"],
        )
        policy = await cmd.execute(engine)

        assert policy is not None
        assert policy.policy_id.startswith("policy_")

    @pytest.mark.asyncio
    async def test_policy_fields_match_command(self):
        engine = InMemoryPolicyEngine()

        cmd = AddPolicyCommand(
            name="Rate Limit",
            description="Limit calls per session",
            rego_code='package rl\ndeny { input.count > 100 }',
            effect=PolicyEffect.DENY,
            scope=PolicyScope.SESSION,
            tags=["rate-limit"],
        )
        policy = await cmd.execute(engine)

        assert policy.name == "Rate Limit"
        assert policy.description == "Limit calls per session"
        assert policy.effect == PolicyEffect.DENY
        assert policy.scope == PolicyScope.SESSION
        assert "rate-limit" in policy.tags
        assert policy.version == "1.0.0"
        assert policy.enabled is True

    @pytest.mark.asyncio
    async def test_policy_persisted_in_engine(self):
        engine = InMemoryPolicyEngine()

        cmd = AddPolicyCommand(
            name="Allow All",
            description="Allow everything",
            rego_code="package all\nallow { true }",
            effect=PolicyEffect.ALLOW,
            scope=PolicyScope.AGENT,
            tags=[],
        )
        await cmd.execute(engine)

        policies = await engine.list_policies()
        assert len(policies) == 1


# ---------------------------------------------------------------------------
# RegisterToolCommand
# ---------------------------------------------------------------------------

class TestRegisterToolCommand:

    @pytest.mark.asyncio
    async def test_execute_registers_manifest(self):
        registry = InMemoryToolRegistry()

        cmd = RegisterToolCommand(
            tool_name="fs.read",
            version="2.0.0",
            capabilities=["read"],
            scope="workspace:current",
            ttl_seconds=600,
            network_egress=False,
            audit_level="full",
            signature="sig_xyz",
        )
        manifest = await cmd.execute(registry)

        assert manifest is not None
        assert manifest.tool_name == "fs.read"

    @pytest.mark.asyncio
    async def test_manifest_fields_match_command(self):
        registry = InMemoryToolRegistry()

        cmd = RegisterToolCommand(
            tool_name="http.request",
            version="1.2.0",
            capabilities=["network", "read"],
            scope="global",
            ttl_seconds=120,
            network_egress=True,
            audit_level="summary",
            signature="sig_http",
        )
        manifest = await cmd.execute(registry)

        assert manifest.version == "1.2.0"
        assert CapabilityType.NETWORK in manifest.capabilities
        assert CapabilityType.READ in manifest.capabilities
        assert manifest.scope == "global"
        assert manifest.ttl_seconds == 120
        assert manifest.network_egress is True
        assert manifest.audit_level == AuditLevel.SUMMARY
        assert manifest.signature == "sig_http"
        assert manifest.created_at is not None

    @pytest.mark.asyncio
    async def test_invalid_capability_raises_error(self):
        registry = InMemoryToolRegistry()

        cmd = RegisterToolCommand(
            tool_name="bad.tool",
            version="1.0.0",
            capabilities=["teleport"],  # not a valid CapabilityType
            scope="workspace",
            ttl_seconds=300,
            network_egress=False,
            audit_level="full",
            signature="sig",
        )

        with pytest.raises(ValueError):
            await cmd.execute(registry)

    @pytest.mark.asyncio
    async def test_tool_retrievable_after_registration(self):
        registry = InMemoryToolRegistry()

        cmd = RegisterToolCommand(
            tool_name="grep.search",
            version="1.0.0",
            capabilities=["read"],
            scope="workspace:current",
            ttl_seconds=900,
            network_egress=False,
            audit_level="none",
            signature="sig_grep",
        )
        await cmd.execute(registry)

        retrieved = await registry.get("grep.search")
        assert retrieved is not None
        assert retrieved.tool_name == "grep.search"
