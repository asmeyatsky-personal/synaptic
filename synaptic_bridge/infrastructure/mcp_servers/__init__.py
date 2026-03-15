"""
MCP Servers

Following skill2026.md Pattern 1 - Bounded Context as MCP Server.
Each bounded context exposed as MCP server with:
- Tools = write operations (commands)
- Resources = read operations (queries)
- Prompts = reusable interaction patterns
"""

import uuid
from typing import Any

from synaptic_bridge.application.commands import (
    CreateSessionCommand,
    ExecuteToolCommand,
    CaptureCorrectionCommand,
    AddPolicyCommand,
    RegisterToolCommand,
)
from synaptic_bridge.application.queries import (
    GetSessionQuery,
    ListToolsQuery,
    GetToolQuery,
    ListPoliciesQuery,
    QueryAuditLogQuery,
)


class SessionMCPServer:
    """
    MCP server for Execution Fabric bounded context.

    Tools:
    - create_session: Create a new agent execution session
    - execute_tool: Execute a tool with policy checks
    - get_session: Get session details

    Resources:
    - session://{id}: Get session by ID
    """

    def __init__(self, container: Any):
        self._container = container

    async def create_session(self, agent_id: str, created_by: str) -> dict:
        """Create a new agent execution session with JWT token."""
        command = CreateSessionCommand(agent_id=agent_id, created_by=created_by)

        execution_port = self._container.resolve("execution_port")
        audit_log = self._container.resolve("audit_log")

        session = await command.execute(execution_port, audit_log)

        return {
            "session_id": session.session_id,
            "execution_token": session.execution_token,
            "status": session.status.value,
            "expires_at": session.expires_at.isoformat()
            if hasattr(session.expires_at, "isoformat")
            else str(session.expires_at),
        }

    async def execute_tool(
        self, session_id: str, tool_name: str, parameters: dict, intent: str
    ) -> dict:
        """Execute a tool with policy checks and CLE."""
        command = ExecuteToolCommand(
            session_id=session_id,
            tool_name=tool_name,
            parameters=parameters,
            intent=intent,
        )

        execution_port = self._container.resolve("execution_port")
        tool_registry = self._container.resolve("tool_registry")
        policy_engine = self._container.resolve("policy_engine")
        audit_log = self._container.resolve("audit_log")

        intent_classifier = None
        correction_store = None
        try:
            intent_classifier = self._container.resolve("intent_classifier")
            correction_store = self._container.resolve("correction_store")
        except Exception:
            pass

        result = await command.execute(
            execution_port,
            tool_registry,
            policy_engine,
            audit_log,
            intent_classifier=intent_classifier,
            correction_store=correction_store,
        )

        return result

    async def get_session(self, session_id: str) -> dict | None:
        """Get session by ID (resource handler)."""
        query = GetSessionQuery(session_id=session_id)
        execution_port = self._container.resolve("execution_port")

        session = await query.execute(execution_port)

        if session:
            return {
                "session_id": session.session_id,
                "agent_id": session.agent_id,
                "status": session.status.value,
                "is_active": session.is_active(),
            }
        return None


class ToolMCPServer:
    """
    MCP server for Tool Management bounded context.

    Tools:
    - register_tool: Register a new tool manifest
    - list_tools: List all registered tools

    Resources:
    - tool://{name}: Get tool by name
    - tools://: List all tools
    """

    def __init__(self, container: Any):
        self._container = container

    async def register_tool(
        self,
        tool_name: str,
        version: str,
        capabilities: list[str],
        scope: str,
        ttl_seconds: int,
        network_egress: bool,
        audit_level: str,
        signature: str,
    ) -> dict:
        """Register a new tool manifest."""
        command = RegisterToolCommand(
            tool_name=tool_name,
            version=version,
            capabilities=capabilities,
            scope=scope,
            ttl_seconds=ttl_seconds,
            network_egress=network_egress,
            audit_level=audit_level,
            signature=signature,
        )

        tool_registry = self._container.resolve("tool_registry")

        manifest = await command.execute(tool_registry)

        return {
            "tool_name": manifest.tool_name,
            "version": manifest.version,
            "status": "registered",
        }

    async def list_tools(self) -> list[dict]:
        """List all registered tools."""
        query = ListToolsQuery()
        tool_registry = self._container.resolve("tool_registry")

        tools = await query.execute(tool_registry)

        return [
            {
                "tool_name": t.tool_name,
                "version": t.version,
                "capabilities": [c.value for c in t.capabilities],
                "scope": t.scope,
            }
            for t in tools
        ]


class CLEMPServer:
    """
    MCP server for Correction Learning Engine bounded context.

    Tools:
    - capture_correction: Capture a human override/correction
    - find_patterns: Find matching correction patterns

    Resources:
    - corrections://session/{session_id}: Get corrections for session
    - patterns://: List all correction patterns
    """

    def __init__(self, container: Any):
        self._container = container

    async def capture_correction(
        self,
        session_id: str,
        agent_id: str,
        original_intent: str,
        inferred_context: str,
        original_tool: str,
        corrected_tool: str,
        correction_metadata: dict,
        operator_identity: str,
        confidence_before: float,
        confidence_after: float,
    ) -> dict:
        """Capture a human override/correction."""
        command = CaptureCorrectionCommand(
            session_id=session_id,
            agent_id=agent_id,
            original_intent=original_intent,
            inferred_context=inferred_context,
            original_tool=original_tool,
            corrected_tool=corrected_tool,
            correction_metadata=correction_metadata,
            operator_identity=operator_identity,
            confidence_before=confidence_before,
            confidence_after=confidence_after,
        )

        correction_store = self._container.resolve("correction_store")

        intent_classifier = None
        try:
            intent_classifier = self._container.resolve("intent_classifier")
        except Exception:
            pass

        correction = await command.execute(correction_store, intent_classifier=intent_classifier)

        return {
            "correction_id": correction.correction_id,
            "captured_at": correction.captured_at.isoformat(),
            "trust_score": correction.trust_score(),
        }


class PolicyMCPServer:
    """
    MCP server for Policy & Governance bounded context.

    Tools:
    - add_policy: Add a new OPA policy
    - list_policies: List all policies

    Resources:
    - policy://{id}: Get policy by ID
    - policies://: List all policies
    """

    def __init__(self, container: Any):
        self._container = container

    async def add_policy(
        self,
        name: str,
        description: str,
        rego_code: str,
        effect: str,
        scope: str,
        tags: list[str],
    ) -> dict:
        """Add a new OPA policy."""
        from synaptic_bridge.domain.entities import PolicyEffect, PolicyScope

        command = AddPolicyCommand(
            name=name,
            description=description,
            rego_code=rego_code,
            effect=PolicyEffect(effect),
            scope=PolicyScope(scope),
            tags=tags,
        )

        policy_engine = self._container.resolve("policy_engine")

        policy = await command.execute(policy_engine)

        return {
            "policy_id": policy.policy_id,
            "name": policy.name,
            "enabled": policy.enabled,
        }

    async def list_policies(self) -> list[dict]:
        """List all policies."""
        query = ListPoliciesQuery()
        policy_engine = self._container.resolve("policy_engine")

        policies = await query.execute(policy_engine)

        return [
            {
                "policy_id": p.policy_id,
                "name": p.name,
                "effect": p.effect.value,
                "scope": p.scope.value,
                "enabled": p.enabled,
            }
            for p in policies
        ]
