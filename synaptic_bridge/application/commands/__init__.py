"""
Application Commands

Command handlers for SynapticBridge operations.
Following CQRS pattern.
"""

from dataclasses import dataclass
from datetime import datetime, UTC
from typing import Any
import uuid

from synaptic_bridge.domain.entities import (
    ExecutionSession,
    SessionStatus,
    ToolManifest,
    CapabilityType,
    AuditLevel,
    Correction,
    Policy,
    PolicyEffect,
    PolicyScope,
)
from synaptic_bridge.domain.ports import (
    ExecutionPort,
    ToolRegistryPort,
    CorrectionStorePort,
    PolicyEnginePort,
    AuditLogPort,
)


DEFAULT_TOKEN_TTL_SECONDS = 900


@dataclass
class CreateSessionCommand:
    agent_id: str
    created_by: str
    ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS

    async def execute(
        self,
        execution_port: ExecutionPort,
        audit_log: AuditLogPort,
    ) -> ExecutionSession:
        session = await execution_port.create_session(self.agent_id, self.created_by)

        await audit_log.write(
            session.domain_events[0] if session.domain_events else None
        )

        return session


@dataclass
class ExecuteToolCommand:
    session_id: str
    tool_name: str
    parameters: dict
    intent: str

    async def execute(
        self,
        execution_port: ExecutionPort,
        tool_registry: ToolRegistryPort,
        policy_engine: PolicyEnginePort,
        audit_log: AuditLogPort,
    ) -> Any:
        session = await execution_port.get_session(self.session_id)
        if not session:
            raise ValueError(f"Session {self.session_id} not found")

        if not session.is_active():
            raise ValueError("Session is not active")

        manifest = await tool_registry.get(self.tool_name)
        if not manifest:
            raise ValueError(f"Tool {self.tool_name} not found")

        policy_context = {
            "session_id": self.session_id,
            "agent_id": session.agent_id,
            "tool_name": self.tool_name,
            "parameters": self.parameters,
        }

        policies = await policy_engine.list_policies()
        for policy in policies:
            if policy.scope in (PolicyScope.TOOL, PolicyScope.SESSION):
                allowed = await policy_engine.evaluate(policy, policy_context)
                if not allowed:
                    from synaptic_bridge.domain.entities import PolicyViolationEvent

                    violation_event = PolicyViolationEvent(
                        aggregate_id=f"viol_{uuid.uuid4().hex[:8]}",
                        session_id=self.session_id,
                        agent_id=session.agent_id,
                        policy_id=policy.policy_id,
                        tool_name=self.tool_name,
                        reason=f"Policy {policy.name} denied execution",
                    )
                    await audit_log.write(violation_event)
                    raise PermissionError(f"Policy {policy.policy_id} denied execution")

        result = await execution_port.execute_tool(
            session, self.tool_name, self.parameters
        )

        from synaptic_bridge.domain.events import ToolCalledEvent

        tool_event = ToolCalledEvent(
            aggregate_id=f"call_{uuid.uuid4().hex[:12]}",
            session_id=self.session_id,
            agent_id=session.agent_id,
            tool_name=self.tool_name,
            was_corrected=False,
        )
        await audit_log.write(tool_event)

        return result


@dataclass
class CaptureCorrectionCommand:
    session_id: str
    agent_id: str
    original_intent: str
    inferred_context: str
    original_tool: str
    corrected_tool: str
    correction_metadata: dict
    operator_identity: str
    confidence_before: float
    confidence_after: float

    async def execute(
        self,
        correction_store: CorrectionStorePort,
    ) -> Correction:
        correction = Correction(
            correction_id=f"corr_{uuid.uuid4().hex[:12]}",
            session_id=self.session_id,
            agent_id=self.agent_id,
            original_intent=self.original_intent,
            inferred_context=self.inferred_context,
            original_tool=self.original_tool,
            corrected_tool=self.corrected_tool,
            correction_metadata=self.correction_metadata,
            operator_identity=self.operator_identity,
            confidence_before=self.confidence_before,
            confidence_after=self.confidence_after,
            captured_at=datetime.now(UTC),
        )

        await correction_store.save_correction(correction)

        return correction


@dataclass
class AddPolicyCommand:
    name: str
    description: str
    rego_code: str
    effect: PolicyEffect
    scope: PolicyScope
    tags: list[str]

    async def execute(
        self,
        policy_engine: PolicyEnginePort,
    ) -> Policy:
        policy = Policy(
            policy_id=f"policy_{uuid.uuid4().hex[:8]}",
            name=self.name,
            description=self.description,
            rego_code=self.rego_code,
            effect=self.effect,
            scope=self.scope,
            tags=frozenset(self.tags),
            version="1.0.0",
            enabled=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        await policy_engine.add_policy(policy)

        return policy


@dataclass
class RegisterToolCommand:
    tool_name: str
    version: str
    capabilities: list[str]
    scope: str
    ttl_seconds: int
    network_egress: bool
    audit_level: str
    signature: str

    async def execute(
        self,
        tool_registry: ToolRegistryPort,
    ) -> ToolManifest:
        caps = frozenset(CapabilityType(c) for c in self.capabilities)
        audit = AuditLevel(self.audit_level)

        manifest = ToolManifest(
            tool_name=self.tool_name,
            version=self.version,
            capabilities=caps,
            scope=self.scope,
            ttl_seconds=self.ttl_seconds,
            network_egress=self.network_egress,
            audit_level=audit,
            signature=self.signature,
            created_at=datetime.now(UTC),
        )

        await tool_registry.register(manifest)

        return manifest
