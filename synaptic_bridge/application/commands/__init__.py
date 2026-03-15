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
    IntentClassifierPort,
)
from synaptic_bridge.domain.constants import (
    DEFAULT_TTL_SECONDS,
    CLE_CONFIDENCE_THRESHOLD,
    CLE_SHADOW_MODE,
)
from synaptic_bridge.domain.exceptions import (
    SessionNotFoundError,
    SessionExpiredError,
    ToolNotFoundError,
    PolicyViolationError,
)


@dataclass
class CreateSessionCommand:
    agent_id: str
    created_by: str
    ttl_seconds: int = DEFAULT_TTL_SECONDS

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
        intent_classifier: IntentClassifierPort | None = None,
        correction_store: CorrectionStorePort | None = None,
        shadow_mode: bool | None = None,
    ) -> Any:
        if shadow_mode is None:
            shadow_mode = CLE_SHADOW_MODE

        session = await execution_port.get_session(self.session_id)
        if not session:
            raise SessionNotFoundError(f"Session {self.session_id} not found")

        if not session.is_active():
            raise SessionExpiredError("Session is not active")

        manifest = await tool_registry.get(self.tool_name)
        if not manifest:
            raise ToolNotFoundError(f"Tool {self.tool_name} not found")

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
                    from synaptic_bridge.domain.events import PolicyViolationEvent

                    violation_event = PolicyViolationEvent(
                        aggregate_id=f"viol_{uuid.uuid4().hex[:8]}",
                        session_id=self.session_id,
                        agent_id=session.agent_id,
                        policy_id=policy.policy_id,
                        tool_name=self.tool_name,
                        reason=f"Policy {policy.name} denied execution",
                    )
                    await audit_log.write(violation_event)
                    raise PolicyViolationError(
                        policy.policy_id,
                        f"Policy {policy.name} denied execution",
                    )

        # CLE consultation: check learned patterns for a better tool
        was_corrected = False
        correction_confidence = 0.0
        effective_tool = self.tool_name

        if intent_classifier is not None and correction_store is not None:
            try:
                embedding = await intent_classifier.get_embedding(self.intent)
                patterns = await correction_store.find_patterns(embedding)

                best_pattern = None
                best_similarity = 0.0
                for pattern in patterns:
                    similarity = pattern.matches_intent(embedding)
                    if similarity > best_similarity:
                        best_similarity = similarity
                        best_pattern = pattern

                if best_pattern is not None and best_similarity >= CLE_CONFIDENCE_THRESHOLD:
                    suggested_tool = best_pattern.corrected_tools[0]

                    if shadow_mode:
                        # Shadow mode: log but don't redirect
                        from synaptic_bridge.domain.events import CLEInterceptionEvent

                        cle_event = CLEInterceptionEvent(
                            aggregate_id=f"cle_{uuid.uuid4().hex[:8]}",
                            original_tool=self.tool_name,
                            suggested_tool=suggested_tool,
                            confidence=best_similarity,
                            pattern_id=best_pattern.pattern_id,
                            shadow_mode=True,
                            applied=False,
                        )
                        await audit_log.write(cle_event)
                    else:
                        # Active mode: verify corrected tool exists, then redirect
                        corrected_manifest = await tool_registry.get(suggested_tool)
                        if corrected_manifest is not None:
                            effective_tool = suggested_tool
                            was_corrected = True
                            correction_confidence = best_similarity

                            from synaptic_bridge.domain.events import CLEInterceptionEvent

                            cle_event = CLEInterceptionEvent(
                                aggregate_id=f"cle_{uuid.uuid4().hex[:8]}",
                                original_tool=self.tool_name,
                                suggested_tool=suggested_tool,
                                confidence=best_similarity,
                                pattern_id=best_pattern.pattern_id,
                                shadow_mode=False,
                                applied=True,
                            )
                            await audit_log.write(cle_event)
                        else:
                            # Corrected tool not in registry, fall back to original
                            from synaptic_bridge.domain.events import CLEInterceptionEvent

                            cle_event = CLEInterceptionEvent(
                                aggregate_id=f"cle_{uuid.uuid4().hex[:8]}",
                                original_tool=self.tool_name,
                                suggested_tool=suggested_tool,
                                confidence=best_similarity,
                                pattern_id=best_pattern.pattern_id,
                                shadow_mode=False,
                                applied=False,
                            )
                            await audit_log.write(cle_event)
            except Exception:
                # CLE failure must never block execution
                pass

        result = await execution_port.execute_tool(
            session, effective_tool, self.parameters
        )

        from synaptic_bridge.domain.events import ToolCalledEvent

        tool_event = ToolCalledEvent(
            aggregate_id=f"call_{uuid.uuid4().hex[:12]}",
            session_id=self.session_id,
            agent_id=session.agent_id,
            tool_name=effective_tool,
            was_corrected=was_corrected,
            correction_confidence=correction_confidence,
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
        intent_classifier: IntentClassifierPort | None = None,
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

        intent_embedding: tuple[float, ...] | None = None
        if intent_classifier is not None and self.original_intent:
            intent_embedding = await intent_classifier.get_embedding(self.original_intent)

        await correction_store.save_correction(correction, intent_embedding=intent_embedding)

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
