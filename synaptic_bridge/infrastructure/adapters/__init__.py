"""
Infrastructure Adapters

Following skill2026.md Rule 2 - Interface-First Development.
Adapters implement ports defined in domain layer.
"""

import os
import uuid
import hashlib
import jwt
from dataclasses import replace
from datetime import datetime, UTC
from typing import Any

from synaptic_bridge.domain.constants import (
    DEFAULT_TTL_SECONDS,
    EMBEDDING_DIM,
)
from synaptic_bridge.domain.exceptions import ConfigurationError
from synaptic_bridge.domain.entities import (
    ExecutionSession,
    SessionStatus,
    ToolManifest,
    Correction,
    CorrectionPattern,
    Policy,
    AuditEvent,
)


def _get_jwt_secret() -> str:
    """Get JWT secret, failing fast if not configured outside tests."""
    secret = os.environ.get("JWT_SECRET", "")
    if not secret and os.environ.get("TESTING") != "1":
        raise ConfigurationError(
            "JWT_SECRET environment variable is required."
        )
    return secret


class InMemoryExecutionAdapter:
    """In-memory implementation of ExecutionPort."""

    def __init__(self):
        self._sessions: dict[str, ExecutionSession] = {}

    async def create_session(self, agent_id: str, created_by: str) -> ExecutionSession:
        session_id = f"session_{uuid.uuid4().hex[:12]}"
        secret = _get_jwt_secret()
        token = jwt.encode(
            {"session_id": session_id, "agent_id": agent_id},
            secret,
            algorithm="HS256",
        )

        session = ExecutionSession(
            session_id=session_id,
            agent_id=agent_id,
            execution_token=token,
            status=SessionStatus.ACTIVE,
            started_at=datetime.now(UTC),
            expires_at=datetime.now(UTC).timestamp() + DEFAULT_TTL_SECONDS,
            tool_calls=(),
            created_by=created_by,
        )

        self._sessions[session_id] = session
        return session

    async def get_session(self, session_id: str) -> ExecutionSession | None:
        session = self._sessions.get(session_id)
        if session and session.is_expired():
            expired = session.expire()
            self._sessions[session_id] = expired
            return expired
        return session

    async def validate_token(self, token: str) -> bool:
        try:
            secret = _get_jwt_secret()
            payload = jwt.decode(token, secret, algorithms=["HS256"])
            session = await self.get_session(payload["session_id"])
            return session is not None and session.is_active()
        except jwt.InvalidTokenError:
            return False

    async def execute_tool(
        self, session: ExecutionSession, tool_name: str, parameters: dict
    ) -> dict:
        return {
            "success": True,
            "tool": tool_name,
            "result": f"Executed {tool_name} with params {parameters}",
            "execution_time_ms": 10.5,
        }


class InMemoryToolRegistry:
    """In-memory implementation of ToolRegistryPort."""

    def __init__(self):
        self._tools: dict[str, ToolManifest] = {}

    async def register(self, manifest: ToolManifest) -> None:
        self._tools[manifest.tool_name] = manifest

    async def get(self, tool_name: str) -> ToolManifest | None:
        return self._tools.get(tool_name)

    async def list_all(self) -> list[ToolManifest]:
        return list(self._tools.values())

    async def validate_signature(self, manifest: ToolManifest) -> bool:
        return True


class InMemoryCorrectionStore:
    """In-memory implementation of CorrectionStorePort."""

    def __init__(self):
        self._corrections: dict[str, Correction] = {}
        self._patterns: dict[str, CorrectionPattern] = {}

    async def save_correction(
        self, correction: Correction, *, intent_embedding: tuple[float, ...] | None = None
    ) -> None:
        self._corrections[correction.correction_id] = correction

        vector = intent_embedding if intent_embedding is not None else tuple([0.0] * EMBEDDING_DIM)

        pattern_key = tuple(sorted([correction.corrected_tool]))

        if pattern_key in self._patterns:
            existing = self._patterns[pattern_key]
            updated = existing.with_increment(
                correction.confidence_after - correction.confidence_before
            )
            if intent_embedding is not None:
                updated = replace(updated, intent_vector=intent_embedding)
            self._patterns[pattern_key] = updated
        else:
            self._patterns[pattern_key] = CorrectionPattern(
                pattern_id=f"pattern_{uuid.uuid4().hex[:8]}",
                intent_vector=vector,
                original_tools=(correction.original_tool,),
                corrected_tools=(correction.corrected_tool,),
                occurrence_count=1,
                avg_confidence_improvement=correction.confidence_after
                - correction.confidence_before,
                last_updated=datetime.now(UTC),
            )

    async def get_correction(self, correction_id: str) -> Correction | None:
        return self._corrections.get(correction_id)

    async def find_patterns(
        self, intent_vector: tuple[float, ...]
    ) -> list[CorrectionPattern]:
        return list(self._patterns.values())


class InMemoryPolicyEngine:
    """In-memory implementation of PolicyEnginePort."""

    def __init__(self):
        self._policies: dict[str, Policy] = {}

    async def evaluate(self, policy: Policy, context: dict) -> bool:
        if policy.effect.value == "deny":
            return False
        return True

    async def add_policy(self, policy: Policy) -> None:
        self._policies[policy.policy_id] = policy

    async def remove_policy(self, policy_id: str) -> None:
        self._policies.pop(policy_id, None)

    async def list_policies(self) -> list[Policy]:
        return [p for p in self._policies.values() if p.enabled]


class InMemoryAuditLog:
    """In-memory implementation of AuditLogPort."""

    def __init__(self):
        self._events: list[AuditEvent] = []

    async def write(self, event: Any) -> None:
        if event is None:
            return

        if hasattr(event, "to_dict"):
            event_dict = event.to_dict()
        else:
            event_dict = {"event": str(event)}

        audit_event = AuditEvent(
            event_id=f"audit_{uuid.uuid4().hex[:12]}",
            event_type=event.__class__.__name__,
            session_id=getattr(event, "session_id", None),
            agent_id=getattr(event, "agent_id", None),
            tool_name=getattr(event, "tool_name", None),
            action="create",
            actor="system",
            resource="",
            outcome="success",
            metadata=event_dict,
            timestamp=datetime.now(UTC),
            signature=self._sign_event(event_dict),
        )

        self._events.append(audit_event)

    async def query(self, filters: dict) -> list[AuditEvent]:
        results = self._events

        for key, value in filters.items():
            results = [e for e in results if getattr(e, key, None) == value]

        return results

    async def get_by_session(self, session_id: str) -> list[AuditEvent]:
        return await self.query({"session_id": session_id})

    async def verify_integrity(self, event_id: str) -> bool:
        for event in self._events:
            if event.event_id == event_id:
                expected_sig = self._sign_event(event.to_dict())
                return event.signature == expected_sig
        return False

    def _sign_event(self, event_dict: dict) -> str:
        data = str(sorted(event_dict.items()))
        return hashlib.sha256(data.encode()).hexdigest()[:16]


class MockIntentClassifier:
    """Mock implementation of IntentClassifierPort."""

    async def classify_intent(self, intent_text: str) -> tuple[str, float]:
        tool_keywords = {
            "read": "filesystem.read",
            "write": "filesystem.write",
            "execute": "bash.execute",
            "search": "search.execute",
            "http": "http.request",
        }

        for keyword, tool in tool_keywords.items():
            if keyword in intent_text.lower():
                return tool, 0.85

        return "unknown", 0.0

    async def get_embedding(self, text: str) -> tuple[float, ...]:
        import random

        random.seed(hash(text) % (2**32))
        return tuple(random.random() for _ in range(EMBEDDING_DIM))

    async def match_tool(self, embedding: tuple[float, ...]) -> tuple[str, float]:
        return "filesystem.read", 0.85
