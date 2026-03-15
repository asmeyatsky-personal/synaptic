"""
Domain Events

Following skill2026.md event-driven communication patterns.
"""

from dataclasses import dataclass, field, fields
from datetime import datetime, UTC
from typing import Any


@dataclass(frozen=True)
class DomainEvent:
    aggregate_id: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def event_type(self) -> str:
        return self.__class__.__name__

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for f in fields(self):
            val = getattr(self, f.name)
            if isinstance(val, datetime):
                val = val.isoformat()
            result[f.name] = val
        return result


@dataclass(frozen=True)
class ToolCalledEvent(DomainEvent):
    session_id: str = ""
    agent_id: str = ""
    tool_name: str = ""
    was_corrected: bool = False
    correction_confidence: float = 0.0


@dataclass(frozen=True)
class CorrectionCapturedEvent(DomainEvent):
    session_id: str = ""
    agent_id: str = ""
    original_tool: str = ""
    corrected_tool: str = ""
    operator_identity: str = ""


@dataclass(frozen=True)
class PolicyViolationEvent(DomainEvent):
    session_id: str = ""
    agent_id: str = ""
    policy_id: str = ""
    tool_name: str = ""
    reason: str = ""


@dataclass(frozen=True)
class SessionStartedEvent(DomainEvent):
    agent_id: str = ""
    execution_token: str = ""


@dataclass(frozen=True)
class SessionEndedEvent(DomainEvent):
    agent_id: str = ""
    reason: str = ""
    duration_seconds: float = 0.0


@dataclass(frozen=True)
class IntentClassifiedEvent(DomainEvent):
    session_id: str = ""
    agent_id: str = ""
    intent_text: str = ""
    matched_tool: str = ""
    confidence: float = 0.0


@dataclass(frozen=True)
class DriftDetectedEvent(DomainEvent):
    session_id: str = ""
    tool_name: str = ""
    expected_behavior: str = ""
    observed_behavior: str = ""
    drift_score: float = 0.0


@dataclass(frozen=True)
class CLEInterceptionEvent(DomainEvent):
    original_tool: str = ""
    suggested_tool: str = ""
    confidence: float = 0.0
    pattern_id: str = ""
    shadow_mode: bool = True
    applied: bool = False
