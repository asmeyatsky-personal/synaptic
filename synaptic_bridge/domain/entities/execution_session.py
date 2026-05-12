"""
Layer: domain
Ports: none
MCP integration: consumed by application use cases; not exposed directly.
Stack: canonical (Python).

Execution Session aggregate. Short-lived agent session with execution token.
Immutable per Architectural Rules §3.3.
"""

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import Enum

from ..events import DomainEvent, SessionEndedEvent


class SessionStatus(Enum):
    INITIATED = "initiated"
    ACTIVE = "active"
    EXPIRED = "expired"
    TERMINATED = "terminated"


def _to_datetime(value: datetime | int | float) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), UTC)
    raise TypeError(f"Unsupported datetime value: {type(value).__name__}")


@dataclass(frozen=True)
class ExecutionSession:
    session_id: str
    agent_id: str
    execution_token: str
    status: SessionStatus
    started_at: datetime
    expires_at: datetime
    tool_calls: tuple[str, ...]
    created_by: str
    domain_events: tuple[DomainEvent, ...] = field(default=())

    def __post_init__(self) -> None:
        expires = _to_datetime(self.expires_at)
        started = _to_datetime(self.started_at)
        if expires <= started:
            raise ValueError("Expiration must be after start")

    def is_expired(self) -> bool:
        return datetime.now(UTC) >= _to_datetime(self.expires_at)

    def is_active(self) -> bool:
        return self.status == SessionStatus.ACTIVE and not self.is_expired()

    def add_tool_call(self, tool_call_id: str) -> "ExecutionSession":
        return replace(self, tool_calls=self.tool_calls + (tool_call_id,))

    def terminate(self) -> "ExecutionSession":
        return replace(
            self,
            status=SessionStatus.TERMINATED,
            domain_events=self.domain_events
            + (
                SessionEndedEvent(
                    aggregate_id=self.session_id,
                    occurred_at=datetime.now(UTC),
                    agent_id=self.agent_id,
                    reason="terminated_by_user",
                ),
            ),
        )

    def expire(self) -> "ExecutionSession":
        return replace(
            self,
            status=SessionStatus.EXPIRED,
            domain_events=self.domain_events
            + (
                SessionEndedEvent(
                    aggregate_id=self.session_id,
                    occurred_at=datetime.now(UTC),
                    agent_id=self.agent_id,
                    reason="token_expired",
                ),
            ),
        )
