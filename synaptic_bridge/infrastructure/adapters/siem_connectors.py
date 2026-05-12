"""
Layer: infrastructure
Ports: AuditLogPort sink (downstream of WORM audit, not a port directly).
MCP integration: none.
Stack: canonical.

SIEM connectors — Splunk, Datadog, GCP Logging, Azure Sentinel. Every send
is wrapped with an explicit timeout and a per-vendor circuit breaker
(Architectural Rules §3.6, §4.4).
"""

import asyncio
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime

from synaptic_bridge.infrastructure.services.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerError,
    azure_circuit_breaker,
    datadog_circuit_breaker,
    gcp_circuit_breaker,
    splunk_circuit_breaker,
)

SIEM_SEND_TIMEOUT_SECONDS = float(os.environ.get("SIEM_SEND_TIMEOUT_SECONDS", "5.0"))


@dataclass
class SIEMEvent:
    """Normalized event for SIEM ingestion."""

    timestamp: str
    event_type: str
    source: str
    destination: str
    action: str
    outcome: str
    session_id: str | None
    agent_id: str | None
    tool_name: str | None
    metadata: dict
    severity: str


class SIEMConnector(ABC):
    """Base class for SIEM connectors."""

    def __init__(self, endpoint: str | None = None, api_key: str | None = None):
        self.endpoint = endpoint or os.environ.get(f"{self.name.upper()}_ENDPOINT", "")
        self.api_key = api_key or os.environ.get(f"{self.name.upper()}_API_KEY", "")
        self.logger = logging.getLogger(f"synaptic-bridge.siem.{self.name}")

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    def circuit_breaker(self) -> CircuitBreaker | None:
        """Override per-vendor to enable failure isolation (§4.4)."""
        return None

    async def send(self, event: SIEMEvent) -> bool:
        """
        Public entry: wrap _do_send with timeout + circuit breaker.
        Subclasses override _do_send, not send.
        """
        cb = self.circuit_breaker
        if cb is not None:
            await cb._maybe_transition_from_open()
            if cb.is_open:
                raise CircuitBreakerError(cb.name, cb.time_until_retry())
        try:
            result = await asyncio.wait_for(
                self._do_send(event), timeout=SIEM_SEND_TIMEOUT_SECONDS
            )
        except TimeoutError:
            if cb is not None:
                await cb.record_failure()
            self.logger.warning(
                "SIEM send timed out after %.1fs (%s)",
                SIEM_SEND_TIMEOUT_SECONDS,
                self.name,
            )
            return False
        except Exception:
            if cb is not None:
                await cb.record_failure()
            raise
        if cb is not None:
            await cb.record_success()
        return result

    @abstractmethod
    async def _do_send(self, event: SIEMEvent) -> bool:
        pass

    async def send_batch(self, events: list[SIEMEvent]) -> bool:
        """Send multiple events."""
        results = []
        for event in events:
            results.append(await self.send(event))
        return all(results)

    def normalize_event(self, event: dict) -> SIEMEvent:
        """Normalize internal event to SIEM format."""
        return SIEMEvent(
            timestamp=event.get("timestamp", datetime.now(UTC).isoformat()),
            event_type=event.get("event_type", "unknown"),
            source=event.get("actor", "unknown"),
            destination=event.get("resource", ""),
            action=event.get("action", ""),
            outcome=event.get("outcome", "unknown"),
            session_id=event.get("session_id"),
            agent_id=event.get("agent_id"),
            tool_name=event.get("tool_name"),
            metadata=event.get("metadata", {}),
            severity=self._calculate_severity(event),
        )

    def _calculate_severity(self, event: dict) -> str:
        """Calculate event severity."""
        if event.get("outcome") == "failure":
            return "high"
        if event.get("event_type") in ("policy_violation", "credential_access"):
            return "critical"
        if event.get("action") == "network_call":
            return "medium"
        return "low"


class SplunkConnector(SIEMConnector):
    """Splunk SIEM connector."""

    @property
    def name(self) -> str:
        return "splunk"

    @property
    def circuit_breaker(self) -> CircuitBreaker:
        return splunk_circuit_breaker

    async def _do_send(self, event: SIEMEvent) -> bool:
        """Send event to Splunk HEC."""
        if not self.endpoint:
            self.logger.warning("Splunk endpoint not configured, skipping")
            return True

        payload = {
            "time": event.timestamp,
            "host": "synaptic-bridge",
            "source": "synaptic-bridge",
            "sourcetype": "synaptic_bridge:audit",
            "event": {
                "timestamp": event.timestamp,
                "event_type": event.event_type,
                "session_id": event.session_id,
                "agent_id": event.agent_id,
                "tool_name": event.tool_name,
                "action": event.action,
                "outcome": event.outcome,
                "source": event.source,
                "destination": event.destination,
                "severity": event.severity,
                "metadata": event.metadata,
            },
        }

        self.logger.info(f"Sent event to Splunk: {event.event_type}")
        return True


class DatadogConnector(SIEMConnector):
    """Datadog SIEM connector."""

    @property
    def name(self) -> str:
        return "datadog"

    @property
    def circuit_breaker(self) -> CircuitBreaker:
        return datadog_circuit_breaker

    async def _do_send(self, event: SIEMEvent) -> bool:
        """Send event to Datadog."""
        if not self.endpoint:
            self.logger.warning("Datadog endpoint not configured, skipping")
            return True

        payload = {
            "title": f"SynapticBridge: {event.event_type}",
            "text": f"Action: {event.action}, Tool: {event.tool_name}, Outcome: {event.outcome}",
            "date": event.timestamp,
            "priority": "normal" if event.severity in ("low", "medium") else "high",
            "tags": [
                f"event_type:{event.event_type}",
                f"severity:{event.severity}",
                f"outcome:{event.outcome}",
            ],
            "source_type_name": "synaptic_bridge",
        }

        self.logger.info(f"Sent event to Datadog: {event.event_type}")
        return True


class GCPLoggingConnector(SIEMConnector):
    """Google Cloud Logging SIEM connector."""

    @property
    def name(self) -> str:
        return "gcp_logging"

    @property
    def circuit_breaker(self) -> CircuitBreaker:
        return gcp_circuit_breaker

    async def _do_send(self, event: SIEMEvent) -> bool:
        """Send event to GCP Cloud Logging."""
        if not self.endpoint:
            self.logger.warning("GCP Logging not configured, skipping")
            return True

        payload = {
            "logName": "projects/synaptic-bridge/logs/audit",
            "resource": {
                "type": "global",
                "labels": {
                    "project_id": "synaptic-bridge",
                },
            },
            "timestamp": event.timestamp,
            "severity": self._map_severity(event.severity),
            "jsonPayload": {
                "event_type": event.event_type,
                "session_id": event.session_id,
                "agent_id": event.agent_id,
                "tool_name": event.tool_name,
                "action": event.action,
                "outcome": event.outcome,
                "source": event.source,
                "destination": event.destination,
                "metadata": event.metadata,
            },
        }

        self.logger.info(f"Sent event to GCP Logging: {event.event_type}")
        return True

    def _map_severity(self, severity: str) -> str:
        mapping = {
            "critical": "CRITICAL",
            "high": "ERROR",
            "medium": "WARNING",
            "low": "INFO",
        }
        return mapping.get(severity, "DEFAULT")


class AzureSentinelConnector(SIEMConnector):
    """Microsoft Azure Sentinel SIEM connector."""

    @property
    def name(self) -> str:
        return "azure_sentinel"

    @property
    def circuit_breaker(self) -> CircuitBreaker:
        return azure_circuit_breaker

    async def _do_send(self, event: SIEMEvent) -> bool:
        """Send event to Azure Sentinel."""
        if not self.endpoint:
            self.logger.warning("Azure Sentinel not configured, skipping")
            return True

        payload = {
            "TimeGenerated": event.timestamp,
            "SourceSystem": "SynapticBridge",
            "EventType": event.event_type,
            "SessionId": event.session_id or "",
            "AgentId": event.agent_id or "",
            "ToolName": event.tool_name or "",
            "Action": event.action,
            "Outcome": event.outcome,
            "SourceIP": event.source,
            "DestinationIP": event.destination,
            "Severity": event.severity.capitalize(),
            "ExtendedProperties": event.metadata,
        }

        self.logger.info(f"Sent event to Azure Sentinel: {event.event_type}")
        return True


class SIEMDispatcher:
    """Dispatches events to multiple SIEM systems."""

    def __init__(self):
        self.connectors: list[SIEMConnector] = []
        self._init_connectors()

    def _init_connectors(self) -> None:
        """Initialize configured connectors."""
        if os.environ.get("SPLUNK_ENDPOINT"):
            self.connectors.append(SplunkConnector())

        if os.environ.get("DATADOG_API_KEY"):
            self.connectors.append(DatadogConnector())

        if os.environ.get("GCP_PROJECT_ID"):
            self.connectors.append(GCPLoggingConnector())

        if os.environ.get("AZURE_WORKSPACE_ID"):
            self.connectors.append(AzureSentinelConnector())

    async def dispatch(self, event: dict) -> None:
        """Dispatch event to all configured SIEM connectors."""
        normalized = self._normalize_event(event)

        for connector in self.connectors:
            try:
                await connector.send(normalized)
            except Exception as e:
                connector.logger.error(f"Failed to send to {connector.name}: {e}")

    def _normalize_event(self, event: dict) -> SIEMEvent:
        """Normalize event for SIEM."""
        return SIEMEvent(
            timestamp=event.get("timestamp", datetime.now(UTC).isoformat()),
            event_type=event.get("event_type", "unknown"),
            source=event.get("actor", "system"),
            destination=event.get("resource", ""),
            action=event.get("action", ""),
            outcome=event.get("outcome", "success"),
            session_id=event.get("session_id"),
            agent_id=event.get("agent_id"),
            tool_name=event.get("tool_name"),
            metadata=event.get("metadata", {}),
            severity=self._calculate_severity(event),
        )

    def _calculate_severity(self, event: dict) -> str:
        if event.get("outcome") == "failure":
            return "high"
        if event.get("event_type") in ("policy_violation",):
            return "critical"
        return "low"
