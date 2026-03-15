"""
WORM (Write Once Read Many) Audit Log Storage

Following PRD: Immutable, cryptographically signed audit events written to append-only log.
WORM storage option with GCS/S3 backend for enterprise.
"""

import os
import json
import hashlib
import hmac
import stat
import logging
from datetime import datetime, UTC
from typing import Any
from dataclasses import dataclass, asdict
from enum import Enum

from synaptic_bridge.domain.entities import AuditEvent
from synaptic_bridge.domain.exceptions import ConfigurationError, AuditIntegrityError

logger = logging.getLogger("synaptic-bridge.worm")


class WORMStorageBackend(Enum):
    LOCAL = "local"
    GCS = "gcs"
    S3 = "s3"


@dataclass
class WORMEvent:
    """Immutable WORM audit event with cryptographic signature."""

    event_id: str
    event_type: str
    session_id: str | None
    agent_id: str | None
    tool_name: str | None
    action: str
    actor: str
    resource: str
    outcome: str
    metadata: dict
    timestamp: str
    sequence_number: int
    previous_hash: str
    event_hash: str
    signature: str

    def to_dict(self) -> dict:
        return asdict(self)


class WORMAuditLog:
    """
    WORM (Write Once Read Many) compliant audit log.

    Following PRD: Cryptographic audit log with local append-only store.
    """

    def __init__(
        self,
        storage_path: str | None = None,
        backend: WORMStorageBackend = WORMStorageBackend.LOCAL,
        secret_key: str | None = None,
    ):
        self.storage_path = storage_path or os.environ.get(
            "WORM_STORAGE_PATH", "/var/lib/synaptic-bridge/audit"
        )
        self.backend = backend
        self.secret_key = secret_key or os.environ.get("WORM_SECRET_KEY", "")
        if not self.secret_key:
            raise ConfigurationError(
                "WORM_SECRET_KEY environment variable or secret_key parameter is required."
            )
        self._sequence = 0
        self._previous_hash = "0" * 64
        self._events: list[WORMEvent] = []

        os.makedirs(self.storage_path, mode=0o700, exist_ok=True)
        self._load_sequence()

    def _load_sequence(self) -> None:
        """Load the current sequence number from storage."""
        seq_file = os.path.join(self.storage_path, ".sequence")
        if os.path.exists(seq_file):
            with open(seq_file, "r") as f:
                self._sequence = int(f.read().strip())

        last_event_file = os.path.join(self.storage_path, ".last_hash")
        if os.path.exists(last_event_file):
            with open(last_event_file, "r") as f:
                self._previous_hash = f.read().strip()

    def _save_sequence(self) -> None:
        """Save the current sequence number."""
        seq_file = os.path.join(self.storage_path, ".sequence")
        with open(seq_file, "w") as f:
            f.write(str(self._sequence))
        os.chmod(seq_file, stat.S_IRUSR | stat.S_IWUSR)

    def _save_last_hash(self, hash_value: str) -> None:
        """Save the last event hash."""
        last_event_file = os.path.join(self.storage_path, ".last_hash")
        with open(last_event_file, "w") as f:
            f.write(hash_value)
        os.chmod(last_event_file, stat.S_IRUSR | stat.S_IWUSR)

    async def append(self, event: AuditEvent) -> WORMEvent:
        """Append an event to the WORM log."""
        self._sequence += 1

        event_data = {
            "event_id": event.event_id,
            "event_type": event.event_type,
            "session_id": event.session_id,
            "agent_id": event.agent_id,
            "tool_name": event.tool_name,
            "action": event.action,
            "actor": event.actor,
            "resource": event.resource,
            "outcome": event.outcome,
            "metadata": event.metadata,
            "timestamp": event.timestamp.isoformat()
            if hasattr(event.timestamp, "isoformat")
            else str(event.timestamp),
        }

        event_json = json.dumps(event_data, sort_keys=True)
        event_hash = hashlib.sha256(event_json.encode()).hexdigest()

        chain_data = f"{self._previous_hash}{event_json}"
        signature = hmac.new(
            self.secret_key.encode(), chain_data.encode(), hashlib.sha256
        ).hexdigest()

        worm_event = WORMEvent(
            event_id=event.event_id,
            event_type=event.event_type,
            session_id=event.session_id,
            agent_id=event.agent_id,
            tool_name=event.tool_name,
            action=event.action,
            actor=event.actor,
            resource=event.resource,
            outcome=event.outcome,
            metadata=event.metadata,
            timestamp=event.timestamp.isoformat()
            if hasattr(event.timestamp, "isoformat")
            else str(event.timestamp),
            sequence_number=self._sequence,
            previous_hash=self._previous_hash,
            event_hash=event_hash,
            signature=signature,
        )

        self._events.append(worm_event)

        await self._write_to_storage(worm_event)

        self._previous_hash = event_hash
        self._save_sequence()
        self._save_last_hash(event_hash)

        return worm_event

    async def _write_to_storage(self, event: WORMEvent) -> None:
        """Write event to storage backend."""
        if self.backend == WORMStorageBackend.LOCAL:
            await self._write_local(event)
        elif self.backend == WORMStorageBackend.GCS:
            await self._write_gcs(event)
        elif self.backend == WORMStorageBackend.S3:
            await self._write_s3(event)

    async def _write_local(self, event: WORMEvent) -> None:
        """Write to local filesystem with restricted permissions."""
        filename = f"{event.sequence_number:012d}_{event.event_id}.json"
        filepath = os.path.join(self.storage_path, filename)

        with open(filepath, "w") as f:
            json.dump(event.to_dict(), f, indent=2)

        # Make audit event read-only after writing
        os.chmod(filepath, stat.S_IRUSR)

    async def _write_gcs(self, event: WORMEvent) -> None:
        """Write to Google Cloud Storage (WORM)."""
        logger.warning("GCS backend not yet implemented, event stored in memory only")

    async def _write_s3(self, event: WORMEvent) -> None:
        """Write to AWS S3 (WORM with bucket policy)."""
        logger.warning("S3 backend not yet implemented, event stored in memory only")

    async def verify_integrity(self) -> dict:
        """Verify the integrity of the entire audit log."""
        results = {
            "valid": True,
            "events_checked": 0,
            "events_valid": 0,
            "first_failure": None,
        }

        for event in self._events:
            results["events_checked"] += 1

            if self._verify_event(event):
                results["events_valid"] += 1
            else:
                results["valid"] = False
                if not results["first_failure"]:
                    results["first_failure"] = event.sequence_number

        return results

    def _verify_event(self, event: WORMEvent) -> bool:
        """Verify a single event's integrity."""
        event_data = {
            "event_id": event.event_id,
            "event_type": event.event_type,
            "session_id": event.session_id,
            "agent_id": event.agent_id,
            "tool_name": event.tool_name,
            "action": event.action,
            "actor": event.actor,
            "resource": event.resource,
            "outcome": event.outcome,
            "metadata": event.metadata,
            "timestamp": event.timestamp,
        }

        event_json = json.dumps(event_data, sort_keys=True)
        computed_hash = hashlib.sha256(event_json.encode()).hexdigest()

        if computed_hash != event.event_hash:
            return False

        chain_data = f"{event.previous_hash}{event_json}"
        computed_sig = hmac.new(
            self.secret_key.encode(), chain_data.encode(), hashlib.sha256
        ).hexdigest()

        return computed_sig == event.signature

    async def get_events(
        self,
        session_id: str | None = None,
        agent_id: str | None = None,
        start_seq: int | None = None,
        end_seq: int | None = None,
    ) -> list[WORMEvent]:
        """Query events from the log."""
        results = self._events

        if session_id:
            results = [e for e in results if e.session_id == session_id]
        if agent_id:
            results = [e for e in results if e.agent_id == agent_id]
        if start_seq:
            results = [e for e in results if e.sequence_number >= start_seq]
        if end_seq:
            results = [e for e in results if e.sequence_number <= end_seq]

        return results
