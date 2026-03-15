"""
Tool Manifest Entity

Represents a tool's capability contract - the core of Secure Execution Fabric.
Following PRD: Tool manifests declare read/write/execute/network capabilities.

Immutable domain model following skill2026.md Rule 3.
"""

from dataclasses import dataclass, field, replace
from datetime import datetime, UTC
from typing import FrozenSet
from enum import Enum

from ...domain.events import DomainEvent


class CapabilityType(Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK = "network"


class AuditLevel(Enum):
    NONE = "none"
    SUMMARY = "summary"
    FULL = "full"


@dataclass(frozen=True)
class ToolManifest:
    tool_name: str
    version: str
    capabilities: FrozenSet[CapabilityType]
    scope: str
    ttl_seconds: int
    network_egress: bool
    audit_level: AuditLevel
    signature: str
    created_at: datetime
    domain_events: tuple[DomainEvent, ...] = field(default=())

    def __post_init__(self):
        if self.ttl_seconds <= 0:
            raise ValueError("TTL must be positive")
        if not self.tool_name:
            raise ValueError("Tool name is required")

    def has_capability(self, cap: CapabilityType) -> bool:
        return cap in self.capabilities

    def allows_network(self) -> bool:
        return self.network_egress

    def with_version(self, new_version: str) -> "ToolManifest":
        return replace(
            self,
            version=new_version,
        )

    def to_toml(self) -> str:
        caps = ", ".join(f'"{c.value}"' for c in self.capabilities)
        return f'''[{self.tool_name}]
capabilities = [{caps}]
scope = "{self.scope}"
ttl_seconds = {self.ttl_seconds}
network_egress = {str(self.network_egress).lower()}
audit_level = "{self.audit_level.value}"
signature = "{self.signature}"
'''
