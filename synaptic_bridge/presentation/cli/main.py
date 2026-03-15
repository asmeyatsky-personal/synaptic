#!/usr/bin/env python3
"""
SynapticBridge CLI

Tool registration, policy management, log inspection CLI.
Following PRD: CLI tooling for tool registration, policy management, log inspection.
"""

import argparse
import asyncio
import json
import sys
from typing import Optional

from synaptic_bridge.infrastructure.config import create_container
from synaptic_bridge.infrastructure.adapters.opa_engine import BuiltInPolicies


class SynapticBridgeCLI:
    """SynapticBridge CLI for managing the platform."""

    def __init__(self):
        self.container = create_container()

    async def register_tool(
        self,
        name: str,
        version: str,
        capabilities: list[str],
        scope: str,
        ttl: int | None = None,
        network: bool = False,
        audit: str = "summary",
    ) -> dict:
        """Register a new tool manifest."""
        from synaptic_bridge.application.commands import RegisterToolCommand
        from synaptic_bridge.domain.constants import DEFAULT_TTL_SECONDS

        command = RegisterToolCommand(
            tool_name=name,
            version=version,
            capabilities=capabilities,
            scope=scope,
            ttl_seconds=ttl if ttl is not None else DEFAULT_TTL_SECONDS,
            network_egress=network,
            audit_level=audit,
            signature="",
        )

        tool_registry = self.container.resolve("tool_registry")
        result = await command.execute(tool_registry)

        return {
            "status": "registered",
            "tool": result.tool_name,
            "version": result.version,
        }

    async def list_tools(self) -> list[dict]:
        """List all registered tools."""
        tool_registry = self.container.resolve("tool_registry")
        tools = await tool_registry.list_all()

        return [
            {
                "name": t.tool_name,
                "version": t.version,
                "capabilities": [c.value for c in t.capabilities],
                "scope": t.scope,
            }
            for t in tools
        ]

    async def add_policy(
        self,
        name: str,
        description: str,
        rego_code: str,
        effect: str,
        scope: str,
        tags: list[str],
    ) -> dict:
        """Add a new policy."""
        from synaptic_bridge.application.commands import AddPolicyCommand
        from synaptic_bridge.domain.entities import PolicyEffect, PolicyScope

        command = AddPolicyCommand(
            name=name,
            description=description,
            rego_code=rego_code,
            effect=PolicyEffect(effect),
            scope=PolicyScope(scope),
            tags=tags,
        )

        policy_engine = self.container.resolve("policy_engine")
        result = await command.execute(policy_engine)

        return {"status": "added", "policy_id": result.policy_id, "name": result.name}

    async def list_policies(self) -> list[dict]:
        """List all policies."""
        policy_engine = self.container.resolve("policy_engine")
        policies = await policy_engine.list_policies()

        return [
            {
                "id": p.policy_id,
                "name": p.name,
                "effect": p.effect.value,
                "scope": p.scope.value,
                "enabled": p.enabled,
            }
            for p in policies
        ]

    async def create_session(self, agent_id: str, created_by: str) -> dict:
        """Create a new execution session."""
        from synaptic_bridge.application.commands import CreateSessionCommand

        command = CreateSessionCommand(
            agent_id=agent_id,
            created_by=created_by,
        )

        execution_port = self.container.resolve("execution_port")
        audit_log = self.container.resolve("audit_log")

        session = await command.execute(execution_port, audit_log)

        return {
            "session_id": session.session_id,
            "token": session.execution_token,
            "expires_at": str(session.expires_at),
        }

    async def query_logs(
        self,
        session_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Query audit logs."""
        audit_log = self.container.resolve("audit_log")

        filters = {}
        if session_id:
            filters["session_id"] = session_id
        if event_type:
            filters["event_type"] = event_type

        events = await audit_log.query(filters)

        return [
            {
                "event_id": e.event_id,
                "event_type": e.event_type,
                "session_id": e.session_id,
                "agent_id": e.agent_id,
                "tool_name": e.tool_name,
                "action": e.action,
                "outcome": e.outcome,
                "timestamp": str(e.timestamp),
            }
            for e in events[:limit]
        ]

    async def capture_correction(
        self,
        session_id: str,
        agent_id: str,
        original_intent: str,
        original_tool: str,
        corrected_tool: str,
        operator: str,
        confidence_before: float,
        confidence_after: float,
    ) -> dict:
        """Capture a human correction."""
        from synaptic_bridge.application.commands import CaptureCorrectionCommand

        command = CaptureCorrectionCommand(
            session_id=session_id,
            agent_id=agent_id,
            original_intent=original_intent,
            inferred_context="",
            original_tool=original_tool,
            corrected_tool=corrected_tool,
            correction_metadata={},
            operator_identity=operator,
            confidence_before=confidence_before,
            confidence_after=confidence_after,
        )

        correction_store = self.container.resolve("correction_store")
        result = await command.execute(correction_store)

        return {
            "correction_id": result.correction_id,
            "trust_score": result.trust_score(),
        }

    async def get_stats(self) -> dict:
        """Get system statistics."""
        correction_store = self.container.resolve("correction_store")

        stats = {
            "correction_patterns": 0,
            "total_corrections": 0,
        }

        if hasattr(correction_store, "get_pattern_stats"):
            stats = await correction_store.get_pattern_stats()

        return stats


async def main():
    parser = argparse.ArgumentParser(
        description="SynapticBridge CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    tool_parser = subparsers.add_parser("register-tool", help="Register a tool")
    tool_parser.add_argument("--name", required=True, help="Tool name")
    tool_parser.add_argument("--version", required=True, help="Tool version")
    tool_parser.add_argument(
        "--capabilities", nargs="+", required=True, help="Capabilities"
    )
    tool_parser.add_argument("--scope", required=True, help="Scope")
    tool_parser.add_argument("--ttl", type=int, default=None, help="TTL in seconds (default: 900)")
    tool_parser.add_argument("--network", action="store_true", help="Allow network")
    tool_parser.add_argument(
        "--audit", default="summary", choices=["none", "summary", "full"]
    )

    subparsers.add_parser("list-tools", help="List all tools")

    policy_parser = subparsers.add_parser("add-policy", help="Add a policy")
    policy_parser.add_argument("--name", required=True, help="Policy name")
    policy_parser.add_argument("--description", required=True, help="Description")
    policy_parser.add_argument("--rego", required=True, help="Rego code")
    policy_parser.add_argument("--effect", required=True, choices=["allow", "deny"])
    policy_parser.add_argument(
        "--scope", required=True, choices=["tool", "session", "agent", "network"]
    )
    policy_parser.add_argument("--tags", nargs="*", default=[], help="Tags")

    subparsers.add_parser("list-policies", help="List all policies")

    session_parser = subparsers.add_parser("create-session", help="Create session")
    session_parser.add_argument("--agent-id", required=True, help="Agent ID")
    session_parser.add_argument("--created-by", required=True, help="Creator")

    log_parser = subparsers.add_parser("query-logs", help="Query audit logs")
    log_parser.add_argument("--session", help="Session ID")
    log_parser.add_argument("--event-type", help="Event type")
    log_parser.add_argument("--limit", type=int, default=100, help="Limit results")

    corr_parser = subparsers.add_parser("capture-correction", help="Capture correction")
    corr_parser.add_argument("--session-id", required=True, help="Session ID")
    corr_parser.add_argument("--agent-id", required=True, help="Agent ID")
    corr_parser.add_argument("--original-intent", required=True, help="Original intent")
    corr_parser.add_argument("--original-tool", required=True, help="Original tool")
    corr_parser.add_argument("--corrected-tool", required=True, help="Corrected tool")
    corr_parser.add_argument("--operator", required=True, help="Operator")
    corr_parser.add_argument(
        "--confidence-before", type=float, required=True, help="Confidence before"
    )
    corr_parser.add_argument(
        "--confidence-after", type=float, required=True, help="Confidence after"
    )

    subparsers.add_parser("stats", help="Get system statistics")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    cli = SynapticBridgeCLI()

    result = None

    if args.command == "register-tool":
        result = await cli.register_tool(
            args.name,
            args.version,
            args.capabilities,
            args.scope,
            args.ttl,
            args.network,
            args.audit,
        )
    elif args.command == "list-tools":
        result = await cli.list_tools()
    elif args.command == "add-policy":
        result = await cli.add_policy(
            args.name, args.description, args.rego, args.effect, args.scope, args.tags
        )
    elif args.command == "list-policies":
        result = await cli.list_policies()
    elif args.command == "create-session":
        result = await cli.create_session(args.agent_id, args.created_by)
    elif args.command == "query-logs":
        result = await cli.query_logs(args.session, args.event_type, args.limit)
    elif args.command == "capture-correction":
        result = await cli.capture_correction(
            args.session_id,
            args.agent_id,
            args.original_intent,
            args.original_tool,
            args.corrected_tool,
            args.operator,
            args.confidence_before,
            args.confidence_after,
        )
    elif args.command == "stats":
        result = await cli.get_stats()

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
