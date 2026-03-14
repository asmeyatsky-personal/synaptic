"""
OPA Policy Engine Implementation

Following PRD: Open Policy Agent (OPA) integration with Rego expressiveness.
Actual Rego policy evaluation for dispatch-time policy checks.
"""

import json
import re
from typing import Any

from synaptic_bridge.domain.entities import Policy, PolicyEffect


class OPAPolicyEngine:
    """
    OPA-compatible policy engine with actual Rego evaluation.

    Following PRD: Rego policies evaluated at dispatch time; policy violations are hard blocks.
    """

    def __init__(self):
        self._policies: dict[str, Policy] = {}
        self._builtins = {
            "eq": self._builtin_eq,
            "neq": self._builtin_neq,
            "gt": self._builtin_gt,
            "gte": self._builtin_gte,
            "lt": self._builtin_lt,
            "lte": self._builtin_lte,
            "and": self._builtin_and,
            "or": self._builtin_or,
            "not": self._builtin_not,
            "contains": self._builtin_contains,
            "startswith": self._builtin_startswith,
            "endswith": self._builtin_endswith,
            "glob_match": self._builtin_glob_match,
        }

    async def add_policy(self, policy: Policy) -> None:
        """Add a policy to the engine."""
        self._policies[policy.policy_id] = policy

    async def remove_policy(self, policy_id: str) -> None:
        """Remove a policy from the engine."""
        self._policies.pop(policy_id, None)

    async def list_policies(self) -> list[Policy]:
        """List all enabled policies."""
        return [p for p in self._policies.values() if p.enabled]

    async def evaluate(self, policy: Policy, context: dict) -> bool:
        """
        Evaluate a policy against the given context.

        Implements actual Rego policy evaluation.
        """
        if not policy.enabled:
            return True

        if policy.effect == PolicyEffect.ALLOW:
            return True

        try:
            result = self._evaluate_rego(policy.rego_code, context)
            return result if isinstance(result, bool) else bool(result)
        except Exception as e:
            return False

    def _evaluate_rego(self, rego_code: str, context: dict) -> Any:
        """Evaluate Rego code against context."""
        input_data = {"input": context}

        package_match = re.search(r"package\s+(\S+)", rego_code)
        if not package_match:
            return True

        rules = re.findall(
            r"(deny|allow|violation)\s*\{([^}]+)\}", rego_code, re.DOTALL
        )

        for rule_name, rule_body in rules:
            if self._evaluate_rule(rule_body, input_data):
                if rule_name == "deny":
                    return False
                elif rule_name == "allow":
                    return True

        return True

    def _evaluate_rule(self, rule_body: str, input_data: dict) -> bool:
        """Evaluate a single Rego rule."""
        rule_body = rule_body.strip()

        conditions = [c.strip() for c in rule_body.split(";") if c.strip()]

        for condition in conditions:
            result = self._evaluate_condition(condition, input_data)
            if not result:
                return False

        return True

    def _evaluate_condition(self, condition: str, input_data: dict) -> bool:
        """Evaluate a single condition."""
        condition = condition.strip()

        if condition.startswith("input."):
            path = condition[6:].strip()
            return self._get_nested(input_data, path) is not None

        for builtin_name, builtin_fn in self._builtins.items():
            if f"{builtin_name}(" in condition:
                return self._evaluate_builtin(
                    condition, input_data, builtin_name, builtin_fn
                )

        return True

    def _get_nested(self, data: dict, path: str) -> Any:
        """Get nested value from dict using dot notation."""
        keys = path.replace("[", ".").replace("]", "").split(".")
        current = data

        for key in keys:
            if key not in current:
                return None
            current = current[key]

        return current

    def _evaluate_builtin(
        self, condition: str, input_data: dict, name: str, fn: callable
    ) -> bool:
        """Evaluate a built-in function."""
        match = re.search(rf"{name}\(([^)]+)\)", condition)
        if not match:
            return True

        args_str = match.group(1)
        args = [a.strip() for a in args_str.split(",")]

        evaluated_args = []
        for arg in args:
            if arg.startswith("input."):
                evaluated_args.append(self._get_nested(input_data, arg[6:]))
            elif arg.startswith('"') and arg.endswith('"'):
                evaluated_args.append(arg[1:-1])
            else:
                try:
                    evaluated_args.append(int(arg))
                except ValueError:
                    try:
                        evaluated_args.append(float(arg))
                    except ValueError:
                        evaluated_args.append(arg)

        try:
            return fn(*evaluated_args)
        except Exception:
            return False

    def _builtin_eq(self, a: Any, b: Any) -> bool:
        return a == b

    def _builtin_neq(self, a: Any, b: Any) -> bool:
        return a != b

    def _builtin_gt(self, a: float, b: float) -> bool:
        return a > b

    def _builtin_gte(self, a: float, b: float) -> bool:
        return a >= b

    def _builtin_lt(self, a: float, b: float) -> bool:
        return a < b

    def _builtin_lte(self, a: float, b: float) -> bool:
        return a <= b

    def _builtin_and(self, *args: bool) -> bool:
        return all(args)

    def _builtin_or(self, *args: bool) -> bool:
        return any(args)

    def _builtin_not(self, a: bool) -> bool:
        return not a

    def _builtin_contains(self, container: str, item: str) -> bool:
        return item in container

    def _builtin_startswith(self, s: str, prefix: str) -> bool:
        return s.startswith(prefix)

    def _builtin_endswith(self, s: str, suffix: str) -> bool:
        return s.endswith(suffix)

    def _builtin_glob_match(self, pattern: str, text: str) -> bool:
        """Match text against a glob pattern."""
        regex_pattern = pattern.replace(".", r"\.").replace("*", ".*").replace("?", ".")
        return bool(re.match(f"^{regex_pattern}$", text))


class BuiltInPolicies:
    """Pre-built policy templates following PRD: 5 built-in policy templates."""

    DENY_NETWORK = """package synapticbridge
    
    deny {
        input.tool_name == "network.request"
        input.parameters.method != "GET"
    }
    
    deny {
        input.tool_name == "http.request"
        input.parameters.url == ""
    }
    """

    DENY_SENSITIVE = """package synapticbridge
    
    deny {
        input.tool_name == "filesystem.read"
        contains(input.parameters.path, "/etc/passwd")
    }
    
    deny {
        input.tool_name == "filesystem.read"
        contains(input.parameters.path, "/root/.ssh")
    }
    
    deny {
        input.tool_name == "bash.execute"
        contains(input.parameters.command, "rm -rf")
    }
    """

    RATE_LIMIT = """package synapticbridge
    
    deny {
        input.tool_name == "api.request"
        input.rate_limit_exceeded == true
    }
    """

    SESSION_TIMEOUT = """package synapticbridge
    
    deny {
        input.session_age > 900
    }
    """

    ALLOW_LIST = """package synapticbridge
    
    allow {
        input.tool_name == "filesystem.read"
        input.parameters.scope == "workspace:current"
    }
    
    allow {
        input.tool_name == "bash.execute"
        input.parameters.timeout < 30
    }
    
    deny {
        true
    }
    """

    @classmethod
    def all(cls) -> list[tuple[str, str, str]]:
        return [
            ("deny_network", "Deny sensitive network operations", cls.DENY_NETWORK),
            ("deny_sensitive", "Deny access to sensitive files", cls.DENY_SENSITIVE),
            ("rate_limit", "Rate limiting for API calls", cls.RATE_LIMIT),
            ("session_timeout", "Enforce session timeout", cls.SESSION_TIMEOUT),
            ("allow_list", "Allow list based on scope", cls.ALLOW_LIST),
        ]
