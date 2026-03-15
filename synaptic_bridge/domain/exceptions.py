"""
Domain Exceptions

Custom exception hierarchy for SynapticBridge.
All exceptions inherit from SynapticBridgeError for consistent handling.
"""


class SynapticBridgeError(Exception):
    """Base exception for all SynapticBridge errors."""


class ConfigurationError(SynapticBridgeError):
    """Raised when required configuration is missing or invalid."""


class SessionNotFoundError(SynapticBridgeError):
    """Raised when a session cannot be found."""


class SessionExpiredError(SynapticBridgeError):
    """Raised when an expired session is used."""


class ToolNotFoundError(SynapticBridgeError):
    """Raised when a tool manifest cannot be found."""


class PolicyViolationError(SynapticBridgeError):
    """Raised when a policy denies an operation."""

    def __init__(self, policy_id: str, reason: str):
        self.policy_id = policy_id
        self.reason = reason
        super().__init__(f"Policy {policy_id} denied: {reason}")


class AuthenticationError(SynapticBridgeError):
    """Raised for authentication failures."""


class AuthorizationError(SynapticBridgeError):
    """Raised for authorization failures."""


class PatternNotFoundError(SynapticBridgeError):
    """Raised when a CLE pattern cannot be found."""


class AuditIntegrityError(SynapticBridgeError):
    """Raised when audit log integrity verification fails."""


class RegoEvaluationError(SynapticBridgeError):
    """Raised when Rego policy evaluation fails."""
