"""
Tests for Domain Layer Extras

Comprehensive tests for constants, exceptions, events, and entity edge cases.
"""

import os

os.environ["TESTING"] = "1"

import pytest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, UTC

from synaptic_bridge.domain.constants import (
    DEFAULT_TTL_SECONDS,
    MAX_TTL_SECONDS,
    MIN_TTL_SECONDS,
    EMBEDDING_DIM,
    CLE_CONFIDENCE_THRESHOLD,
    PATTERN_SIMILARITY_THRESHOLD,
    DRIFT_WINDOW_SIZE,
    DRIFT_THRESHOLD,
    DRIFT_MIN_SAMPLES,
    SPIFFE_CACHE_TTL_SECONDS,
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    SESSION_ID_PREFIX,
    CORRECTION_ID_PREFIX,
    PATTERN_ID_PREFIX,
    POLICY_ID_PREFIX,
    TOOL_ID_PREFIX,
    EVENT_ID_PREFIX,
    API_VERSION,
)
from synaptic_bridge.domain.exceptions import (
    SynapticBridgeError,
    ConfigurationError,
    SessionNotFoundError,
    SessionExpiredError,
    ToolNotFoundError,
    PolicyViolationError,
    AuthenticationError,
    AuthorizationError,
    PatternNotFoundError,
    AuditIntegrityError,
    RegoEvaluationError,
)
from synaptic_bridge.domain.events import (
    DomainEvent,
    ToolCalledEvent,
    CorrectionCapturedEvent,
    PolicyViolationEvent,
    SessionStartedEvent,
    SessionEndedEvent,
    DriftDetectedEvent,
)
from synaptic_bridge.domain.entities import (
    ExecutionSession,
    SessionStatus,
    Policy,
    PolicyEffect,
    PolicyScope,
    ToolManifest,
    CapabilityType,
    AuditLevel,
    Correction,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestConstants:

    def test_ttl_constants_types_values_and_ordering(self):
        assert isinstance(DEFAULT_TTL_SECONDS, int)
        assert isinstance(MAX_TTL_SECONDS, int)
        assert isinstance(MIN_TTL_SECONDS, int)
        assert DEFAULT_TTL_SECONDS == 900
        assert MAX_TTL_SECONDS == 86400
        assert MIN_TTL_SECONDS == 60
        assert MIN_TTL_SECONDS < DEFAULT_TTL_SECONDS < MAX_TTL_SECONDS

    def test_numeric_constants(self):
        assert isinstance(EMBEDDING_DIM, int) and EMBEDDING_DIM == 128
        assert isinstance(CLE_CONFIDENCE_THRESHOLD, float) and 0.0 < CLE_CONFIDENCE_THRESHOLD < 1.0
        assert isinstance(PATTERN_SIMILARITY_THRESHOLD, float) and 0.0 < PATTERN_SIMILARITY_THRESHOLD < 1.0
        assert DRIFT_WINDOW_SIZE == 100 and DRIFT_THRESHOLD == 2.0 and DRIFT_MIN_SAMPLES == 10
        assert DEFAULT_PAGE_SIZE == 50 and MAX_PAGE_SIZE == 500
        assert isinstance(SPIFFE_CACHE_TTL_SECONDS, int) and SPIFFE_CACHE_TTL_SECONDS == 3600

    def test_id_prefixes_and_api_version(self):
        for prefix in (SESSION_ID_PREFIX, CORRECTION_ID_PREFIX, PATTERN_ID_PREFIX,
                       POLICY_ID_PREFIX, TOOL_ID_PREFIX, EVENT_ID_PREFIX):
            assert isinstance(prefix, str) and prefix.endswith("_")
        assert API_VERSION == "1.0.0"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TestExceptions:

    def test_all_exceptions_inherit_from_base(self):
        exception_classes = [
            ConfigurationError, SessionNotFoundError, SessionExpiredError,
            ToolNotFoundError, AuthenticationError, AuthorizationError,
            PatternNotFoundError, AuditIntegrityError, RegoEvaluationError,
        ]
        for cls in exception_classes:
            err = cls("test message")
            assert isinstance(err, SynapticBridgeError)
            assert isinstance(err, Exception)

    def test_policy_violation_error_attributes_and_format(self):
        err = PolicyViolationError(policy_id="pol_1", reason="blocked")
        assert err.policy_id == "pol_1"
        assert err.reason == "blocked"
        assert str(err) == "Policy pol_1 denied: blocked"
        assert isinstance(err, SynapticBridgeError)

    def test_all_exceptions_catchable_as_base(self):
        instances = [
            ConfigurationError("a"), SessionNotFoundError("b"),
            SessionExpiredError("c"), ToolNotFoundError("d"),
            PolicyViolationError("pol", "reason"), AuthenticationError("e"),
            AuthorizationError("f"), PatternNotFoundError("g"),
            AuditIntegrityError("h"), RegoEvaluationError("i"),
        ]
        for exc in instances:
            with pytest.raises(SynapticBridgeError):
                raise exc


# ---------------------------------------------------------------------------
# Domain Events
# ---------------------------------------------------------------------------

class TestDomainEvents:

    def test_event_creation_and_event_type(self):
        cases = [
            (ToolCalledEvent(aggregate_id="c1", session_id="s", agent_id="a",
                             tool_name="fs.read", was_corrected=False), "ToolCalledEvent"),
            (CorrectionCapturedEvent(aggregate_id="c2", original_tool="a",
                                     corrected_tool="b"), "CorrectionCapturedEvent"),
            (PolicyViolationEvent(aggregate_id="v1", policy_id="p1",
                                  reason="blocked"), "PolicyViolationEvent"),
            (SessionStartedEvent(aggregate_id="s1", agent_id="a1",
                                 execution_token="tok"), "SessionStartedEvent"),
            (SessionEndedEvent(aggregate_id="s1", agent_id="a1",
                               reason="terminated", duration_seconds=42.5), "SessionEndedEvent"),
            (DriftDetectedEvent(aggregate_id="d1", tool_name="bash",
                                drift_score=3.5), "DriftDetectedEvent"),
            (DomainEvent(aggregate_id="base"), "DomainEvent"),
        ]
        for event, expected_type in cases:
            assert event.event_type == expected_type
            assert event.occurred_at is not None and isinstance(event.occurred_at, datetime)

    def test_event_field_values(self):
        tc = ToolCalledEvent(aggregate_id="c1", session_id="s1", agent_id="a1",
                             tool_name="fs.read", was_corrected=False)
        assert tc.correction_confidence == 0.0

        se = SessionEndedEvent(aggregate_id="s1", reason="terminated_by_user",
                               duration_seconds=42.5)
        assert se.duration_seconds == 42.5

        dd = DriftDetectedEvent(aggregate_id="d1", drift_score=3.5)
        assert dd.drift_score == 3.5

    def test_event_immutability(self):
        event = ToolCalledEvent(aggregate_id="c1", tool_name="fs.read")
        with pytest.raises(FrozenInstanceError):
            event.tool_name = "changed"


# ---------------------------------------------------------------------------
# ExecutionSession edge cases
# ---------------------------------------------------------------------------

class TestExecutionSessionEdgeCases:

    def _make_active_session(self, **overrides):
        now = datetime.now(UTC)
        defaults = dict(
            session_id="sess_1", agent_id="agent_1", execution_token="tok",
            status=SessionStatus.ACTIVE, started_at=now,
            expires_at=now + timedelta(minutes=15), tool_calls=(),
            created_by="system",
        )
        defaults.update(overrides)
        return ExecutionSession(**defaults)

    def test_terminate_and_expire(self):
        session = self._make_active_session()

        terminated = session.terminate()
        assert terminated.status == SessionStatus.TERMINATED
        assert not terminated.is_active()
        assert len(terminated.domain_events) == 1
        assert terminated.domain_events[0].reason == "terminated_by_user"

        expired = session.expire()
        assert expired.status == SessionStatus.EXPIRED
        assert expired.domain_events[0].reason == "token_expired"

    def test_add_tool_calls(self):
        session = self._make_active_session()
        updated = session.add_tool_call("c1").add_tool_call("c2").add_tool_call("c3")
        assert updated.tool_calls == ("c1", "c2", "c3")

    def test_post_init_validation(self):
        now = datetime.now(UTC)
        with pytest.raises(ValueError, match="Expiration must be after start"):
            ExecutionSession(
                session_id="bad", agent_id="a", execution_token="t",
                status=SessionStatus.ACTIVE, started_at=now,
                expires_at=now - timedelta(minutes=5), tool_calls=(),
                created_by="system",
            )

        # Numeric expires_at should be accepted
        session = ExecutionSession(
            session_id="num", agent_id="a", execution_token="t",
            status=SessionStatus.ACTIVE, started_at=now,
            expires_at=now.timestamp() + 900, tool_calls=(), created_by="system",
        )
        assert session.session_id == "num"

    def test_session_immutability(self):
        session = self._make_active_session()
        with pytest.raises(FrozenInstanceError):
            session.status = SessionStatus.TERMINATED


# ---------------------------------------------------------------------------
# Policy edge cases
# ---------------------------------------------------------------------------

class TestPolicyEdgeCases:

    def _make_policy(self, **overrides):
        now = datetime.now(UTC)
        defaults = dict(
            policy_id="pol_1", name="Test Policy", description="A test policy",
            rego_code="package test\nallow { true }", effect=PolicyEffect.ALLOW,
            scope=PolicyScope.TOOL, tags=frozenset(["test"]), version="1.0.0",
            enabled=True, created_at=now, updated_at=now,
        )
        defaults.update(overrides)
        return Policy(**defaults)

    def test_with_toggle_and_with_version(self):
        policy = self._make_policy(enabled=True)
        disabled = policy.with_toggle(False)
        assert disabled.enabled is False
        re_enabled = disabled.with_toggle(True)
        assert re_enabled.enabled is True

        updated = policy.with_version("2.0.0", "package v2\nallow { true }")
        assert updated.version == "2.0.0"
        assert updated.rego_code == "package v2\nallow { true }"

    def test_post_init_validation(self):
        with pytest.raises(ValueError, match="Policy name is required"):
            self._make_policy(name="")
        with pytest.raises(ValueError, match="Rego code is required"):
            self._make_policy(rego_code="")

    def test_policy_immutability(self):
        policy = self._make_policy()
        with pytest.raises(FrozenInstanceError):
            policy.enabled = False


# ---------------------------------------------------------------------------
# ToolManifest edge cases
# ---------------------------------------------------------------------------

class TestToolManifestEdgeCases:

    def _make_manifest(self, **overrides):
        defaults = dict(
            tool_name="fs.read", version="1.0.0",
            capabilities=frozenset([CapabilityType.READ]),
            scope="workspace:current", ttl_seconds=900, network_egress=False,
            audit_level=AuditLevel.FULL, signature="sig_123",
            created_at=datetime.now(UTC),
        )
        defaults.update(overrides)
        return ToolManifest(**defaults)

    def test_with_version(self):
        manifest = self._make_manifest(version="1.0.0")
        updated = manifest.with_version("2.0.0")
        assert updated.version == "2.0.0"
        assert updated.tool_name == manifest.tool_name

    def test_post_init_validation(self):
        with pytest.raises(ValueError, match="TTL must be positive"):
            self._make_manifest(ttl_seconds=0)
        with pytest.raises(ValueError, match="TTL must be positive"):
            self._make_manifest(ttl_seconds=-100)
        with pytest.raises(ValueError, match="Tool name is required"):
            self._make_manifest(tool_name="")

    def test_to_toml_output(self):
        manifest = self._make_manifest(
            tool_name="my.tool", scope="project", ttl_seconds=600,
            network_egress=True, audit_level=AuditLevel.SUMMARY, signature="abc",
        )
        toml = manifest.to_toml()
        assert "[my.tool]" in toml
        assert 'scope = "project"' in toml
        assert "ttl_seconds = 600" in toml
        assert "network_egress = true" in toml
        assert 'audit_level = "summary"' in toml
        assert 'signature = "abc"' in toml

        # Also verify false egress rendering
        toml2 = self._make_manifest(network_egress=False).to_toml()
        assert "network_egress = false" in toml2

    def test_manifest_immutability(self):
        manifest = self._make_manifest()
        with pytest.raises(FrozenInstanceError):
            manifest.version = "changed"


# ---------------------------------------------------------------------------
# Correction edge cases
# ---------------------------------------------------------------------------

class TestCorrectionEdgeCases:

    def _make_correction(self, **overrides):
        defaults = dict(
            correction_id="corr_1", session_id="sess_1", agent_id="agent_1",
            original_intent="read", inferred_context="context",
            original_tool="a.tool", corrected_tool="b.tool",
            correction_metadata={}, operator_identity="admin",
            confidence_before=0.3, confidence_after=0.9,
            captured_at=datetime.now(UTC),
        )
        defaults.update(overrides)
        return Correction(**defaults)

    def test_trust_score_range(self):
        # Improvement
        assert self._make_correction(confidence_before=0.2, confidence_after=0.8).trust_score() == pytest.approx(0.8)
        # No change
        assert self._make_correction(confidence_before=0.5, confidence_after=0.5).trust_score() == pytest.approx(0.5)
        # Decrease
        assert self._make_correction(confidence_before=0.9, confidence_after=0.3).trust_score() == pytest.approx(0.2)
        # Clamped to 1.0
        assert self._make_correction(confidence_before=0.0, confidence_after=1.0).trust_score() == pytest.approx(1.0)
        # Clamped to 0.0
        assert self._make_correction(confidence_before=1.0, confidence_after=0.0).trust_score() == pytest.approx(0.0)

    def test_invalid_confidence_values(self):
        with pytest.raises(ValueError, match="Confidence must be between"):
            self._make_correction(confidence_before=1.5)
        with pytest.raises(ValueError, match="Confidence must be between"):
            self._make_correction(confidence_before=-0.1)
        with pytest.raises(ValueError, match="Confidence must be between"):
            self._make_correction(confidence_after=2.0)
        with pytest.raises(ValueError, match="Confidence must be between"):
            self._make_correction(confidence_after=-0.5)

    def test_correction_immutability(self):
        c = self._make_correction()
        with pytest.raises(FrozenInstanceError):
            c.confidence_after = 0.99
