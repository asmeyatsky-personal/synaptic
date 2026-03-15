"""
Infrastructure Engine Tests

Comprehensive tests for OPA policy engine, intent classifier,
and drift detector.

Following skill2026.md Rule 4 - Mandatory Testing Coverage.
"""

import os

os.environ["TESTING"] = "1"

import pytest
from datetime import datetime, UTC

from synaptic_bridge.infrastructure.adapters.opa_engine import OPAPolicyEngine, BuiltInPolicies
from synaptic_bridge.infrastructure.adapters.intent_classifier import (
    IntentClassifier,
    SemanticToolMatcher,
)
from synaptic_bridge.infrastructure.adapters.drift_detector import DriftDetector
from synaptic_bridge.domain.entities import (
    Policy,
    PolicyEffect,
    PolicyScope,
    ToolManifest,
    CapabilityType,
    AuditLevel,
)


# ---------------------------------------------------------------------------
# OPA Policy Engine
# ---------------------------------------------------------------------------


class TestOPAPolicyEngine:
    """Tests for OPA Rego policy evaluation engine."""

    def _make_policy(self, pid, rego, effect=PolicyEffect.DENY, enabled=True):
        return Policy(
            policy_id=pid,
            name=f"Policy {pid}",
            description="Test policy",
            rego_code=rego,
            effect=effect,
            scope=PolicyScope.TOOL,
            tags=frozenset(["test"]),
            version="1.0.0",
            enabled=enabled,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

    @pytest.mark.asyncio
    async def test_deny_rule_matches(self):
        engine = OPAPolicyEngine()
        policy = self._make_policy(
            "deny_bad",
            'package test\ndeny { eq(input.tool, "bad_tool") }',
        )
        await engine.add_policy(policy)

        result = await engine.evaluate(policy, {"tool": "bad_tool"})
        assert result is False

    @pytest.mark.asyncio
    async def test_deny_rule_no_match(self):
        engine = OPAPolicyEngine()
        policy = self._make_policy(
            "deny_bad",
            'package test\ndeny { eq(input.tool, "bad_tool") }',
        )
        await engine.add_policy(policy)

        result = await engine.evaluate(policy, {"tool": "good_tool"})
        assert result is True

    @pytest.mark.asyncio
    async def test_allow_policy_always_true(self):
        engine = OPAPolicyEngine()
        policy = self._make_policy(
            "allow_all",
            "package test\nallow { true }",
            effect=PolicyEffect.ALLOW,
        )
        await engine.add_policy(policy)

        result = await engine.evaluate(policy, {"tool": "anything"})
        assert result is True

    @pytest.mark.asyncio
    async def test_contains_builtin(self):
        engine = OPAPolicyEngine()
        policy = self._make_policy(
            "deny_sensitive",
            'package test\ndeny { contains(input.path, "/etc/passwd") }',
        )
        await engine.add_policy(policy)

        result = await engine.evaluate(policy, {"path": "/etc/passwd"})
        assert result is False

        result = await engine.evaluate(policy, {"path": "/home/user/file.txt"})
        assert result is True

    @pytest.mark.asyncio
    async def test_glob_match_builtin(self):
        engine = OPAPolicyEngine()
        policy = self._make_policy(
            "deny_glob",
            'package test\ndeny { glob_match("*.secret", input.filename) }',
        )
        await engine.add_policy(policy)

        result = await engine.evaluate(policy, {"filename": "config.secret"})
        assert result is False

        result = await engine.evaluate(policy, {"filename": "config.json"})
        assert result is True

    @pytest.mark.asyncio
    async def test_nested_input_access(self):
        engine = OPAPolicyEngine()
        policy = self._make_policy(
            "deny_nested",
            'package test\ndeny { eq(input.parameters.method, "DELETE") }',
        )
        await engine.add_policy(policy)

        result = await engine.evaluate(
            policy, {"parameters": {"method": "DELETE"}}
        )
        assert result is False

        result = await engine.evaluate(
            policy, {"parameters": {"method": "GET"}}
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_disabled_policy_returns_true(self):
        engine = OPAPolicyEngine()
        policy = self._make_policy(
            "disabled",
            'package test\ndeny { eq(input.tool, "bad") }',
            enabled=False,
        )
        await engine.add_policy(policy)

        # Should return True because disabled policies are skipped
        result = await engine.evaluate(policy, {"tool": "bad"})
        assert result is True

    @pytest.mark.asyncio
    async def test_multiple_deny_rules_first_match_wins(self):
        engine = OPAPolicyEngine()
        rego = """package test
deny { eq(input.tool, "tool_a") }
deny { eq(input.tool, "tool_b") }
"""
        policy = self._make_policy("multi_deny", rego)
        await engine.add_policy(policy)

        result_a = await engine.evaluate(policy, {"tool": "tool_a"})
        assert result_a is False

        result_b = await engine.evaluate(policy, {"tool": "tool_b"})
        assert result_b is False

        result_c = await engine.evaluate(policy, {"tool": "tool_c"})
        assert result_c is True

    @pytest.mark.asyncio
    async def test_list_policies_excludes_disabled(self):
        engine = OPAPolicyEngine()
        await engine.add_policy(
            self._make_policy("p1", "package t\nallow { true }", enabled=True)
        )
        await engine.add_policy(
            self._make_policy("p2", "package t\nallow { true }", enabled=False)
        )

        policies = await engine.list_policies()
        assert len(policies) == 1
        assert policies[0].policy_id == "p1"

    @pytest.mark.asyncio
    async def test_remove_policy(self):
        engine = OPAPolicyEngine()
        await engine.add_policy(
            self._make_policy("p1", "package t\nallow { true }")
        )
        assert len(await engine.list_policies()) == 1

        await engine.remove_policy("p1")
        assert len(await engine.list_policies()) == 0

    @pytest.mark.asyncio
    async def test_rego_with_semicolon_conditions(self):
        engine = OPAPolicyEngine()
        # Two conditions joined by semicolon - both must be true
        policy = self._make_policy(
            "multi_cond",
            'package test\ndeny { eq(input.tool, "http.request"); eq(input.method, "POST") }',
        )
        await engine.add_policy(policy)

        # Both conditions match
        result = await engine.evaluate(
            policy, {"tool": "http.request", "method": "POST"}
        )
        assert result is False

        # Only one condition matches - deny should not trigger
        result = await engine.evaluate(
            policy, {"tool": "http.request", "method": "GET"}
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_builtin_policies_are_valid(self):
        """Ensure all built-in policy templates can be loaded."""
        engine = OPAPolicyEngine()
        all_policies = BuiltInPolicies.all()
        assert len(all_policies) == 5

        for pid, desc, rego_code in all_policies:
            assert "package" in rego_code
            assert pid  # non-empty id

    @pytest.mark.asyncio
    async def test_gt_builtin(self):
        engine = OPAPolicyEngine()
        policy = self._make_policy(
            "deny_timeout",
            "package test\ndeny { gt(input.session_age, 900) }",
        )
        await engine.add_policy(policy)

        result = await engine.evaluate(policy, {"session_age": 1000})
        assert result is False

        result = await engine.evaluate(policy, {"session_age": 500})
        assert result is True

    @pytest.mark.asyncio
    async def test_no_package_returns_true(self):
        engine = OPAPolicyEngine()
        policy = self._make_policy(
            "no_pkg",
            "deny { true }",  # no package statement
        )
        await engine.add_policy(policy)

        result = await engine.evaluate(policy, {})
        assert result is True  # no package => defaults to True


# ---------------------------------------------------------------------------
# Intent Classifier
# ---------------------------------------------------------------------------


class TestIntentClassifier:
    """Tests for the intent embedding and classification engine."""

    @pytest.mark.asyncio
    async def test_embedding_generation(self):
        classifier = IntentClassifier()
        embedding = await classifier.get_embedding("read a file from disk")

        assert len(embedding) == 128
        assert all(isinstance(v, float) for v in embedding)

    @pytest.mark.asyncio
    async def test_deterministic_embeddings(self):
        classifier = IntentClassifier()
        e1 = await classifier.get_embedding("read a file")
        e2 = await classifier.get_embedding("read a file")

        assert e1 == e2

    @pytest.mark.asyncio
    async def test_different_texts_different_embeddings(self):
        classifier = IntentClassifier()
        e1 = await classifier.get_embedding("read a file")
        e2 = await classifier.get_embedding("send an email notification")

        assert e1 != e2

    @pytest.mark.asyncio
    async def test_classify_intent_filesystem_read(self):
        classifier = IntentClassifier()
        tool, confidence = await classifier.classify_intent("read file content from disk")

        assert tool == "filesystem.read"
        assert confidence > 0.0

    @pytest.mark.asyncio
    async def test_classify_intent_bash_execute(self):
        classifier = IntentClassifier()
        tool, confidence = await classifier.classify_intent("run a shell command in terminal")

        assert tool == "bash.execute"
        assert confidence > 0.0

    @pytest.mark.asyncio
    async def test_classify_intent_http_request(self):
        classifier = IntentClassifier()
        tool, confidence = await classifier.classify_intent("make an http api request to fetch data")

        assert tool == "http.request"
        assert confidence > 0.0

    @pytest.mark.asyncio
    async def test_match_tool(self):
        classifier = IntentClassifier()
        embedding = await classifier.get_embedding("read a file from disk")
        tool, score = await classifier.match_tool(embedding)

        assert isinstance(tool, str)
        assert tool != "unknown"
        assert score >= 0.0

    @pytest.mark.asyncio
    async def test_add_tool(self):
        classifier = IntentClassifier()
        classifier.add_tool("custom.tool", "do custom things with widgets")

        tools = classifier.get_available_tools()
        assert "custom.tool" in tools

    @pytest.mark.asyncio
    async def test_get_available_tools_default(self):
        classifier = IntentClassifier()
        tools = classifier.get_available_tools()

        assert "filesystem.read" in tools
        assert "bash.execute" in tools
        assert "http.request" in tools
        assert len(tools) >= 10  # 10 default tools

    @pytest.mark.asyncio
    async def test_empty_text_embedding(self):
        classifier = IntentClassifier()
        embedding = await classifier.get_embedding("")

        # Empty text -> all zeros
        assert all(v == 0.0 for v in embedding)
        assert len(embedding) == 128

    @pytest.mark.asyncio
    async def test_semantic_tool_matcher_plan_chain(self):
        classifier = IntentClassifier()
        matcher = SemanticToolMatcher(classifier)

        chains = await matcher.plan_chain("read file content")
        assert isinstance(chains, list)
        assert len(chains) >= 1
        # First element of each chain should be the primary tool
        for chain in chains:
            assert isinstance(chain, list)
            assert len(chain) >= 1

    @pytest.mark.asyncio
    async def test_semantic_tool_matcher_find_related(self):
        classifier = IntentClassifier()
        matcher = SemanticToolMatcher(classifier)

        related = await matcher.find_related_tools("filesystem.write")
        assert "filesystem.read" in related

        no_related = await matcher.find_related_tools("filesystem.read")
        assert no_related == []

    @pytest.mark.asyncio
    async def test_semantic_tool_matcher_suggest_alternatives(self):
        classifier = IntentClassifier()
        matcher = SemanticToolMatcher(classifier)

        alternatives = await matcher.suggest_alternatives("filesystem.read")
        assert isinstance(alternatives, list)
        # Should not include the tool itself
        for alt in alternatives:
            assert alt["tool"] != "filesystem.read"
            assert "similarity" in alt

    @pytest.mark.asyncio
    async def test_semantic_tool_matcher_unknown_tool(self):
        classifier = IntentClassifier()
        matcher = SemanticToolMatcher(classifier)

        alternatives = await matcher.suggest_alternatives("nonexistent.tool")
        assert alternatives == []


# ---------------------------------------------------------------------------
# Drift Detector
# ---------------------------------------------------------------------------


class TestDriftDetector:
    """Tests for the statistical drift detection engine."""

    @pytest.mark.asyncio
    async def test_check_drift_no_baseline(self):
        detector = DriftDetector(window_size=10, drift_threshold=2.0)
        drift = await detector.check_drift("tool_a", {"execution_time_ms": 100})

        # No baseline yet, drift score should be 0.0
        assert drift == 0.0

    @pytest.mark.asyncio
    async def test_update_baseline_requires_min_samples(self):
        detector = DriftDetector(window_size=100, min_samples=10)

        # Add fewer than min_samples
        for i in range(5):
            await detector.check_drift("tool_a", {"execution_time_ms": 100 + i})

        manifest = ToolManifest(
            tool_name="tool_a",
            version="1.0",
            capabilities=frozenset([CapabilityType.READ]),
            scope="test",
            ttl_seconds=900,
            network_egress=False,
            audit_level=AuditLevel.NONE,
            signature="sig",
            created_at=datetime.now(UTC),
        )

        await detector.update_baseline("tool_a", manifest)
        baseline = await detector.get_baseline("tool_a")
        # Should NOT have created baseline since < min_samples
        assert baseline is None

    @pytest.mark.asyncio
    async def test_update_baseline_with_enough_samples(self):
        detector = DriftDetector(window_size=100, min_samples=5)

        for i in range(10):
            await detector.check_drift("tool_a", {"execution_time_ms": 100 + i})

        manifest = ToolManifest(
            tool_name="tool_a",
            version="1.0",
            capabilities=frozenset([CapabilityType.READ]),
            scope="test",
            ttl_seconds=900,
            network_egress=False,
            audit_level=AuditLevel.NONE,
            signature="sig",
            created_at=datetime.now(UTC),
        )

        await detector.update_baseline("tool_a", manifest)
        baseline = await detector.get_baseline("tool_a")
        assert baseline is not None
        assert "execution_time_ms" in baseline
        assert "error_rate" in baseline

    @pytest.mark.asyncio
    async def test_detect_anomalies_no_baseline(self):
        detector = DriftDetector()
        anomalies = await detector.detect_anomalies("tool_a")
        assert anomalies == []

    @pytest.mark.asyncio
    async def test_detect_anomalies_with_outlier(self):
        detector = DriftDetector(window_size=100, min_samples=5, drift_threshold=2.0)

        # Build up history with slight variance so stdev > 0
        import random
        random.seed(42)
        for i in range(20):
            exec_time = 100 + random.gauss(0, 5)  # mean=100, stdev~5
            await detector.check_drift("tool_a", {"execution_time_ms": exec_time, "error_rate": 0.0})

        # Create baseline from this history
        manifest = ToolManifest(
            tool_name="tool_a",
            version="1.0",
            capabilities=frozenset([CapabilityType.READ]),
            scope="test",
            ttl_seconds=900,
            network_egress=False,
            audit_level=AuditLevel.NONE,
            signature="sig",
            created_at=datetime.now(UTC),
        )
        await detector.update_baseline("tool_a", manifest)

        # Add an extreme outlier (10000ms vs ~100ms baseline)
        await detector.check_drift("tool_a", {"execution_time_ms": 10000, "error_rate": 0.0})

        anomalies = await detector.detect_anomalies("tool_a")
        # The outlier (10000ms vs ~100ms baseline with stdev~5) should be detected
        assert len(anomalies) >= 1
        assert anomalies[-1]["type"] == "execution_time"
        assert abs(anomalies[-1]["z_score"]) > 2.0

    @pytest.mark.asyncio
    async def test_get_drift_report_empty(self):
        detector = DriftDetector()
        report = detector.get_drift_report()

        assert report["tools_monitored"] == 0
        assert report["tools_with_baselines"] == 0
        assert report["tools"] == []

    @pytest.mark.asyncio
    async def test_get_drift_report_with_data(self):
        detector = DriftDetector(min_samples=3)

        for i in range(5):
            await detector.check_drift("tool_a", {"execution_time_ms": 100 + i})
        for i in range(5):
            await detector.check_drift("tool_b", {"execution_time_ms": 200 + i})

        report = detector.get_drift_report()
        assert report["tools_monitored"] == 2
        assert len(report["tools"]) == 2

        tool_names = {t["tool_name"] for t in report["tools"]}
        assert "tool_a" in tool_names
        assert "tool_b" in tool_names

    @pytest.mark.asyncio
    async def test_z_score_calculation(self):
        detector = DriftDetector()

        # Standard z-score: (value - mean) / stdev
        z = detector._z_score(120.0, 100.0, 10.0)
        assert z == pytest.approx(2.0)

        # Zero stdev -> 0.0
        z_zero = detector._z_score(120.0, 100.0, 0.0)
        assert z_zero == 0.0

    @pytest.mark.asyncio
    async def test_drift_score_with_baseline(self):
        detector = DriftDetector(window_size=100, min_samples=5, drift_threshold=2.0)

        # Build consistent history
        for i in range(15):
            await detector.check_drift("tool_a", {"execution_time_ms": 100, "error_rate": 0.0})

        manifest = ToolManifest(
            tool_name="tool_a",
            version="1.0",
            capabilities=frozenset([CapabilityType.READ]),
            scope="test",
            ttl_seconds=900,
            network_egress=False,
            audit_level=AuditLevel.NONE,
            signature="sig",
            created_at=datetime.now(UTC),
        )
        await detector.update_baseline("tool_a", manifest)

        # Normal value -> low drift
        drift_normal = await detector.check_drift(
            "tool_a", {"execution_time_ms": 100, "error_rate": 0.0}
        )
        assert drift_normal < 1.0

    @pytest.mark.asyncio
    async def test_get_behavior_stats(self):
        detector = DriftDetector(min_samples=3)

        for i in range(5):
            await detector.check_drift("tool_a", {"execution_time_ms": 100 + i * 10})

        stats = await detector.get_behavior_stats("tool_a")
        assert stats is not None
        assert stats["tool_name"] == "tool_a"
        assert stats["sample_count"] == 5
        assert stats["has_baseline"] is False

    @pytest.mark.asyncio
    async def test_get_behavior_stats_unknown_tool(self):
        detector = DriftDetector()
        stats = await detector.get_behavior_stats("unknown_tool")
        assert stats is None

    @pytest.mark.asyncio
    async def test_window_size_limits_history(self):
        detector = DriftDetector(window_size=5)

        for i in range(10):
            await detector.check_drift("tool_a", {"execution_time_ms": i * 10})

        stats = await detector.get_behavior_stats("tool_a")
        assert stats["sample_count"] == 5  # limited by window_size

    @pytest.mark.asyncio
    async def test_get_stats_helper(self):
        detector = DriftDetector()

        # Empty list
        empty_stats = detector._get_stats([])
        assert empty_stats["count"] == 0
        assert empty_stats["mean"] == 0

        # Single value
        single_stats = detector._get_stats([42.0])
        assert single_stats["count"] == 1
        assert single_stats["mean"] == 42.0
        assert single_stats["stdev"] == 0  # Can't compute stdev with 1 value

        # Multiple values
        multi_stats = detector._get_stats([10.0, 20.0, 30.0])
        assert multi_stats["count"] == 3
        assert multi_stats["mean"] == pytest.approx(20.0)
        assert multi_stats["min"] == 10.0
        assert multi_stats["max"] == 30.0
