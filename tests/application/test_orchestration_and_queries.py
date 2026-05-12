"""Coverage for application orchestration and queries."""

from datetime import UTC, datetime

import pytest

from synaptic_bridge.application.commands import AddPolicyCommand
from synaptic_bridge.application.orchestration import (
    CLEPredictiveDispatchWorkflow,
    DAGOrchestrator,
    MultiHopChainPlanner,
    WorkflowStep,
)
from synaptic_bridge.application.queries import (
    FindCorrectionPatternsQuery,
    GetPolicyQuery,
    GetSessionQuery,
    GetToolQuery,
    ListPoliciesQuery,
    ListToolsQuery,
    QueryAuditLogQuery,
)
from synaptic_bridge.domain.entities import (
    CorrectionPattern,
    PolicyEffect,
    PolicyScope,
)
from synaptic_bridge.infrastructure.adapters import (
    InMemoryAuditLog,
    InMemoryExecutionAdapter,
    InMemoryPolicyEngine,
    InMemoryToolRegistry,
    MockIntentClassifier,
)

# ---------- DAGOrchestrator ----------


@pytest.mark.asyncio
async def test_dag_runs_steps_respecting_dependencies():
    log: list[str] = []

    async def step_a(ctx, done):
        log.append("a")
        return "A"

    async def step_b(ctx, done):
        log.append("b")
        return "B"

    async def step_c(ctx, done):
        log.append("c")
        return "C"

    steps = [
        WorkflowStep("a", step_a),
        WorkflowStep("b", step_b, depends_on=["a"]),
        WorkflowStep("c", step_c, depends_on=["b"]),
    ]
    result = await DAGOrchestrator(steps).execute({})
    assert result == {"a": "A", "b": "B", "c": "C"}
    assert log == ["a", "b", "c"]


def test_dag_rejects_cycles():
    async def f(ctx, done):
        return None

    steps = [
        WorkflowStep("a", f, depends_on=["b"]),
        WorkflowStep("b", f, depends_on=["a"]),
    ]
    with pytest.raises(ValueError, match="Circular dependency"):
        DAGOrchestrator(steps)


@pytest.mark.asyncio
async def test_dag_propagates_step_errors():
    async def good(ctx, done):
        return "ok"

    async def bad(ctx, done):
        raise RuntimeError("boom")

    steps = [WorkflowStep("a", good), WorkflowStep("b", bad)]
    with pytest.raises(RuntimeError, match="Step b failed"):
        await DAGOrchestrator(steps).execute({})


# ---------- CLEPredictiveDispatchWorkflow ----------


@pytest.mark.asyncio
async def test_cle_workflow_corrects_when_pattern_matches():
    classifier = MockIntentClassifier()
    store = type(
        "S",
        (),
        {
            "find_patterns": staticmethod(
                lambda emb: _fake_patterns_with_match(emb)
            )
        },
    )

    wf = CLEPredictiveDispatchWorkflow(
        intent="read the file",
        original_tool="filesystem.read",
        parameters={},
        confidence_threshold=0.0,
        intent_classifier=classifier,
        correction_store=store,
    )
    result = await wf.execute()
    assert result["execute_tool"]["was_corrected"] is True
    assert result["execute_tool"]["executed_tool"] == "filesystem.read_safe"


async def _fake_patterns_with_match(emb):
    return [
        CorrectionPattern(
            pattern_id="p",
            intent_vector=emb,
            original_tools=("filesystem.read",),
            corrected_tools=("filesystem.read_safe",),
            occurrence_count=5,
            avg_confidence_improvement=0.5,
            last_updated=datetime.now(UTC),
            total_undo_count=0,
        )
    ]


@pytest.mark.asyncio
async def test_cle_workflow_falls_through_without_pattern():
    classifier = MockIntentClassifier()
    store = type("S", (), {"find_patterns": staticmethod(lambda emb: _empty(emb))})

    wf = CLEPredictiveDispatchWorkflow(
        intent="read",
        original_tool="filesystem.read",
        parameters={},
        intent_classifier=classifier,
        correction_store=store,
    )
    result = await wf.execute()
    assert result["execute_tool"]["was_corrected"] is False
    assert result["execute_tool"]["executed_tool"] == "filesystem.read"


async def _empty(_emb):
    return []


# ---------- MultiHopChainPlanner ----------


@pytest.mark.asyncio
async def test_chain_planner_dependencies_and_circular():
    planner = MultiHopChainPlanner(tool_registry=None)
    planner.add_dependency("custom", "filesystem.read")
    assert "filesystem.read" in planner.get_dependencies("custom")

    chains = await planner.plan("intent", ["filesystem.read", "filesystem.write"])
    assert chains

    assert await planner.detect_circular(["a", "a"]) is True
    assert await planner.detect_circular(["a", "b"]) is False
    assert await planner.validate_dependencies(["a", "b"]) is True
    assert await planner.validate_dependencies(["a", "a"]) is False

    single = await planner.plan("intent", ["only.one"])
    assert single == [["only.one"]]


# ---------- Queries ----------


@pytest.mark.asyncio
async def test_queries_round_trip():
    exec_adapter = InMemoryExecutionAdapter()
    registry = InMemoryToolRegistry()
    policies = InMemoryPolicyEngine()
    audit = InMemoryAuditLog()
    classifier = MockIntentClassifier()

    session = await exec_adapter.create_session("agent", "creator")

    # GetSessionQuery
    found = await GetSessionQuery(session.session_id).execute(exec_adapter)
    assert found is not None

    # ListToolsQuery / GetToolQuery
    assert await ListToolsQuery().execute(registry) == []
    assert await GetToolQuery("missing").execute(registry) is None

    # Policies
    policy = await AddPolicyCommand(
        name="p",
        description="d",
        rego_code="x",
        effect=PolicyEffect.ALLOW,
        scope=PolicyScope.TOOL,
        tags=["t"],
    ).execute(policies)
    listed = await ListPoliciesQuery().execute(policies)
    assert any(p.policy_id == policy.policy_id for p in listed)
    found_policy = await GetPolicyQuery(policy.policy_id).execute(policies)
    assert found_policy is not None
    missing = await GetPolicyQuery("none").execute(policies)
    assert missing is None

    # Audit
    audit_result = await QueryAuditLogQuery(
        session_id=session.session_id, event_type="X"
    ).execute(audit)
    assert audit_result == []

    # Correction patterns
    result = await FindCorrectionPatternsQuery("read").execute(
        intent_classifier=classifier,
        correction_store=type("S", (), {"find_patterns": staticmethod(_empty)})(),
    )
    assert result == []
