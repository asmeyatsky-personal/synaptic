"""
Workflow Orchestration

DAG-based execution for multi-step workflows with parallelization.
Following skill2026.md Rule 7 - Parallel-Safe Orchestration.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable

from synaptic_bridge.domain.entities import CorrectionPattern


@dataclass
class WorkflowStep:
    name: str
    execute: Callable
    depends_on: list[str] = field(default_factory=list)


class DAGOrchestrator:
    """
    Executes workflow steps respecting dependency order,
    parallelizing independent steps automatically.
    """

    def __init__(self, steps: list[WorkflowStep]):
        self.steps = {s.name: s for s in steps}
        self._validate_no_cycles()

    def _validate_no_cycles(self) -> None:
        visited = set()
        path = set()

        def visit(name: str) -> None:
            if name in path:
                raise ValueError(f"Circular dependency detected at {name}")
            if name in visited:
                return

            path.add(name)
            visited.add(name)

            for dep in self.steps[name].depends_on:
                visit(dep)

            path.remove(name)

        for name in self.steps:
            visit(name)

    async def execute(self, context: dict) -> dict:
        completed: dict[str, Any] = {}
        pending = set(self.steps.keys())

        while pending:
            ready = [
                name
                for name in pending
                if all(dep in completed for dep in self.steps[name].depends_on)
            ]

            if not ready:
                raise RuntimeError("Circular dependency detected")

            results = await asyncio.gather(
                *(self.steps[name].execute(context, completed) for name in ready),
                return_exceptions=True,
            )

            for name, result in zip(ready, results):
                if isinstance(result, Exception):
                    raise RuntimeError(f"Step {name} failed: {result}")
                completed[name] = result
                pending.discard(name)

        return completed


class CLEPredictiveDispatchWorkflow:
    """
    Correction Learning Engine Predictive Dispatch Workflow.

    Following PRD: Scores tool calls against rule graph; if confidence threshold met,
    dispatches corrected tool instead of original.

    Steps:
    1. Classify intent
    2. Check CLE for matching patterns
    3. Validate correction confidence threshold
    4. Execute (potentially corrected) tool
    """

    def __init__(
        self,
        intent: str,
        original_tool: str,
        parameters: dict,
        confidence_threshold: float | None = None,
        intent_classifier: Any = None,
        correction_store: Any = None,
        execution_port: Any = None,
    ):
        self.intent = intent
        self.original_tool = original_tool
        self.parameters = parameters
        from synaptic_bridge.domain.constants import CLE_CONFIDENCE_THRESHOLD
        self.confidence_threshold = confidence_threshold if confidence_threshold is not None else CLE_CONFIDENCE_THRESHOLD
        self.intent_classifier = intent_classifier
        self.correction_store = correction_store
        self.execution_port = execution_port

    async def execute(self) -> dict:
        steps = [
            WorkflowStep("classify_intent", self._classify_intent),
            WorkflowStep(
                "check_patterns",
                self._check_cle_patterns,
                depends_on=["classify_intent"],
            ),
            WorkflowStep(
                "validate_correction",
                self._validate_correction,
                depends_on=["check_patterns"],
            ),
            WorkflowStep(
                "execute_tool", self._execute_tool, depends_on=["validate_correction"]
            ),
        ]

        orchestrator = DAGOrchestrator(steps)
        return await orchestrator.execute({})

    async def _classify_intent(self, context: dict, completed: dict) -> dict:
        tool_name, confidence = await self.intent_classifier.classify_intent(
            self.intent
        )
        return {"matched_tool": tool_name, "confidence": confidence}

    async def _check_cle_patterns(self, context: dict, completed: dict) -> dict:
        classification = completed["classify_intent"]
        embedding = await self.intent_classifier.get_embedding(self.intent)

        patterns = await self.correction_store.find_patterns(embedding)

        best_match = None
        best_score = 0.0

        for pattern in patterns:
            if self.original_tool in pattern.original_tools:
                score = pattern.matches_intent(embedding)
                if score > best_score:
                    best_score = score
                    best_match = pattern

        return {
            "pattern": best_match,
            "score": best_score,
            "should_correct": best_score >= self.confidence_threshold,
        }

    async def _validate_correction(self, context: dict, completed: dict) -> dict:
        patterns_result = completed["check_patterns"]

        if patterns_result["should_correct"] and patterns_result["pattern"]:
            corrected_tool = patterns_result["pattern"].corrected_tools[0]
            return {
                "should_correct": True,
                "tool_to_execute": corrected_tool,
                "confidence": patterns_result["score"],
                "pattern_id": patterns_result["pattern"].pattern_id,
            }

        return {
            "should_correct": False,
            "tool_to_execute": self.original_tool,
            "confidence": 1.0,
            "pattern_id": None,
        }

    async def _execute_tool(self, context: dict, completed: dict) -> dict:
        validation = completed["validate_correction"]
        tool_to_execute = validation["tool_to_execute"]

        return {
            "executed_tool": tool_to_execute,
            "was_corrected": validation["should_correct"],
            "confidence": validation["confidence"],
            "pattern_id": validation["pattern_id"],
        }


class MultiHopChainPlanner:
    """
    Plans multi-hop tool chains with dependency resolution.
    Following PRD: Dependency graphs, circular call detection, graceful degradation.
    """

    def __init__(self, tool_registry: Any):
        self.tool_registry = tool_registry

    async def plan(self, intent: str, available_tools: list[str]) -> list[list[str]]:
        """
        Plan chains of tools to fulfill an intent.
        Returns list of possible chains (each chain is a list of tool names).
        """
        chains = []

        if len(available_tools) == 1:
            return [available_tools]

        for i, tool in enumerate(available_tools):
            remaining = available_tools[:i] + available_tools[i + 1 :]

            sub_chains = await self._plan_with_tool(tool, remaining, [tool])
            chains.extend(sub_chains)

        unique_chains = []
        seen = set()
        for chain in chains:
            key = tuple(sorted(chain))
            if key not in seen:
                seen.add(key)
                unique_chains.append(chain)

        return unique_chains

    async def _plan_with_tool(
        self, tool: str, remaining: list[str], current_chain: list[str]
    ) -> list[list[str]]:
        if not remaining:
            return [current_chain]

        chains = []
        for i, next_tool in enumerate(remaining):
            new_remaining = remaining[:i] + remaining[i + 1 :]
            new_chain = current_chain + [next_tool]

            if self._has_dependency(next_tool, current_chain):
                sub_chains = await self._plan_with_tool(
                    next_tool, new_remaining, new_chain
                )
                chains.extend(sub_chains)

        return chains if chains else [current_chain]

    def _has_dependency(self, tool: str, chain: list[str]) -> bool:
        return True

    async def detect_circular(self, chain: list[str]) -> bool:
        return len(chain) != len(set(chain))

    async def validate_dependencies(self, chain: list[str]) -> bool:
        return not await self.detect_circular(chain)
