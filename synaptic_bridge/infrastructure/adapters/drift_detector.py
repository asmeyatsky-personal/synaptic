"""
Drift Detection Implementation

Following PRD: Runtime behavior compared against declared signatures; statistical drift alerts.
Statistical monitoring of tool runtime behavior against declared manifest signatures.
"""

import json
import statistics
import uuid
from collections import deque
from datetime import datetime, UTC
from typing import Any

from synaptic_bridge.domain.entities import ToolManifest


class DriftDetector:
    """
    Statistical drift detection for tool behavior.

    Following PRD: Drift detection with OpenTelemetry export.
    """

    def __init__(
        self,
        window_size: int = 100,
        drift_threshold: float = 2.0,
        min_samples: int = 10,
    ):
        self.window_size = window_size
        self.drift_threshold = drift_threshold
        self.min_samples = min_samples

        self._baselines: dict[str, dict[str, Any]] = {}
        self._behavior_history: dict[str, deque] = {}

    async def check_drift(self, tool_name: str, behavior: dict[str, Any]) -> float:
        """
        Check for drift in tool behavior.

        Returns drift score: 0.0 = no drift, >2.0 = significant drift
        """
        execution_time = behavior.get("execution_time_ms", 0)
        memory_usage = behavior.get("memory_usage_mb", 0)
        error_rate = behavior.get("error_rate", 0)
        return_value_size = behavior.get("return_value_size", 0)

        if tool_name not in self._behavior_history:
            self._behavior_history[tool_name] = deque(maxlen=self.window_size)

        self._behavior_history[tool_name].append(
            {
                "execution_time_ms": execution_time,
                "memory_usage_mb": memory_usage,
                "error_rate": error_rate,
                "return_value_size": return_value_size,
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )

        if tool_name not in self._baselines:
            return 0.0

        baseline = self._baselines[tool_name]
        drift_scores = []

        if "execution_time_ms" in baseline:
            current_stats = self._get_stats(
                [b["execution_time_ms"] for b in self._behavior_history[tool_name]]
            )
            if current_stats["count"] >= self.min_samples:
                z_score = self._z_score(
                    execution_time, current_stats["mean"], current_stats["stdev"]
                )
                drift_scores.append(abs(z_score))

        if "error_rate" in baseline:
            current_error_rate = error_rate
            baseline_error_rate = baseline["error_rate"]
            if baseline_error_rate > 0:
                error_drift = (
                    abs(current_error_rate - baseline_error_rate) / baseline_error_rate
                )
                drift_scores.append(error_drift)

        return max(drift_scores) if drift_scores else 0.0

    def _z_score(self, value: float, mean: float, stdev: float) -> float:
        if stdev == 0:
            return 0.0
        return (value - mean) / stdev

    def _get_stats(self, values: list[float]) -> dict[str, float]:
        if not values:
            return {"mean": 0, "stdev": 0, "count": 0, "min": 0, "max": 0}

        return {
            "mean": statistics.mean(values),
            "stdev": statistics.stdev(values) if len(values) > 1 else 0,
            "count": len(values),
            "min": min(values),
            "max": max(values),
        }

    async def update_baseline(self, tool_name: str, manifest: ToolManifest) -> None:
        """Update baseline from tool manifest."""
        history = self._behavior_history.get(tool_name, [])

        if len(history) < self.min_samples:
            return

        execution_times = [b["execution_time_ms"] for b in history]
        error_rates = [b["error_rate"] for b in history]

        self._baselines[tool_name] = {
            "execution_time_ms": self._get_stats(execution_times),
            "error_rate": statistics.mean(error_rates),
            "updated_at": datetime.now(UTC).isoformat(),
        }

    async def get_baseline(self, tool_name: str) -> dict | None:
        """Get baseline for a tool."""
        return self._baselines.get(tool_name)

    async def get_behavior_stats(self, tool_name: str) -> dict | None:
        """Get current behavior statistics for a tool."""
        history = self._behavior_history.get(tool_name)
        if not history:
            return None

        execution_times = [b["execution_time_ms"] for b in history]

        return {
            "tool_name": tool_name,
            "sample_count": len(history),
            "execution_time_ms": self._get_stats(execution_times),
            "has_baseline": tool_name in self._baselines,
        }

    async def detect_anomalies(self, tool_name: str) -> list[dict]:
        """Detect individual anomalous executions."""
        if tool_name not in self._behavior_history:
            return []

        history = list(self._behavior_history[tool_name])
        if len(history) < self.min_samples:
            return []

        baseline = self._baselines.get(tool_name)
        if not baseline:
            return []

        anomalies = []

        for i, behavior in enumerate(history):
            execution_time = behavior.get("execution_time_ms", 0)
            stats = baseline.get("execution_time_ms", {})

            if stats and stats.get("stdev", 0) > 0:
                z = (execution_time - stats["mean"]) / stats["stdev"]
                if abs(z) > self.drift_threshold:
                    anomalies.append(
                        {
                            "index": i,
                            "type": "execution_time",
                            "expected": stats["mean"],
                            "actual": execution_time,
                            "z_score": z,
                            "timestamp": behavior.get("timestamp"),
                        }
                    )

        return anomalies

    def get_drift_report(self) -> dict:
        """Get a comprehensive drift report for all tools."""
        report = {
            "tools_monitored": len(self._behavior_history),
            "tools_with_baselines": len(self._baselines),
            "tools": [],
        }

        for tool_name in self._behavior_history.keys():
            history = self._behavior_history[tool_name]
            has_baseline = tool_name in self._baselines

            execution_times = [b["execution_time_ms"] for b in history]

            tool_info = {
                "tool_name": tool_name,
                "sample_count": len(history),
                "has_baseline": has_baseline,
            }

            if execution_times:
                stats = self._get_stats(execution_times)
                tool_info["execution_time_stats"] = stats

            if has_baseline:
                baseline = self._baselines[tool_name]
                if "execution_time_ms" in baseline:
                    tool_info["baseline"] = baseline

            report["tools"].append(tool_info)

        return report
