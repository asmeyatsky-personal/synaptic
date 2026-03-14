"""
Dependency Injection Configuration

Following skill2026.md Rule 2 - Interface-First Development.
Wires implementations to ports at composition root.
"""

import os
from typing import Any, Callable


class DependencyContainer:
    """
    Simple dependency injection container.
    """

    def __init__(self):
        self._services: dict[str, Any] = {}
        self._factories: dict[str, Callable] = {}

    def register(self, name: str, instance: Any) -> None:
        self._services[name] = instance

    def register_factory(self, name: str, factory: Callable) -> None:
        self._factories[name] = factory

    def resolve(self, name: str) -> Any:
        if name in self._services:
            return self._services[name]

        if name in self._factories:
            instance = self._factories[name]()
            self._services[name] = instance
            return instance

        raise KeyError(f"Service '{name}' not registered")


def create_container() -> DependencyContainer:
    """
    Create and configure the dependency container.

    Uses DuckDB for corrections if DUCKDB_PATH is set, otherwise falls back to in-memory.
    Uses OPAPolicyEngine for real Rego evaluation.
    Uses IntentClassifier for actual embeddings.
    Uses DriftDetector for drift detection.
    """
    from synaptic_bridge.infrastructure.adapters import (
        InMemoryExecutionAdapter,
        InMemoryToolRegistry,
        InMemoryAuditLog,
    )
    from synaptic_bridge.infrastructure.adapters.duckdb_store import (
        DuckDBCorrectionStore,
    )
    from synaptic_bridge.infrastructure.adapters.opa_engine import OPAPolicyEngine
    from synaptic_bridge.infrastructure.adapters.intent_classifier import (
        IntentClassifier,
    )
    from synaptic_bridge.infrastructure.adapters.drift_detector import DriftDetector

    container = DependencyContainer()

    container.register("execution_port", InMemoryExecutionAdapter())
    container.register("tool_registry", InMemoryToolRegistry())
    container.register("audit_log", InMemoryAuditLog())

    duckdb_path = os.environ.get("DUCKDB_PATH")
    if duckdb_path:
        container.register("correction_store", DuckDBCorrectionStore(duckdb_path))
    else:
        from synaptic_bridge.infrastructure.adapters import InMemoryCorrectionStore

        container.register("correction_store", InMemoryCorrectionStore())

    container.register("policy_engine", OPAPolicyEngine())
    container.register("intent_classifier", IntentClassifier())
    container.register("drift_detector", DriftDetector())

    return container
