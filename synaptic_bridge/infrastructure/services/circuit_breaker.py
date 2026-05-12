"""
Circuit Breaker Pattern Implementation

Provides fault tolerance for external service calls.
Prevents cascading failures by failing fast when a service is unhealthy.

States:
- CLOSED: Normal operation, requests pass through
- OPEN: Service is failing, requests fail immediately
- HALF_OPEN: Testing if service recovered
"""

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from functools import wraps
from typing import Any, TypeVar

T = TypeVar("T")


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerError(Exception):
    """Raised when circuit breaker is open and request is rejected."""

    def __init__(self, service_name: str, retry_after: float):
        self.name = service_name
        self.retry_after = retry_after
        super().__init__(
            f"Circuit breaker is open for '{service_name}'. Retry after {retry_after:.1f} seconds."
        )


@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    success_threshold: int = 2
    timeout_seconds: float = 30.0


class CircuitBreaker:
    """
    Circuit breaker for external service calls.

    Usage:
        cb = CircuitBreaker("siem-service", CircuitBreakerConfig())

        @cb
        async def call_siem(data):
            return await siem_client.send(data)

        result = await call_siem(payload)
    """

    def __init__(self, name: str, config: CircuitBreakerConfig | None = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: float | None = None
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def is_open(self) -> bool:
        return self._state == CircuitState.OPEN

    @property
    def is_closed(self) -> bool:
        return self._state == CircuitState.CLOSED

    @property
    def is_half_open(self) -> bool:
        return self._state == CircuitState.HALF_OPEN

    async def record_success(self) -> None:
        """Record a successful call."""
        async with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.config.success_threshold:
                    self._transition_to(CircuitState.CLOSED)
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0

    async def record_failure(self) -> None:
        """Record a failed call."""
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()

            if self._state == CircuitState.HALF_OPEN or (
                self._state == CircuitState.CLOSED
                and self._failure_count >= self.config.failure_threshold
            ):
                self._transition_to(CircuitState.OPEN)

    async def _maybe_transition_from_open(self) -> None:
        """Check if we should transition from OPEN to HALF_OPEN."""
        if self._state != CircuitState.OPEN:
            return

        if self._last_failure_time is None:
            self._transition_to(CircuitState.HALF_OPEN)
            return

        elapsed = time.time() - self._last_failure_time
        if elapsed >= self.config.timeout_seconds:
            self._transition_to(CircuitState.HALF_OPEN)

    def _transition_to(self, new_state: CircuitState) -> None:
        """Transition to a new state."""
        if self._state == new_state:
            return

        self._state = new_state
        self._success_count = 0

        if new_state == CircuitState.CLOSED:
            self._failure_count = 0

    def time_until_retry(self) -> float:
        """Get seconds until circuit might close (only meaningful when OPEN)."""
        if self._state != CircuitState.OPEN or self._last_failure_time is None:
            return 0.0

        elapsed = time.time() - self._last_failure_time
        return max(0.0, self.config.timeout_seconds - elapsed)

    def get_status(self) -> dict:
        """Get circuit breaker status for monitoring."""
        return {
            "name": self.name,
            "state": self._state.value,
            "failure_count": self._failure_count,
            "success_count": self._success_count,
            "last_failure_time": self._last_failure_time,
            "time_until_retry": self.time_until_retry(),
        }

    async def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        """
        Decorator to wrap a function with circuit breaker protection.

        Usage:
            @circuit_breaker
            async def call_service():
                ...
        """

        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            await self._maybe_transition_from_open()

            if self._state == CircuitState.OPEN:
                raise CircuitBreakerError(self.name, self.time_until_retry())

            try:
                result = await func(*args, **kwargs)
                await self.record_success()
                return result
            except Exception:
                await self.record_failure()
                raise

        @wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            if self._state == CircuitState.OPEN:
                raise CircuitBreakerError(self.name, self.time_until_retry())

            try:
                result = func(*args, **kwargs)
                if asyncio.iscoroutine(result):
                    return self._wrap_async(result)
                return result
            except Exception:
                return None

        async def _wrap_async(coro):
            try:
                result = await coro
                await self.record_success()
                return result
            except Exception:
                await self.record_failure()
                raise

        if asyncio.iscoroutinefunction(func):
            return wrapper
        return sync_wrapper

    async def force_open(self) -> None:
        """Force circuit breaker to open (for maintenance)."""
        async with self._lock:
            self._transition_to(CircuitState.OPEN)

    async def force_close(self) -> None:
        """Force circuit breaker to close (after maintenance)."""
        async with self._lock:
            self._transition_to(CircuitState.CLOSED)

    async def reset(self) -> None:
        """Reset circuit breaker to initial closed state."""
        async with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            self._last_failure_time = None


class CircuitBreakerRegistry:
    """Registry for managing multiple circuit breakers."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._breakers = {}
            cls._instance._lock = asyncio.Lock()
        return cls._instance

    async def get_or_create(
        self, name: str, config: CircuitBreakerConfig | None = None
    ) -> CircuitBreaker:
        """Get existing or create new circuit breaker."""
        async with self._lock:
            if name not in self._breakers:
                self._breakers[name] = CircuitBreaker(name, config)
            return self._breakers[name]

    async def get(self, name: str) -> CircuitBreaker | None:
        """Get circuit breaker by name."""
        return self._breakers.get(name)

    async def get_all_status(self) -> list[dict]:
        """Get status of all circuit breakers."""
        return [cb.get_status() for cb in self._breakers.values()]


registry = CircuitBreakerRegistry()

SIEM_CIRCUIT_BREAKER_CONFIG = CircuitBreakerConfig(
    failure_threshold=3,
    success_threshold=2,
    timeout_seconds=60.0,
)

splunk_circuit_breaker = CircuitBreaker("splunk", SIEM_CIRCUIT_BREAKER_CONFIG)
datadog_circuit_breaker = CircuitBreaker("datadog", SIEM_CIRCUIT_BREAKER_CONFIG)
gcp_circuit_breaker = CircuitBreaker("gcp-logging", SIEM_CIRCUIT_BREAKER_CONFIG)
azure_circuit_breaker = CircuitBreaker("azure-sentinel", SIEM_CIRCUIT_BREAKER_CONFIG)
