"""Tests for SecretManager adapters."""


import pytest

from synaptic_bridge.domain.exceptions import ConfigurationError
from synaptic_bridge.infrastructure.adapters.secret_manager import (
    EnvSecretManager,
    GCPSecretManager,
    build_default_secret_manager,
    default_secret_manager,
)


@pytest.mark.asyncio
async def test_env_secret_manager_reads_env(monkeypatch):
    monkeypatch.setenv("MY_KEY", "value-1")
    sm = EnvSecretManager()
    assert await sm.get_secret("MY_KEY") == "value-1"
    assert await sm.get_secret_or_none("MY_KEY") == "value-1"


@pytest.mark.asyncio
async def test_env_secret_manager_missing_raises(monkeypatch):
    monkeypatch.delenv("MISSING_KEY", raising=False)
    sm = EnvSecretManager()
    assert await sm.get_secret_or_none("MISSING_KEY") is None
    with pytest.raises(ConfigurationError):
        await sm.get_secret("MISSING_KEY")


def test_build_default_uses_env_when_testing(monkeypatch):
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("GCP_PROJECT", "prod-project")
    sm = build_default_secret_manager()
    assert isinstance(sm, EnvSecretManager)


def test_build_default_uses_gcp_in_production(monkeypatch):
    monkeypatch.delenv("TESTING", raising=False)
    monkeypatch.setenv("GCP_PROJECT", "prod-project")
    sm = build_default_secret_manager()
    assert isinstance(sm, GCPSecretManager)
    assert sm.project_id == "prod-project"


def test_default_secret_manager_cached(monkeypatch):
    from synaptic_bridge.infrastructure.adapters import secret_manager as sm_module

    monkeypatch.setattr(sm_module, "_default", None)
    monkeypatch.setenv("TESTING", "1")
    first = default_secret_manager()
    second = default_secret_manager()
    assert first is second


@pytest.mark.asyncio
async def test_gcp_secret_manager_raises_without_sdk(monkeypatch):
    """If google-cloud-secret-manager isn't installed, fail with a clear error."""
    sm = GCPSecretManager("some-project")
    # Force ImportError by hiding the module name
    import sys

    monkeypatch.setitem(sys.modules, "google.cloud", None)
    with pytest.raises(ConfigurationError, match="google-cloud-secret-manager"):
        await sm.get_secret_or_none("any")
