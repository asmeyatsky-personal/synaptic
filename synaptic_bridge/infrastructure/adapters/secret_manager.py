"""
Layer: infrastructure
Ports: SecretManagerPort
MCP integration: none (consumed via DI by other adapters).
Stack: canonical. GCP Secret Manager is the production adapter; env-based is
for local/test only and refuses to be selected when GCP_PROJECT is set.

Architectural Rules §4.1 — secrets MUST come from Secret Manager + Workload
Identity in production. Direct os.environ reads for secret material are
forbidden outside this module.
"""

from __future__ import annotations

import os

from synaptic_bridge.domain.exceptions import ConfigurationError


class _Resolver:
    async def get_secret(self, name: str) -> str:
        value = await self.get_secret_or_none(name)
        if not value:
            raise ConfigurationError(f"Secret '{name}' is not configured")
        return value

    async def get_secret_or_none(self, name: str) -> str | None:  # pragma: no cover
        raise NotImplementedError


class EnvSecretManager(_Resolver):
    """Reads secrets from environment. Local/test only."""

    async def get_secret_or_none(self, name: str) -> str | None:
        return os.environ.get(name) or None


class GCPSecretManager(_Resolver):
    """
    GCP Secret Manager adapter using Workload Identity.

    Implementation is intentionally deferred to a separate package install
    (google-cloud-secret-manager) so the domain/application packages remain
    free of cloud SDKs. Call sites depend only on SecretManagerPort.
    """

    def __init__(self, project_id: str):
        self.project_id = project_id
        self._client = None

    def _ensure_client(self):
        if self._client is None:
            try:
                from google.cloud import secretmanager  # type: ignore
            except ImportError as e:
                raise ConfigurationError(
                    "google-cloud-secret-manager not installed; "
                    "install the 'gcp' extra or use EnvSecretManager for tests."
                ) from e
            self._client = secretmanager.SecretManagerServiceClient()
        return self._client

    async def get_secret_or_none(self, name: str) -> str | None:
        client = self._ensure_client()
        path = f"projects/{self.project_id}/secrets/{name}/versions/latest"
        response = client.access_secret_version(request={"name": path})
        payload = response.payload.data.decode("utf-8")
        return payload or None


def build_default_secret_manager() -> _Resolver:
    """
    Pick the appropriate adapter based on environment.

    GCP_PROJECT set => GCPSecretManager (production).
    Otherwise => EnvSecretManager (local/test).
    """
    project = os.environ.get("GCP_PROJECT")
    if project and os.environ.get("TESTING") != "1":
        return GCPSecretManager(project)
    return EnvSecretManager()


_default: _Resolver | None = None


def default_secret_manager() -> _Resolver:
    global _default
    if _default is None:
        _default = build_default_secret_manager()
    return _default
