# ADR-0003: SecretManagerPort with Env and GCP adapters

**Status:** Accepted
**Date:** 2026-05-12
**Architectural Rules reference:** §4.1 (Secret Manager + Workload Identity only)

## Decision

Secrets are accessed through `SecretManagerPort`. Two adapters:

- `GCPSecretManager` — production. Resolves via Workload Identity, no static
  credentials on disk. Selected when `GCP_PROJECT` is set and `TESTING != "1"`.
- `EnvSecretManager` — local development and CI test runs only. Reads from
  `os.environ`. Selecting it in production raises `ConfigurationError`
  unless `TESTING=1`.

Direct `os.environ` reads for secret material outside
`infrastructure/adapters/secret_manager.py` are an architectural violation and
will be caught by code review (a future `bandit` rule should flag this
mechanically).

## Migration

Existing call sites (`_get_jwt_secret`, SIEM connector init, WORM audit init)
should be migrated to inject the port in their constructor. v1 keeps a
synchronous `default_secret_manager()` shim for backwards compatibility; v2
removes the shim.

## Consequences

- All secret resolution is testable with an in-memory port.
- `GCP_PROJECT` becomes the single switch between local and production secret
  resolution.
