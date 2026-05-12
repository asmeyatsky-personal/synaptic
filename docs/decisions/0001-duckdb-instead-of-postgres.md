# ADR-0001: DuckDB as the correction/audit store for v1

**Status:** Accepted
**Date:** 2026-05-12
**Architectural Rules reference:** §1 (stack defaults) — Postgres is the default primary

## Decision

We use DuckDB for the v1 correction store and local audit cache instead of
Postgres.

## Why the default fails for v1

- The Correction Learning Engine is shipped as an **embedded library inside the
  agent runtime**, not a network service. A Postgres dependency would require
  every deployment to run/connect to a database; DuckDB runs in-process.
- v1 workloads are append-heavy analytical scans (pattern lookup over
  embeddings, audit replay) — exactly DuckDB's strength.
- Postgres remains the default for the **multi-tenant orchestration plane**
  (sessions, policies, tenants) when that plane is built; this ADR scopes
  only to the embedded CLE/audit cache.

## Migration path

When CLE moves from per-agent embedded to a shared service:
1. Switch `CorrectionStorePort` adapter from `duckdb_store` to a Postgres
   adapter (already isolated behind the port).
2. WORM audit ledger graduates to a dedicated append-only Postgres + BigQuery
   long-term tier.

## Consequences

- Domain stays clean (port-based), so the swap is a single adapter change.
- Lockfile + SBOM still required (done in CI).
