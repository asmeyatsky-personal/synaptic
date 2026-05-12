# ADR-0002: Python-only for v1; defer Rust hot paths

**Status:** Accepted
**Date:** 2026-05-12
**Architectural Rules reference:** §1 (Rust for ledgers, parsers, hot-path APIs <50ms)

## Decision

v1 is Python-only. Rust ports for the audit ledger and policy hot path are
explicitly deferred to v2.

## Why the default fails for v1

- p99 latency targets in the PRD are not yet ratified at <50ms; current SLOs
  are <200ms which Python comfortably meets.
- Rewriting the WORM audit hasher in Rust before measuring real bottlenecks
  would be premature optimisation and double the maintenance surface.
- The ports (`AuditLogPort`, `PolicyEnginePort`) already exist, so the v2
  rewrite is a drop-in adapter swap — no domain change.

## Trigger for revisiting

- p99 of `audit_log.write` exceeds 30ms in staging benchmark, OR
- policy evaluation exceeds 20ms p99 under projected v2 traffic.

The observability module emits `synaptic.duration_ms` histogram per op, so
breaching the threshold will be visible in dashboards.
