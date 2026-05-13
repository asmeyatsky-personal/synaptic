# ADR-0005: Synthera ledger is canonical; SynapticBridge is a SIEM fan-out router

**Status:** Accepted
**Date:** 2026-05-13
**Architectural Rules reference:** §4.3 (audit append-only, separate IAM), §6 (observability)
**Depends on:** [ADR-0004](0004-synthera-boundary-contract.md)
**Amends:** [ADR-0001](0001-duckdb-instead-of-postgres.md) (audit-cache scope)

## Context

Both Synthera (`synthera-ledger` + `synthera-trust-audit`) and SynapticBridge
(`infrastructure/adapters/worm_audit.py`) currently write canonical audit
events. Dual-write is an anti-pattern: it produces drift, splits the
investigative source-of-truth, and forces every consumer to choose a side.

Per [ADR-0004](0004-synthera-boundary-contract.md), Synthera owns substrate
primitives. The audit ledger is a substrate primitive (it backs ZT-identity
provenance, policy decisions, and tenant compliance). SynapticBridge owns
the management plane: SIEM fan-out, compliance dashboards, retention policy
configuration, replay/search UI.

## Decision

**Synthera's ledger is the canonical record. SynapticBridge becomes a
read-side fan-out router that subscribes to the Synthera audit stream and
delivers events to SIEMs and compliance consumers.**

Write direction collapses to one path:

```
                                Synthera ledger (canonical)
                                       ▲
                                       │  append (hash-chained, WORM)
                                       │
   tenant ──── tool call ──▶ Synthera kernel ──▶ AuditEvent v2
                                       │
                                       │  BusEnvelope subscription
                                       ▼
                          SynapticBridge audit router
                                       │
              ┌────────────┬───────────┼────────────┬─────────────┐
              ▼            ▼           ▼            ▼             ▼
            Splunk      Datadog    GCP Logging   Azure       Compliance
                                                Sentinel       reports
```

### Rules

1. **SynapticBridge does not write to its own audit log as a canonical
   destination.** The `worm_audit` adapter becomes a *replica*: write-through
   to Synthera first, then mirror locally only as a router buffer. If
   Synthera is unreachable, writes fail closed — no fallback canonical
   path.

2. **Hash chain is owned by Synthera.** SynapticBridge does not produce
   chain hashes. It carries Synthera's hash forward into SIEM events for
   tamper verification at the SIEM tier.

3. **SynapticBridge's `AuditLogPort` becomes a read-and-fanout port.** The
   `write(event)` method is preserved at the application layer (commands
   still emit events), but the infrastructure adapter forwards to Synthera
   over MCP rather than persisting locally.

4. **Local cache, not local truth.** DuckDB-backed `audit_query_cache` may
   exist for fast `/audit?session_id=...` lookups in the admin portal, but
   it MUST be reconstructable from Synthera's stream alone and MUST
   advertise its lag in the response.

5. **Retention is Synthera's call; compliance reporting is
   SynapticBridge's.** Synthera decides what survives where (cold storage,
   purge policy). SynapticBridge produces SOC 2 / ISO / FedRAMP-shaped
   reports from the canonical stream.

6. **SIEM fan-out failures never block writes.** SynapticBridge buffers and
   retries to SIEMs; circuit breakers (already in place) bound the failure
   blast radius. SIEM-side data loss is recoverable from Synthera; the
   reverse is not.

### Event schema

All events flow as Synthera's `AuditEvent v2` (BusEnvelope-wrapped). The
existing `synaptic_bridge.domain.entities.AuditEvent` becomes a thin
adapter type — a Pydantic view over Synthera's schema for the FastAPI
surface, not a parallel definition. Adding fields requires a Synthera
schema bump.

## Why the alternatives lose

- **Dual canonical (status quo).** Two stores, two retention policies, two
  hash chains, two answers to "what really happened." Compliance auditors
  reject this on sight.
- **SynapticBridge canonical, Synthera replica.** Inverts the substrate
  direction and violates [[synthera-vs-products]] (memory).
  Synthera would have to depend on a Python service for its own provenance
  — unacceptable.
- **Pick per-event type.** Splitting events between two canonical stores
  multiplies the failure modes (which store has policy-violation events?
  what about tool-call events emitted by a SynapticBridge admin action?).
  Reject as needlessly complicated.

## Migration

1. Add `SyntheraLedgerAdapter` implementing `AuditLogPort`, writing to
   Synthera over MCP. Land behind a feature flag (`AUDIT_SINK=synthera`).
2. Wire the existing `worm_audit` adapter as a read-only replica from
   Synthera's stream; remove its write path once the flag flips.
3. Migrate historical events. Synthera ingests the existing WORM log as
   bootstrap; SynapticBridge keeps the local file read-only for archive.
4. Update [ADR-0001](0001-duckdb-instead-of-postgres.md) — the DuckDB
   audit-cache scope shrinks to admin-portal lookup only.
5. Adjust SIEM dispatcher to consume Synthera's subscription instead of
   SynapticBridge's local write hook.
6. Compliance reports re-pointed to Synthera as source.

## Consequences

- The §4.3 invariant (append-only, separate IAM) is enforced *once*, in
  Synthera, not twice. Easier to audit.
- One fewer canonical store on the compliance attestation diagram.
- SynapticBridge's audit footprint shrinks to a router + cache, which is
  the shape it should have been all along.
- All four SIEM circuit breakers stay — fan-out reliability concern is
  unchanged.

## Trigger for revisiting

- Synthera's ledger ever needs to be partitioned per tenant in a way that
  doesn't fit the current event schema.
- A regulator demands a separately-IAM'd second canonical (extremely
  unlikely; usually they want fewer, not more).
- BusEnvelope v3 is published; verify the assumptions still hold.
