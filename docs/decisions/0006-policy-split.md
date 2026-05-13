# ADR-0006: Synthera evaluates policy; SynapticBridge authors, simulates, and governs

**Status:** Accepted
**Date:** 2026-05-13
**Architectural Rules reference:** §3.6 (DAGs and timeouts), §4 (security), §6 (observability)
**Depends on:** [ADR-0004](0004-synthera-boundary-contract.md)

## Context

Two policy engines exist:

- `synthera-policy` (Rust crate) — designed for inline, per-call evaluation
  on the agent hot path. Target p99 < 5 ms.
- SynapticBridge's OPA/Rego engine — designed for human-authored,
  version-controlled, simulation-friendly policy management.

Both can answer "is this tool call allowed?" but their shapes are
incompatible: OPA/Rego is too slow for inline gating, and Rust hot-path
bytecode is too opaque for product owners to author.

Per [ADR-0004](0004-synthera-boundary-contract.md), Synthera owns substrate.
Policy evaluation on the agent hot path is substrate; policy *lifecycle*
(authoring, review, simulation, marketplace, audit, retirement) is
management plane.

## Decision

**Synthera owns runtime policy evaluation. SynapticBridge owns the policy
lifecycle and compiles authored policies into Synthera's native format.**

```
   ┌──────────────────────────────────────────┐
   │           SynapticBridge                  │
   │                                           │
   │  ┌─────────────┐   ┌─────────────────┐   │
   │  │  Rego/OPA   │──▶│ Policy compiler  │   │
   │  │  authoring  │   │  Rego → Synthera │   │
   │  └─────────────┘   │     bytecode     │   │
   │                    └────────┬─────────┘   │
   │  ┌─────────────┐            │             │
   │  │ Simulation  │            ▼             │
   │  │ shadow runs │   ┌─────────────────┐   │
   │  └─────────────┘   │  Signed bundle  │   │
   │  ┌─────────────┐   │   (versioned)   │   │
   │  │ Marketplace │   └────────┬─────────┘   │
   │  │ approval    │            │             │
   │  └─────────────┘            │ MCP publish │
   └─────────────────────────────┼─────────────┘
                                 ▼
   ┌──────────────────────────────────────────┐
   │   Synthera-policy (per-call hot path)     │
   │   evaluates compiled bytecode <5 ms p99   │
   └──────────────────────────────────────────┘
                  ▲
                  │ inline gate
   ┌──────────────────────────────────────────┐
   │          Tenant agent execution           │
   └──────────────────────────────────────────┘
```

### Rules

1. **Synthera-policy is the only evaluator on the hot path.** No tenant
   call invokes OPA at request time. If the policy isn't in Synthera's
   evaluator, it isn't enforced.

2. **SynapticBridge produces signed, versioned policy bundles.** A bundle
   carries: source Rego (for auditability), compiled Synthera bytecode (for
   execution), a SemVer, a SHA-256, a signing key reference, and a
   `simulated_against` field listing the traces it was shadow-tested on.

3. **Policies are published over MCP.** SynapticBridge's
   `PolicyMCPServer.publish_bundle` is the *write*. Synthera pulls and
   activates after its own verification (signature, schema, dry-run pass).
   No direct DB writes across the boundary.

4. **The Rego→Synthera compiler is a deterministic library.** Same
   source produces same bytecode, same SHA. Compiler version is part of
   the bundle. If the compiler changes how a Rego construct lowers, that
   forces a bundle re-publish — the lower-level bytecode is *not* edited
   by hand.

5. **Simulation is mandatory before activation.** SynapticBridge runs the
   candidate policy against the last N production traces in shadow mode;
   the report is attached to the bundle. Synthera rejects bundles missing
   the simulation manifest.

6. **Emergency overrides** (kill-switches, break-glass) bypass the normal
   publish flow but produce an `EmergencyPolicyOverride` audit event on
   the canonical ledger (see [ADR-0005](0005-audit-canonicality.md)).

### What stays in SynapticBridge

- Rego authoring UI / admin portal policy pages
- Policy version control, diff review, approval workflow
- Shadow simulation harness (replay against historical traces)
- Marketplace (publish/subscribe to community policy bundles)
- Per-tenant policy roll-out (canary % per tenant)
- Compliance reports ("which controls map to which active policies?")
- Tags, scopes, descriptions — metadata Synthera doesn't need at runtime

### What leaves SynapticBridge

- The OPA evaluator at request time
- `evaluate(policy, context) -> bool` returning from
  `infrastructure/adapters/opa_engine.py` for hot-path calls — replaced by
  a thin Synthera-MCP client adapter

## Why the alternatives lose

- **OPA inline on the hot path.** OPA evaluation latency is a known issue
  in agent runtimes; Synthera's <5 ms target is incompatible.
- **Synthera-policy as the only surface.** Forces product owners to author
  in Rust-flavoured bytecode. Unacceptable usability tax; only ML engineers
  end up able to write policy, which becomes a bottleneck and a security
  risk.
- **Sync both directions.** Bi-directional policy state quickly drifts.
  One-way publish (Bridge → Synthera) keeps the model coherent.
- **Skip simulation.** A policy change can lock a whole tenant out of tool
  use. Shadow-run is the cheapest possible safety net.

## Migration

1. Define bundle schema (`PolicyBundle v1`) in `synthera-types`.
   SynapticBridge consumes the schema; never redefines it.
2. Build the Rego→Synthera compiler. Initial scope: the subset of Rego
   already used in production policies. Reject unsupported constructs at
   author time, not at publish time.
3. Replace `OPAPolicyEngine.evaluate(...)` in
   `synaptic_bridge/infrastructure/adapters/opa_engine.py` with a
   `SyntheraPolicyEvaluator` that calls Synthera over MCP. Keep the OPA
   binding for the simulation/shadow path only.
4. Wire a `PolicyMCPServer.publish_bundle` tool; remove direct policy
   inserts from FastAPI.
5. Update [`AddPolicyCommand`](../../synaptic_bridge/application/commands/__init__.py)
   to produce a bundle and call `publish_bundle`, not a local store.
6. Update the admin portal "Policies" view to surface activation status
   reported by Synthera, not local DB state.

## Consequences

- SynapticBridge no longer enforces policy at request time. Tenants who
  bypass Synthera (impossible by design after ADR-0004) would lose
  enforcement — acceptable because that path doesn't exist.
- Policy authoring stays ergonomic; runtime stays fast.
- One source of truth for "what's active right now" — Synthera.
- Simulation gate becomes a first-class artifact, addressing a real-world
  failure mode (policy change locks a tenant out).

## Trigger for revisiting

- Synthera changes its policy bytecode format (compiler re-write needed,
  not an ADR change).
- A class of policy emerges that can't lower into Synthera bytecode
  (extremely unlikely if compiler scope is honest about what it accepts).
- Shadow-simulation latency becomes a publish-time bottleneck — split into
  async pipeline, still under this ADR.
