# ADR-0004: SynapticBridge is a management plane on the Synthera OS

**Status:** Accepted
**Date:** 2026-05-13
**Architectural Rules reference:** §2 (layer direction), §3.5 (one MCP server per bounded context), §7.4 (no MCP sprawl)
**Supersedes:** implicit parity model in v1.0 PRD
**Related:** [ADR-0001](0001-duckdb-instead-of-postgres.md), [ADR-0003](0003-secret-manager-port.md), [ADR-0005](0005-audit-canonicality.md), [ADR-0006](0006-policy-split.md)

## Context

Synthera is the agent operating system — Rust, 19 crates, owner of identity
(VAID v2), the bus envelope, ZT-identity, the scheduler, the sandbox, the
policy hot path, the audit ledger, the trust audit, and the MCP fabric.
Products (Storia, Zetu, Crucible, ShadowStack) consume Synthera over MCP and
never merge into it.

SynapticBridge and Synthera both grew out of the same Labs effort, so they
have overlapping primitives: identity, policy, audit, sandbox, MCP
orchestration. Left unresolved, that overlap produces dual-write bugs, two
canonical stores per concern, and slow drift between OS and management plane.

This ADR picks a direction and commits to it.

## Decision

**Synthera is the substrate. SynapticBridge is a horizontal management plane
that runs as a Synthera tenant.** SynapticBridge does not re-implement
substrate primitives; it consumes them through Synthera's MCP fabric and
exposes higher-level governance, learning, and compliance capabilities to
other Synthera tenants.

The boundary is the MCP fabric in both directions:

```
                ┌─────────────────────────────────────────┐
                │             Synthera (OS)               │
                │  identity · policy(hot) · ledger ·      │
                │  sandbox · scheduler · mesh · kernel    │
                └──┬──────────────────────────────────┬───┘
                   │ MCP                          MCP │
        consumes   ▼                                  ▲   emits
                ┌──────────────────────────────────────┐
                │      SynapticBridge (mgmt plane)     │
                │  CLE · tool registry · policy author │
                │  SIEM fan-out · admin portal · UI    │
                └──────────────────────────────────────┘
                   ▲                                  │
                   │ MCP                          MCP ▼
                ┌──────────────────────────────────────┐
                │  Tenants (Storia, Zetu, Crucible, …) │
                └──────────────────────────────────────┘
```

### Ownership map

| Concern | Owner | SynapticBridge role |
|---|---|---|
| Agent identity (VAID v2) | Synthera (`synthera-zt-identity`) | consumer |
| Bus envelope / wire format | Synthera (`synthera-types`) | consumer |
| Policy *evaluation* (hot path) | Synthera (`synthera-policy`) | consumer |
| Policy *authoring / lifecycle* | SynapticBridge | owner — see ADR-0006 |
| Audit ledger (canonical) | Synthera (`synthera-ledger`, `synthera-trust-audit`) | consumer + replica — see ADR-0005 |
| SIEM fan-out (Splunk/Datadog/GCP/Azure) | SynapticBridge | owner |
| Sandbox execution | Synthera (`synthera-sandbox`) | consumer |
| Tool manifest registry | SynapticBridge | owner; published to Synthera as a resource |
| MCP server lifecycle | SynapticBridge | owner of management-plane servers; Synthera owns kernel-level MCP fabric |
| Correction Learning Engine (algorithm) | SynapticBridge (today) → Synthera (when stable) | owner with graduation path |
| Correction marketplace / UI / admin portal | SynapticBridge | owner |
| Compliance reports (SOC 2, ISO, FedRAMP) | SynapticBridge | owner |
| Per-AI-call cost/latency telemetry | SynapticBridge emits; Synthera (`synthera-telemetry`) aggregates | producer |

### Wire-level rules

1. **Synthera owns the wire formats.** VAID, BusEnvelope, audit event
   schemas, policy DSL bytecode. SynapticBridge consumes them; it MUST NOT
   redefine them. Any duplicated type in SynapticBridge is a bug, caught at
   review.

2. **One canonical store per concern.** No dual-writes. Where SynapticBridge
   needs local state for performance (e.g., DuckDB pattern cache), it is a
   *replica* of a Synthera-owned upstream and must be reconstructable from
   the upstream alone.

3. **All Synthera↔SynapticBridge traffic is BusEnvelope v2.** No bespoke
   HTTP/JSON between the two. The presentation/api FastAPI app stays for
   external tenants, but Synthera↔SynapticBridge speaks MCP.

4. **SynapticBridge's domain layer is Synthera-free.** Import-linter
   enforces. Synthera SDK imports live only under
   `synaptic_bridge/infrastructure/synthera/` (new package, to be created).

### Graduation path for primitives

SynapticBridge is where Labs incubates capabilities that may eventually
graduate to Synthera substrate. Graduation rules:

- A capability graduates when (a) its API has been stable for ≥2 minor
  versions, (b) it has measurable hot-path demand (p99 latency target
  documented), and (c) it has zero Python-ecosystem-only dependencies.
- The CLE algorithm core (cosine sim + pattern decay + undo penalty math) is
  the first graduation candidate → `synthera-cle` Rust crate, expected once
  the math hardens past v1.0.
- After graduation, SynapticBridge keeps the *management plane* for the
  capability (authoring, simulation, marketplace, dashboards) and consumes
  the Synthera crate for runtime evaluation. This is the same shape as
  ADR-0006 for policy.

## Why the alternatives lose

- **Two-substrate parity.** Two identity systems, two ledgers, two policy
  hot paths. Dual-write bugs, drift, and a violation of [[synthera-vs-products]]
  (memory): Synthera is the substrate; nothing else duplicates the substrate.
- **Merge SynapticBridge into Synthera.** Synthera is Rust and substrate-shaped.
  SynapticBridge contains research-shaped ML (CLE), product-shaped UI (admin
  portal), and integration-shaped SIEM glue — all wrong shapes for the OS
  repo. Memory [[synthera-vs-products]] explicitly forbids folding products
  into the OS.
- **Hard fork the CLE to Synthera now.** The CLE algorithm is still
  research-iterating (embedding model swaps, threshold tuning, undo-penalty
  curves). Locking it into Rust before the math stabilises burns velocity.

## Migration

The boundary is largely already correct because SynapticBridge's hex
architecture exists. The work:

1. Create `synaptic_bridge/infrastructure/synthera/` package. Implement
   Synthera-backed adapters for `ExecutionPort`, `AuditLogPort` (see
   ADR-0005), `PolicyEnginePort` (see ADR-0006), and a new
   `IdentityPort` (VAID-aware).
2. Add an MCP client to Synthera's kernel; SynapticBridge calls become MCP
   tool invocations under the hood. The existing FastAPI surface stays for
   external tenants.
3. Add `import-linter` contracts:
   - `synaptic_bridge.domain` and `synaptic_bridge.application` forbid the
     `synthera_sdk` package.
   - `synaptic_bridge.infrastructure.synthera` is the only module allowed to
     import `synthera_sdk`.
4. Tenants stop talking to SynapticBridge directly for identity/audit/policy
   evaluation; they call Synthera and Synthera enriches with
   SynapticBridge data via MCP.

## Consequences

- Existing in-memory adapters (`InMemoryAuditLog`, `InMemoryPolicyEngine`,
  `InMemoryExecutionAdapter`) stay for tests; Synthera-backed adapters
  replace them in prod.
- The DuckDB correction store becomes a local cache only; ADR-0001 is
  amended accordingly when the Synthera-backed `CorrectionStorePort`
  adapter lands.
- The admin portal and tool registry remain in SynapticBridge — these are
  the management surfaces tenants will want.
- Versioning: SynapticBridge ships as a *Synthera-compatible* tenant; major
  version bumps pin against a Synthera BusEnvelope version.

## Trigger for revisiting

- Synthera changes its substrate boundary (new substrate primitive
  introduced or removed).
- The CLE graduates to Synthera; that triggers an amendment, not a new ADR.
- A tenant requires capabilities that don't fit either side cleanly.
