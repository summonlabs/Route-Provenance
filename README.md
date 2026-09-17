# Route Provenance

Route Provenance is the authoritative route-lineage, derivation-history, evidence-binding and
explanation runtime of the Distributed Fabric Infrastructure stack. It answers one question:

> Why does this exact route state exist, which authoritative facts, decisions, generations,
> policies, paths, publishers and prior route states produced it, what lineage connects it to
> what came before, and when must that provenance be rejected, fenced, superseded, invalidated
> or revalidated?

Version 1.0.0. C++20. Vendor neutral: nothing in this runtime depends on a specific switch,
silicon vendor or orchestration product.

## Boundary

Route Provenance owns route-provenance record identity, route-lineage identity, derivation
identity, parent/child route-state ancestry, predecessor/successor relationships, route,
path-authority, planner, adaptive, convergence, policy, ECMP and weighted-path generation
bindings, evidence-vector binding, mutation/publisher/authority provenance, supersession,
replacement, withdrawal, retirement, revocation, rollback, correction, explanation traces,
deterministic provenance graphs, snapshots, diffs, digests, stale-provenance fencing,
currentness, bounded history, persistence, conservative recovery and distributed publication
authority.

Route Provenance does **not** own canonical entity identity, topology, link-state truth, port
configuration, capability truth, failure-domain truth, Fabric Epoch issuance, path computation,
path legality, route lifecycle, route installation, multipath membership, ECMP assignment,
weighted-path policy, adaptive-routing policy, convergence sequencing, traffic engineering,
bandwidth reservation, congestion control or physical forwarding.

| Authority | Owns | Route Provenance binds |
| --- | --- | --- |
| Route Fabric | authoritative route lifecycle and route state | RouteId, exact RouteGeneration, route-state digest |
| Path Planner | candidate path computation | planner request, planner generation, candidate rank, plan digest, selected PathId |
| Path Authority | exact path legality | PathId, PathAuthorityGeneration, authorization decision digest |
| Adaptive Routing Fabric | evidence-driven preference change | AdaptationDecisionId, adaptation/policy/evidence generations, decision digest |
| Route Convergence | deterministic transition execution | ConvergencePlanId, plan generation, step id, completion evidence |
| ECMP Governor | equal-cost assignment | EcmpGroupId, membership and assignment generations |
| Weighted Path Fabric | explicit path weights | WeightedPathSetId, weight-policy and assignment generations |
| Fabric Registry, Topology, Link State, Port Fabric, Capability Registry, Failure Domain Registry, Fabric Epoch | identity, graph, link state, ports, capabilities, failure domains, epoch | the exact generations recorded in the evidence vector |

Route Provenance never creates route authority, installs or withdraws a route, mutates next
hops, decides path legality, computes candidates, chooses adaptations, executes convergence, or
programs forwarding state. It records and governs why those route states exist.

## Provenance is not logging

A provenance record is structured, typed, generation-bound, queryable, validated control-plane
state. Logs may exist for diagnostics; they are not the provenance authority. Every record
carries structured reason codes (`INITIAL_ROUTE`, `ROUTE_REPLACED`, `ADAPTIVE_CHANGE`,
`CONVERGENCE_COMPLETE`, `ROLLBACK`, `REVOCATION`, `RETIREMENT`, `CORRECTION`, ...), a source
class, an explicit authority context and an exact evidence vector.

## Provenance is not history alone

History answers "what happened?". Provenance answers "what authoritative facts and decisions
caused this exact state?". The provenance graph is an explicit bounded DAG whose nodes are
records (route state, path authorization, planner candidate, adaptive decision, convergence plan,
policy decision, administrative action, compaction summary) and whose edges are **typed
derivations**, never a generic "parent" relation:

`DERIVED_FROM`, `SUPERSEDES`, `REPLACES`, `WITHDRAWS`, `REVALIDATES`, `AUTHORIZED_BY`,
`COMPUTED_FROM`, `SELECTED_FROM`, `ADAPTED_FROM`, `TRANSITIONED_BY`, `ROLLED_BACK_FROM`,
`REVOKED_BY`, `RETIRED_BY`, `CORRECTS`, `INVALIDATES`.

Edge direction is causal: an edge points from a record towards the records that caused it. In
Route Provenance, *parents* are direct causes, *children* are direct effects, *ancestors* are
the causal ancestry of a record and *descendants* are the records that derive from it.

## Lineage identity

A route lineage is the stable ancestry chain for one semantic route identity
(`RouteId` + semantic key). Lineage identity is derived deterministically and survives
ordinary generation changes; unrelated lineage identities are never minted for a new
generation.

## Records, derivation identity and digests

Record identity is content addressed over a canonical encoding of the immutable core of the
record (lineage, kind, route, exact generation, route-state digest, reason, source, root reason,
evidence vector, authority context, bindings). Two identical records constructed in any
insertion order therefore receive the same identity, and no insertion-order information can
leak into a digest. Record *state* (lifecycle, currentness, pending revalidation, correction
markers) is never part of identity. Each typed derivation has its own content-addressed
`DerivationId`; graph digests, node digests, snapshot digests and diff digests are computed over
canonical encodings that exclude timestamps, addresses, thread ids, handles, insertion order and
diagnostic counters.

## Evidence vectors

An evidence vector binds the exact upstream generations a derivation depends on (topology,
link-state, port, capability, failure-domain, Fabric Epoch, path authority, planner, adaptive
policy, convergence plan, route, publisher). Entries are canonicalised: equivalent evidence
inserted in a different order yields an identical digest, explanation and snapshot. Absent
generations are never "generation zero": a zero generation is rejected.

## Historical validity versus currentness

Historical validity and currentness are separate. A record can be historically valid and no
longer current evidence for present authority. For example: route generation 7 was legitimately
authorized by PathAuthorityGeneration 12; generation 13 later supersedes path legality; the
provenance of generation 7 remains historically valid, but it no longer proves present
authority. Route Provenance reports that as `historically_valid=true, currentness=STALE_PATH_AUTHORITY`.

Currentness values: `CURRENT`, `STALE_ROUTE`, `STALE_PATH_AUTHORITY`, `STALE_POLICY`,
`STALE_EVIDENCE`, `STALE_EPOCH`, `FENCED_PUBLISHER`, `HISTORICAL_ONLY`,
`REVALIDATION_REQUIRED`. Currentness is a pure function of record state, lineage state, upstream
watermarks and publisher liveness, evaluated in a fixed documented precedence. No later
dependency change ever erases valid history.

## Lifecycle operations

* **Supersession** records predecessor, successor, typed edge, reason and authority context.
* **Withdrawal** is not deletion: the withdrawal is a typed administrative record and the
  historical ancestry is preserved.
* **Revocation** is an explicit administrative act, distinct from evidence-driven invalidation.
* **Retirement** permanently ends lineage currentness; late supersession, revalidation,
  correction and replay cannot resurrect it.
* **Rollback** records the abandoned target, the actual rollback source, the rollback target,
  the convergence plan and the authority; the failed branch stays visible.
* **Correction** never rewrites history: the corrected record remains visible and marked
  invalid, the replacement becomes the authoritative explanation, and the replacement re-binds
  the same causal predecessors.
* **Recovery** after restart is recorded separately and never rewrites the original cause.

## Queries, explanations and bounded traversal

Queries cover parents, children, ancestors, descendants, predecessor and successor chains,
causes, explanations, routes derived from a `PathId`, routes derived from a policy generation,
routes bound to a path-authority generation and publications by a worker boot. Reverse indexes
answer these without scanning every record. Explanations support immediate cause, full bounded
ancestry, authority-only, policy-only, path-only and mutation-lineage modes; results are
canonically ordered. Every traversal is bounded by maximum depth, maximum results and maximum
visited nodes, and a bound breach is reported as a structured `RESOURCE_LIMIT` outcome (an
explanation reports `truncated=true`).

## Snapshots, diffs and digests

Snapshots are immutable, canonically ordered and digest-bound. Diffs report node additions,
edge additions, currentness changes, lifecycle changes, supersession, revocation, retirement,
correction and authority changes in a stable order.

## Persistence and recovery

The store file is versioned, deterministic, integrity-checked (SHA-256 trailer over the whole
image), bounds-checked and written atomically through a temporary file. Loading rejects wrong
magic, unsupported versions, truncation, trailing bytes, integrity mismatches, duplicate records
or edges, missing endpoints, cycles, invalid source generations, impossible lifecycles, absurd
counts and malformed enumerations. Live session authority is never persisted as current: after a
restart every record whose currentness depended on live process state requires revalidation,
while all history survives byte for byte.

## Distributed model

The coordinator (`rp_coordinator`) hosts one store and owns publication authority for it. A
publisher (`rp_publisher`) is a real OS process that registers a worker boot with the current
coordinator epoch and then publishes. Frames are fixed-layout, explicitly versioned, bound in
size and integrity-checked over the semantic header and payload; payloads are canonical field
bags that reject unknown fields, duplicated fields, length mismatches, trailing bytes, unknown
message identifiers and unknown enumeration values. Partial frames are assembled against a
bounded budget and a peer that never completes a frame is failed explicitly. A session that ends
— by clean disconnect or by process death — fences that worker boot permanently: the boot may
never publish again, its historical records stay valid, and a restarted publisher must present a
fresh `WorkerBootId`. The coordinator detects session loss with an independent liveness probe so
a killed worker is observed without waiting for a timeout.

This is a **single-coordinator authority model**. It is not a consensus protocol, it does not
provide shared exclusion and it makes no split-brain-prevention claim.

## Validation classes

REAL: real OS coordinator, publisher and client processes; real process termination; real
loopback TCP transport; real persistence files; real cryptographic digests (SHA-256).

SYNTHETIC: large provenance DAGs, deep chains, broad DAGs, 1k/10k lineage populations and
fabricated policy, convergence and adaptation histories. Synthetic scale figures are labelled as
such and are evidence about provenance volume and graph shape only.

UNSUPPORTED / NOT IMPLEMENTED: physical switch programming, physical packet tracing,
cryptographically attested or signed provenance, multi-host consensus, split-brain prevention,
and integrations with providers that are not present in this repository. Route Provenance makes
no claim about any of these.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Options: `RP_BUILD_TOOLS`, `RP_BUILD_EXAMPLES`, `RP_BUILD_TESTS`, `RP_BUILD_BENCHMARKS`,
`RP_WARNINGS_AS_ERRORS` (default ON), `RP_ENABLE_ANALYZE` (MSVC `/analyze`) and
`RP_ENABLE_ASAN` (AddressSanitizer where the toolchain actually ships it).

## Test

```sh
ctest --test-dir build -C Release --output-on-failure
```

Suites: `unit`, `store`, `persistence`, `wire`, `race`, `property`, `adversarial`, `oracle`,
`scale` and `distributed` (real processes). No test timeout is configured anywhere: every bounded
wait inside the suites fails explicitly with a diagnostic instead of hanging.

## Install and consume

```sh
cmake --install build --prefix /somewhere
```

```cmake
find_package(RouteProvenance CONFIG REQUIRED)
target_link_libraries(app PRIVATE SummonSoftwareLabs::RouteProvenance)
```

The exported package provides `RouteProvenanceConfig.cmake`, a version file and the imported
target `SummonSoftwareLabs::RouteProvenance` with its include directories and the package
version.

## Examples

Nine examples use the public API only and are registered as tests:

`ex_initial_lineage`, `ex_supersession`, `ex_path_authority`, `ex_adaptive_decision`,
`ex_convergence`, `ex_rollback`, `ex_historical_currentness`, `ex_worker_reincarnation`,
`ex_coordinator_restart`.

## Tools

* `rp_coordinator --store <path> [--port N] [--load] [--ready-file <path>]` — hosts the store,
  serves sessions and accepts `save`, `stats`, `epoch <n>` and `quit` on stdin.
* `rp_publisher --connect <ip:port> --publisher N --boot N --epoch N --script <file>` — executes
  a deterministic publication script.
* `rpctl version | store inspect | lineage list|show | provenance show | ancestry | descendants |
  cause | snapshot | diff` — read-only against a store file, or online against a coordinator;
  mutation commands require a live coordinator because publication authority is not a local
  privilege. Output is one `key=value` record per line with no timestamps.

## Ownership, lifetime and thread safety

Values are copyable and self-contained. `ProvenanceStore` is not copyable; a single instance
may be queried concurrently from many threads, and independent lineages may be published
concurrently. Mutations of one lineage are serialised and resolve deterministically. Snapshots,
explanations and traversal results are immutable values. Accessors that return references refer
to the returned value, never to store internals.

## Retention semantics

`Limits::max_nodes_per_lineage`, `max_edges_per_lineage`, `max_parents_per_node`,
`max_children_per_node` and `max_history_nodes_per_lineage` bound lineage growth; reaching the
bounded-history bound is reported as `RESOURCE_LIMIT` and requires compaction
(`compact()`) or an explicit limit change. Compaction never prunes a record that the present
explanation still needs, and every compacted record leaves a tombstone that preserves its
identity, route generation and semantic digest so that predecessor and successor chains stay
intact. `max_traversal_depth`, `max_query_results`, `max_visited_nodes` and
`max_explanation_nodes` bound every traversal; caller-supplied bounds may narrow a traversal but
never widen it beyond the configured limits.

## Genuine limitations

* A coordinator restart advances the epoch and requires explicit revalidation before recovered
  records are current again; Route Provenance does not claim that live authority survives a
  restart, and it does not restore publisher sessions.
* Fencing is enforced by the coordinator that owns the store. There is no shared exclusion
  between two coordinators, so running two coordinators over one store is not supported.
* Provenance authenticity is integrity-checked, not cryptographically attested or signed.
* Verification was performed on Windows x64 with MSVC; the POSIX socket and file paths are
  implemented but were not validated on this host (see [VALIDATION.md](VALIDATION.md)).
* AddressSanitizer for x64 MSVC is not installed in this build environment; the exact linker
  evidence is recorded in [VALIDATION.md](VALIDATION.md). The Debug configuration, which enables
  the MSVC debug runtime checks, was used as the compensating control instead.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
