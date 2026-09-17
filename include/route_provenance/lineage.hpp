// Route Provenance - route lineage state.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "route_provenance/digest.hpp"
#include "route_provenance/enums.hpp"
#include "route_provenance/id.hpp"
#include "route_provenance/node.hpp"

namespace route_provenance {

/// Mutable lineage-level state. Lineage identity is stable; generations advance only on
/// semantic mutation, never on reads, exact replays or unchanged revalidation.
struct LineageState {
  RouteLineageId id;
  LineageKey key;
  LineageLifecycle lifecycle = LineageLifecycle::Active;
  RouteGeneration current_route_generation;
  ProvenanceNodeId current_node;
  LineageGeneration lineage_generation;
  AuthorityGeneration authority_generation;
  std::uint64_t node_count = 0;
  std::uint64_t edge_count = 0;
  std::uint64_t compacted_node_count = 0;
  /// Derived: number of records that count against the bounded-history policy.
  std::uint64_t history_node_count = 0;
  /// Publisher boot that most recently published into this lineage.
  WorkerBootId last_publisher_boot;
  Digest last_mutation_digest;
};

/// Immutable, canonically ordered view of a lineage.
struct LineageView {
  RouteLineageId id;
  LineageKey key;
  LineageLifecycle lifecycle = LineageLifecycle::Active;
  RouteGeneration current_route_generation;
  ProvenanceNodeId current_node;
  LineageGeneration lineage_generation;
  AuthorityGeneration authority_generation;
  std::uint64_t node_count = 0;
  std::uint64_t edge_count = 0;
  std::uint64_t compacted_node_count = 0;
  Currentness current_currentness = Currentness::HistoricalOnly;
  Digest digest;
};

}  // namespace route_provenance
