// Route Provenance - immutable snapshots and deterministic diffs.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "route_provenance/digest.hpp"
#include "route_provenance/id.hpp"
#include "route_provenance/lineage.hpp"
#include "route_provenance/node.hpp"
#include "route_provenance/result.hpp"

namespace route_provenance {

struct SnapshotOptions {
  bool include_edges = true;
  bool include_historical = true;
  std::uint32_t max_nodes = 0;  ///< 0 means "use Limits::max_nodes_per_lineage".
  std::uint32_t max_edges = 0;
};

/// Immutable snapshot of one lineage. Nodes and edges are canonically ordered; the digest is
/// the graph digest at capture time.
struct Snapshot {
  SnapshotId id;
  RouteLineageId lineage;
  LineageKey key;
  LineageLifecycle lifecycle = LineageLifecycle::Active;
  RouteGeneration current_route_generation;
  ProvenanceNodeId current_node;
  LineageGeneration lineage_generation;
  AuthorityGeneration authority_generation;
  ProvenanceGeneration store_generation;
  CoordinatorEpoch coordinator_epoch;
  Currentness current_currentness = Currentness::HistoricalOnly;
  std::vector<ProvenanceNode> nodes;
  std::vector<ProvenanceEdge> edges;
  Digest digest;
  bool truncated = false;

  [[nodiscard]] const ProvenanceNode* find_node(ProvenanceNodeId id) const noexcept;
};

enum class DiffKind : std::uint16_t {
  NodeAdded = 1,
  NodeRemoved = 2,
  EdgeAdded = 3,
  EdgeRemoved = 4,
  CurrentnessChanged = 5,
  LifecycleChanged = 6,
  SupersessionRecorded = 7,
  RevocationRecorded = 8,
  RetirementRecorded = 9,
  CorrectionRecorded = 10,
  AuthorityChanged = 11,
  LineageGenerationChanged = 12,
};

[[nodiscard]] std::string_view to_string(DiffKind kind) noexcept;

struct DiffEntry {
  DiffKind kind = DiffKind::NodeAdded;
  ProvenanceNodeId node;
  ProvenanceEdgeId edge;
  Currentness before_currentness = Currentness::HistoricalOnly;
  Currentness after_currentness = Currentness::HistoricalOnly;
  NodeLifecycle before_lifecycle = NodeLifecycle::Declared;
  NodeLifecycle after_lifecycle = NodeLifecycle::Declared;
  std::string detail;

  friend bool operator==(const DiffEntry&, const DiffEntry&) noexcept = default;
};

/// Deterministic diff between two snapshots of the same lineage.
struct Diff {
  RouteLineageId lineage;
  ProvenanceGeneration from_generation;
  ProvenanceGeneration to_generation;
  LineageGeneration from_lineage_generation;
  LineageGeneration to_lineage_generation;
  std::vector<DiffEntry> entries;  ///< Canonically ordered by (kind, node, edge).
  Digest digest;

  [[nodiscard]] bool empty() const noexcept { return entries.empty(); }
};

struct SnapshotPair {
  Snapshot before;
  Snapshot after;
};

/// Computes the diff from \p before to \p after. Both snapshots must belong to the same
/// lineage; a mismatch is reported as MalformedRequest.
[[nodiscard]] Result<Diff> compute_diff(const Snapshot& before, const Snapshot& after);

}  // namespace route_provenance
