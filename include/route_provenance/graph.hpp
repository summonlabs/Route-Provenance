// Route Provenance - bounded provenance DAG.
//
// The graph is explicit and typed. All traversal is bounded by depth, result count and
// visited-node count; all iteration exposed to callers is canonically ordered.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <vector>

#include "route_provenance/limits.hpp"
#include "route_provenance/lineage.hpp"
#include "route_provenance/node.hpp"

namespace route_provenance {

/// Traversal bounds. Zero means "use the store limit".
struct TraversalBounds {
  std::uint32_t max_depth = 0;
  std::uint32_t max_results = 0;
  std::uint32_t max_visited = 0;
};

/// Traversal direction in causal terms. Outgoing edges point from a record towards its
/// causes (predecessor route state, path authorization, adaptive decision, ...); incoming
/// edges point from a record towards the records it caused or that acted upon it.
enum class TraversalDirection : std::uint8_t {
  Outgoing = 0,
  Incoming = 1,
};

/// Optional edge-type filter applied during traversal.
using EdgeTypeFilter = bool (*)(EdgeType);

struct TraversalEntry {
  ProvenanceNode node;
  std::uint32_t depth = 0;
};

struct TraversalResult {
  /// Ordered by (depth, node id).
  std::vector<TraversalEntry> nodes;
  /// Ordered by edge id; every edge whose endpoints are both in frame.
  std::vector<ProvenanceEdge> edges;
  bool truncated = false;
  std::uint32_t max_depth_reached = 0;

  [[nodiscard]] bool contains(ProvenanceNodeId id) const noexcept;
};

class ProvenanceGraph {
 public:
  ProvenanceGraph() = default;

  [[nodiscard]] std::size_t node_count() const noexcept { return nodes_.size(); }
  [[nodiscard]] std::size_t edge_count() const noexcept { return edges_.size(); }

  [[nodiscard]] const ProvenanceNode* find_node(ProvenanceNodeId id) const noexcept;
  [[nodiscard]] const ProvenanceEdge* find_edge(ProvenanceEdgeId id) const noexcept;
  [[nodiscard]] const ProvenanceEdge* find_edge_by_derivation(DerivationId id) const noexcept;

  /// Canonical iteration order: ascending node id.
  [[nodiscard]] std::vector<ProvenanceNode> nodes_in_order() const;
  /// Canonical iteration order: ascending edge id.
  [[nodiscard]] std::vector<ProvenanceEdge> edges_in_order() const;

  [[nodiscard]] Status add_node(const ProvenanceNode& node, const Limits& limits);
  [[nodiscard]] Status add_edge(const ProvenanceEdge& edge, const Limits& limits);

  /// Non-mutating cycle check: returns CycleDetected when inserting from -> to would close a
  /// cycle or create a self edge. A successful return means the edge can be committed.
  [[nodiscard]] Status check_add_edge(ProvenanceNodeId from, ProvenanceNodeId to,
                                      const Limits& limits) const;

  [[nodiscard]] std::vector<ProvenanceEdge> incoming_edges(ProvenanceNodeId id) const;
  [[nodiscard]] std::vector<ProvenanceEdge> outgoing_edges(ProvenanceNodeId id) const;
  [[nodiscard]] std::size_t incoming_count(ProvenanceNodeId id) const noexcept;
  [[nodiscard]] std::size_t outgoing_count(ProvenanceNodeId id) const noexcept;

  [[nodiscard]] Status traverse(ProvenanceNodeId origin, TraversalDirection direction,
                                TraversalBounds bounds, const Limits& limits, TraversalResult& out,
                                EdgeTypeFilter filter = nullptr) const;

  /// Deterministic topological order (Kahn, smallest node id first). Returns nullopt when the
  /// graph contains a cycle, which is a store-integrity failure.
  [[nodiscard]] std::optional<std::vector<ProvenanceNodeId>> topological_order() const;

  /// Canonical digest of the graph and lineage-level state. Independent of insertion order.
  [[nodiscard]] Digest digest(const LineageState& state) const noexcept;

  /// Replaces a node's detail with a compaction summary, preserving its identity so that every
  /// existing edge and every predecessor/successor chain stays intact.
  [[nodiscard]] Status compact_node(ProvenanceNodeId id, const ProvenanceNode& tombstone);

  /// Applies a record-state change (lifecycle, currentness, pending revalidation) to an
  /// existing node. Record state is never part of node identity.
  [[nodiscard]] Status update_node_state(ProvenanceNodeId id, NodeLifecycle lifecycle,
                                         Currentness currentness, bool revalidation_required);
  /// Records that a node has been corrected by another record.
  [[nodiscard]] Status set_corrected_by(ProvenanceNodeId id, ProvenanceNodeId corrected_by);
  /// Records an explicit revalidation of a node by a live authority.
  [[nodiscard]] Status mark_revalidated(ProvenanceNodeId id);

  /// Structural self-check used by tests and by the persistence loader: every edge references
  /// existing nodes, index maps agree with the node/edge sets, and the graph is acyclic.
  [[nodiscard]] Status validate_structure() const;

 private:
  std::map<ProvenanceNodeId, ProvenanceNode> nodes_;
  std::map<ProvenanceEdgeId, ProvenanceEdge> edges_;
  std::map<DerivationId, ProvenanceEdgeId> derivations_;
  std::map<ProvenanceNodeId, std::vector<ProvenanceEdgeId>> outgoing_;
  std::map<ProvenanceNodeId, std::vector<ProvenanceEdgeId>> incoming_;
};

}  // namespace route_provenance
