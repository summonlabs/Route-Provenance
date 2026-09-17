// Route Provenance - internal store structures shared by the store and persistence units.
//
// This header is not installed and is not part of the public API.
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <shared_mutex>
#include <string>
#include <vector>

#include "route_provenance/store.hpp"

namespace route_provenance {

/// Checked generation advance: returns false instead of wrapping at the 64-bit boundary.
template <class Generation>
[[nodiscard]] inline bool bump_generation(Generation& value) noexcept {
  const std::optional<Generation> next = value.try_next();
  if (!next.has_value()) {
    return false;
  }
  value = *next;
  return true;
}

/// Validates a lineage key (route identity, bounded printable semantic key).
[[nodiscard]] Status check_lineage_key(const LineageKey& key, const Limits& limits);

/// The operation a normalized request performs.
enum class PublishKind : std::uint16_t {
  RouteState = 1,
  Declaration = 2,
  Link = 3,
  Withdrawal = 4,
  Revocation = 5,
  Retirement = 6,
  Revalidation = 7,
  Invalidation = 8,
  Correction = 9,
};

/// A publication request after request-level validation, in the single form the commit
/// pipeline consumes.
struct NormalizedPublication {
  PublishKind kind = PublishKind::RouteState;
  LineageKey key;
  std::optional<RouteLineageId> explicit_lineage;
  NodeKind node_kind = NodeKind::RouteGeneration;
  RouteId route;
  RouteGeneration route_generation;
  Digest route_state_digest;
  ReasonCode reason = ReasonCode::InitialRoute;
  SourceClass source = SourceClass::RouteFabric;
  std::optional<RootReason> root_reason;
  EvidenceVector evidence;
  AuthorityContext authority;
  Bindings bindings;
  std::vector<EdgeSpec> edges;
  EdgeType link_type = EdgeType::AuthorizedBy;
  ProvenanceNodeId link_from;
  ProvenanceNodeId target;
  Digest completion_evidence;
  bool allow_non_current_target = false;
};

/// Internal state of a two-phase publication session.
struct PublicationSessionState {
  PublishRouteRequest request;
  NormalizedPublication normalized;
};

/// True when the record kind denotes an upstream authority declaration.
[[nodiscard]] bool is_declaration_kind(NodeKind kind) noexcept;

/// A declaration must carry exactly the binding that identifies the authority it declares.
[[nodiscard]] Status check_declaration_bindings(NodeKind kind, const Bindings& bindings);

/// Ledger entry for one publication attempt. Exact replay returns the recorded publication;
/// the same attempt id with different content is a conflict.
struct AttemptRecord {
  Digest request;
  ProvenanceNodeId node;
  std::vector<ProvenanceEdgeId> edges;
  Outcome outcome = Outcome::Created;
  Currentness currentness = Currentness::HistoricalOnly;
  NodeLifecycle lifecycle = NodeLifecycle::Current;
};

/// Attempt identity is scoped to the publisher that chose it: two publishers may independently
/// use the same attempt number without colliding.
struct AttemptKey {
  PublisherId publisher;
  MutationAttemptId attempt;

  friend bool operator<(const AttemptKey& left, const AttemptKey& right) noexcept {
    if (left.publisher != right.publisher) {
      return left.publisher < right.publisher;
    }
    return left.attempt < right.attempt;
  }
};

/// One route lineage: stable identity, bounded DAG, attempt ledger.
struct Lineage {
  mutable std::shared_mutex mutex;
  LineageState state;
  ProvenanceGraph graph;
  std::map<AttemptKey, AttemptRecord> attempts;
};

/// Liveness of a publisher boot as known to this process.
enum class PublisherLiveness : std::uint8_t {
  Live = 0,     ///< Registered and permitted to publish.
  Fenced = 1,   ///< Registered and explicitly fenced, or superseded by a fresh boot.
  Unknown = 2,  ///< Never registered in this process (for example after a restart).
};

struct PublisherKey {
  PublisherId publisher;
  WorkerBootId boot;

  friend bool operator<(const PublisherKey& left, const PublisherKey& right) noexcept {
    if (left.publisher != right.publisher) {
      return left.publisher < right.publisher;
    }
    return left.boot < right.boot;
  }
};

struct ProvenanceStore::Impl {
  explicit Impl(Limits store_limits) : limits(store_limits) {}

  Limits limits;

  /// Guards the lineage registry and the route-to-lineage index. Acquired before a lineage
  /// lock and never while holding one.
  mutable std::shared_mutex registry_mutex;
  std::map<RouteLineageId, std::shared_ptr<Lineage>> lineages;
  std::map<RouteId, RouteLineageId> route_index;

  /// Leaf lock: guards the reverse indexes, the node owner map and the global watermarks.
  /// No other lock is ever acquired while this one is held.
  mutable std::shared_mutex index_mutex;
  std::map<ProvenanceNodeId, RouteLineageId> node_owner;
  std::map<RouteId, std::map<RouteGeneration, ProvenanceNodeId>> route_generation_index;
  std::map<PathId, std::set<ProvenanceNodeId>> path_index;
  std::map<PathAuthorityGeneration, std::set<ProvenanceNodeId>> path_authority_index;
  std::map<PolicyGeneration, std::set<ProvenanceNodeId>> policy_index;
  std::map<EvidenceGeneration, std::set<ProvenanceNodeId>> evidence_index;
  std::map<WorkerBootId, std::set<ProvenanceNodeId>> boot_index;
  std::map<PublisherId, std::set<ProvenanceNodeId>> publisher_index;
  DependencyWatermarks watermarks;

  /// Leaf lock: guards the publisher registry.
  mutable std::mutex publisher_mutex;
  std::map<PublisherKey, PublisherRecord> publishers;

  bool recovered = false;
  /// Set once a recovered coordinator has re-established epoch authority.
  bool epoch_bootstrapped = false;
  Digest image_digest;

  [[nodiscard]] std::optional<PublisherRecord> find_publisher(PublisherId publisher,
                                                              WorkerBootId boot) const;
  [[nodiscard]] bool publisher_is_live(PublisherId publisher, WorkerBootId boot) const;
  [[nodiscard]] PublisherLiveness publisher_state(PublisherId publisher, WorkerBootId boot) const;
  [[nodiscard]] DependencyWatermarks read_watermarks() const;

  /// Finds or creates a lineage. Returns nullptr when the lineage limit is reached.
  [[nodiscard]] std::shared_ptr<Lineage> acquire_lineage(RouteLineageId id, const LineageKey& key,
                                                         bool create, bool& created);
  [[nodiscard]] std::shared_ptr<Lineage> find_lineage(RouteLineageId id) const;

  /// The single authoritative commit pipeline. Stage order is fixed and documented.
  [[nodiscard]] Result<Publication> commit(const NormalizedPublication& request);

  /// Recomputes record state for one node of a lineage (lineage lock must be held).
  void reevaluate_node(Lineage& lineage, ProvenanceNodeId id);
  /// Recomputes record state for every node of a lineage (lineage lock must be held).
  void reevaluate_all(Lineage& lineage);
  /// Recomputes record state for the given nodes of a lineage (lineage lock must be held).
  Status reevaluate_nodes(Lineage& lineage, const std::vector<ProvenanceNodeId>& ids);
  /// Recomputes record state for nodes selected by a store index, without holding a lineage
  /// lock on entry. Used by dependency notifications, fencing and epoch advance.
  void reevaluate_index(const std::vector<ProvenanceNodeId>& ids);

  [[nodiscard]] Result<TraversalResult> traverse_from(ProvenanceNodeId id, TraversalDirection direction,
                                                     TraversalBounds bounds,
                                                     EdgeTypeFilter filter) const;
  [[nodiscard]] Result<std::vector<ProvenanceNode>> nodes_from_index(
      const std::vector<ProvenanceNodeId>& ids, TraversalBounds bounds) const;

  void index_node(const ProvenanceNode& node, RouteLineageId lineage);
  void index_edge(const ProvenanceEdge& edge);
  [[nodiscard]] std::uint64_t next_store_generation(bool& ok);
};

}  // namespace route_provenance
