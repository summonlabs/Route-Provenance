// Route Provenance - provenance nodes, typed derivation edges and identities.
//
// Identity is content-addressed over a canonical encoding of the immutable core of a
// record. Two identical records constructed in different insertion orders therefore receive
// the same identity, and no insertion-order information can leak into a digest.
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "route_provenance/authority.hpp"
#include "route_provenance/bindings.hpp"
#include "route_provenance/digest.hpp"
#include "route_provenance/enums.hpp"
#include "route_provenance/evidence.hpp"
#include "route_provenance/id.hpp"
#include "route_provenance/result.hpp"

namespace route_provenance {

/// Stable identity of one semantic route: the lineage key. Lineage identity survives
/// ordinary route-generation changes and is derived from this key.
struct LineageKey {
  RouteId route;
  /// Namespace-qualified semantic name of the route (for example a prefix or service key).
  /// Bounded by Limits::max_semantic_key_bytes.
  std::string semantic_key;

  friend bool operator==(const LineageKey&, const LineageKey&) noexcept = default;
};

/// Derives the stable lineage identity for a semantic route key.
[[nodiscard]] RouteLineageId derive_lineage_id(const LineageKey& key) noexcept;

struct ProvenanceNode {
  ProvenanceNodeId id;
  RouteLineageId lineage;
  NodeKind kind = NodeKind::RouteGeneration;
  RouteId route;
  RouteGeneration route_generation;
  Digest route_state_digest;
  ReasonCode reason = ReasonCode::InitialRoute;
  SourceClass source = SourceClass::RouteFabric;
  std::optional<RootReason> root_reason;
  EvidenceVector evidence;
  AuthorityContext authority;
  Bindings bindings;

  // Mutable record state. Never part of the record's identity.
  NodeLifecycle lifecycle = NodeLifecycle::Declared;
  Currentness currentness = Currentness::HistoricalOnly;
  bool revalidation_required = false;
  /// Set when a live authority has explicitly revalidated this record. Revalidation is an
  /// explicit act: it vouches for the record without rewriting who published it.
  bool revalidated = false;
  std::optional<ProvenanceNodeId> corrected_by;
  /// Set on a correction record: the record this one corrects. Part of the record identity.
  std::optional<ProvenanceNodeId> corrects;
  /// Digest of the node detail this tombstone replaced (compaction only).
  std::optional<Digest> compacted_digest;

  [[nodiscard]] Digest core_digest() const noexcept;
  [[nodiscard]] Digest digest() const noexcept;
  [[nodiscard]] bool is_root() const noexcept { return root_reason.has_value(); }
  [[nodiscard]] bool is_route_state() const noexcept { return kind == NodeKind::RouteGeneration; }
};

/// Canonical identity digest of a node: everything except record state and the id itself.
[[nodiscard]] Digest node_core_digest(const ProvenanceNode& node) noexcept;
/// Canonical semantic digest of a node, including lifecycle and currentness.
[[nodiscard]] Digest node_digest(const ProvenanceNode& node) noexcept;

/// A typed derivation edge. The derivation identity is content-addressed over the derivation
/// semantics; the edge identity is content-addressed over the endpoints and that derivation.
struct ProvenanceEdge {
  ProvenanceEdgeId id;
  DerivationId derivation;
  RouteLineageId lineage;
  EdgeType type = EdgeType::DerivedFrom;
  ProvenanceNodeId from;
  ProvenanceNodeId to;
  RouteGeneration predecessor_route_generation;
  RouteGeneration successor_route_generation;
  ReasonCode reason = ReasonCode::InitialRoute;
  SourceClass source = SourceClass::RouteFabric;
  EvidenceVector evidence;
  AuthorityContext authority;

  [[nodiscard]] Digest core_digest() const noexcept;
  [[nodiscard]] Digest digest() const noexcept { return core_digest(); }
};

/// Explicit derivation record bound to its materialised edge.
struct Derivation {
  DerivationId id;
  ProvenanceEdgeId edge;
  RouteLineageId lineage;
  EdgeType type = EdgeType::DerivedFrom;
  ProvenanceNodeId from;
  ProvenanceNodeId to;
  RouteGeneration predecessor_route_generation;
  RouteGeneration successor_route_generation;
  ReasonCode reason = ReasonCode::InitialRoute;
  SourceClass source = SourceClass::RouteFabric;
  EvidenceVector evidence;
  AuthorityContext authority;
};

[[nodiscard]] DerivationId compute_derivation_id(const ProvenanceEdge& edge) noexcept;
[[nodiscard]] ProvenanceEdgeId compute_edge_id(const ProvenanceEdge& edge) noexcept;
/// Assigns derivation and edge identities from content.
void finalize_edge(ProvenanceEdge& edge) noexcept;
/// Assigns the node identity from content.
void finalize_node(ProvenanceNode& node) noexcept;
/// Identity a record must have for its content. Compaction tombstones keep the identity of the
/// record they summarise instead.
[[nodiscard]] ProvenanceNodeId derive_node_id(const ProvenanceNode& node) noexcept;

/// True when the edge type denotes "from is a successor/cause of to" in the route-state
/// successor sense. Used for predecessor/successor chains.
[[nodiscard]] bool edge_type_is_successor_relation(EdgeType type) noexcept;
/// True when the edge type denotes "from is authorized/computed/selected from to".
[[nodiscard]] bool edge_type_is_evidence_relation(EdgeType type) noexcept;
/// True when the edge type denotes an administrative action applied to \p to.
[[nodiscard]] bool edge_type_is_action_relation(EdgeType type) noexcept;

/// Structural consistency of a record. Used by the store before commit and by the
/// persistence loader before admitting a stored node.
[[nodiscard]] Status validate_node_consistency(const ProvenanceNode& node);
[[nodiscard]] Status validate_edge_consistency(const ProvenanceEdge& edge);
/// Legal lifecycle transitions. Prevents impossible lifecycle states from being persisted.
[[nodiscard]] bool is_valid_lifecycle_transition(NodeLifecycle from, NodeLifecycle to) noexcept;

/// True when a record counts against the bounded-history retention policy: superseded,
/// historical or invalidated detail that compaction may summarise. Compaction summaries and
/// current records never count.
[[nodiscard]] bool node_is_history_record(const ProvenanceNode& node) noexcept;

}  // namespace route_provenance
