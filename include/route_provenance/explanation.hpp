// Route Provenance - bounded explanations.
//
// Human rendering is derived from structured provenance. Nothing here stores prose as the
// authority; an explanation is a traversal result over typed edges with structured reasons.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "route_provenance/digest.hpp"
#include "route_provenance/enums.hpp"
#include "route_provenance/id.hpp"
#include "route_provenance/node.hpp"
#include "route_provenance/result.hpp"

namespace route_provenance {

struct ExplainRequest {
  ProvenanceNodeId subject;
  ExplainMode mode = ExplainMode::ImmediateCause;
  std::uint32_t max_depth = 0;  ///< 0 means "use Limits::max_traversal_depth".
  std::uint32_t max_nodes = 0;  ///< 0 means "use Limits::max_explanation_nodes".
};

struct ExplanationStep {
  std::uint32_t depth = 0;
  ProvenanceEdgeId edge;
  EdgeType type = EdgeType::DerivedFrom;
  ProvenanceNodeId from;
  ProvenanceNodeId to;
  NodeKind kind = NodeKind::RouteGeneration;
  ReasonCode reason = ReasonCode::InitialRoute;
  SourceClass source = SourceClass::RouteFabric;
  RouteGeneration route_generation;
  NodeLifecycle lifecycle = NodeLifecycle::Declared;
  Currentness currentness = Currentness::HistoricalOnly;
  bool historically_valid = false;
  bool current = false;
};

/// A bounded explanation of why a record exists. Historical validity and currentness are
/// reported separately: a record can remain historically valid while no longer proving
/// present authority.
struct Explanation {
  ProvenanceNodeId subject;
  ExplainMode mode = ExplainMode::ImmediateCause;
  RouteLineageId lineage;
  LineageKey key;
  NodeLifecycle subject_lifecycle = NodeLifecycle::Declared;
  Currentness subject_currentness = Currentness::HistoricalOnly;
  bool historically_valid = false;
  bool current = false;
  std::vector<ExplanationStep> steps;  ///< Ordered by (depth, edge id).
  bool truncated = false;
  Digest digest;
};

/// True when a record was accepted and remains a truthful statement about the past, whether
/// or not it still proves present authority.
[[nodiscard]] bool node_is_historically_valid(const ProvenanceNode& node) noexcept;

/// Edge-type filter for an explanation mode. Exposed because it is part of the documented
/// explanation semantics.
[[nodiscard]] bool edge_matches_mode(EdgeType type, ExplainMode mode) noexcept;

/// Deterministic multi-line rendering used by the CLI. Derived, never authoritative.
[[nodiscard]] std::string render_explanation(const Explanation& explanation);

}  // namespace route_provenance
