// Route Provenance - queries, snapshots, diffs, explanations, compaction and statistics.
#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include "route_provenance/version.hpp"
#include "store_internal.hpp"

namespace route_provenance {
namespace {

[[nodiscard]] LineageView make_view(const Lineage& lineage) {
  LineageView view;
  view.id = lineage.state.id;
  view.key = lineage.state.key;
  view.lifecycle = lineage.state.lifecycle;
  view.current_route_generation = lineage.state.current_route_generation;
  view.current_node = lineage.state.current_node;
  view.lineage_generation = lineage.state.lineage_generation;
  view.authority_generation = lineage.state.authority_generation;
  view.node_count = lineage.graph.node_count();
  view.edge_count = lineage.graph.edge_count();
  view.compacted_node_count = 0;
  for (const ProvenanceNode& node : lineage.graph.nodes_in_order()) {
    if (node.kind == NodeKind::CompactedSummary) {
      view.compacted_node_count += 1;
    }
  }
  const ProvenanceNode* current = lineage.graph.find_node(lineage.state.current_node);
  view.current_currentness = current != nullptr ? current->currentness : Currentness::HistoricalOnly;
  view.digest = lineage.graph.digest(lineage.state);
  return view;
}

[[nodiscard]] Result<TraversalResult> traverse_lineage(const Lineage& lineage, ProvenanceNodeId origin,
                                                       TraversalDirection direction,
                                                       TraversalBounds bounds, const Limits& limits,
                                                       EdgeTypeFilter filter) {
  TraversalResult out;
  const Status status = lineage.graph.traverse(origin, direction, bounds, limits, out, filter);
  if (!status.is_ok()) {
    return Result<TraversalResult>::failure(status.outcome(), status.detail());
  }
  return Result<TraversalResult>::ok(std::move(out));
}

[[nodiscard]] bool successor_only(EdgeType type) noexcept { return edge_type_is_successor_relation(type); }

// Edge-type filters for explanation modes are plain function pointers so that traversal never
// allocates and never captures mutable state.
[[nodiscard]] bool mode_filter_immediate(EdgeType) noexcept { return true; }
[[nodiscard]] bool mode_filter_full(EdgeType) noexcept { return true; }
[[nodiscard]] bool mode_filter_authority(EdgeType type) noexcept {
  return edge_matches_mode(type, ExplainMode::AuthorityOnly);
}
[[nodiscard]] bool mode_filter_policy(EdgeType type) noexcept {
  return edge_matches_mode(type, ExplainMode::PolicyOnly);
}
[[nodiscard]] bool mode_filter_path(EdgeType type) noexcept {
  return edge_matches_mode(type, ExplainMode::PathOnly);
}
[[nodiscard]] bool mode_filter_mutation(EdgeType type) noexcept {
  return edge_matches_mode(type, ExplainMode::MutationLineage);
}

[[nodiscard]] EdgeTypeFilter filter_for_mode(ExplainMode mode) noexcept {
  switch (mode) {
    case ExplainMode::ImmediateCause: return &mode_filter_immediate;
    case ExplainMode::FullAncestry: return &mode_filter_full;
    case ExplainMode::AuthorityOnly: return &mode_filter_authority;
    case ExplainMode::PolicyOnly: return &mode_filter_policy;
    case ExplainMode::PathOnly: return &mode_filter_path;
    case ExplainMode::MutationLineage: return &mode_filter_mutation;
  }
  return &mode_filter_full;
}
[[nodiscard]] bool causal_only(EdgeType type) noexcept {
  return edge_type_is_successor_relation(type) || edge_type_is_evidence_relation(type);
}

[[nodiscard]] std::vector<ProvenanceNode> materialize(const Lineage& lineage,
                                                      const std::vector<ProvenanceNodeId>& ids,
                                                      std::uint32_t max_results) {
  std::vector<ProvenanceNode> out;
  for (const ProvenanceNodeId id : ids) {
    if (out.size() >= max_results) {
      break;
    }
    const ProvenanceNode* node = lineage.graph.find_node(id);
    if (node != nullptr) {
      out.push_back(*node);
    }
  }
  std::sort(out.begin(), out.end(), [](const ProvenanceNode& left, const ProvenanceNode& right) {
    return left.id < right.id;
  });
  return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// Lineage and record queries
// ---------------------------------------------------------------------------

Result<LineageView> ProvenanceStore::lineage(RouteLineageId id) const {
  if (!id.valid()) {
    return Result<LineageView>::failure(Outcome::MalformedRequest, "lineage identity is not valid");
  }
  const std::shared_ptr<Lineage> lineage = impl_->find_lineage(id);
  if (lineage == nullptr) {
    return Result<LineageView>::failure(Outcome::LineageNotFound, "no such route lineage");
  }
  std::shared_lock<std::shared_mutex> lock(lineage->mutex);
  return Result<LineageView>::ok(make_view(*lineage));
}

Result<LineageView> ProvenanceStore::lineage_for_route(RouteId route) const {
  if (!route.valid()) {
    return Result<LineageView>::failure(Outcome::MalformedRequest, "route identity is not valid");
  }
  RouteLineageId id;
  {
    std::shared_lock<std::shared_mutex> lock(impl_->registry_mutex);
    const auto it = impl_->route_index.find(route);
    if (it == impl_->route_index.end()) {
      return Result<LineageView>::failure(Outcome::LineageNotFound, "no lineage for that route");
    }
    id = it->second;
  }
  return lineage(id);
}

Result<std::vector<LineageView>> ProvenanceStore::list_lineages() const {
  std::vector<std::shared_ptr<Lineage>> snapshot;
  {
    std::shared_lock<std::shared_mutex> lock(impl_->registry_mutex);
    snapshot.reserve(impl_->lineages.size());
    for (const auto& entry : impl_->lineages) {
      snapshot.push_back(entry.second);
    }
  }
  if (snapshot.size() > impl_->limits.max_query_results) {
    return Result<std::vector<LineageView>>::failure(Outcome::ResourceLimit,
                                                     "lineage count exceeds max_query_results");
  }
  std::vector<LineageView> views;
  views.reserve(snapshot.size());
  for (const std::shared_ptr<Lineage>& lineage : snapshot) {
    std::shared_lock<std::shared_mutex> lock(lineage->mutex);
    views.push_back(make_view(*lineage));
  }
  std::sort(views.begin(), views.end(),
            [](const LineageView& left, const LineageView& right) { return left.id < right.id; });
  return Result<std::vector<LineageView>>::ok(std::move(views));
}

Result<ProvenanceNode> ProvenanceStore::node(ProvenanceNodeId id) const {
  if (!id.valid()) {
    return Result<ProvenanceNode>::failure(Outcome::MalformedRequest, "record identity is not valid");
  }
  RouteLineageId owner;
  {
    std::shared_lock<std::shared_mutex> lock(impl_->index_mutex);
    const auto it = impl_->node_owner.find(id);
    if (it == impl_->node_owner.end()) {
      return Result<ProvenanceNode>::failure(Outcome::NodeNotFound, "no such provenance record");
    }
    owner = it->second;
  }
  const std::shared_ptr<Lineage> lineage = impl_->find_lineage(owner);
  if (lineage == nullptr) {
    return Result<ProvenanceNode>::failure(Outcome::LineageNotFound, "record owner lineage is missing");
  }
  std::shared_lock<std::shared_mutex> lock(lineage->mutex);
  const ProvenanceNode* found = lineage->graph.find_node(id);
  if (found == nullptr) {
    return Result<ProvenanceNode>::failure(Outcome::NodeNotFound, "no such provenance record");
  }
  return Result<ProvenanceNode>::ok(*found);
}

Result<ProvenanceNode> ProvenanceStore::route_node(RouteId route, RouteGeneration generation) const {
  if (!route.valid() || !generation.valid()) {
    return Result<ProvenanceNode>::failure(Outcome::MalformedRequest,
                                           "route identity and generation are required");
  }
  ProvenanceNodeId id;
  {
    std::shared_lock<std::shared_mutex> lock(impl_->index_mutex);
    const auto route_it = impl_->route_generation_index.find(route);
    if (route_it == impl_->route_generation_index.end()) {
      return Result<ProvenanceNode>::failure(Outcome::NodeNotFound, "no provenance for that route");
    }
    const auto generation_it = route_it->second.find(generation);
    if (generation_it == route_it->second.end()) {
      return Result<ProvenanceNode>::failure(Outcome::NodeNotFound,
                                             "no provenance record for that route generation");
    }
    id = generation_it->second;
  }
  return node(id);
}

Result<std::vector<ProvenanceEdge>> ProvenanceStore::parents(ProvenanceNodeId id) const {
  if (!id.valid()) {
    return Result<std::vector<ProvenanceEdge>>::failure(Outcome::MalformedRequest,
                                                        "record identity is not valid");
  }
  RouteLineageId owner;
  {
    std::shared_lock<std::shared_mutex> lock(impl_->index_mutex);
    const auto it = impl_->node_owner.find(id);
    if (it == impl_->node_owner.end()) {
      return Result<std::vector<ProvenanceEdge>>::failure(Outcome::NodeNotFound,
                                                          "no such provenance record");
    }
    owner = it->second;
  }
  const std::shared_ptr<Lineage> lineage = impl_->find_lineage(owner);
  if (lineage == nullptr) {
    return Result<std::vector<ProvenanceEdge>>::failure(Outcome::LineageNotFound,
                                                        "record owner lineage is missing");
  }
  std::shared_lock<std::shared_mutex> lock(lineage->mutex);
  if (lineage->graph.find_node(id) == nullptr) {
    return Result<std::vector<ProvenanceEdge>>::failure(Outcome::NodeNotFound,
                                                        "no such provenance record");
  }
  return Result<std::vector<ProvenanceEdge>>::ok(lineage->graph.outgoing_edges(id));
}

Result<std::vector<ProvenanceEdge>> ProvenanceStore::children(ProvenanceNodeId id) const {
  if (!id.valid()) {
    return Result<std::vector<ProvenanceEdge>>::failure(Outcome::MalformedRequest,
                                                        "record identity is not valid");
  }
  RouteLineageId owner;
  {
    std::shared_lock<std::shared_mutex> lock(impl_->index_mutex);
    const auto it = impl_->node_owner.find(id);
    if (it == impl_->node_owner.end()) {
      return Result<std::vector<ProvenanceEdge>>::failure(Outcome::NodeNotFound,
                                                          "no such provenance record");
    }
    owner = it->second;
  }
  const std::shared_ptr<Lineage> lineage = impl_->find_lineage(owner);
  if (lineage == nullptr) {
    return Result<std::vector<ProvenanceEdge>>::failure(Outcome::LineageNotFound,
                                                        "record owner lineage is missing");
  }
  std::shared_lock<std::shared_mutex> lock(lineage->mutex);
  if (lineage->graph.find_node(id) == nullptr) {
    return Result<std::vector<ProvenanceEdge>>::failure(Outcome::NodeNotFound,
                                                        "no such provenance record");
  }
  return Result<std::vector<ProvenanceEdge>>::ok(lineage->graph.incoming_edges(id));
}

// ---------------------------------------------------------------------------
// Bounded traversal
// ---------------------------------------------------------------------------

Result<TraversalResult> ProvenanceStore::Impl::traverse_from(ProvenanceNodeId id,
                                                             TraversalDirection direction,
                                                             TraversalBounds bounds,
                                                             EdgeTypeFilter filter) const {
  const Impl& impl = *this;
  if (!id.valid()) {
    return Result<TraversalResult>::failure(Outcome::MalformedRequest, "record identity is not valid");
  }
  RouteLineageId owner;
  {
    std::shared_lock<std::shared_mutex> lock(impl.index_mutex);
    const auto it = impl.node_owner.find(id);
    if (it == impl.node_owner.end()) {
      return Result<TraversalResult>::failure(Outcome::NodeNotFound, "no such provenance record");
    }
    owner = it->second;
  }
  const std::shared_ptr<Lineage> lineage = impl.find_lineage(owner);
  if (lineage == nullptr) {
    return Result<TraversalResult>::failure(Outcome::LineageNotFound, "record owner lineage is missing");
  }
  std::shared_lock<std::shared_mutex> lock(lineage->mutex);
  return traverse_lineage(*lineage, id, direction, bounds, impl.limits, filter);
}

Result<TraversalResult> ProvenanceStore::ancestors(ProvenanceNodeId id, TraversalBounds bounds) const {
  return impl_->traverse_from(id, TraversalDirection::Outgoing, bounds, nullptr);
}

Result<TraversalResult> ProvenanceStore::descendants(ProvenanceNodeId id, TraversalBounds bounds) const {
  return impl_->traverse_from(id, TraversalDirection::Incoming, bounds, nullptr);
}

Result<TraversalResult> ProvenanceStore::predecessor_chain(ProvenanceNodeId id,
                                                           TraversalBounds bounds) const {
  return impl_->traverse_from(id, TraversalDirection::Outgoing, bounds, &successor_only);
}

Result<TraversalResult> ProvenanceStore::successor_chain(ProvenanceNodeId id,
                                                         TraversalBounds bounds) const {
  return impl_->traverse_from(id, TraversalDirection::Incoming, bounds, &successor_only);
}

Result<std::vector<ProvenanceNode>> ProvenanceStore::causes(ProvenanceNodeId id,
                                                            TraversalBounds bounds) const {
  const Result<TraversalResult> traversal =
      impl_->traverse_from(id, TraversalDirection::Outgoing, bounds, &causal_only);
  if (!traversal.has_value()) {
    return Result<std::vector<ProvenanceNode>>::failure(traversal.outcome(), traversal.detail());
  }
  std::vector<ProvenanceNode> nodes;
  for (const TraversalEntry& entry : traversal.value().nodes) {
    if (entry.node.id != id) {
      nodes.push_back(entry.node);
    }
  }
  return Result<std::vector<ProvenanceNode>>::ok(std::move(nodes));
}

// ---------------------------------------------------------------------------
// Explanations
// ---------------------------------------------------------------------------

Result<Explanation> ProvenanceStore::explain(const ExplainRequest& request) const {
  if (!request.subject.valid()) {
    return Result<Explanation>::failure(Outcome::MalformedRequest, "explanation subject is not valid");
  }
  RouteLineageId owner;
  {
    std::shared_lock<std::shared_mutex> lock(impl_->index_mutex);
    const auto it = impl_->node_owner.find(request.subject);
    if (it == impl_->node_owner.end()) {
      return Result<Explanation>::failure(Outcome::NodeNotFound, "no such provenance record");
    }
    owner = it->second;
  }
  const std::shared_ptr<Lineage> lineage = impl_->find_lineage(owner);
  if (lineage == nullptr) {
    return Result<Explanation>::failure(Outcome::LineageNotFound, "record owner lineage is missing");
  }
  std::shared_lock<std::shared_mutex> lock(lineage->mutex);
  const ProvenanceNode* subject = lineage->graph.find_node(request.subject);
  if (subject == nullptr) {
    return Result<Explanation>::failure(Outcome::NodeNotFound, "no such provenance record");
  }

  Explanation explanation;
  explanation.subject = subject->id;
  explanation.mode = request.mode;
  explanation.lineage = lineage->state.id;
  explanation.key = lineage->state.key;
  explanation.subject_lifecycle = subject->lifecycle;
  explanation.subject_currentness = subject->currentness;
  explanation.historically_valid = node_is_historically_valid(*subject);
  explanation.current = subject->currentness == Currentness::Current;

  TraversalBounds bounds;
  bounds.max_depth = request.max_depth;
  bounds.max_results = request.max_nodes;
  bounds.max_visited = request.max_nodes == 0 ? impl_->limits.max_visited_nodes
                                              : (request.max_nodes > impl_->limits.max_visited_nodes
                                                     ? request.max_nodes
                                                     : impl_->limits.max_visited_nodes);
  if (request.mode == ExplainMode::ImmediateCause && bounds.max_depth == 0) {
    bounds.max_depth = 1;
  }
  TraversalResult traversal;
  const Status status =
      lineage->graph.traverse(subject->id, TraversalDirection::Outgoing, bounds, impl_->limits,
                              traversal, filter_for_mode(request.mode));
  if (!status.is_ok()) {
    if (status.outcome() != Outcome::ResourceLimit) {
      return Result<Explanation>::failure(status.outcome(), status.detail());
    }
    explanation.truncated = true;
  }

  std::map<ProvenanceNodeId, std::uint32_t> depth_of;
  for (const TraversalEntry& entry : traversal.nodes) {
    depth_of[entry.node.id] = entry.depth;
  }
  struct StepKey {
    std::uint32_t depth;
    ProvenanceEdgeId edge;
  };
  std::vector<std::pair<StepKey, ExplanationStep>> steps;
  for (const TraversalEntry& entry : traversal.nodes) {
    for (const ProvenanceEdge& edge : lineage->graph.outgoing_edges(entry.node.id)) {
      if (!edge_matches_mode(edge.type, request.mode)) {
        continue;
      }
      const auto target_depth = depth_of.find(edge.to);
      if (target_depth == depth_of.end()) {
        continue;
      }
      const ProvenanceNode* target = lineage->graph.find_node(edge.to);
      if (target == nullptr) {
        continue;
      }
      ExplanationStep step;
      step.depth = entry.depth + 1;
      step.edge = edge.id;
      step.type = edge.type;
      step.from = edge.from;
      step.to = edge.to;
      step.kind = target->kind;
      step.reason = edge.reason;
      step.source = edge.source;
      step.route_generation = target->route_generation;
      step.lifecycle = target->lifecycle;
      step.currentness = target->currentness;
      step.historically_valid = node_is_historically_valid(*target);
      step.current = target->currentness == Currentness::Current;
      steps.emplace_back(StepKey{step.depth, edge.id}, step);
    }
  }
  std::sort(steps.begin(), steps.end(), [](const auto& left, const auto& right) {
    if (left.first.depth != right.first.depth) {
      return left.first.depth < right.first.depth;
    }
    return left.first.edge < right.first.edge;
  });
  const std::uint32_t max_steps =
      request.max_nodes == 0 ? impl_->limits.max_explanation_nodes : request.max_nodes;
  for (const auto& entry : steps) {
    if (explanation.steps.size() >= max_steps) {
      explanation.truncated = true;
      break;
    }
    explanation.steps.push_back(entry.second);
  }

  CanonicalEncoder encoder;
  encoder.add_u32(1, kGraphEncodingVersion);
  encoder.add_u64(2, explanation.subject.value());
  encoder.add_u16(3, static_cast<std::uint16_t>(explanation.mode));
  encoder.add_u64(4, explanation.lineage.value());
  encoder.add_bool(5, explanation.historically_valid);
  encoder.add_bool(6, explanation.current);
  encoder.add_u32(7, static_cast<std::uint32_t>(explanation.steps.size()));
  for (const ExplanationStep& step : explanation.steps) {
    CanonicalEncoder nested;
    nested.add_u32(1, step.depth);
    nested.add_u64(2, step.edge.value());
    nested.add_u16(3, static_cast<std::uint16_t>(step.type));
    nested.add_u64(4, step.from.value());
    nested.add_u64(5, step.to.value());
    nested.add_u16(6, static_cast<std::uint16_t>(step.reason));
    nested.add_u16(7, static_cast<std::uint16_t>(step.currentness));
    encoder.add_nested(8, nested);
  }
  explanation.digest = encoder.digest("rp.explanation.v1");
  return Result<Explanation>::ok(std::move(explanation));
}

// ---------------------------------------------------------------------------
// Reverse-index queries
// ---------------------------------------------------------------------------

Result<std::vector<ProvenanceNode>> ProvenanceStore::Impl::nodes_from_index(
    const std::vector<ProvenanceNodeId>& ids, TraversalBounds bounds) const {
  const Impl& impl = *this;
  const std::uint32_t configured = impl.limits.max_query_results;
  const std::uint32_t max_results =
      bounds.max_results == 0 ? configured
                              : (bounds.max_results < configured ? bounds.max_results : configured);
  if (ids.size() > max_results) {
    return Result<std::vector<ProvenanceNode>>::failure(
        Outcome::ResourceLimit, "query result count exceeds the configured bound");
  }
  std::map<RouteLineageId, std::vector<ProvenanceNodeId>> grouped;
  {
    std::shared_lock<std::shared_mutex> lock(impl.index_mutex);
    for (const ProvenanceNodeId id : ids) {
      const auto owner = impl.node_owner.find(id);
      if (owner != impl.node_owner.end()) {
        grouped[owner->second].push_back(id);
      }
    }
  }
  std::vector<ProvenanceNode> out;
  for (const auto& entry : grouped) {
    const std::shared_ptr<Lineage> lineage = impl.find_lineage(entry.first);
    if (lineage == nullptr) {
      continue;
    }
    std::shared_lock<std::shared_mutex> lock(lineage->mutex);
    const std::vector<ProvenanceNode> nodes = materialize(*lineage, entry.second, max_results);
    out.insert(out.end(), nodes.begin(), nodes.end());
  }
  std::sort(out.begin(), out.end(), [](const ProvenanceNode& left, const ProvenanceNode& right) {
    return left.id < right.id;
  });
  if (out.size() > max_results) {
    out.resize(max_results);
  }
  return Result<std::vector<ProvenanceNode>>::ok(std::move(out));
}

Result<std::vector<ProvenanceNode>> ProvenanceStore::routes_derived_from_path(
    PathId path, TraversalBounds bounds) const {
  if (!path.valid()) {
    return Result<std::vector<ProvenanceNode>>::failure(Outcome::MalformedRequest,
                                                        "path identity is not valid");
  }
  std::vector<ProvenanceNodeId> ids;
  {
    std::shared_lock<std::shared_mutex> lock(impl_->index_mutex);
    const auto it = impl_->path_index.find(path);
    if (it != impl_->path_index.end()) {
      ids.assign(it->second.begin(), it->second.end());
    }
  }
  return impl_->nodes_from_index(ids, bounds);
}

Result<std::vector<ProvenanceNode>> ProvenanceStore::routes_for_path_authority(
    PathAuthorityGeneration generation, TraversalBounds bounds) const {
  if (!generation.valid()) {
    return Result<std::vector<ProvenanceNode>>::failure(Outcome::MalformedRequest,
                                                        "path authority generation is not valid");
  }
  std::vector<ProvenanceNodeId> ids;
  {
    std::shared_lock<std::shared_mutex> lock(impl_->index_mutex);
    const auto it = impl_->path_authority_index.find(generation);
    if (it != impl_->path_authority_index.end()) {
      ids.assign(it->second.begin(), it->second.end());
    }
  }
  return impl_->nodes_from_index(ids, bounds);
}

Result<std::vector<ProvenanceNode>> ProvenanceStore::routes_derived_from_policy(
    PolicyGeneration generation, TraversalBounds bounds) const {
  if (!generation.valid()) {
    return Result<std::vector<ProvenanceNode>>::failure(Outcome::MalformedRequest,
                                                        "policy generation is not valid");
  }
  std::vector<ProvenanceNodeId> ids;
  {
    std::shared_lock<std::shared_mutex> lock(impl_->index_mutex);
    const auto it = impl_->policy_index.find(generation);
    if (it != impl_->policy_index.end()) {
      ids.assign(it->second.begin(), it->second.end());
    }
  }
  return impl_->nodes_from_index(ids, bounds);
}

Result<std::vector<ProvenanceNode>> ProvenanceStore::publications_by_publisher_boot(
    WorkerBootId boot, TraversalBounds bounds) const {
  if (!boot.valid()) {
    return Result<std::vector<ProvenanceNode>>::failure(Outcome::MalformedRequest,
                                                        "worker boot identity is not valid");
  }
  std::vector<ProvenanceNodeId> ids;
  {
    std::shared_lock<std::shared_mutex> lock(impl_->index_mutex);
    const auto it = impl_->boot_index.find(boot);
    if (it != impl_->boot_index.end()) {
      ids.assign(it->second.begin(), it->second.end());
    }
  }
  return impl_->nodes_from_index(ids, bounds);
}

// ---------------------------------------------------------------------------
// Snapshots and diffs
// ---------------------------------------------------------------------------

Result<Snapshot> ProvenanceStore::snapshot(RouteLineageId id, SnapshotOptions options) const {
  if (!id.valid()) {
    return Result<Snapshot>::failure(Outcome::MalformedRequest, "lineage identity is not valid");
  }
  const std::shared_ptr<Lineage> lineage = impl_->find_lineage(id);
  if (lineage == nullptr) {
    return Result<Snapshot>::failure(Outcome::LineageNotFound, "no such route lineage");
  }
  std::shared_lock<std::shared_mutex> lock(lineage->mutex);
  const std::uint32_t max_nodes =
      options.max_nodes == 0 ? impl_->limits.max_nodes_per_lineage : options.max_nodes;
  const std::uint32_t max_edges =
      options.max_edges == 0 ? impl_->limits.max_edges_per_lineage : options.max_edges;
  if (lineage->graph.node_count() > max_nodes) {
    return Result<Snapshot>::failure(Outcome::ResourceLimit, "snapshot exceeds max_nodes");
  }
  if (options.include_edges && lineage->graph.edge_count() > max_edges) {
    return Result<Snapshot>::failure(Outcome::ResourceLimit, "snapshot exceeds max_edges");
  }

  Snapshot snapshot;
  snapshot.lineage = lineage->state.id;
  snapshot.key = lineage->state.key;
  snapshot.lifecycle = lineage->state.lifecycle;
  snapshot.current_route_generation = lineage->state.current_route_generation;
  snapshot.current_node = lineage->state.current_node;
  snapshot.lineage_generation = lineage->state.lineage_generation;
  snapshot.authority_generation = lineage->state.authority_generation;
  snapshot.store_generation = impl_->read_watermarks().store_generation;
  snapshot.coordinator_epoch = impl_->read_watermarks().epoch;
  const ProvenanceNode* current = lineage->graph.find_node(lineage->state.current_node);
  snapshot.current_currentness = current != nullptr ? current->currentness : Currentness::HistoricalOnly;
  snapshot.nodes = lineage->graph.nodes_in_order();
  if (!options.include_historical) {
    snapshot.nodes.erase(
        std::remove_if(snapshot.nodes.begin(), snapshot.nodes.end(),
                       [](const ProvenanceNode& node) {
                         return node.currentness != Currentness::Current;
                       }),
        snapshot.nodes.end());
  }
  if (options.include_edges) {
    snapshot.edges = lineage->graph.edges_in_order();
  }
  snapshot.digest = lineage->graph.digest(lineage->state);
  snapshot.id = SnapshotId::from_value(derive_id(snapshot.digest));
  return Result<Snapshot>::ok(std::move(snapshot));
}

Result<Diff> ProvenanceStore::diff(const Snapshot& before, const Snapshot& after) const {
  return compute_diff(before, after);
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

Result<StoreStats> ProvenanceStore::stats() const {
  std::vector<std::shared_ptr<Lineage>> lineages;
  {
    std::shared_lock<std::shared_mutex> lock(impl_->registry_mutex);
    lineages.reserve(impl_->lineages.size());
    for (const auto& entry : impl_->lineages) {
      lineages.push_back(entry.second);
    }
  }
  StoreStats stats;
  stats.lineage_count = lineages.size();
  for (const std::shared_ptr<Lineage>& lineage : lineages) {
    std::shared_lock<std::shared_mutex> lock(lineage->mutex);
    stats.node_count += lineage->graph.node_count();
    stats.edge_count += lineage->graph.edge_count();
    for (const ProvenanceNode& node : lineage->graph.nodes_in_order()) {
      if (node.currentness == Currentness::Current) {
        stats.current_node_count += 1;
      }
      if (node.kind == NodeKind::CompactedSummary) {
        stats.compacted_node_count += 1;
      } else if (node.lifecycle == NodeLifecycle::Invalid) {
        stats.invalid_node_count += 1;
      } else if (node.lifecycle == NodeLifecycle::Historical ||
                 node.lifecycle == NodeLifecycle::Superseded) {
        stats.historical_node_count += 1;
      }
    }
  }
  {
    std::lock_guard<std::mutex> lock(impl_->publisher_mutex);
    stats.publisher_count = impl_->publishers.size();
    for (const auto& entry : impl_->publishers) {
      if (entry.second.live) {
        stats.live_publisher_count += 1;
      }
    }
  }
  {
    std::shared_lock<std::shared_mutex> lock(impl_->index_mutex);
    stats.route_index_entries = impl_->route_generation_index.size();
    stats.path_index_entries = impl_->path_index.size();
    stats.policy_index_entries = impl_->policy_index.size();
    stats.publisher_index_entries = impl_->boot_index.size();
    stats.store_generation = impl_->watermarks.store_generation;
    stats.epoch = impl_->watermarks.epoch;
  }
  return Result<StoreStats>::ok(stats);
}

// ---------------------------------------------------------------------------
// Bounded-history compaction
// ---------------------------------------------------------------------------

Result<CompactResult> ProvenanceStore::compact(RouteLineageId id, const AuthorityContext& authority,
                                               CompactOptions options) {
  if (!id.valid()) {
    return Result<CompactResult>::failure(Outcome::MalformedRequest, "lineage identity is not valid");
  }
  if (!authority.has_identity()) {
    return Result<CompactResult>::failure(Outcome::Unauthorized,
                                          "compaction requires a full publisher identity");
  }
  const DependencyWatermarks marks = impl_->read_watermarks();
  if (!marks.epoch.valid() || authority.publisher.epoch != marks.epoch) {
    return Result<CompactResult>::failure(Outcome::StaleEpoch, "compaction epoch is not current");
  }
  if (!impl_->publisher_is_live(authority.publisher.publisher, authority.publisher.boot)) {
    return Result<CompactResult>::failure(Outcome::StaleWorker,
                                          "compaction requires a live administrative session");
  }
  const std::shared_ptr<Lineage> lineage = impl_->find_lineage(id);
  if (lineage == nullptr) {
    return Result<CompactResult>::failure(Outcome::LineageNotFound, "no such route lineage");
  }
  std::unique_lock<std::shared_mutex> lock(lineage->mutex);
  const ScopeTarget target{RoutingNamespaceId{}, id, lineage->state.key.route};
  if (!authority.scope.permits(target)) {
    return Result<CompactResult>::failure(Outcome::Unauthorized,
                                          "compaction authority scope does not cover the lineage");
  }

  // Records that the present explanation still needs are never pruned.
  std::set<ProvenanceNodeId> protected_nodes;
  protected_nodes.insert(lineage->state.current_node);
  for (const ProvenanceNode& node : lineage->graph.nodes_in_order()) {
    if (node.currentness == Currentness::Current || node.revalidation_required) {
      protected_nodes.insert(node.id);
    }
  }
  TraversalResult ancestry;
  if (lineage->state.current_node.valid()) {
    TraversalBounds bounds;
    bounds.max_depth = options.retain_explanation_depth == 0 ? impl_->limits.max_traversal_depth
                                                             : options.retain_explanation_depth;
    static_cast<void>(lineage->graph.traverse(lineage->state.current_node,
                                              TraversalDirection::Outgoing, bounds, impl_->limits,
                                              ancestry, nullptr));
    for (const TraversalEntry& entry : ancestry.nodes) {
      protected_nodes.insert(entry.node.id);
    }
  }

  std::vector<ProvenanceNode> candidates;
  for (const ProvenanceNode& node : lineage->graph.nodes_in_order()) {
    if (node.kind == NodeKind::CompactedSummary) {
      continue;
    }
    if (!node_is_history_record(node)) {
      continue;
    }
    if (protected_nodes.find(node.id) != protected_nodes.end()) {
      continue;
    }
    candidates.push_back(node);
  }
  std::sort(candidates.begin(), candidates.end(),
            [](const ProvenanceNode& left, const ProvenanceNode& right) {
              if (left.route_generation != right.route_generation) {
                return left.route_generation < right.route_generation;
              }
              return left.id < right.id;
            });

  std::uint32_t budget = options.max_compactions == 0 ? impl_->limits.max_batch_size
                                                      : options.max_compactions;
  CompactResult result;
  for (const ProvenanceNode& candidate : candidates) {
    if (budget == 0) {
      break;
    }
    --budget;
    ProvenanceNode tombstone = candidate;
    tombstone.kind = NodeKind::CompactedSummary;
    tombstone.reason = ReasonCode::HistoryCompaction;
    tombstone.source = SourceClass::Administrative;
    tombstone.authority = authority;
    tombstone.lifecycle = NodeLifecycle::Historical;
    tombstone.currentness = Currentness::HistoricalOnly;
    tombstone.revalidation_required = false;
    tombstone.corrected_by.reset();
    tombstone.corrects.reset();
    tombstone.root_reason.reset();
    tombstone.evidence = EvidenceVector{};
    tombstone.bindings = Bindings{};
    tombstone.compacted_digest = candidate.core_digest();
    const Status compacted = lineage->graph.compact_node(candidate.id, tombstone);
    if (!compacted.is_ok()) {
      return Result<CompactResult>(compacted.outcome(), std::nullopt, compacted.detail());
    }
    result.tombstones.push_back(candidate.id);
    result.compacted += 1;
  }

  lineage->state.node_count = lineage->graph.node_count();
  lineage->state.edge_count = lineage->graph.edge_count();
  lineage->state.compacted_node_count += result.compacted;
  lineage->state.history_node_count = 0;
  for (const ProvenanceNode& node : lineage->graph.nodes_in_order()) {
    if (node_is_history_record(node)) {
      lineage->state.history_node_count += 1;
    }
  }
  if (result.compacted > 0) {
    if (!bump_generation(lineage->state.lineage_generation)) {
      return Result<CompactResult>::failure(Outcome::ResourceLimit, "lineage generation exhausted");
    }
    bool advanced = true;
    {
      std::unique_lock<std::shared_mutex> index_lock(impl_->index_mutex);
      static_cast<void>(impl_->next_store_generation(advanced));
    }
    if (!advanced) {
      return Result<CompactResult>::failure(Outcome::ResourceLimit, "store generation exhausted");
    }
  }
  result.lineage_generation = lineage->state.lineage_generation;
  result.store_generation = impl_->read_watermarks().store_generation;
  return Result<CompactResult>::ok(std::move(result));
}

}  // namespace route_provenance