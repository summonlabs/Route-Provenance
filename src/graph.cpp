// Route Provenance - bounded provenance DAG, snapshots, diffs and explanation semantics.
#include <algorithm>
#include <queue>
#include <set>
#include <string>
#include <vector>

#include "route_provenance/explanation.hpp"
#include "route_provenance/graph.hpp"
#include "route_provenance/snapshot.hpp"
#include "route_provenance/version.hpp"

namespace route_provenance {
namespace {

struct QueueEntry {
  ProvenanceNodeId node;
  std::uint32_t depth = 0;
};

[[nodiscard]] bool depth_less(const TraversalEntry& left, const TraversalEntry& right) noexcept {
  if (left.depth != right.depth) {
    return left.depth < right.depth;
  }
  return left.node.id < right.node.id;
}

[[nodiscard]] bool edge_id_less(const ProvenanceEdge& left, const ProvenanceEdge& right) noexcept {
  return left.id < right.id;
}

}  // namespace

const ProvenanceNode* ProvenanceGraph::find_node(ProvenanceNodeId id) const noexcept {
  const auto it = nodes_.find(id);
  return it == nodes_.end() ? nullptr : &it->second;
}

const ProvenanceEdge* ProvenanceGraph::find_edge(ProvenanceEdgeId id) const noexcept {
  const auto it = edges_.find(id);
  return it == edges_.end() ? nullptr : &it->second;
}

const ProvenanceEdge* ProvenanceGraph::find_edge_by_derivation(DerivationId id) const noexcept {
  const auto it = derivations_.find(id);
  if (it == derivations_.end()) {
    return nullptr;
  }
  return find_edge(it->second);
}

std::vector<ProvenanceNode> ProvenanceGraph::nodes_in_order() const {
  std::vector<ProvenanceNode> out;
  out.reserve(nodes_.size());
  for (const auto& entry : nodes_) {
    out.push_back(entry.second);
  }
  return out;
}

std::vector<ProvenanceEdge> ProvenanceGraph::edges_in_order() const {
  std::vector<ProvenanceEdge> out;
  out.reserve(edges_.size());
  for (const auto& entry : edges_) {
    out.push_back(entry.second);
  }
  return out;
}

Status ProvenanceGraph::add_node(const ProvenanceNode& node, const Limits& limits) {
  if (!node.id.valid()) {
    return Status::failure(Outcome::MalformedRequest, "node identity is not valid");
  }
  const Status consistency = validate_node_consistency(node);
  if (!consistency.is_ok()) {
    return consistency;
  }
  const auto existing = nodes_.find(node.id);
  if (existing != nodes_.end()) {
    if (existing->second.core_digest() == node.core_digest()) {
      return Status::failure(Outcome::Duplicate, "identical provenance node already recorded");
    }
    return Status::failure(Outcome::Conflict, "provenance node identity collision with different content");
  }
  if (nodes_.size() >= limits.max_nodes_per_lineage) {
    return Status::failure(Outcome::ResourceLimit, "max_nodes_per_lineage reached");
  }
  nodes_.emplace(node.id, node);
  outgoing_.try_emplace(node.id);
  incoming_.try_emplace(node.id);
  return Status::ok();
}

Status ProvenanceGraph::check_add_edge(ProvenanceNodeId from, ProvenanceNodeId to,
                                       const Limits& limits) const {
  if (!from.valid() || !to.valid()) {
    return Status::failure(Outcome::MalformedRequest, "edge endpoint identity is not valid");
  }
  if (from == to) {
    return Status::failure(Outcome::CycleDetected, "self edge rejected");
  }
  // Either endpoint may be a record that the same publication is creating, so absence is not
  // an error here: callers validate lineage membership themselves. A record that does not yet
  // exist cannot participate in a cycle.
  if (nodes_.find(from) == nodes_.end() || nodes_.find(to) == nodes_.end()) {
    return Status::ok();
  }
  // Adding from -> to is cyclic exactly when from is already reachable from to.
  std::vector<ProvenanceNodeId> stack;
  std::set<ProvenanceNodeId> visited;
  stack.push_back(to);
  visited.insert(to);
  while (!stack.empty()) {
    const ProvenanceNodeId current = stack.back();
    stack.pop_back();
    if (current == from) {
      return Status::failure(Outcome::CycleDetected, "edge would close a provenance cycle");
    }
    const auto adjacency = outgoing_.find(current);
    if (adjacency == outgoing_.end()) {
      continue;
    }
    for (const ProvenanceEdgeId edge_id : adjacency->second) {
      const auto edge = edges_.find(edge_id);
      if (edge == edges_.end()) {
        continue;
      }
      if (visited.insert(edge->second.to).second) {
        if (visited.size() > limits.max_visited_nodes) {
          return Status::failure(Outcome::ResourceLimit, "cycle check exceeded max_visited_nodes");
        }
        stack.push_back(edge->second.to);
      }
    }
  }
  return Status::ok();
}

Status ProvenanceGraph::add_edge(const ProvenanceEdge& edge, const Limits& limits) {
  const Status consistency = validate_edge_consistency(edge);
  if (!consistency.is_ok()) {
    return consistency;
  }
  if (edge.lineage != RouteLineageId{} && !nodes_.empty()) {
    const auto anchor = nodes_.find(edge.from);
    if (anchor != nodes_.end() && anchor->second.lineage != edge.lineage) {
      return Status::failure(Outcome::InvalidDerivation, "edge lineage disagrees with its endpoints");
    }
  }
  const auto existing = edges_.find(edge.id);
  if (existing != edges_.end()) {
    if (existing->second.core_digest() == edge.core_digest()) {
      return Status::failure(Outcome::Duplicate, "identical derivation edge already recorded");
    }
    return Status::failure(Outcome::Conflict, "derivation edge identity collision with different content");
  }
  if (edges_.size() >= limits.max_edges_per_lineage) {
    return Status::failure(Outcome::ResourceLimit, "max_edges_per_lineage reached");
  }
  const auto from_it = nodes_.find(edge.from);
  const auto to_it = nodes_.find(edge.to);
  if (from_it == nodes_.end() || to_it == nodes_.end()) {
    return Status::failure(Outcome::MissingParent, "edge endpoint is not present in this lineage");
  }
  if (incoming_count(edge.to) >= limits.max_parents_per_node) {
    return Status::failure(Outcome::ResourceLimit, "max_parents_per_node reached");
  }
  if (outgoing_count(edge.from) >= limits.max_children_per_node) {
    return Status::failure(Outcome::ResourceLimit, "max_children_per_node reached");
  }
  const Status cycle = check_add_edge(edge.from, edge.to, limits);
  if (!cycle.is_ok()) {
    return cycle;
  }

  edges_.emplace(edge.id, edge);
  derivations_.emplace(edge.derivation, edge.id);
  auto& out = outgoing_[edge.from];
  out.insert(std::upper_bound(out.begin(), out.end(), edge.id), edge.id);
  auto& in = incoming_[edge.to];
  in.insert(std::upper_bound(in.begin(), in.end(), edge.id), edge.id);
  outgoing_.try_emplace(edge.to);
  incoming_.try_emplace(edge.from);
  return Status::ok();
}

std::size_t ProvenanceGraph::incoming_count(ProvenanceNodeId id) const noexcept {
  const auto it = incoming_.find(id);
  return it == incoming_.end() ? 0U : it->second.size();
}

std::size_t ProvenanceGraph::outgoing_count(ProvenanceNodeId id) const noexcept {
  const auto it = outgoing_.find(id);
  return it == outgoing_.end() ? 0U : it->second.size();
}

std::vector<ProvenanceEdge> ProvenanceGraph::incoming_edges(ProvenanceNodeId id) const {
  std::vector<ProvenanceEdge> out;
  const auto it = incoming_.find(id);
  if (it == incoming_.end()) {
    return out;
  }
  out.reserve(it->second.size());
  for (const ProvenanceEdgeId edge_id : it->second) {
    const auto edge = edges_.find(edge_id);
    if (edge != edges_.end()) {
      out.push_back(edge->second);
    }
  }
  std::sort(out.begin(), out.end(), edge_id_less);
  return out;
}

std::vector<ProvenanceEdge> ProvenanceGraph::outgoing_edges(ProvenanceNodeId id) const {
  std::vector<ProvenanceEdge> out;
  const auto it = outgoing_.find(id);
  if (it == outgoing_.end()) {
    return out;
  }
  out.reserve(it->second.size());
  for (const ProvenanceEdgeId edge_id : it->second) {
    const auto edge = edges_.find(edge_id);
    if (edge != edges_.end()) {
      out.push_back(edge->second);
    }
  }
  std::sort(out.begin(), out.end(), edge_id_less);
  return out;
}

Status ProvenanceGraph::traverse(ProvenanceNodeId origin, TraversalDirection direction,
                                 TraversalBounds bounds, const Limits& limits, TraversalResult& out,
                                 EdgeTypeFilter filter) const {
  out = TraversalResult{};
  if (!origin.valid()) {
    return Status::failure(Outcome::MalformedRequest, "traversal origin is not valid");
  }
  if (nodes_.find(origin) == nodes_.end()) {
    return Status::failure(Outcome::NodeNotFound, "traversal origin is not present in this lineage");
  }
  // Caller bounds may narrow a traversal but never widen it beyond the configured limits.
  const std::uint32_t max_depth =
      bounds.max_depth == 0 ? limits.max_traversal_depth
                            : (bounds.max_depth < limits.max_traversal_depth ? bounds.max_depth
                                                                             : limits.max_traversal_depth);
  const std::uint32_t max_results =
      bounds.max_results == 0 ? limits.max_query_results
                              : (bounds.max_results < limits.max_query_results ? bounds.max_results
                                                                               : limits.max_query_results);
  const std::uint32_t max_visited =
      bounds.max_visited == 0 ? limits.max_visited_nodes
                              : (bounds.max_visited < limits.max_visited_nodes ? bounds.max_visited
                                                                               : limits.max_visited_nodes);

  std::set<ProvenanceNodeId> visited;
  std::vector<QueueEntry> queue;
  queue.push_back(QueueEntry{origin, 0});
  visited.insert(origin);
  std::size_t cursor = 0;
  while (cursor < queue.size()) {
    const QueueEntry entry = queue[cursor++];
    if (entry.depth >= max_depth) {
      continue;
    }
    const auto& adjacency_source = direction == TraversalDirection::Outgoing ? outgoing_ : incoming_;
    const auto adjacency = adjacency_source.find(entry.node);
    if (adjacency == adjacency_source.end()) {
      continue;
    }
    for (const ProvenanceEdgeId edge_id : adjacency->second) {
      const auto edge = edges_.find(edge_id);
      if (edge == edges_.end()) {
        continue;
      }
      if (filter != nullptr && !filter(edge->second.type)) {
        continue;
      }
      const ProvenanceNodeId next =
          direction == TraversalDirection::Outgoing ? edge->second.to : edge->second.from;
      if (!visited.insert(next).second) {
        continue;
      }
      if (visited.size() > max_visited) {
        out.truncated = true;
        return Status::failure(Outcome::ResourceLimit, "traversal exceeded max_visited_nodes");
      }
      if (queue.size() >= max_results) {
        out.truncated = true;
        return Status::failure(Outcome::ResourceLimit, "traversal exceeded max_query_results");
      }
      queue.push_back(QueueEntry{next, entry.depth + 1});
    }
  }

  for (const QueueEntry& entry : queue) {
    const auto node = nodes_.find(entry.node);
    if (node == nodes_.end()) {
      continue;
    }
    out.nodes.push_back(TraversalEntry{node->second, entry.depth});
  }
  std::sort(out.nodes.begin(), out.nodes.end(), depth_less);
  for (const TraversalEntry& entry : out.nodes) {
    out.max_depth_reached = entry.depth > out.max_depth_reached ? entry.depth : out.max_depth_reached;
  }
  for (const auto& entry : edges_) {
    const ProvenanceEdge& edge = entry.second;
    if (out.contains(edge.from) && out.contains(edge.to)) {
      out.edges.push_back(edge);
    }
  }
  std::sort(out.edges.begin(), out.edges.end(), edge_id_less);
  return Status::ok();
}

bool TraversalResult::contains(ProvenanceNodeId id) const noexcept {
  for (const TraversalEntry& entry : nodes) {
    if (entry.node.id == id) {
      return true;
    }
  }
  return false;
}

std::optional<std::vector<ProvenanceNodeId>> ProvenanceGraph::topological_order() const {
  std::map<ProvenanceNodeId, std::size_t> in_degree;
  for (const auto& entry : nodes_) {
    in_degree.emplace(entry.first, incoming_count(entry.first));
  }
  std::priority_queue<ProvenanceNodeId, std::vector<ProvenanceNodeId>, std::greater<>> ready;
  for (const auto& entry : in_degree) {
    if (entry.second == 0) {
      ready.push(entry.first);
    }
  }
  std::vector<ProvenanceNodeId> order;
  order.reserve(nodes_.size());
  while (!ready.empty()) {
    const ProvenanceNodeId current = ready.top();
    ready.pop();
    order.push_back(current);
    const auto adjacency = outgoing_.find(current);
    if (adjacency == outgoing_.end()) {
      continue;
    }
    for (const ProvenanceEdgeId edge_id : adjacency->second) {
      const auto edge = edges_.find(edge_id);
      if (edge == edges_.end()) {
        continue;
      }
      auto degree = in_degree.find(edge->second.to);
      if (degree == in_degree.end() || degree->second == 0) {
        continue;
      }
      degree->second -= 1;
      if (degree->second == 0) {
        ready.push(edge->second.to);
      }
    }
  }
  if (order.size() != nodes_.size()) {
    return std::nullopt;
  }
  return order;
}

Digest ProvenanceGraph::digest(const LineageState& state) const noexcept {
  CanonicalEncoder encoder;
  encoder.add_u32(1, kGraphEncodingVersion);
  encoder.add_u64(2, state.id.value());
  encoder.add_u64(3, state.key.route.value());
  encoder.add_string(4, state.key.semantic_key);
  encoder.add_u16(5, static_cast<std::uint16_t>(state.lifecycle));
  encoder.add_u64(6, state.current_route_generation.value());
  encoder.add_u64(7, state.current_node.value());
  encoder.add_u64(8, state.lineage_generation.value());
  encoder.add_u64(9, state.authority_generation.value());
  encoder.add_u32(10, static_cast<std::uint32_t>(nodes_.size()));
  for (const auto& entry : nodes_) {
    encoder.add_digest(11, entry.second.digest());
  }
  encoder.add_u32(12, static_cast<std::uint32_t>(edges_.size()));
  for (const auto& entry : edges_) {
    encoder.add_digest(13, entry.second.digest());
  }
  return encoder.digest("rp.graph.v1");
}

Status ProvenanceGraph::compact_node(ProvenanceNodeId id, const ProvenanceNode& tombstone) {
  const auto it = nodes_.find(id);
  if (it == nodes_.end()) {
    return Status::failure(Outcome::NodeNotFound, "compaction target is not present in this lineage");
  }
  if (tombstone.id != id) {
    return Status::failure(Outcome::MalformedRequest, "compaction must preserve node identity");
  }
  if (tombstone.kind != NodeKind::CompactedSummary) {
    return Status::failure(Outcome::MalformedRequest, "compaction must produce a summary node");
  }
  const Status consistency = validate_node_consistency(tombstone);
  if (!consistency.is_ok()) {
    return consistency;
  }
  it->second = tombstone;
  return Status::ok();
}

Status ProvenanceGraph::update_node_state(ProvenanceNodeId id, NodeLifecycle lifecycle,
                                        Currentness currentness, bool revalidation_required) {
  const auto it = nodes_.find(id);
  if (it == nodes_.end()) {
    return Status::failure(Outcome::NodeNotFound, "record state update for a missing node");
  }
  if (!is_valid_lifecycle_transition(it->second.lifecycle, lifecycle)) {
    return Status::failure(Outcome::InvalidDerivation,
                           std::string("impossible lifecycle transition ") +
                               std::string(to_string(it->second.lifecycle)) + " -> " +
                               std::string(to_string(lifecycle)));
  }
  it->second.lifecycle = lifecycle;
  it->second.currentness = currentness;
  it->second.revalidation_required = revalidation_required;
  return Status::ok();
}

Status ProvenanceGraph::mark_revalidated(ProvenanceNodeId id) {
  const auto it = nodes_.find(id);
  if (it == nodes_.end()) {
    return Status::failure(Outcome::NodeNotFound, "revalidation of a missing record");
  }
  it->second.revalidated = true;
  return Status::ok();
}

Status ProvenanceGraph::set_corrected_by(ProvenanceNodeId id, ProvenanceNodeId corrected_by) {
  const auto it = nodes_.find(id);
  if (it == nodes_.end()) {
    return Status::failure(Outcome::NodeNotFound, "correction marker for a missing node");
  }
  if (!corrected_by.valid()) {
    return Status::failure(Outcome::MalformedRequest, "correction marker requires a valid record identity");
  }
  it->second.corrected_by = corrected_by;
  return Status::ok();
}

Status ProvenanceGraph::validate_structure() const {
  for (const auto& entry : edges_) {
    const ProvenanceEdge& edge = entry.second;
    const ProvenanceNode* from = find_node(edge.from);
    const ProvenanceNode* to = find_node(edge.to);
    if (from == nullptr || to == nullptr) {
      return Status::failure(Outcome::MissingParent, "edge references a missing endpoint");
    }
    if (from->lineage != edge.lineage || to->lineage != edge.lineage) {
      return Status::failure(Outcome::InvalidDerivation, "edge crosses lineage boundaries");
    }
    const auto derivation = derivations_.find(edge.derivation);
    if (derivation == derivations_.end() || derivation->second != edge.id) {
      return Status::failure(Outcome::Conflict, "derivation index disagrees with the edge set");
    }
  }
  for (const auto& entry : outgoing_) {
    if (nodes_.find(entry.first) == nodes_.end()) {
      return Status::failure(Outcome::Conflict, "outgoing index references a missing node");
    }
    for (const ProvenanceEdgeId edge_id : entry.second) {
      const auto edge = edges_.find(edge_id);
      if (edge == edges_.end() || edge->second.from != entry.first) {
        return Status::failure(Outcome::Conflict, "outgoing index disagrees with the edge set");
      }
    }
  }
  for (const auto& entry : incoming_) {
    if (nodes_.find(entry.first) == nodes_.end()) {
      return Status::failure(Outcome::Conflict, "incoming index references a missing node");
    }
    for (const ProvenanceEdgeId edge_id : entry.second) {
      const auto edge = edges_.find(edge_id);
      if (edge == edges_.end() || edge->second.to != entry.first) {
        return Status::failure(Outcome::Conflict, "incoming index disagrees with the edge set");
      }
    }
  }
  if (!topological_order().has_value()) {
    return Status::failure(Outcome::CycleDetected, "graph is not acyclic");
  }
  return Status::ok();
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

const ProvenanceNode* Snapshot::find_node(ProvenanceNodeId node_id) const noexcept {
  for (const ProvenanceNode& node : nodes) {
    if (node.id == node_id) {
      return &node;
    }
  }
  return nullptr;
}

std::string_view to_string(DiffKind kind) noexcept {
  switch (kind) {
    case DiffKind::NodeAdded: return "NODE_ADDED";
    case DiffKind::NodeRemoved: return "NODE_REMOVED";
    case DiffKind::EdgeAdded: return "EDGE_ADDED";
    case DiffKind::EdgeRemoved: return "EDGE_REMOVED";
    case DiffKind::CurrentnessChanged: return "CURRENTNESS_CHANGED";
    case DiffKind::LifecycleChanged: return "LIFECYCLE_CHANGED";
    case DiffKind::SupersessionRecorded: return "SUPERSESSION_RECORDED";
    case DiffKind::RevocationRecorded: return "REVOCATION_RECORDED";
    case DiffKind::RetirementRecorded: return "RETIREMENT_RECORDED";
    case DiffKind::CorrectionRecorded: return "CORRECTION_RECORDED";
    case DiffKind::AuthorityChanged: return "AUTHORITY_CHANGED";
    case DiffKind::LineageGenerationChanged: return "LINEAGE_GENERATION_CHANGED";
  }
  return "UNKNOWN";
}

namespace {

[[nodiscard]] bool diff_entry_less(const DiffEntry& left, const DiffEntry& right) noexcept {
  if (left.kind != right.kind) {
    return static_cast<std::uint16_t>(left.kind) < static_cast<std::uint16_t>(right.kind);
  }
  if (left.node != right.node) {
    return left.node < right.node;
  }
  return left.edge < right.edge;
}

}  // namespace

Result<Diff> compute_diff(const Snapshot& before, const Snapshot& after) {
  if (before.lineage != after.lineage) {
    return Result<Diff>::failure(Outcome::MalformedRequest, "snapshots belong to different lineages");
  }
  Diff diff;
  diff.lineage = before.lineage;
  diff.from_generation = before.store_generation;
  diff.to_generation = after.store_generation;
  diff.from_lineage_generation = before.lineage_generation;
  diff.to_lineage_generation = after.lineage_generation;

  for (const ProvenanceNode& node : after.nodes) {
    const ProvenanceNode* previous = before.find_node(node.id);
    if (previous == nullptr) {
      DiffEntry entry;
      entry.kind = DiffKind::NodeAdded;
      entry.node = node.id;
      entry.after_currentness = node.currentness;
      entry.after_lifecycle = node.lifecycle;
      entry.detail = std::string(to_string(node.kind));
      diff.entries.push_back(entry);
    }
  }
  for (const ProvenanceNode& node : before.nodes) {
    if (after.find_node(node.id) == nullptr) {
      DiffEntry entry;
      entry.kind = DiffKind::NodeRemoved;
      entry.node = node.id;
      entry.before_currentness = node.currentness;
      entry.before_lifecycle = node.lifecycle;
      entry.detail = std::string(to_string(node.kind));
      diff.entries.push_back(entry);
    }
  }

  std::set<ProvenanceEdgeId> before_edges;
  for (const ProvenanceEdge& edge : before.edges) {
    before_edges.insert(edge.id);
  }
  std::set<ProvenanceEdgeId> after_edges;
  for (const ProvenanceEdge& edge : after.edges) {
    after_edges.insert(edge.id);
  }
  for (const ProvenanceEdge& edge : after.edges) {
    if (before_edges.find(edge.id) == before_edges.end()) {
      DiffEntry entry;
      entry.kind = DiffKind::EdgeAdded;
      entry.edge = edge.id;
      entry.node = edge.from;
      entry.detail = std::string(to_string(edge.type));
      diff.entries.push_back(entry);
      switch (edge.type) {
        case EdgeType::Supersedes:
        case EdgeType::Replaces:
        case EdgeType::RolledBackFrom: {
          DiffEntry recorded;
          recorded.kind = DiffKind::SupersessionRecorded;
          recorded.edge = edge.id;
          recorded.node = edge.from;
          recorded.detail = std::string(to_string(edge.type));
          diff.entries.push_back(recorded);
          break;
        }
        case EdgeType::RevokedBy: {
          DiffEntry recorded;
          recorded.kind = DiffKind::RevocationRecorded;
          recorded.edge = edge.id;
          recorded.node = edge.to;
          recorded.detail = std::string(to_string(edge.type));
          diff.entries.push_back(recorded);
          break;
        }
        case EdgeType::RetiredBy: {
          DiffEntry recorded;
          recorded.kind = DiffKind::RetirementRecorded;
          recorded.edge = edge.id;
          recorded.node = edge.to;
          recorded.detail = std::string(to_string(edge.type));
          diff.entries.push_back(recorded);
          break;
        }
        case EdgeType::Corrects: {
          DiffEntry recorded;
          recorded.kind = DiffKind::CorrectionRecorded;
          recorded.edge = edge.id;
          recorded.node = edge.to;
          recorded.detail = std::string(to_string(edge.type));
          diff.entries.push_back(recorded);
          break;
        }
        default:
          break;
      }
    }
  }
  for (const ProvenanceEdge& edge : before.edges) {
    if (after_edges.find(edge.id) == after_edges.end()) {
      DiffEntry entry;
      entry.kind = DiffKind::EdgeRemoved;
      entry.edge = edge.id;
      entry.node = edge.from;
      entry.detail = std::string(to_string(edge.type));
      diff.entries.push_back(entry);
    }
  }

  for (const ProvenanceNode& node : after.nodes) {
    const ProvenanceNode* previous = before.find_node(node.id);
    if (previous == nullptr) {
      continue;
    }
    if (previous->currentness != node.currentness) {
      DiffEntry entry;
      entry.kind = DiffKind::CurrentnessChanged;
      entry.node = node.id;
      entry.before_currentness = previous->currentness;
      entry.after_currentness = node.currentness;
      diff.entries.push_back(entry);
    }
    if (previous->lifecycle != node.lifecycle) {
      DiffEntry entry;
      entry.kind = DiffKind::LifecycleChanged;
      entry.node = node.id;
      entry.before_lifecycle = previous->lifecycle;
      entry.after_lifecycle = node.lifecycle;
      diff.entries.push_back(entry);
    }
  }

  if (before.authority_generation != after.authority_generation) {
    DiffEntry entry;
    entry.kind = DiffKind::AuthorityChanged;
    entry.detail = "authority_generation " + before.authority_generation.to_string() + " -> " +
                   after.authority_generation.to_string();
    diff.entries.push_back(entry);
  }
  if (before.lineage_generation != after.lineage_generation) {
    DiffEntry entry;
    entry.kind = DiffKind::LineageGenerationChanged;
    entry.detail = "lineage_generation " + before.lineage_generation.to_string() + " -> " +
                   after.lineage_generation.to_string();
    diff.entries.push_back(entry);
  }

  std::sort(diff.entries.begin(), diff.entries.end(), diff_entry_less);

  CanonicalEncoder encoder;
  encoder.add_u32(1, kGraphEncodingVersion);
  encoder.add_u64(2, diff.lineage.value());
  encoder.add_u64(3, diff.from_generation.value());
  encoder.add_u64(4, diff.to_generation.value());
  encoder.add_u32(5, static_cast<std::uint32_t>(diff.entries.size()));
  for (const DiffEntry& entry : diff.entries) {
    CanonicalEncoder nested;
    nested.add_u16(1, static_cast<std::uint16_t>(entry.kind));
    nested.add_u64(2, entry.node.value());
    nested.add_u64(3, entry.edge.value());
    nested.add_u16(4, static_cast<std::uint16_t>(entry.before_currentness));
    nested.add_u16(5, static_cast<std::uint16_t>(entry.after_currentness));
    nested.add_u16(6, static_cast<std::uint16_t>(entry.before_lifecycle));
    nested.add_u16(7, static_cast<std::uint16_t>(entry.after_lifecycle));
    nested.add_string(8, entry.detail);
    encoder.add_nested(6, nested);
  }
  diff.digest = encoder.digest("rp.diff.v1");
  return Result<Diff>::ok(std::move(diff));
}

// ---------------------------------------------------------------------------
// Explanation semantics
// ---------------------------------------------------------------------------

bool node_is_historically_valid(const ProvenanceNode& node) noexcept {
  switch (node.lifecycle) {
    case NodeLifecycle::Declared:
    case NodeLifecycle::Invalid:
      return false;
    case NodeLifecycle::Current:
    case NodeLifecycle::Historical:
    case NodeLifecycle::RevalidationRequired:
    case NodeLifecycle::Superseded:
    case NodeLifecycle::Revoked:
    case NodeLifecycle::Retired:
      return true;
  }
  return false;
}

bool edge_matches_mode(EdgeType type, ExplainMode mode) noexcept {
  switch (mode) {
    case ExplainMode::ImmediateCause:
      return true;
    case ExplainMode::FullAncestry:
      return true;
    case ExplainMode::AuthorityOnly:
      return edge_type_is_evidence_relation(type);
    case ExplainMode::PolicyOnly:
      return type == EdgeType::AdaptedFrom || type == EdgeType::SelectedFrom ||
             type == EdgeType::DerivedFrom;
    case ExplainMode::PathOnly:
      return type == EdgeType::AuthorizedBy || type == EdgeType::ComputedFrom ||
             type == EdgeType::SelectedFrom;
    case ExplainMode::MutationLineage:
      return edge_type_is_action_relation(type) || edge_type_is_successor_relation(type) ||
             type == EdgeType::TransitionedBy;
  }
  return false;
}

std::string render_explanation(const Explanation& explanation) {
  std::string out;
  out += "subject=" + explanation.subject.to_string();
  out += "\nlineage=" + explanation.lineage.to_string();
  out += "\nmode=" + std::string(to_string(explanation.mode));
  out += "\nlifecycle=" + std::string(to_string(explanation.subject_lifecycle));
  out += "\ncurrentness=" + std::string(to_string(explanation.subject_currentness));
  out += "\nhistorically_valid=";
  out += explanation.historically_valid ? "true" : "false";
  out += "\ncurrent=";
  out += explanation.current ? "true" : "false";
  out += "\ntruncated=";
  out += explanation.truncated ? "true" : "false";
  out += "\nsteps=" + std::to_string(explanation.steps.size());
  out += "\n";
  for (const ExplanationStep& step : explanation.steps) {
    out += "step depth=" + std::to_string(step.depth);
    out += " edge=" + step.edge.to_string();
    out += " type=" + std::string(to_string(step.type));
    out += " from=" + step.from.to_string();
    out += " to=" + step.to.to_string();
    out += " kind=" + std::string(to_string(step.kind));
    out += " reason=" + std::string(to_string(step.reason));
    out += " source=" + std::string(to_string(step.source));
    out += " generation=" + step.route_generation.to_string();
    out += " lifecycle=" + std::string(to_string(step.lifecycle));
    out += " currentness=" + std::string(to_string(step.currentness));
    out += " current=";
    out += step.current ? "true" : "false";
    out += "\n";
  }
  return out;
}

}  // namespace route_provenance