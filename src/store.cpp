// Route Provenance - the provenance runtime: publication, authority and currentness.
#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "route_provenance/version.hpp"
#include "store_internal.hpp"

namespace route_provenance {

[[nodiscard]] Status check_lineage_key(const LineageKey& key, const Limits& limits) {
  if (!key.route.valid()) {
    return Status::failure(Outcome::MalformedRequest, "lineage key requires a valid RouteId");
  }
  if (key.semantic_key.empty()) {
    return Status::failure(Outcome::MalformedRequest, "lineage key requires a semantic key");
  }
  if (key.semantic_key.size() > limits.max_semantic_key_bytes) {
    return Status::failure(Outcome::ResourceLimit, "semantic key exceeds max_semantic_key_bytes");
  }
  for (const char ch : key.semantic_key) {
    const unsigned char raw = static_cast<unsigned char>(ch);
    if (raw < 0x20U || raw == 0x7FU) {
      return Status::failure(Outcome::MalformedRequest, "semantic key contains control characters");
    }
  }
  return Status::ok();
}

namespace {

/// Digest of the semantic content of a request. Used for exact-replay classification.
[[nodiscard]] Digest request_digest(const NormalizedPublication& request) {
  CanonicalEncoder encoder;
  encoder.add_u32(1, kGraphEncodingVersion);
  encoder.add_u16(2, static_cast<std::uint16_t>(request.kind));
  encoder.add_u64(3, request.key.route.value());
  encoder.add_string(4, request.key.semantic_key);
  encoder.add_u16(5, static_cast<std::uint16_t>(request.node_kind));
  encoder.add_u64(6, request.route.value());
  encoder.add_u64(7, request.route_generation.value());
  encoder.add_digest(8, request.route_state_digest);
  encoder.add_u16(9, static_cast<std::uint16_t>(request.reason));
  encoder.add_u16(10, static_cast<std::uint16_t>(request.source));
  encoder.add_u16(11, request.root_reason.has_value() ? static_cast<std::uint16_t>(*request.root_reason) : 0);
  request.evidence.encode(encoder, 12);
  request.authority.encode(encoder, 13);
  encode_bindings(request.bindings, encoder, 14);
  encoder.add_u64(15, request.target.value());
  encoder.add_u64(16, request.link_from.value());
  encoder.add_digest(17, request.completion_evidence);
  encoder.add_u32(18, static_cast<std::uint32_t>(request.edges.size()));
  for (const EdgeSpec& spec : request.edges) {
    CanonicalEncoder nested;
    nested.add_u16(1, static_cast<std::uint16_t>(spec.type));
    nested.add_u64(2, spec.target.value());
    nested.add_u16(3, static_cast<std::uint16_t>(spec.reason));
    nested.add_u16(4, static_cast<std::uint16_t>(spec.source));
    nested.add_digest(5, spec.evidence.digest());
    encoder.add_nested(19, nested);
  }
  return encoder.digest("rp.request.v1");
}

/// Currentness is a pure function of record state, lineage state, upstream watermarks and
/// publisher liveness. The check order below is the documented precedence.
[[nodiscard]] Currentness compute_currentness(const LineageState& state, const ProvenanceNode& node,
                                              const DependencyWatermarks& watermarks,
                                              PublisherLiveness publisher_liveness) noexcept {
  if (state.lifecycle == LineageLifecycle::Retired || node.lifecycle == NodeLifecycle::Retired) {
    return Currentness::HistoricalOnly;
  }
  switch (node.lifecycle) {
    case NodeLifecycle::Invalid:
    case NodeLifecycle::Revoked:
    case NodeLifecycle::Historical:
    case NodeLifecycle::Superseded:
      return Currentness::HistoricalOnly;
    default:
      break;
  }
  if (node.revalidation_required) {
    return Currentness::RevalidationRequired;
  }
  if (node.is_route_state() && node.route_generation != state.current_route_generation) {
    return Currentness::StaleRoute;
  }
  if (node.bindings.path.has_value() && watermarks.path_authority_generation.valid() &&
      node.bindings.path->generation != watermarks.path_authority_generation) {
    return Currentness::StalePathAuthority;
  }
  if (node.bindings.policy.has_value() && watermarks.policy_generation.valid() &&
      node.bindings.policy->generation != watermarks.policy_generation) {
    return Currentness::StalePolicy;
  }
  if (node.bindings.adaptation.has_value() && watermarks.policy_generation.valid() &&
      node.bindings.adaptation->policy != watermarks.policy_generation) {
    return Currentness::StalePolicy;
  }
  if (node.bindings.adaptation.has_value() && watermarks.evidence_generation.valid() &&
      node.bindings.adaptation->evidence != watermarks.evidence_generation) {
    return Currentness::StaleEvidence;
  }
  const std::optional<std::uint64_t> bound_epoch = node.evidence.get(EvidenceField::FabricEpoch);
  if (bound_epoch.has_value() && watermarks.epoch.valid() &&
      *bound_epoch != watermarks.epoch.value()) {
    return Currentness::StaleEpoch;
  }
  if (watermarks.epoch.valid() && node.authority.publisher.epoch != watermarks.epoch) {
    return Currentness::StaleEpoch;
  }
  if (node.revalidated) {
    // A live authority has explicitly revalidated this record, so liveness of the original
    // publisher is no longer what makes the record current.
    return Currentness::Current;
  }
  if (publisher_liveness == PublisherLiveness::Fenced) {
    return Currentness::FencedPublisher;
  }
  if (publisher_liveness == PublisherLiveness::Unknown) {
    // Live authority does not survive a process restart: the record stays historically valid
    // and becomes current again only through explicit revalidation.
    return Currentness::RevalidationRequired;
  }
  return Currentness::Current;
}

/// True when a newly created record is the origin of a typed edge. Revocation and retirement
/// are recorded from the affected route state towards the administrative action.
[[nodiscard]] bool edge_from_new_node(EdgeType type) noexcept {
  switch (type) {
    case EdgeType::RevokedBy:
    case EdgeType::RetiredBy:
      return false;
    default:
      return true;
  }
}

}  // namespace

[[nodiscard]] bool is_declaration_kind(NodeKind kind) noexcept {
  switch (kind) {
    case NodeKind::PathAuthorization:
    case NodeKind::PlannerCandidate:
    case NodeKind::AdaptiveDecision:
    case NodeKind::ConvergencePlan:
    case NodeKind::PolicyDecision:
      return true;
    default:
      return false;
  }
}

/// A declaration must carry exactly the binding that identifies the authority it declares.
[[nodiscard]] Status check_declaration_bindings(NodeKind kind, const Bindings& bindings) {
  const bool path = bindings.path.has_value();
  const bool planner = bindings.planner.has_value();
  const bool adaptation = bindings.adaptation.has_value();
  const bool convergence = bindings.convergence.has_value();
  const bool policy = bindings.policy.has_value();
  switch (kind) {
    case NodeKind::PathAuthorization:
      if (!path) {
        return Status::failure(Outcome::MalformedRequest, "PATH_AUTHORIZATION requires a path binding");
      }
      break;
    case NodeKind::PlannerCandidate:
      if (!planner) {
        return Status::failure(Outcome::MalformedRequest, "PLANNER_CANDIDATE requires a planner binding");
      }
      break;
    case NodeKind::AdaptiveDecision:
      if (!adaptation) {
        return Status::failure(Outcome::MalformedRequest, "ADAPTIVE_DECISION requires an adaptation binding");
      }
      break;
    case NodeKind::ConvergencePlan:
      if (!convergence) {
        return Status::failure(Outcome::MalformedRequest, "CONVERGENCE_PLAN requires a convergence binding");
      }
      break;
    case NodeKind::PolicyDecision:
      if (!policy) {
        return Status::failure(Outcome::MalformedRequest, "POLICY_DECISION requires a policy binding");
      }
      break;
    default:
      return Status::failure(Outcome::MalformedRequest, "unsupported declaration kind");
  }
  return Status::ok();
}

namespace {

[[nodiscard]] Publication make_publication(RouteLineageId lineage, ProvenanceNodeId node,
                                           std::vector<ProvenanceEdgeId> edges,
                                           const LineageState& state,
                                           const DependencyWatermarks& watermarks,
                                           NodeLifecycle lifecycle, Currentness currentness) {
  Publication publication;
  publication.lineage = lineage;
  publication.node = node;
  publication.edges = std::move(edges);
  publication.lineage_generation = state.lineage_generation;
  publication.store_generation = watermarks.store_generation;
  publication.lifecycle = lifecycle;
  publication.currentness = currentness;
  return publication;
}

}  // namespace

// ---------------------------------------------------------------------------
// Publisher registry
// ---------------------------------------------------------------------------

std::optional<PublisherRecord> ProvenanceStore::Impl::find_publisher(PublisherId publisher,
                                                                     WorkerBootId boot) const {
  std::lock_guard<std::mutex> lock(publisher_mutex);
  const auto it = publishers.find(PublisherKey{publisher, boot});
  if (it == publishers.end()) {
    return std::nullopt;
  }
  return it->second;
}

bool ProvenanceStore::Impl::publisher_is_live(PublisherId publisher, WorkerBootId boot) const {
  const std::optional<PublisherRecord> record = find_publisher(publisher, boot);
  return record.has_value() && record->live;
}

PublisherLiveness ProvenanceStore::Impl::publisher_state(PublisherId publisher,
                                                           WorkerBootId boot) const {
  const std::optional<PublisherRecord> record = find_publisher(publisher, boot);
  if (!record.has_value()) {
    return PublisherLiveness::Unknown;
  }
  return record->live ? PublisherLiveness::Live : PublisherLiveness::Fenced;
}

DependencyWatermarks ProvenanceStore::Impl::read_watermarks() const {
  std::shared_lock<std::shared_mutex> lock(index_mutex);
  return watermarks;
}

std::uint64_t ProvenanceStore::Impl::next_store_generation(bool& ok) {
  if (!bump_generation(watermarks.store_generation)) {
    ok = false;
    return watermarks.store_generation.value();
  }
  ok = true;
  return watermarks.store_generation.value();
}

// ---------------------------------------------------------------------------
// Lineage registry
// ---------------------------------------------------------------------------

std::shared_ptr<Lineage> ProvenanceStore::Impl::find_lineage(RouteLineageId id) const {
  std::shared_lock<std::shared_mutex> lock(registry_mutex);
  const auto it = lineages.find(id);
  if (it == lineages.end()) {
    return nullptr;
  }
  return it->second;
}

std::shared_ptr<Lineage> ProvenanceStore::Impl::acquire_lineage(RouteLineageId id, const LineageKey& key,
                                                                bool create, bool& created) {
  created = false;
  {
    std::shared_lock<std::shared_mutex> lock(registry_mutex);
    const auto it = lineages.find(id);
    if (it != lineages.end()) {
      return it->second;
    }
  }
  if (!create) {
    return nullptr;
  }
  std::unique_lock<std::shared_mutex> lock(registry_mutex);
  const auto it = lineages.find(id);
  if (it != lineages.end()) {
    return it->second;
  }
  if (lineages.size() >= limits.max_lineages) {
    return nullptr;
  }
  auto lineage = std::make_shared<Lineage>();
  lineage->state.id = id;
  lineage->state.key = key;
  lineage->state.lifecycle = LineageLifecycle::Active;
  lineages.emplace(id, lineage);
  route_index[key.route] = id;
  created = true;
  return lineage;
}

// ---------------------------------------------------------------------------
// Indexes
// ---------------------------------------------------------------------------

void ProvenanceStore::Impl::index_node(const ProvenanceNode& node, RouteLineageId lineage) {
  std::unique_lock<std::shared_mutex> lock(index_mutex);
  node_owner[node.id] = lineage;
  if (node.kind == NodeKind::RouteGeneration) {
    route_generation_index[node.route][node.route_generation] = node.id;
  }
  if (node.bindings.path.has_value()) {
    path_index[node.bindings.path->path].insert(node.id);
    path_authority_index[node.bindings.path->generation].insert(node.id);
  }
  if (node.bindings.planner.has_value()) {
    path_index[node.bindings.planner->selected_path].insert(node.id);
  }
  if (node.bindings.policy.has_value()) {
    policy_index[node.bindings.policy->generation].insert(node.id);
  }
  if (node.bindings.adaptation.has_value()) {
    policy_index[node.bindings.adaptation->policy].insert(node.id);
    evidence_index[node.bindings.adaptation->evidence].insert(node.id);
  }
  boot_index[node.authority.publisher.boot].insert(node.id);
  publisher_index[node.authority.publisher.publisher].insert(node.id);
}

void ProvenanceStore::Impl::index_edge(const ProvenanceEdge& edge) {
  std::unique_lock<std::shared_mutex> lock(index_mutex);
  node_owner.try_emplace(edge.from, edge.lineage);
  node_owner.try_emplace(edge.to, edge.lineage);
}

// ---------------------------------------------------------------------------
// Currentness evaluation
// ---------------------------------------------------------------------------

void ProvenanceStore::Impl::reevaluate_node(Lineage& lineage, ProvenanceNodeId id) {
  const ProvenanceNode* node = lineage.graph.find_node(id);
  if (node == nullptr) {
    return;
  }
  const PublisherLiveness liveness =
      publisher_state(node->authority.publisher.publisher, node->authority.publisher.boot);
  const DependencyWatermarks marks = read_watermarks();
  const Currentness currentness = compute_currentness(lineage.state, *node, marks, liveness);
  if (currentness == node->currentness) {
    return;
  }
  static_cast<void>(lineage.graph.update_node_state(id, node->lifecycle, currentness,
                                                    node->revalidation_required));
}

void ProvenanceStore::Impl::reevaluate_all(Lineage& lineage) {
  const std::vector<ProvenanceNode> nodes = lineage.graph.nodes_in_order();
  const DependencyWatermarks marks = read_watermarks();
  for (const ProvenanceNode& node : nodes) {
    const PublisherLiveness liveness =
        publisher_state(node.authority.publisher.publisher, node.authority.publisher.boot);
    const Currentness currentness = compute_currentness(lineage.state, node, marks, liveness);
    if (currentness == node.currentness) {
      continue;
    }
    static_cast<void>(
        lineage.graph.update_node_state(node.id, node.lifecycle, currentness, node.revalidation_required));
  }
}

Status ProvenanceStore::Impl::reevaluate_nodes(Lineage& lineage, const std::vector<ProvenanceNodeId>& ids) {
  const DependencyWatermarks marks = read_watermarks();
  for (const ProvenanceNodeId id : ids) {
    const ProvenanceNode* node = lineage.graph.find_node(id);
    if (node == nullptr) {
      continue;
    }
    const PublisherLiveness liveness =
        publisher_state(node->authority.publisher.publisher, node->authority.publisher.boot);
    const Currentness currentness = compute_currentness(lineage.state, *node, marks, liveness);
    if (currentness == node->currentness) {
      continue;
    }
    const Status status =
        lineage.graph.update_node_state(id, node->lifecycle, currentness, node->revalidation_required);
    if (!status.is_ok()) {
      return status;
    }
  }
  return Status::ok();
}

void ProvenanceStore::Impl::reevaluate_index(const std::vector<ProvenanceNodeId>& ids) {
  std::map<RouteLineageId, std::vector<ProvenanceNodeId>> grouped;
  {
    std::shared_lock<std::shared_mutex> lock(index_mutex);
    for (const ProvenanceNodeId id : ids) {
      const auto owner = node_owner.find(id);
      if (owner != node_owner.end()) {
        grouped[owner->second].push_back(id);
      }
    }
  }
  for (const auto& entry : grouped) {
    const std::shared_ptr<Lineage> lineage = find_lineage(entry.first);
    if (lineage == nullptr) {
      continue;
    }
    std::unique_lock<std::shared_mutex> lock(lineage->mutex);
    static_cast<void>(reevaluate_nodes(*lineage, entry.second));
  }
}

// ---------------------------------------------------------------------------
// The commit pipeline
// ---------------------------------------------------------------------------

Result<Publication> ProvenanceStore::Impl::commit(const NormalizedPublication& request) {
  // Stage 3: caller identity.
  if (!request.authority.has_identity()) {
    return Result<Publication>::failure(
        Outcome::Unauthorized, "publication requires PublisherId, WorkerBootId, CoordinatorEpoch and attempt");
  }
  // Stage 4: epoch.
  const DependencyWatermarks marks = read_watermarks();
  if (!marks.epoch.valid()) {
    return Result<Publication>::failure(Outcome::StaleEpoch, "store has no current coordinator epoch");
  }
  if (request.authority.publisher.epoch != marks.epoch) {
    return Result<Publication>::failure(Outcome::StaleEpoch, "publication epoch is not the current epoch");
  }
  // Stage 5: worker authority.
  if (!publisher_is_live(request.authority.publisher.publisher, request.authority.publisher.boot)) {
    return Result<Publication>::failure(Outcome::StaleWorker,
                                        "publisher boot is not a live registered session");
  }
  // Stage 6: authority scope.
  const RouteLineageId derived = derive_lineage_id(request.key);
  const RouteLineageId lineage_id = request.explicit_lineage.value_or(derived);
  if (request.explicit_lineage.has_value() && *request.explicit_lineage != derived) {
    return Result<Publication>::failure(
        Outcome::MalformedRequest, "explicit lineage identity does not match the lineage key");
  }
  const ScopeTarget scope_target{RoutingNamespaceId{}, lineage_id, request.key.route};
  if (!request.authority.scope.permits(scope_target)) {
    return Result<Publication>::failure(
        Outcome::Unauthorized, std::string("authority scope does not cover the target: ") +
                                   request.authority.scope.describe());
  }

  bool created = false;
  const std::shared_ptr<Lineage> lineage = acquire_lineage(lineage_id, request.key, true, created);
  if (lineage == nullptr) {
    return Result<Publication>::failure(Outcome::ResourceLimit, "max_lineages reached");
  }

  std::unique_lock<std::shared_mutex> lock(lineage->mutex);

  // Stage 7: lineage lifecycle.
  if (lineage->state.lifecycle == LineageLifecycle::Retired) {
    return Result<Publication>::failure(Outcome::Retired, "lineage is retired");
  }
  if (lineage->state.lifecycle == LineageLifecycle::Revoked) {
    return Result<Publication>::failure(Outcome::Revoked, "lineage is administratively revoked");
  }

  const Digest digest_of_request = request_digest(request);
  const AttemptKey attempt_key{request.authority.publisher.publisher, request.authority.attempt};
  const auto attempt = lineage->attempts.find(attempt_key);

  // Stage 8: expected generation (bypassed for a known attempt, which stage 9 classifies).
  if (attempt == lineage->attempts.end()) {
    if (request.authority.expected_lineage_generation.has_value() &&
        *request.authority.expected_lineage_generation != lineage->state.lineage_generation) {
      return Result<Publication>::failure(Outcome::StaleLineageGeneration,
                                          "expected lineage generation is no longer current");
    }
    if (request.authority.expected_provenance_generation.has_value() &&
        *request.authority.expected_provenance_generation != marks.store_generation) {
      return Result<Publication>::failure(Outcome::StaleStoreGeneration,
                                          "expected store generation is no longer current");
    }
  } else {
    // Stage 9: attempt classification.
    const AttemptRecord& record = attempt->second;
    if (record.request == digest_of_request) {
      Publication publication;
      publication.lineage = lineage_id;
      publication.node = record.node;
      publication.edges = record.edges;
      publication.lineage_generation = lineage->state.lineage_generation;
      publication.store_generation = marks.store_generation;
      publication.lifecycle = record.lifecycle;
      publication.currentness = record.currentness;
      return Result<Publication>(Outcome::Idempotent, std::move(publication),
                                 "exact replay of a committed mutation attempt");
    }
    return Result<Publication>::failure(
        Outcome::Conflict, "mutation attempt identity already used with a different payload");
  }

  // Stage 10: route generation and target binding.
  ProvenanceNode node;
  node.lineage = lineage_id;
  node.kind = request.node_kind;
  node.route = request.kind == PublishKind::RouteState ? request.key.route : request.route;
  node.route_generation = request.route_generation;
  node.route_state_digest = request.route_state_digest;
  node.reason = request.reason;
  node.source = request.source;
  node.root_reason = request.root_reason;
  node.evidence = request.evidence;
  node.authority = request.authority;
  node.bindings = request.bindings;

  if (request.kind == PublishKind::RouteState) {
    if (request.route_generation.value() < lineage->state.current_route_generation.value()) {
      return Result<Publication>::failure(Outcome::StaleRoute,
                                          "route generation is older than the lineage current generation");
    }
    ProvenanceNodeId existing_generation;
    {
      std::shared_lock<std::shared_mutex> index_lock(index_mutex);
      const auto route_entry = route_generation_index.find(node.route);
      if (route_entry != route_generation_index.end()) {
        const auto generation_entry = route_entry->second.find(node.route_generation);
        if (generation_entry != route_entry->second.end()) {
          existing_generation = generation_entry->second;
        }
      }
    }
    if (existing_generation.valid()) {
      const ProvenanceNode* existing = lineage->graph.find_node(existing_generation);
      if (existing != nullptr) {
        ProvenanceNode probe = node;
        probe.authority.attempt = existing->authority.attempt;
        finalize_node(probe);
        if (probe.id == existing->id) {
          Publication publication =
              make_publication(lineage_id, existing->id, {}, lineage->state, marks,
                               existing->lifecycle, existing->currentness);
          for (const ProvenanceEdge& edge : lineage->graph.outgoing_edges(existing->id)) {
            publication.edges.push_back(edge.id);
          }
          return Result<Publication>(Outcome::Duplicate, std::move(publication),
                                     "an identical provenance record already exists for this generation");
        }
        return Result<Publication>::failure(
            Outcome::Conflict, "a different provenance record already exists for this route generation");
      }
    }
    if (!request.root_reason.has_value() && request.edges.empty()) {
      // A route generation that is not a declared root must identify its causal predecessor.
      // The predecessor is never inferred from the generation number.
      return Result<Publication>::failure(
          Outcome::InvalidDerivation, "non-root route generation requires an explicit causal predecessor");
    }
    if (request.root_reason.has_value()) {
      if (lineage->state.current_route_generation.valid()) {
        return Result<Publication>::failure(
            Outcome::InvalidDerivation, "root provenance declared in a lineage that already has route state");
      }
      for (const EdgeSpec& spec : request.edges) {
        if (edge_type_is_successor_relation(spec.type)) {
          return Result<Publication>::failure(Outcome::InvalidDerivation,
                                              "root provenance cannot carry a successor relation");
        }
      }
    }
    node.lifecycle = NodeLifecycle::Current;
  } else if (request.kind == PublishKind::Declaration) {
    node.lifecycle = NodeLifecycle::Declared;
    node.route = request.route;
    node.route_generation = request.route_generation;
    node.route_state_digest = Digest{};
  } else if (request.kind == PublishKind::Link) {
    // No new record: linking promotes the target of an evidence relation.
  } else {
    const ProvenanceNode* target = lineage->graph.find_node(request.target);
    if (target == nullptr) {
      std::shared_lock<std::shared_mutex> index_lock(index_mutex);
      const bool elsewhere = node_owner.find(request.target) != node_owner.end();
      index_lock.unlock();
      if (elsewhere) {
        return Result<Publication>::failure(Outcome::InvalidDerivation,
                                            "target record belongs to a different lineage");
      }
      return Result<Publication>::failure(Outcome::NodeNotFound, "target record is not present");
    }
    if (request.kind == PublishKind::Correction) {
      if (target->kind == NodeKind::CompactedSummary) {
        return Result<Publication>::failure(
            Outcome::InvalidDerivation, "a compacted summary cannot be corrected; publish a new record");
      }
      node.kind = target->kind;
      node.route = target->route;
      node.route_generation = target->route_generation;
      node.route_state_digest =
          request.route_state_digest.is_zero() ? target->route_state_digest : request.route_state_digest;
      node.root_reason = target->root_reason;
      node.corrects = target->id;
      node.lifecycle = NodeLifecycle::Current;
    } else {
      if (target->lifecycle == NodeLifecycle::Retired || target->lifecycle == NodeLifecycle::Revoked) {
        return Result<Publication>::failure(
            Outcome::InvalidDerivation, "record has already been retired or revoked");
      }
      if (request.kind == PublishKind::Revalidation && !request.allow_non_current_target &&
          target->id != lineage->state.current_node) {
        return Result<Publication>::failure(
            Outcome::InvalidDerivation, "revalidation target is not the current record of the lineage");
      }
      node.kind = NodeKind::AdministrativeAction;
      node.route = target->route;
      node.route_generation = target->route_generation;
      node.route_state_digest = target->route_state_digest;
      node.lifecycle = NodeLifecycle::Current;
    }
  }

  // Stage 11: upstream binding freshness.
  if (node.bindings.path.has_value() && marks.path_authority_generation.valid()) {
    if (node.bindings.path->generation.value() < marks.path_authority_generation.value()) {
      return Result<Publication>::failure(Outcome::StalePathAuthority,
                                          "path authority generation is superseded");
    }
    if (node.bindings.path->generation.value() > marks.path_authority_generation.value()) {
      return Result<Publication>::failure(
          Outcome::InvalidSourceGeneration, "path authority generation is ahead of the announced authority");
    }
  }
  if (node.bindings.policy.has_value() && marks.policy_generation.valid()) {
    if (node.bindings.policy->generation.value() < marks.policy_generation.value()) {
      return Result<Publication>::failure(Outcome::StalePolicy, "policy generation is superseded");
    }
    if (node.bindings.policy->generation.value() > marks.policy_generation.value()) {
      return Result<Publication>::failure(Outcome::InvalidSourceGeneration,
                                          "policy generation is ahead of the announced authority");
    }
  }
  if (node.bindings.convergence.has_value() && marks.plan_generation.valid() &&
      node.bindings.convergence->generation.value() < marks.plan_generation.value()) {
    return Result<Publication>::failure(Outcome::StalePlan, "convergence plan generation is superseded");
  }

  // Stage 12: graph validation, in a deterministic order, without any mutation.
  std::vector<ProvenanceEdge> edges;
  if (request.kind == PublishKind::Link) {
    const ProvenanceNode* from = lineage->graph.find_node(request.link_from);
    const ProvenanceNode* to = lineage->graph.find_node(request.target);
    if (from == nullptr || to == nullptr) {
      return Result<Publication>::failure(Outcome::MissingParent,
                                          "link endpoints must both exist in the lineage");
    }
    ProvenanceEdge edge;
    edge.lineage = lineage_id;
    edge.type = request.link_type;
    edge.from = request.link_from;
    edge.to = request.target;
    if (edge_type_is_successor_relation(edge.type)) {
      if (to->kind != NodeKind::RouteGeneration || from->kind != NodeKind::RouteGeneration) {
        return Result<Publication>::failure(Outcome::InvalidDerivation,
                                            "successor relations connect route state records");
      }
      edge.predecessor_route_generation = to->route_generation;
      edge.successor_route_generation = from->route_generation;
    }
    edge.reason = request.reason;
    edge.source = request.source;
    edge.evidence = request.evidence;
    edge.authority = request.authority;
    finalize_edge(edge);
    const Status consistency = validate_edge_consistency(edge);
    if (!consistency.is_ok()) {
      return Result<Publication>(consistency.outcome(), std::nullopt, consistency.detail());
    }
    const Status cycle = lineage->graph.check_add_edge(edge.from, edge.to, limits);
    if (!cycle.is_ok()) {
      return Result<Publication>(cycle.outcome(), std::nullopt, cycle.detail());
    }
    edges.push_back(std::move(edge));
  } else {
    finalize_node(node);
    for (const EdgeSpec& spec : request.edges) {
      const ProvenanceNode* target = lineage->graph.find_node(spec.target);
      if (target == nullptr) {
        std::shared_lock<std::shared_mutex> index_lock(index_mutex);
        const bool elsewhere = node_owner.find(spec.target) != node_owner.end();
        index_lock.unlock();
        if (elsewhere) {
          return Result<Publication>::failure(Outcome::InvalidDerivation,
                                              "derivation edge target belongs to a different lineage");
        }
        return Result<Publication>::failure(Outcome::MissingParent,
                                            "derivation edge target is not present in this lineage");
      }
      ProvenanceEdge edge;
      edge.lineage = lineage_id;
      edge.type = spec.type;
      edge.from = edge_from_new_node(spec.type) ? node.id : target->id;
      edge.to = edge_from_new_node(spec.type) ? target->id : node.id;
      edge.reason = spec.reason;
      edge.source = spec.source;
      edge.evidence = spec.evidence;
      edge.authority = request.authority;
      if (edge_type_is_successor_relation(spec.type)) {
        if (target->kind != NodeKind::RouteGeneration) {
          return Result<Publication>::failure(Outcome::InvalidDerivation,
                                              "successor relations must reference route state");
        }
        edge.predecessor_route_generation = target->route_generation;
        edge.successor_route_generation = node.route_generation;
      }
      finalize_edge(edge);
      const Status consistency = validate_edge_consistency(edge);
      if (!consistency.is_ok()) {
        return Result<Publication>(consistency.outcome(), std::nullopt, consistency.detail());
      }
      const Status cycle = lineage->graph.check_add_edge(edge.from, edge.to, limits);
      if (!cycle.is_ok()) {
        return Result<Publication>(cycle.outcome(), std::nullopt, cycle.detail());
      }
      edges.push_back(std::move(edge));
    }
  }

  // Stage 13: resource limits.
  if (request.edges.size() > limits.max_batch_size) {
    return Result<Publication>::failure(Outcome::ResourceLimit, "batch exceeds max_batch_size");
  }
  if (request.kind != PublishKind::Link) {
    if (lineage->graph.node_count() >= limits.max_nodes_per_lineage) {
      return Result<Publication>::failure(Outcome::ResourceLimit, "max_nodes_per_lineage reached");
    }
    if (lineage->graph.edge_count() + edges.size() > limits.max_edges_per_lineage) {
      return Result<Publication>::failure(Outcome::ResourceLimit, "max_edges_per_lineage reached");
    }
  } else if (lineage->graph.edge_count() >= limits.max_edges_per_lineage) {
    return Result<Publication>::failure(Outcome::ResourceLimit, "max_edges_per_lineage reached");
  }
  if (lineage->state.history_node_count >= limits.max_history_nodes_per_lineage) {
    return Result<Publication>::failure(
        Outcome::ResourceLimit,
        "bounded history reached: compact the lineage or raise max_history_nodes_per_lineage");
  }
  if (attempt == lineage->attempts.end() &&
      lineage->attempts.size() >= limits.max_attempts_per_lineage) {
    return Result<Publication>::failure(Outcome::ResourceLimit, "max_attempts_per_lineage reached");
  }

  // Stage 14: commit.
  std::vector<ProvenanceNodeId> affected;
  Outcome outcome = Outcome::Created;

  if (request.kind == PublishKind::Link) {
    ProvenanceEdge edge;
    edge.lineage = lineage_id;
    edge.type = request.link_type;
    edge.from = request.link_from;
    edge.to = request.target;
    if (edge_type_is_successor_relation(edge.type)) {
      const ProvenanceNode* link_from = lineage->graph.find_node(edge.from);
      const ProvenanceNode* link_to = lineage->graph.find_node(edge.to);
      if (link_from == nullptr || link_to == nullptr ||
          link_from->kind != NodeKind::RouteGeneration ||
          link_to->kind != NodeKind::RouteGeneration) {
        return Result<Publication>::failure(Outcome::InvalidDerivation,
                                            "successor relations connect route state records");
      }
      edge.predecessor_route_generation = link_to->route_generation;
      edge.successor_route_generation = link_from->route_generation;
    }
    edge.reason = request.reason;
    edge.source = request.source;
    edge.evidence = request.evidence;
    edge.authority = request.authority;
    finalize_edge(edge);
    const Status added = lineage->graph.add_edge(edge, limits);
    if (!added.is_ok() && added.outcome() != Outcome::Duplicate) {
      return Result<Publication>(added.outcome(), std::nullopt, added.detail());
    }
    outcome = added.outcome() == Outcome::Duplicate ? Outcome::Duplicate : Outcome::Linked;
    affected.push_back(edge.from);
    affected.push_back(edge.to);
    edges.push_back(edge);
  } else {
    const Status added = lineage->graph.add_node(node, limits);
    if (!added.is_ok()) {
      if (added.outcome() == Outcome::Duplicate) {
        outcome = Outcome::Duplicate;
      } else {
        return Result<Publication>(added.outcome(), std::nullopt, added.detail());
      }
    }
    for (ProvenanceEdge& edge : edges) {
      const Status edge_added = lineage->graph.add_edge(edge, limits);
      if (!edge_added.is_ok()) {
        if (edge_added.outcome() == Outcome::Duplicate) {
          continue;
        }
        return Result<Publication>(edge_added.outcome(), std::nullopt, edge_added.detail());
      }
      if (outcome == Outcome::Duplicate) {
        outcome = Outcome::Linked;
      }
    }
    affected.push_back(node.id);
    for (const ProvenanceEdge& edge : edges) {
      affected.push_back(edge.to);
    }
  }

  // Commit bookkeeping.
  bool generation_ok = true;
  {
    std::unique_lock<std::shared_mutex> index_lock(index_mutex);
    static_cast<void>(next_store_generation(generation_ok));
  }
  if (!generation_ok) {
    return Result<Publication>::failure(Outcome::ResourceLimit, "store generation exhausted");
  }
  if (!bump_generation(lineage->state.lineage_generation)) {
    return Result<Publication>::failure(Outcome::ResourceLimit, "lineage generation exhausted");
  }
  if (!lineage->state.last_publisher_boot.valid() ||
      lineage->state.last_publisher_boot != request.authority.publisher.boot) {
    static_cast<void>(bump_generation(lineage->state.authority_generation));
    lineage->state.last_publisher_boot = request.authority.publisher.boot;
  }

  if (request.kind == PublishKind::RouteState) {
    const ProvenanceNode* previous = lineage->graph.find_node(lineage->state.current_node);
    lineage->state.current_route_generation = request.route_generation;
    if (request.root_reason.has_value() &&
        *request.root_reason == RootReason::RecoveredDurableState) {
      // Recovery publications do not restore live authority on their own.
      affected.push_back(node.id);
    }
    if (previous != nullptr && previous->id != node.id) {
      NodeLifecycle next = NodeLifecycle::Historical;
      for (const ProvenanceEdge& edge : edges) {
        if (edge.type == EdgeType::Supersedes && edge.to == previous->id) {
          next = NodeLifecycle::Superseded;
        }
      }
      static_cast<void>(lineage->graph.update_node_state(previous->id, next,
                                                         Currentness::HistoricalOnly, false));
      affected.push_back(previous->id);
    }
    if (lineage->state.lifecycle == LineageLifecycle::Withdrawn) {
      lineage->state.lifecycle = LineageLifecycle::Active;
    }
    lineage->state.current_node = node.id;
  } else if (request.kind == PublishKind::Correction) {
    // The replacement explains the same route state, so it re-binds the same causal
    // predecessors; without this the corrected ancestry would be unreachable.
    for (const ProvenanceEdge& original : lineage->graph.outgoing_edges(request.target)) {
      if (!edge_type_is_successor_relation(original.type)) {
        continue;
      }
      ProvenanceEdge rebound = original;
      rebound.from = node.id;
      rebound.authority = request.authority;
      finalize_edge(rebound);
      const Status added = lineage->graph.add_edge(rebound, limits);
      if (added.is_ok()) {
        edges.push_back(rebound);
      }
    }
    static_cast<void>(lineage->graph.set_corrected_by(request.target, node.id));
    static_cast<void>(lineage->graph.update_node_state(request.target, NodeLifecycle::Invalid,
                                                       Currentness::HistoricalOnly, false));
    if (lineage->state.current_node == request.target) {
      lineage->state.current_node = node.id;
    }
    affected.push_back(request.target);
    affected.push_back(node.id);
  } else if (request.kind == PublishKind::Withdrawal) {
    static_cast<void>(lineage->graph.update_node_state(request.target, NodeLifecycle::Historical,
                                                       Currentness::HistoricalOnly, false));
    lineage->state.lifecycle = LineageLifecycle::Withdrawn;
    affected.push_back(request.target);
  } else if (request.kind == PublishKind::Revocation) {
    static_cast<void>(lineage->graph.update_node_state(request.target, NodeLifecycle::Revoked,
                                                       Currentness::HistoricalOnly, false));
    lineage->state.lifecycle = LineageLifecycle::Revoked;
    affected.push_back(request.target);
  } else if (request.kind == PublishKind::Retirement) {
    static_cast<void>(lineage->graph.update_node_state(request.target, NodeLifecycle::Retired,
                                                       Currentness::HistoricalOnly, false));
    lineage->state.lifecycle = LineageLifecycle::Retired;
    affected.push_back(request.target);
  } else if (request.kind == PublishKind::Revalidation) {
    static_cast<void>(lineage->graph.update_node_state(request.target, NodeLifecycle::Current,
                                                       Currentness::RevalidationRequired, false));
    static_cast<void>(lineage->graph.mark_revalidated(request.target));
    static_cast<void>(bump_generation(lineage->state.authority_generation));
    affected.push_back(request.target);
  } else if (request.kind == PublishKind::Invalidation) {
    static_cast<void>(lineage->graph.update_node_state(request.target, NodeLifecycle::Invalid,
                                                       Currentness::HistoricalOnly, false));
    affected.push_back(request.target);
  } else if (request.kind == PublishKind::Declaration) {
    affected.push_back(node.id);
  }

  // Evidence relations promote a declared record to current authority.
  if (request.kind != PublishKind::Link) {
    for (const ProvenanceEdge& edge : edges) {
      const ProvenanceNode* target = lineage->graph.find_node(edge.to);
      if (target != nullptr && target->lifecycle == NodeLifecycle::Declared &&
          edge_type_is_evidence_relation(edge.type)) {
        static_cast<void>(
            lineage->graph.update_node_state(edge.to, NodeLifecycle::Current, target->currentness, false));
        affected.push_back(edge.to);
      }
    }
  } else {
    const ProvenanceNode* target = lineage->graph.find_node(request.target);
    if (target != nullptr && target->lifecycle == NodeLifecycle::Declared) {
      static_cast<void>(
          lineage->graph.update_node_state(request.target, NodeLifecycle::Current,
                                           target->currentness, false));
    }
  }

  // Refresh derived counters before the record state is recomputed.
  lineage->state.node_count = lineage->graph.node_count();
  lineage->state.edge_count = lineage->graph.edge_count();
  lineage->state.history_node_count = 0;
  for (const ProvenanceNode& existing : lineage->graph.nodes_in_order()) {
    if (node_is_history_record(existing)) {
      lineage->state.history_node_count += 1;
    }
  }

  const Status reevaluated = reevaluate_nodes(*lineage, affected);
  if (!reevaluated.is_ok()) {
    return Result<Publication>(reevaluated.outcome(), std::nullopt, reevaluated.detail());
  }
  static_cast<void>(reevaluate_nodes(*lineage, {lineage->state.current_node}));

  if (outcome != Outcome::Duplicate) {
    std::unique_lock<std::shared_mutex> index_lock(index_mutex);
    if (request.kind != PublishKind::Link) {
      node_owner[node.id] = lineage_id;
      if (node.kind == NodeKind::RouteGeneration) {
        route_generation_index[node.route][node.route_generation] = node.id;
      }
      if (node.bindings.path.has_value()) {
        path_index[node.bindings.path->path].insert(node.id);
        path_authority_index[node.bindings.path->generation].insert(node.id);
      }
      if (node.bindings.planner.has_value()) {
        path_index[node.bindings.planner->selected_path].insert(node.id);
      }
      if (node.bindings.policy.has_value()) {
        policy_index[node.bindings.policy->generation].insert(node.id);
      }
      if (node.bindings.adaptation.has_value()) {
        policy_index[node.bindings.adaptation->policy].insert(node.id);
        evidence_index[node.bindings.adaptation->evidence].insert(node.id);
      }
      boot_index[node.authority.publisher.boot].insert(node.id);
      publisher_index[node.authority.publisher.publisher].insert(node.id);
    }
  }

  AttemptRecord record;
  record.request = digest_of_request;
  record.node = request.kind == PublishKind::Link ? request.link_from : node.id;
  record.outcome = outcome;
  record.lifecycle = lineage->graph.find_node(record.node) != nullptr
                         ? lineage->graph.find_node(record.node)->lifecycle
                         : NodeLifecycle::Current;
  record.currentness = lineage->graph.find_node(record.node) != nullptr
                           ? lineage->graph.find_node(record.node)->currentness
                           : Currentness::HistoricalOnly;
  for (const ProvenanceEdge& edge : edges) {
    record.edges.push_back(edge.id);
  }
  lineage->attempts.emplace(attempt_key, record);
  lineage->state.last_mutation_digest = digest_of_request;

  Publication publication = make_publication(
      lineage_id, record.node, record.edges, lineage->state, read_watermarks(), record.lifecycle,
      record.currentness);
  return Result<Publication>(outcome, std::move(publication), std::string{});
}

}  // namespace route_provenance