// Route Provenance - shared canonical binary codec implementation.
#include <string>
#include <vector>

#include "codec.hpp"

namespace route_provenance {
namespace codec {
namespace {

// Binding presence bits. A binding that is absent is not encoded at all, and a presence bit
// that is not defined here is rejected rather than ignored.
constexpr std::uint32_t kBindingPresencePath = 1U << 0U;
constexpr std::uint32_t kBindingPresencePlanner = 1U << 1U;
constexpr std::uint32_t kBindingPresenceEcmp = 1U << 2U;
constexpr std::uint32_t kBindingPresenceWeighted = 1U << 3U;
constexpr std::uint32_t kBindingPresenceAdaptation = 1U << 4U;
constexpr std::uint32_t kBindingPresenceConvergence = 1U << 5U;
constexpr std::uint32_t kBindingPresencePolicy = 1U << 6U;
constexpr std::uint32_t kBindingPresenceAll = kBindingPresencePath | kBindingPresencePlanner |
                                             kBindingPresenceEcmp | kBindingPresenceWeighted |
                                             kBindingPresenceAdaptation |
                                             kBindingPresenceConvergence | kBindingPresencePolicy;

}  // namespace

bool is_known(NodeKind value) noexcept { return to_string(value) != "UNKNOWN"; }
bool is_known(EdgeType value) noexcept { return to_string(value) != "UNKNOWN"; }
bool is_known(ReasonCode value) noexcept { return to_string(value) != "UNKNOWN"; }
bool is_known(SourceClass value) noexcept { return to_string(value) != "UNKNOWN"; }
bool is_known(NodeLifecycle value) noexcept { return to_string(value) != "UNKNOWN"; }
bool is_known(Currentness value) noexcept { return to_string(value) != "UNKNOWN"; }
bool is_known(LineageLifecycle value) noexcept { return to_string(value) != "UNKNOWN"; }
bool is_known(Outcome value) noexcept { return to_string(value) != "UNKNOWN"; }
bool is_known(RootReason value) noexcept { return to_string(value) != "UNKNOWN"; }

void write_evidence(Writer& writer, const EvidenceVector& evidence) {
  writer.u16(static_cast<std::uint16_t>(evidence.size()));
  for (const EvidenceEntry& entry : evidence.entries()) {
    writer.u16(static_cast<std::uint16_t>(entry.field));
    writer.u64(entry.value);
  }
}

bool read_evidence(Reader& reader, EvidenceVector& out, const Limits& limits) {
  const std::uint16_t count = reader.u16();
  if (reader.failed() || count > limits.max_evidence_entries) {
    return false;
  }
  std::vector<EvidenceEntry> entries;
  entries.reserve(count);
  for (std::uint16_t i = 0; i < count; ++i) {
    EvidenceEntry entry;
    entry.field = static_cast<EvidenceField>(reader.u16());
    entry.value = reader.u64();
    if (reader.failed()) {
      return false;
    }
    entries.push_back(entry);
  }
  const Result<EvidenceVector> canonical = EvidenceVector::create(std::move(entries), limits);
  if (!canonical.has_value()) {
    return false;
  }
  out = canonical.value();
  return true;
}

void write_authority(Writer& writer, const AuthorityContext& authority) {
  writer.u64(authority.publisher.publisher.value());
  writer.u64(authority.publisher.boot.value());
  writer.u64(authority.publisher.epoch.value());
  writer.u64(authority.attempt.value());
  writer.u16(static_cast<std::uint16_t>(authority.scope.kind()));
  writer.u64(authority.scope.subject());
  writer.u64(authority.expected_lineage_generation.has_value()
                 ? authority.expected_lineage_generation->value()
                 : 0);
  writer.u64(authority.expected_provenance_generation.has_value()
                 ? authority.expected_provenance_generation->value()
                 : 0);
}

bool read_authority(Reader& reader, AuthorityContext& out) {
  AuthorityContext authority;
  authority.publisher.publisher = PublisherId::from_value(reader.u64());
  authority.publisher.boot = WorkerBootId::from_value(reader.u64());
  authority.publisher.epoch = CoordinatorEpoch::from_value(reader.u64());
  authority.attempt = MutationAttemptId::from_value(reader.u64());
  const auto kind_raw = static_cast<std::uint16_t>(reader.u16());
  const std::uint64_t subject = reader.u64();
  const std::uint64_t expected_lineage = reader.u64();
  const std::uint64_t expected_provenance = reader.u64();
  if (reader.failed()) {
    return false;
  }
  switch (kind_raw) {
    case static_cast<std::uint16_t>(ScopeKind::None):
      authority.scope = AuthorityScope::none();
      break;
    case static_cast<std::uint16_t>(ScopeKind::Fabric):
      authority.scope = AuthorityScope::fabric();
      break;
    case static_cast<std::uint16_t>(ScopeKind::RoutingNamespace):
      authority.scope = AuthorityScope::routing_namespace(RoutingNamespaceId::from_value(subject));
      break;
    case static_cast<std::uint16_t>(ScopeKind::Lineage):
      authority.scope = AuthorityScope::lineage(RouteLineageId::from_value(subject));
      break;
    case static_cast<std::uint16_t>(ScopeKind::Route):
      authority.scope = AuthorityScope::route(RouteId::from_value(subject));
      break;
    default:
      return false;
  }
  if (expected_lineage != 0) {
    authority.expected_lineage_generation = LineageGeneration::from_value(expected_lineage);
  }
  if (expected_provenance != 0) {
    authority.expected_provenance_generation = ProvenanceGeneration::from_value(expected_provenance);
  }
  out = authority;
  return true;
}

void write_bindings(Writer& writer, const Bindings& bindings) {
  std::uint32_t presence = 0;
  if (bindings.path.has_value()) {
    presence |= kBindingPresencePath;
  }
  if (bindings.planner.has_value()) {
    presence |= kBindingPresencePlanner;
  }
  if (bindings.ecmp.has_value()) {
    presence |= kBindingPresenceEcmp;
  }
  if (bindings.weighted.has_value()) {
    presence |= kBindingPresenceWeighted;
  }
  if (bindings.adaptation.has_value()) {
    presence |= kBindingPresenceAdaptation;
  }
  if (bindings.convergence.has_value()) {
    presence |= kBindingPresenceConvergence;
  }
  if (bindings.policy.has_value()) {
    presence |= kBindingPresencePolicy;
  }
  writer.u32(presence);
  if (bindings.path.has_value()) {
    writer.u64(bindings.path->path.value());
    writer.u64(bindings.path->generation.value());
    writer.digest(bindings.path->decision_digest);
  }
  if (bindings.planner.has_value()) {
    writer.u64(bindings.planner->request.value());
    writer.u64(bindings.planner->generation.value());
    writer.u32(bindings.planner->candidate_rank);
    writer.digest(bindings.planner->plan_digest);
    writer.u64(bindings.planner->selected_path.value());
  }
  if (bindings.ecmp.has_value()) {
    writer.u64(bindings.ecmp->group.value());
    writer.u64(bindings.ecmp->membership.value());
    writer.u64(bindings.ecmp->assignment.value());
  }
  if (bindings.weighted.has_value()) {
    writer.u64(bindings.weighted->set.value());
    writer.u64(bindings.weighted->policy.value());
    writer.u64(bindings.weighted->assignment.value());
  }
  if (bindings.adaptation.has_value()) {
    writer.u64(bindings.adaptation->decision.value());
    writer.u64(bindings.adaptation->generation.value());
    writer.u64(bindings.adaptation->policy.value());
    writer.u64(bindings.adaptation->evidence.value());
    writer.digest(bindings.adaptation->decision_digest);
  }
  if (bindings.convergence.has_value()) {
    writer.u64(bindings.convergence->plan.value());
    writer.u64(bindings.convergence->generation.value());
    writer.u64(bindings.convergence->step.value());
    writer.digest(bindings.convergence->completion_evidence);
  }
  if (bindings.policy.has_value()) {
    writer.u64(bindings.policy->generation.value());
  }
}

bool read_bindings(Reader& reader, Bindings& out) {
  const std::uint32_t presence = reader.u32();
  if (reader.failed() || (presence & ~kBindingPresenceAll) != 0) {
    return false;
  }
  Bindings bindings;
  if ((presence & kBindingPresencePath) != 0) {
    PathBinding binding;
    binding.path = PathId::from_value(reader.u64());
    binding.generation = PathAuthorityGeneration::from_value(reader.u64());
    binding.decision_digest = reader.digest();
    bindings.path = binding;
  }
  if ((presence & kBindingPresencePlanner) != 0) {
    PlannerBinding binding;
    binding.request = PlannerRequestId::from_value(reader.u64());
    binding.generation = PlannerGeneration::from_value(reader.u64());
    binding.candidate_rank = reader.u32();
    binding.plan_digest = reader.digest();
    binding.selected_path = PathId::from_value(reader.u64());
    bindings.planner = binding;
  }
  if ((presence & kBindingPresenceEcmp) != 0) {
    EcmpBinding binding;
    binding.group = EcmpGroupId::from_value(reader.u64());
    binding.membership = MembershipGeneration::from_value(reader.u64());
    binding.assignment = AssignmentGeneration::from_value(reader.u64());
    bindings.ecmp = binding;
  }
  if ((presence & kBindingPresenceWeighted) != 0) {
    WeightedPathBinding binding;
    binding.set = WeightedPathSetId::from_value(reader.u64());
    binding.policy = WeightPolicyGeneration::from_value(reader.u64());
    binding.assignment = AssignmentGeneration::from_value(reader.u64());
    bindings.weighted = binding;
  }
  if ((presence & kBindingPresenceAdaptation) != 0) {
    AdaptationBinding binding;
    binding.decision = AdaptationDecisionId::from_value(reader.u64());
    binding.generation = AdaptationGeneration::from_value(reader.u64());
    binding.policy = PolicyGeneration::from_value(reader.u64());
    binding.evidence = EvidenceGeneration::from_value(reader.u64());
    binding.decision_digest = reader.digest();
    bindings.adaptation = binding;
  }
  if ((presence & kBindingPresenceConvergence) != 0) {
    ConvergenceBinding binding;
    binding.plan = ConvergencePlanId::from_value(reader.u64());
    binding.generation = ConvergencePlanGeneration::from_value(reader.u64());
    binding.step = ConvergenceStepId::from_value(reader.u64());
    binding.completion_evidence = reader.digest();
    bindings.convergence = binding;
  }
  if ((presence & kBindingPresencePolicy) != 0) {
    PolicyBinding binding;
    binding.generation = PolicyGeneration::from_value(reader.u64());
    bindings.policy = binding;
  }
  if (reader.failed()) {
    return false;
  }
  out = bindings;
  return true;
}

void write_node(Writer& writer, const ProvenanceNode& node) {
  writer.u64(node.id.value());
  writer.u16(static_cast<std::uint16_t>(node.kind));
  writer.u16(static_cast<std::uint16_t>(node.reason));
  writer.u16(static_cast<std::uint16_t>(node.source));
  writer.u16(node.root_reason.has_value() ? static_cast<std::uint16_t>(*node.root_reason) : 0);
  writer.u16(static_cast<std::uint16_t>(node.lifecycle));
  writer.u16(static_cast<std::uint16_t>(node.currentness));
  writer.u8(node.revalidation_required ? 1U : 0U);
  writer.u8(node.revalidated ? 1U : 0U);
  writer.u16(0);
  writer.u64(node.lineage.value());
  writer.u64(node.route.value());
  writer.u64(node.route_generation.value());
  writer.u64(node.corrects.has_value() ? node.corrects->value() : 0);
  writer.u64(node.corrected_by.has_value() ? node.corrected_by->value() : 0);
  writer.digest(node.route_state_digest);
  writer.u8(node.compacted_digest.has_value() ? 1U : 0U);
  writer.digest(node.compacted_digest.value_or(Digest{}));
  write_evidence(writer, node.evidence);
  write_authority(writer, node.authority);
  write_bindings(writer, node.bindings);
}

bool read_node(Reader& reader, ProvenanceNode& out, const Limits& limits) {
  ProvenanceNode node;
  node.id = ProvenanceNodeId::from_value(reader.u64());
  const auto kind_raw = reader.u16();
  const auto reason_raw = reader.u16();
  const auto source_raw = reader.u16();
  const auto root_raw = reader.u16();
  const auto lifecycle_raw = reader.u16();
  const auto currentness_raw = reader.u16();
  const std::uint8_t revalidation = reader.u8();
  const std::uint8_t revalidated = reader.u8();
  static_cast<void>(reader.u16());
  if (reader.failed()) {
    return false;
  }
  node.kind = static_cast<NodeKind>(kind_raw);
  node.reason = static_cast<ReasonCode>(reason_raw);
  node.source = static_cast<SourceClass>(source_raw);
  node.lifecycle = static_cast<NodeLifecycle>(lifecycle_raw);
  node.currentness = static_cast<Currentness>(currentness_raw);
  if (!is_known(node.kind) || !is_known(node.reason) || !is_known(node.source) ||
      !is_known(node.lifecycle) || !is_known(node.currentness)) {
    return false;
  }
  if (root_raw != 0) {
    const auto root = static_cast<RootReason>(root_raw);
    if (!is_known(root)) {
      return false;
    }
    node.root_reason = root;
  }
  if (revalidation > 1U || revalidated > 1U) {
    return false;
  }
  node.revalidation_required = revalidation == 1U;
  node.revalidated = revalidated == 1U;
  node.lineage = RouteLineageId::from_value(reader.u64());
  node.route = RouteId::from_value(reader.u64());
  node.route_generation = RouteGeneration::from_value(reader.u64());
  const std::uint64_t corrects = reader.u64();
  const std::uint64_t corrected_by = reader.u64();
  node.route_state_digest = reader.digest();
  const std::uint8_t has_compacted = reader.u8();
  const Digest compacted = reader.digest();
  if (reader.failed() || has_compacted > 1U) {
    return false;
  }
  if (corrects != 0) {
    node.corrects = ProvenanceNodeId::from_value(corrects);
  }
  if (corrected_by != 0) {
    node.corrected_by = ProvenanceNodeId::from_value(corrected_by);
  }
  if (has_compacted == 1U) {
    node.compacted_digest = compacted;
  }
  if (!read_evidence(reader, node.evidence, limits)) {
    return false;
  }
  if (!read_authority(reader, node.authority)) {
    return false;
  }
  if (!read_bindings(reader, node.bindings)) {
    return false;
  }
  out = node;
  return true;
}

void write_edge(Writer& writer, const ProvenanceEdge& edge) {
  writer.u64(edge.id.value());
  writer.u64(edge.derivation.value());
  writer.u64(edge.lineage.value());
  writer.u16(static_cast<std::uint16_t>(edge.type));
  writer.u16(static_cast<std::uint16_t>(edge.reason));
  writer.u16(static_cast<std::uint16_t>(edge.source));
  writer.u16(0);
  writer.u64(edge.from.value());
  writer.u64(edge.to.value());
  writer.u64(edge.predecessor_route_generation.value());
  writer.u64(edge.successor_route_generation.value());
  write_evidence(writer, edge.evidence);
  write_authority(writer, edge.authority);
}

bool read_edge(Reader& reader, ProvenanceEdge& out, const Limits& limits) {
  ProvenanceEdge edge;
  edge.id = ProvenanceEdgeId::from_value(reader.u64());
  edge.derivation = DerivationId::from_value(reader.u64());
  edge.lineage = RouteLineageId::from_value(reader.u64());
  const auto type_raw = reader.u16();
  const auto reason_raw = reader.u16();
  const auto source_raw = reader.u16();
  static_cast<void>(reader.u16());
  if (reader.failed()) {
    return false;
  }
  edge.type = static_cast<EdgeType>(type_raw);
  edge.reason = static_cast<ReasonCode>(reason_raw);
  edge.source = static_cast<SourceClass>(source_raw);
  if (!is_known(edge.type) || !is_known(edge.reason) || !is_known(edge.source)) {
    return false;
  }
  edge.from = ProvenanceNodeId::from_value(reader.u64());
  edge.to = ProvenanceNodeId::from_value(reader.u64());
  edge.predecessor_route_generation = RouteGeneration::from_value(reader.u64());
  edge.successor_route_generation = RouteGeneration::from_value(reader.u64());
  if (!read_evidence(reader, edge.evidence, limits)) {
    return false;
  }
  if (!read_authority(reader, edge.authority)) {
    return false;
  }
  out = edge;
  return true;
}

void write_attempt(Writer& writer, const StoredAttempt& attempt) {
  writer.u64(attempt.publisher.value());
  writer.u64(attempt.attempt.value());
  writer.digest(attempt.request);
  writer.u64(attempt.node.value());
  writer.u16(static_cast<std::uint16_t>(attempt.outcome));
  writer.u16(static_cast<std::uint16_t>(attempt.lifecycle));
  writer.u16(static_cast<std::uint16_t>(attempt.currentness));
  writer.u16(0);
  writer.u32(static_cast<std::uint32_t>(attempt.edges.size()));
  for (const ProvenanceEdgeId id : attempt.edges) {
    writer.u64(id.value());
  }
}

bool read_attempt(Reader& reader, StoredAttempt& out, const Limits& limits) {
  StoredAttempt attempt;
  attempt.publisher = PublisherId::from_value(reader.u64());
  attempt.attempt = MutationAttemptId::from_value(reader.u64());
  attempt.request = reader.digest();
  attempt.node = ProvenanceNodeId::from_value(reader.u64());
  const auto outcome_raw = reader.u16();
  const auto lifecycle_raw = reader.u16();
  const auto currentness_raw = reader.u16();
  static_cast<void>(reader.u16());
  const std::uint32_t edge_count = reader.u32();
  if (reader.failed() || edge_count > limits.max_edges_per_lineage) {
    return false;
  }
  attempt.outcome = static_cast<Outcome>(outcome_raw);
  attempt.lifecycle = static_cast<NodeLifecycle>(lifecycle_raw);
  attempt.currentness = static_cast<Currentness>(currentness_raw);
  if (!is_known(attempt.outcome) || !is_known(attempt.lifecycle) || !is_known(attempt.currentness)) {
    return false;
  }
  attempt.edges.reserve(edge_count);
  for (std::uint32_t i = 0; i < edge_count; ++i) {
    attempt.edges.push_back(ProvenanceEdgeId::from_value(reader.u64()));
  }
  if (reader.failed()) {
    return false;
  }
  out = attempt;
  return true;
}

}  // namespace codec
}  // namespace route_provenance