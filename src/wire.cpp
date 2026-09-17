// Route Provenance - framed wire protocol implementation.
#include <algorithm>
#include <set>
#include <string>
#include <vector>

#include "codec.hpp"
#include "route_provenance/wire.hpp"

namespace route_provenance {
namespace {

/// Field identifiers are 16-bit on the wire; all arithmetic is narrowed explicitly so that no
/// implicit integer conversion can silently truncate a field identifier.
[[nodiscard]] constexpr std::uint16_t fid(std::uint16_t base, std::uint16_t offset) noexcept {
  return static_cast<std::uint16_t>(base + offset);
}

/// Field bases of the composite payload sections. These identifiers are stable and are part
/// of the wire protocol contract.
constexpr std::uint16_t kAuthorityBase = 8;
constexpr std::uint16_t kEvidenceField = 16;
constexpr std::uint16_t kBindingsBase = 20;
constexpr std::uint16_t kEdgesBase = 100;

constexpr std::uint8_t kMagicFirst = 0x52U;  // 'R'
constexpr std::uint8_t kMagicSecond = 0x50U;  // 'P'
constexpr std::size_t kFramePrefixBytes = 16;

[[nodiscard]] Status check_fields(const FieldBag& bag, const std::set<std::uint16_t>& allowed,
                                  const std::set<std::uint16_t>& required) {
  for (const std::uint16_t field : bag.field_ids()) {
    if (allowed.find(field) == allowed.end()) {
      return Status::failure(Outcome::ProtocolFailure, "payload contains an unknown field identifier");
    }
  }
  for (const std::uint16_t field : required) {
    if (!bag.has(field)) {
      return Status::failure(Outcome::MalformedRequest, "payload is missing a required field");
    }
  }
  return Status::ok();
}

/// Builds the set of field identifiers a message may carry, from inclusive ranges.
[[nodiscard]] std::set<std::uint16_t> field_ranges(
    std::initializer_list<std::pair<std::uint32_t, std::uint32_t>> ranges) {
  std::set<std::uint16_t> allowed;
  for (const auto& range : ranges) {
    for (std::uint32_t value = range.first; value <= range.second; ++value) {
      allowed.insert(static_cast<std::uint16_t>(value));
    }
  }
  return allowed;
}

/// Field ranges of a message that carries an authority context, evidence and bindings.
[[nodiscard]] std::set<std::uint16_t> standard_ranges(const Limits& limits) {
  const std::uint32_t edges_last = kEdgesBase + 5U * limits.max_batch_size;
  return field_ranges({{1, 7},
                       {kAuthorityBase, kAuthorityBase + 7U},
                       {kEvidenceField, kEvidenceField},
                       {kBindingsBase, kBindingsBase + 24U},
                       {kEdgesBase, edges_last}});
}

void put_authority(FieldBag& bag, const AuthorityContext& authority, std::uint16_t base) {
  bag.set_u64(fid(base, 0), authority.publisher.publisher.value());
  bag.set_u64(fid(base, 1), authority.publisher.boot.value());
  bag.set_u64(fid(base, 2), authority.publisher.epoch.value());
  bag.set_u64(fid(base, 3), authority.attempt.value());
  bag.set_u16(fid(base, 4), static_cast<std::uint16_t>(authority.scope.kind()));
  bag.set_u64(fid(base, 5), authority.scope.subject());
  bag.set_u64(fid(base, 6), authority.expected_lineage_generation.has_value()
                                ? authority.expected_lineage_generation->value()
                                : 0);
  bag.set_u64(fid(base, 7), authority.expected_provenance_generation.has_value()
                                ? authority.expected_provenance_generation->value()
                                : 0);
}

[[nodiscard]] Result<AuthorityContext> take_authority(const FieldBag& bag, std::uint16_t base,
                                                      const Limits& limits) {
  static_cast<void>(limits);
  AuthorityContext authority;
  authority.publisher.publisher = PublisherId::from_value(bag.u64(fid(base, 0)).value_or(0));
  authority.publisher.boot = WorkerBootId::from_value(bag.u64(fid(base, 1)).value_or(0));
  authority.publisher.epoch = CoordinatorEpoch::from_value(bag.u64(fid(base, 2)).value_or(0));
  authority.attempt = MutationAttemptId::from_value(bag.u64(fid(base, 3)).value_or(0));
  const std::uint16_t scope_kind = bag.u16(fid(base, 4)).value_or(0xFFFFU);
  const std::uint64_t subject = bag.u64(fid(base, 5)).value_or(0);
  switch (scope_kind) {
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
      return Result<AuthorityContext>::failure(Outcome::ProtocolFailure, "unknown authority scope kind");
  }
  const std::uint64_t expected_lineage = bag.u64(fid(base, 6)).value_or(0);
  const std::uint64_t expected_store = bag.u64(fid(base, 7)).value_or(0);
  if (expected_lineage != 0) {
    authority.expected_lineage_generation = LineageGeneration::from_value(expected_lineage);
  }
  if (expected_store != 0) {
    authority.expected_provenance_generation = ProvenanceGeneration::from_value(expected_store);
  }
  return Result<AuthorityContext>::ok(authority);
}

void put_evidence(FieldBag& bag, const EvidenceVector& evidence, std::uint16_t field) {
  FieldBag nested;
  for (const EvidenceEntry& entry : evidence.entries()) {
    nested.set_u64(static_cast<std::uint16_t>(entry.field), entry.value);
  }
  bag.set_nested(field, nested);
}

[[nodiscard]] Result<EvidenceVector> take_evidence(const FieldBag& bag, std::uint16_t field,
                                                   const Limits& limits) {
  if (!bag.has(field)) {
    return Result<EvidenceVector>::ok(EvidenceVector{});
  }
  const std::optional<FieldBag> nested = bag.nested(field, limits);
  if (!nested.has_value()) {
    return Result<EvidenceVector>::failure(Outcome::ProtocolFailure, "malformed evidence vector");
  }
  static constexpr EvidenceField kFields[] = {
      EvidenceField::TopologyGeneration,      EvidenceField::LinkStateGeneration,
      EvidenceField::PortGeneration,          EvidenceField::CapabilityGeneration,
      EvidenceField::FailureDomainGeneration, EvidenceField::FabricEpoch,
      EvidenceField::PathAuthorityGeneration, EvidenceField::PlannerGeneration,
      EvidenceField::AdaptivePolicyGeneration, EvidenceField::ConvergencePlanGeneration,
      EvidenceField::RouteGeneration,         EvidenceField::PublisherGeneration};
  std::set<std::uint16_t> allowed;
  for (const EvidenceField known : kFields) {
    allowed.insert(static_cast<std::uint16_t>(known));
  }
  const Status fields = check_fields(nested.value(), allowed, {});
  if (!fields.is_ok()) {
    return Result<EvidenceVector>::failure(fields.outcome(), fields.detail());
  }
  std::vector<EvidenceEntry> entries;
  for (const EvidenceField known : kFields) {
    const std::optional<std::uint64_t> value = nested->u64(static_cast<std::uint16_t>(known));
    if (value.has_value()) {
      entries.push_back(EvidenceEntry{known, *value});
    }
  }
  return EvidenceVector::create(std::move(entries), limits);
}

void put_bindings(FieldBag& bag, const Bindings& bindings, std::uint16_t base) {
  std::uint32_t presence = 0;
  std::uint32_t bit = 1;
  const auto mark = [&presence, &bit](bool present) {
    if (present) {
      presence |= bit;
    }
    bit <<= 1U;
  };
  mark(bindings.path.has_value());
  mark(bindings.planner.has_value());
  mark(bindings.ecmp.has_value());
  mark(bindings.weighted.has_value());
  mark(bindings.adaptation.has_value());
  mark(bindings.convergence.has_value());
  mark(bindings.policy.has_value());
  bag.set_u32(fid(base, 0), presence);
  std::uint16_t cursor = fid(base, 1);
  const auto next = [&cursor]() { return static_cast<std::uint16_t>(cursor++); };
  if (bindings.path.has_value()) {
    bag.set_u64(next(), bindings.path->path.value());
    bag.set_u64(next(), bindings.path->generation.value());
    bag.set_digest(next(), bindings.path->decision_digest);
  }
  if (bindings.planner.has_value()) {
    bag.set_u64(next(), bindings.planner->request.value());
    bag.set_u64(next(), bindings.planner->generation.value());
    bag.set_u32(next(), bindings.planner->candidate_rank);
    bag.set_digest(next(), bindings.planner->plan_digest);
    bag.set_u64(next(), bindings.planner->selected_path.value());
  }
  if (bindings.ecmp.has_value()) {
    bag.set_u64(next(), bindings.ecmp->group.value());
    bag.set_u64(next(), bindings.ecmp->membership.value());
    bag.set_u64(next(), bindings.ecmp->assignment.value());
  }
  if (bindings.weighted.has_value()) {
    bag.set_u64(next(), bindings.weighted->set.value());
    bag.set_u64(next(), bindings.weighted->policy.value());
    bag.set_u64(next(), bindings.weighted->assignment.value());
  }
  if (bindings.adaptation.has_value()) {
    bag.set_u64(next(), bindings.adaptation->decision.value());
    bag.set_u64(next(), bindings.adaptation->generation.value());
    bag.set_u64(next(), bindings.adaptation->policy.value());
    bag.set_u64(next(), bindings.adaptation->evidence.value());
    bag.set_digest(next(), bindings.adaptation->decision_digest);
  }
  if (bindings.convergence.has_value()) {
    bag.set_u64(next(), bindings.convergence->plan.value());
    bag.set_u64(next(), bindings.convergence->generation.value());
    bag.set_u64(next(), bindings.convergence->step.value());
    bag.set_digest(next(), bindings.convergence->completion_evidence);
  }
  if (bindings.policy.has_value()) {
    bag.set_u64(next(), bindings.policy->generation.value());
  }
}

[[nodiscard]] Result<Bindings> take_bindings(const FieldBag& bag, std::uint16_t base) {
  const std::optional<std::uint32_t> presence = bag.u32(fid(base, 0));
  if (!presence.has_value()) {
    return Result<Bindings>::failure(Outcome::MalformedRequest, "missing binding presence mask");
  }
  if ((*presence & ~0x7FU) != 0) {
    return Result<Bindings>::failure(Outcome::ProtocolFailure, "unknown binding presence bit");
  }
  Bindings bindings;
  std::uint16_t cursor = fid(base, 1);
  const auto next = [&cursor]() { return static_cast<std::uint16_t>(cursor++); };
  if ((*presence & 0x01U) != 0) {
    PathBinding binding;
    binding.path = PathId::from_value(bag.u64(next()).value_or(0));
    binding.generation = PathAuthorityGeneration::from_value(bag.u64(next()).value_or(0));
    binding.decision_digest = bag.digest(next()).value_or(Digest{});
    bindings.path = binding;
  }
  if ((*presence & 0x02U) != 0) {
    PlannerBinding binding;
    binding.request = PlannerRequestId::from_value(bag.u64(next()).value_or(0));
    binding.generation = PlannerGeneration::from_value(bag.u64(next()).value_or(0));
    binding.candidate_rank = bag.u32(next()).value_or(0);
    binding.plan_digest = bag.digest(next()).value_or(Digest{});
    binding.selected_path = PathId::from_value(bag.u64(next()).value_or(0));
    bindings.planner = binding;
  }
  if ((*presence & 0x04U) != 0) {
    EcmpBinding binding;
    binding.group = EcmpGroupId::from_value(bag.u64(next()).value_or(0));
    binding.membership = MembershipGeneration::from_value(bag.u64(next()).value_or(0));
    binding.assignment = AssignmentGeneration::from_value(bag.u64(next()).value_or(0));
    bindings.ecmp = binding;
  }
  if ((*presence & 0x08U) != 0) {
    WeightedPathBinding binding;
    binding.set = WeightedPathSetId::from_value(bag.u64(next()).value_or(0));
    binding.policy = WeightPolicyGeneration::from_value(bag.u64(next()).value_or(0));
    binding.assignment = AssignmentGeneration::from_value(bag.u64(next()).value_or(0));
    bindings.weighted = binding;
  }
  if ((*presence & 0x10U) != 0) {
    AdaptationBinding binding;
    binding.decision = AdaptationDecisionId::from_value(bag.u64(next()).value_or(0));
    binding.generation = AdaptationGeneration::from_value(bag.u64(next()).value_or(0));
    binding.policy = PolicyGeneration::from_value(bag.u64(next()).value_or(0));
    binding.evidence = EvidenceGeneration::from_value(bag.u64(next()).value_or(0));
    binding.decision_digest = bag.digest(next()).value_or(Digest{});
    bindings.adaptation = binding;
  }
  if ((*presence & 0x20U) != 0) {
    ConvergenceBinding binding;
    binding.plan = ConvergencePlanId::from_value(bag.u64(next()).value_or(0));
    binding.generation = ConvergencePlanGeneration::from_value(bag.u64(next()).value_or(0));
    binding.step = ConvergenceStepId::from_value(bag.u64(next()).value_or(0));
    binding.completion_evidence = bag.digest(next()).value_or(Digest{});
    bindings.convergence = binding;
  }
  if ((*presence & 0x40U) != 0) {
    PolicyBinding binding;
    binding.generation = PolicyGeneration::from_value(bag.u64(next()).value_or(0));
    bindings.policy = binding;
  }
  return Result<Bindings>::ok(bindings);
}

void put_edges(FieldBag& bag, const std::vector<EdgeSpec>& edges, std::uint16_t base) {
  bag.set_u32(base, static_cast<std::uint32_t>(edges.size()));
  std::uint16_t cursor = fid(base, 1);
  const auto next = [&cursor]() { return static_cast<std::uint16_t>(cursor++); };
  for (const EdgeSpec& spec : edges) {
    bag.set_u16(next(), static_cast<std::uint16_t>(spec.type));
    bag.set_u64(next(), spec.target.value());
    bag.set_u16(next(), static_cast<std::uint16_t>(spec.reason));
    bag.set_u16(next(), static_cast<std::uint16_t>(spec.source));
    FieldBag evidence;
    put_evidence(evidence, spec.evidence, 1);
    bag.set_nested(next(), evidence);
  }
}

[[nodiscard]] Result<std::vector<EdgeSpec>> take_edges(const FieldBag& bag, std::uint16_t base,
                                                       const Limits& limits) {
  const std::optional<std::uint32_t> count = bag.u32(base);
  if (!count.has_value()) {
    return Result<std::vector<EdgeSpec>>::failure(Outcome::MalformedRequest, "missing derivation count");
  }
  if (*count > limits.max_batch_size) {
    return Result<std::vector<EdgeSpec>>::failure(Outcome::ResourceLimit, "derivation batch exceeds the bound");
  }
  std::vector<EdgeSpec> edges;
  std::uint16_t cursor = fid(base, 1);
  const auto next = [&cursor]() { return static_cast<std::uint16_t>(cursor++); };
  for (std::uint32_t i = 0; i < *count; ++i) {
    EdgeSpec spec;
    const std::optional<std::uint16_t> type = bag.u16(next());
    spec.target = ProvenanceNodeId::from_value(bag.u64(next()).value_or(0));
    const std::optional<std::uint16_t> reason = bag.u16(next());
    const std::optional<std::uint16_t> source = bag.u16(next());
    if (!type.has_value() || !reason.has_value() || !source.has_value()) {
      return Result<std::vector<EdgeSpec>>::failure(Outcome::MalformedRequest, "malformed derivation edge");
    }
    spec.type = static_cast<EdgeType>(*type);
    spec.reason = static_cast<ReasonCode>(*reason);
    spec.source = static_cast<SourceClass>(*source);
    if (to_string(spec.type) == "UNKNOWN" || to_string(spec.reason) == "UNKNOWN" ||
        to_string(spec.source) == "UNKNOWN") {
      return Result<std::vector<EdgeSpec>>::failure(Outcome::ProtocolFailure, "unknown derivation enum value");
    }
    const Result<EvidenceVector> evidence = take_evidence(bag, next(), limits);
    if (!evidence.has_value()) {
      return Result<std::vector<EdgeSpec>>::failure(evidence.outcome(), evidence.detail());
    }
    spec.evidence = evidence.value();
    edges.push_back(std::move(spec));
  }
  return Result<std::vector<EdgeSpec>>::ok(std::move(edges));
}

[[nodiscard]] Result<LineageKey> take_key(const FieldBag& bag, std::uint16_t route_field,
                                          std::uint16_t key_field, const Limits& limits) {
  LineageKey key;
  key.route = RouteId::from_value(bag.u64(route_field).value_or(0));
  const std::optional<std::string> text = bag.text(key_field);
  if (!text.has_value()) {
    return Result<LineageKey>::failure(Outcome::MalformedRequest, "lineage key is missing");
  }
  if (text->size() > limits.max_semantic_key_bytes) {
    return Result<LineageKey>::failure(Outcome::ResourceLimit, "lineage key exceeds the bound");
  }
  key.semantic_key = *text;
  return Result<LineageKey>::ok(std::move(key));
}

}  // namespace
// ---------------------------------------------------------------------------
// Frame layer
// ---------------------------------------------------------------------------

Digest frame_digest(const FrameHeader& header, ByteSpan payload) noexcept {
  CanonicalEncoder encoder;
  encoder.add_u32(1, kGraphEncodingVersion);
  encoder.add_u16(2, header.protocol_version);
  encoder.add_u16(3, static_cast<std::uint16_t>(header.message));
  encoder.add_u16(4, header.flags);
  encoder.add_u64(5, header.epoch.value());
  encoder.add_u64(6, header.publisher.value());
  encoder.add_u64(7, header.boot.value());
  encoder.add_u64(8, header.attempt.value());
  encoder.add_u32(9, header.payload_bytes);
  Hasher hasher;
  const ByteVector& encoded = encoder.bytes();
  hasher.update(ByteSpan(encoded.data(), encoded.size()));
  hasher.update(payload);
  return hasher.finish();
}

Status encode_frame(const FrameHeader& header, ByteSpan payload, const Limits& limits, ByteVector& out) {
  if (to_string(header.message) == "UNKNOWN") {
    return Status::failure(Outcome::ProtocolFailure, "unknown message identifier");
  }
  if (header.protocol_version != kWireProtocolVersion) {
    return Status::failure(Outcome::UnsupportedVersion, "wire protocol version mismatch");
  }
  if (header.flags != 0) {
    return Status::failure(Outcome::MalformedRequest, "unsupported frame flags");
  }
  if (payload.size() > limits.max_frame_bytes) {
    return Status::failure(Outcome::ResourceLimit, "payload exceeds max_frame_bytes");
  }
  const std::uint64_t total = static_cast<std::uint64_t>(kFrameHeaderBytes) + payload.size() +
                              static_cast<std::uint64_t>(kFrameTrailerBytes);
  if (total > limits.max_frame_bytes) {
    return Status::failure(Outcome::ResourceLimit, "frame exceeds max_frame_bytes");
  }
  FrameHeader effective = header;
  effective.payload_bytes = static_cast<std::uint32_t>(payload.size());
  out.clear();
  out.reserve(static_cast<std::size_t>(total));
  const auto push = [&out](std::uint8_t value) { out.push_back(static_cast<std::byte>(value)); };
  push(kMagicFirst);
  push(kMagicSecond);
  const auto push_u16 = [&push](std::uint16_t value) {
    push(static_cast<std::uint8_t>(value & 0xFFU));
    push(static_cast<std::uint8_t>((value >> 8) & 0xFFU));
  };
  const auto push_u32 = [&push](std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
      push(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFU));
    }
  };
  const auto push_u64 = [&push](std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
      push(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFU));
    }
  };
  push_u16(header.protocol_version);
  push_u16(static_cast<std::uint16_t>(header.message));
  push_u16(header.flags);
  push_u32(static_cast<std::uint32_t>(kFrameHeaderBytes));
  push_u32(static_cast<std::uint32_t>(payload.size()));
  push_u64(header.epoch.value());
  push_u64(header.publisher.value());
  push_u64(header.boot.value());
  push_u64(header.attempt.value());
  push_u64(0);  // reserved
  push_u64(0);  // reserved
  out.insert(out.end(), payload.begin(), payload.end());
  const Digest trailer = frame_digest(effective, payload);
  for (const std::uint8_t byte : trailer.bytes()) {
    push(byte);
  }
  return Status::ok();
}

Result<DecodedFrame> decode_frame(ByteSpan frame, const Limits& limits) {
  if (frame.size() < kFrameHeaderBytes + kFrameTrailerBytes) {
    return Result<DecodedFrame>::failure(Outcome::WireIntegrityFailure, "frame is shorter than its envelope");
  }
  if (frame.size() > limits.max_frame_bytes) {
    return Result<DecodedFrame>::failure(Outcome::ResourceLimit, "frame exceeds max_frame_bytes");
  }
  const auto* raw = reinterpret_cast<const std::uint8_t*>(frame.data());
  if (raw[0] != kMagicFirst || raw[1] != kMagicSecond) {
    return Result<DecodedFrame>::failure(Outcome::WireIntegrityFailure, "bad frame magic");
  }
  FrameHeader header;
  header.protocol_version = load_le16(raw + 2);
  const std::uint16_t message_raw = load_le16(raw + 4);
  header.flags = load_le16(raw + 6);
  const std::uint32_t header_bytes = load_le32(raw + 8);
  const std::uint32_t payload_bytes = load_le32(raw + 12);
  header.epoch = CoordinatorEpoch::from_value(load_le64(raw + 16));
  header.publisher = PublisherId::from_value(load_le64(raw + 24));
  header.boot = WorkerBootId::from_value(load_le64(raw + 32));
  header.attempt = MutationAttemptId::from_value(load_le64(raw + 40));
  const std::uint64_t reserved_a = load_le64(raw + 48);
  const std::uint64_t reserved_b = load_le64(raw + 56);
  if (header.protocol_version != kWireProtocolVersion) {
    return Result<DecodedFrame>::failure(Outcome::UnsupportedVersion, "unsupported wire protocol version");
  }
  const std::optional<MessageId> message = parse_message_id(message_raw);
  if (!message.has_value()) {
    return Result<DecodedFrame>::failure(Outcome::ProtocolFailure, "unknown message identifier");
  }
  header.message = *message;
  if (header.flags != 0) {
    return Result<DecodedFrame>::failure(Outcome::ProtocolFailure, "unsupported frame flags");
  }
  if (header_bytes != kFrameHeaderBytes) {
    return Result<DecodedFrame>::failure(Outcome::ProtocolFailure, "unexpected frame header size");
  }
  if (reserved_a != 0 || reserved_b != 0) {
    return Result<DecodedFrame>::failure(Outcome::ProtocolFailure, "non-zero reserved frame field");
  }
  if (payload_bytes > limits.max_frame_bytes) {
    return Result<DecodedFrame>::failure(Outcome::ResourceLimit, "frame payload exceeds max_frame_bytes");
  }
  const std::uint64_t expected = static_cast<std::uint64_t>(kFrameHeaderBytes) + payload_bytes +
                                 static_cast<std::uint64_t>(kFrameTrailerBytes);
  if (expected != frame.size()) {
    return Result<DecodedFrame>::failure(Outcome::WireIntegrityFailure,
                                         "frame size does not match its header");
  }
  header.payload_bytes = payload_bytes;
  const ByteSpan payload(reinterpret_cast<const std::byte*>(raw + kFrameHeaderBytes), payload_bytes);
  const Digest trailer = frame_digest(header, payload);
  for (std::size_t i = 0; i < kFrameTrailerBytes; ++i) {
    if (trailer.data()[i] != raw[kFrameHeaderBytes + payload_bytes + i]) {
      return Result<DecodedFrame>::failure(Outcome::WireIntegrityFailure, "frame integrity check failed");
    }
  }
  DecodedFrame decoded;
  decoded.header = header;
  decoded.payload.assign(payload.begin(), payload.end());
  return Result<DecodedFrame>::ok(std::move(decoded));
}

// ---------------------------------------------------------------------------
// Field bag
// ---------------------------------------------------------------------------

void FieldBag::set_bytes(std::uint16_t field, ByteSpan value) {
  fields_[field] = ByteVector(value.begin(), value.end());
  rebuild();
}

void FieldBag::set_bool(std::uint16_t field, bool value) { set_u8(field, value ? 1U : 0U); }

void FieldBag::set_u8(std::uint16_t field, std::uint8_t value) {
  fields_[field] = ByteVector{static_cast<std::byte>(value)};
  rebuild();
}

void FieldBag::set_u16(std::uint16_t field, std::uint16_t value) {
  std::uint8_t raw[2];
  store_le16(raw, value);
  set_bytes(field, ByteSpan(reinterpret_cast<const std::byte*>(raw), 2));
}

void FieldBag::set_u32(std::uint16_t field, std::uint32_t value) {
  std::uint8_t raw[4];
  store_le32(raw, value);
  set_bytes(field, ByteSpan(reinterpret_cast<const std::byte*>(raw), 4));
}

void FieldBag::set_u64(std::uint16_t field, std::uint64_t value) {
  std::uint8_t raw[8];
  store_le64(raw, value);
  set_bytes(field, ByteSpan(reinterpret_cast<const std::byte*>(raw), 8));
}

void FieldBag::set_text(std::uint16_t field, std::string_view value) {
  set_bytes(field, ByteSpan(reinterpret_cast<const std::byte*>(value.data()), value.size()));
}

void FieldBag::set_digest(std::uint16_t field, const Digest& value) {
  set_bytes(field, ByteSpan(reinterpret_cast<const std::byte*>(value.bytes().data()),
                           value.bytes().size()));
}

void FieldBag::set_nested(std::uint16_t field, const FieldBag& nested) {
  set_bytes(field, ByteSpan(nested.encode().data(), nested.encode().size()));
}

void FieldBag::rebuild() {
  encoded_.clear();
  for (const auto& entry : fields_) {
    std::uint8_t header[6];
    store_le16(header, entry.first);
    store_le32(header + 2, static_cast<std::uint32_t>(entry.second.size()));
    for (const std::uint8_t byte : header) {
      encoded_.push_back(static_cast<std::byte>(byte));
    }
    encoded_.insert(encoded_.end(), entry.second.begin(), entry.second.end());
  }
}

const ByteVector* FieldBag::find(std::uint16_t field) const noexcept {
  const auto it = fields_.find(field);
  return it == fields_.end() ? nullptr : &it->second;
}

bool FieldBag::has(std::uint16_t field) const noexcept { return find(field) != nullptr; }

std::vector<std::uint16_t> FieldBag::field_ids() const {
  std::vector<std::uint16_t> ids;
  ids.reserve(fields_.size());
  for (const auto& entry : fields_) {
    ids.push_back(entry.first);
  }
  return ids;
}

Result<FieldBag> FieldBag::decode(ByteSpan encoded, const Limits& limits) {
  if (encoded.size() > limits.max_frame_bytes) {
    return Result<FieldBag>::failure(Outcome::ResourceLimit, "payload exceeds max_frame_bytes");
  }
  FieldBag bag;
  const auto* raw = reinterpret_cast<const std::uint8_t*>(encoded.data());
  std::size_t cursor = 0;
  while (cursor < encoded.size()) {
    if (encoded.size() - cursor < 6) {
      return Result<FieldBag>::failure(Outcome::ProtocolFailure, "truncated payload field header");
    }
    const std::uint16_t field = load_le16(raw + cursor);
    const std::uint32_t length = load_le32(raw + cursor + 2);
    cursor += 6;
    if (length > encoded.size() - cursor) {
      return Result<FieldBag>::failure(Outcome::ProtocolFailure, "truncated payload field body");
    }
    if (bag.fields_.find(field) != bag.fields_.end()) {
      return Result<FieldBag>::failure(Outcome::ProtocolFailure, "duplicate payload field identifier");
    }
    bag.fields_[field] = ByteVector(encoded.begin() + static_cast<std::ptrdiff_t>(cursor),
                                    encoded.begin() + static_cast<std::ptrdiff_t>(cursor + length));
    cursor += length;
  }
  bag.rebuild();
  return Result<FieldBag>::ok(std::move(bag));
}

std::optional<std::uint8_t> FieldBag::u8(std::uint16_t field) const noexcept {
  const ByteVector* value = find(field);
  if (value == nullptr || value->size() != 1) {
    return std::nullopt;
  }
  return std::to_integer<std::uint8_t>((*value)[0]);
}

std::optional<bool> FieldBag::boolean(std::uint16_t field) const noexcept {
  const std::optional<std::uint8_t> value = u8(field);
  if (!value.has_value()) {
    return std::nullopt;
  }
  if (*value > 1U) {
    return std::nullopt;
  }
  return *value == 1U;
}

std::optional<std::uint16_t> FieldBag::u16(std::uint16_t field) const noexcept {
  const ByteVector* value = find(field);
  if (value == nullptr || value->size() != 2) {
    return std::nullopt;
  }
  const auto* raw = reinterpret_cast<const std::uint8_t*>(value->data());
  return load_le16(raw);
}

std::optional<std::uint32_t> FieldBag::u32(std::uint16_t field) const noexcept {
  const ByteVector* value = find(field);
  if (value == nullptr || value->size() != 4) {
    return std::nullopt;
  }
  const auto* raw = reinterpret_cast<const std::uint8_t*>(value->data());
  return load_le32(raw);
}

std::optional<std::uint64_t> FieldBag::u64(std::uint16_t field) const noexcept {
  const ByteVector* value = find(field);
  if (value == nullptr || value->size() != 8) {
    return std::nullopt;
  }
  const auto* raw = reinterpret_cast<const std::uint8_t*>(value->data());
  return load_le64(raw);
}

std::optional<std::string> FieldBag::text(std::uint16_t field) const {
  const ByteVector* value = find(field);
  if (value == nullptr) {
    return std::nullopt;
  }
  return std::string(reinterpret_cast<const char*>(value->data()), value->size());
}

std::optional<Digest> FieldBag::digest(std::uint16_t field) const {
  const ByteVector* value = find(field);
  if (value == nullptr || value->size() != Digest::kSize) {
    return std::nullopt;
  }
  return Digest::from_bytes(ByteSpan(value->data(), value->size()));
}

std::optional<ByteVector> FieldBag::bytes(std::uint16_t field) const {
  const ByteVector* value = find(field);
  if (value == nullptr) {
    return std::nullopt;
  }
  return *value;
}

std::optional<FieldBag> FieldBag::nested(std::uint16_t field, const Limits& limits) const {
  const ByteVector* value = find(field);
  if (value == nullptr) {
    return std::nullopt;
  }
  const Result<FieldBag> decoded = FieldBag::decode(ByteSpan(value->data(), value->size()), limits);
  if (!decoded.has_value()) {
    return std::nullopt;
  }
  return decoded.value();
}
// ---------------------------------------------------------------------------
// Message payload codecs
// ---------------------------------------------------------------------------

namespace {

[[nodiscard]] Status encode_bag(const FieldBag& bag, ByteVector& out, const Limits& limits) {
  const ByteVector& encoded = bag.encode();
  if (encoded.size() > limits.max_frame_bytes) {
    return Status::failure(Outcome::ResourceLimit, "payload exceeds max_frame_bytes");
  }
  out = encoded;
  return Status::ok();
}

[[nodiscard]] Result<FieldBag> decode_bag(ByteSpan payload, const Limits& limits) {
  return FieldBag::decode(payload, limits);
}

[[nodiscard]] Result<std::vector<ProvenanceNode>> decode_records(ByteSpan blob, const Limits& limits,
                                                                std::uint32_t count) {
  if (blob.size() > limits.max_frame_bytes) {
    return Result<std::vector<ProvenanceNode>>::failure(Outcome::ResourceLimit, "record blob exceeds the bound");
  }
  codec::Reader reader(reinterpret_cast<const std::uint8_t*>(blob.data()), blob.size());
  std::vector<ProvenanceNode> nodes;
  nodes.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    const std::uint32_t length = reader.u32();
    if (reader.failed() || length > reader.remaining()) {
      return Result<std::vector<ProvenanceNode>>::failure(Outcome::ProtocolFailure, "malformed record blob");
    }
    const ByteSpan record = reader.span(length);
    codec::Reader record_reader(reinterpret_cast<const std::uint8_t*>(record.data()), record.size());
    ProvenanceNode node;
    if (!codec::read_node(record_reader, node, limits) || !record_reader.at_end()) {
      return Result<std::vector<ProvenanceNode>>::failure(Outcome::ProtocolFailure, "malformed record");
    }
    nodes.push_back(node);
  }
  if (reader.failed() || !reader.at_end()) {
    return Result<std::vector<ProvenanceNode>>::failure(Outcome::ProtocolFailure,
                                                        "record blob has trailing bytes");
  }
  return Result<std::vector<ProvenanceNode>>::ok(std::move(nodes));
}

[[nodiscard]] Result<std::vector<ProvenanceEdge>> decode_edge_records(ByteSpan blob, const Limits& limits,
                                                                     std::uint32_t count) {
  if (blob.size() > limits.max_frame_bytes) {
    return Result<std::vector<ProvenanceEdge>>::failure(Outcome::ResourceLimit, "edge blob exceeds the bound");
  }
  codec::Reader reader(reinterpret_cast<const std::uint8_t*>(blob.data()), blob.size());
  std::vector<ProvenanceEdge> edges;
  edges.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    const std::uint32_t length = reader.u32();
    if (reader.failed() || length > reader.remaining()) {
      return Result<std::vector<ProvenanceEdge>>::failure(Outcome::ProtocolFailure, "malformed edge blob");
    }
    const ByteSpan record = reader.span(length);
    codec::Reader record_reader(reinterpret_cast<const std::uint8_t*>(record.data()), record.size());
    ProvenanceEdge edge;
    if (!codec::read_edge(record_reader, edge, limits) || !record_reader.at_end()) {
      return Result<std::vector<ProvenanceEdge>>::failure(Outcome::ProtocolFailure, "malformed edge record");
    }
    edges.push_back(edge);
  }
  if (reader.failed() || !reader.at_end()) {
    return Result<std::vector<ProvenanceEdge>>::failure(Outcome::ProtocolFailure,
                                                        "edge blob has trailing bytes");
  }
  return Result<std::vector<ProvenanceEdge>>::ok(std::move(edges));
}

}  // namespace

Status encode_registration(const RegistrationPayload& payload, ByteVector& out, const Limits& limits) {
  FieldBag bag;
  bag.set_u16(1, payload.role);
  bag.set_u64(2, payload.identity.publisher.value());
  bag.set_u64(3, payload.identity.boot.value());
  bag.set_u64(4, payload.identity.epoch.value());
  bag.set_u16(5, static_cast<std::uint16_t>(payload.scope.kind()));
  bag.set_u64(6, payload.scope.subject());
  bag.set_u16(7, payload.protocol_version);
  return encode_bag(bag, out, limits);
}

Result<RegistrationPayload> decode_registration(ByteSpan payload, const Limits& limits) {
  const Result<FieldBag> bag = decode_bag(payload, limits);
  if (!bag.has_value()) {
    return Result<RegistrationPayload>::failure(bag.outcome(), bag.detail());
  }
  const Status fields = check_fields(bag.value(), {1, 2, 3, 4, 5, 6, 7}, {1, 2, 3, 4, 5, 7});
  if (!fields.is_ok()) {
    return Result<RegistrationPayload>::failure(fields.outcome(), fields.detail());
  }
  RegistrationPayload registration;
  registration.role = bag->u16(1).value_or(0);
  registration.identity.publisher = PublisherId::from_value(bag->u64(2).value_or(0));
  registration.identity.boot = WorkerBootId::from_value(bag->u64(3).value_or(0));
  registration.identity.epoch = CoordinatorEpoch::from_value(bag->u64(4).value_or(0));
  const std::uint16_t scope_kind = bag->u16(5).value_or(0xFFFFU);
  const std::uint64_t subject = bag->u64(6).value_or(0);
  switch (scope_kind) {
    case static_cast<std::uint16_t>(ScopeKind::None): registration.scope = AuthorityScope::none(); break;
    case static_cast<std::uint16_t>(ScopeKind::Fabric): registration.scope = AuthorityScope::fabric(); break;
    case static_cast<std::uint16_t>(ScopeKind::RoutingNamespace):
      registration.scope = AuthorityScope::routing_namespace(RoutingNamespaceId::from_value(subject));
      break;
    case static_cast<std::uint16_t>(ScopeKind::Lineage):
      registration.scope = AuthorityScope::lineage(RouteLineageId::from_value(subject));
      break;
    case static_cast<std::uint16_t>(ScopeKind::Route):
      registration.scope = AuthorityScope::route(RouteId::from_value(subject));
      break;
    default:
      return Result<RegistrationPayload>::failure(Outcome::ProtocolFailure, "unknown authority scope kind");
  }
  registration.protocol_version = bag->u16(7).value_or(0);
  return Result<RegistrationPayload>::ok(std::move(registration));
}

Status encode_hello_ack(const HelloAckPayload& payload, ByteVector& out, const Limits& limits) {
  FieldBag bag;
  bag.set_u64(1, payload.epoch.value());
  bag.set_bool(2, payload.accepted);
  bag.set_u32(3, payload.max_frame_bytes);
  bag.set_u16(4, payload.protocol_version);
  bag.set_text(5, payload.detail);
  return encode_bag(bag, out, limits);
}

Result<HelloAckPayload> decode_hello_ack(ByteSpan payload, const Limits& limits) {
  const Result<FieldBag> bag = decode_bag(payload, limits);
  if (!bag.has_value()) {
    return Result<HelloAckPayload>::failure(bag.outcome(), bag.detail());
  }
  const Status fields = check_fields(bag.value(), {1, 2, 3, 4, 5}, {1, 2, 3, 4});
  if (!fields.is_ok()) {
    return Result<HelloAckPayload>::failure(fields.outcome(), fields.detail());
  }
  HelloAckPayload ack;
  ack.epoch = CoordinatorEpoch::from_value(bag->u64(1).value_or(0));
  ack.accepted = bag->boolean(2).value_or(false);
  ack.max_frame_bytes = bag->u32(3).value_or(0);
  ack.protocol_version = bag->u16(4).value_or(0);
  ack.detail = bag->text(5).value_or(std::string{});
  return Result<HelloAckPayload>::ok(std::move(ack));
}

Status encode_publication(const PublicationPayload& payload, ByteVector& out, const Limits& limits) {
  FieldBag bag;
  bag.set_u64(1, payload.key.route.value());
  bag.set_text(2, payload.key.semantic_key);
  bag.set_u64(3, payload.route_generation.value());
  bag.set_digest(4, payload.route_state_digest);
  bag.set_u16(5, static_cast<std::uint16_t>(payload.reason));
  bag.set_u16(6, static_cast<std::uint16_t>(payload.source));
  bag.set_u16(7, payload.root_reason.has_value() ? static_cast<std::uint16_t>(*payload.root_reason) : 0);
  put_authority(bag, payload.authority, kAuthorityBase);
  put_evidence(bag, payload.evidence, kEvidenceField);
  put_bindings(bag, payload.bindings, kBindingsBase);
  put_edges(bag, payload.edges, kEdgesBase);
  return encode_bag(bag, out, limits);
}

Result<PublicationPayload> decode_publication(ByteSpan payload, const Limits& limits) {
  const Result<FieldBag> bag = decode_bag(payload, limits);
  if (!bag.has_value()) {
    return Result<PublicationPayload>::failure(bag.outcome(), bag.detail());
  }
  const Status fields = check_fields(bag.value(), standard_ranges(limits),
                                     {1, 2, 3, 4, 5, 6});
  if (!fields.is_ok()) {
    return Result<PublicationPayload>::failure(fields.outcome(), fields.detail());
  }
  if (bag->u64(1).value_or(0) == 0 || !bag->has(2) || bag->u64(3).value_or(0) == 0) {
    return Result<PublicationPayload>::failure(Outcome::MalformedRequest,
                                               "publication payload is missing core identity fields");
  }
  PublicationPayload publication;
  const Result<LineageKey> key = take_key(bag.value(), 1, 2, limits);
  if (!key.has_value()) {
    return Result<PublicationPayload>::failure(key.outcome(), key.detail());
  }
  publication.key = key.value();
  publication.route_generation = RouteGeneration::from_value(bag->u64(3).value_or(0));
  publication.route_state_digest = bag->digest(4).value_or(Digest{});
  const std::uint16_t reason = bag->u16(5).value_or(0xFFFFU);
  const std::uint16_t source = bag->u16(6).value_or(0xFFFFU);
  publication.reason = static_cast<ReasonCode>(reason);
  publication.source = static_cast<SourceClass>(source);
  if (to_string(publication.reason) == "UNKNOWN" || to_string(publication.source) == "UNKNOWN") {
    return Result<PublicationPayload>::failure(Outcome::ProtocolFailure, "unknown publication enum value");
  }
  const std::uint16_t root = bag->u16(7).value_or(0);
  if (root != 0) {
    const auto parsed = static_cast<RootReason>(root);
    if (to_string(parsed) == "UNKNOWN") {
      return Result<PublicationPayload>::failure(Outcome::ProtocolFailure, "unknown root reason");
    }
    publication.root_reason = parsed;
  }
  const Result<AuthorityContext> authority = take_authority(bag.value(), kAuthorityBase, limits);
  if (!authority.has_value()) {
    return Result<PublicationPayload>::failure(authority.outcome(), authority.detail());
  }
  publication.authority = authority.value();
  const Result<EvidenceVector> evidence = take_evidence(bag.value(), kEvidenceField, limits);
  if (!evidence.has_value()) {
    return Result<PublicationPayload>::failure(evidence.outcome(), evidence.detail());
  }
  publication.evidence = evidence.value();
  const Result<Bindings> bindings = take_bindings(bag.value(), kBindingsBase);
  if (!bindings.has_value()) {
    return Result<PublicationPayload>::failure(bindings.outcome(), bindings.detail());
  }
  publication.bindings = bindings.value();
  const Result<std::vector<EdgeSpec>> edges = take_edges(bag.value(), kEdgesBase, limits);
  if (!edges.has_value()) {
    return Result<PublicationPayload>::failure(edges.outcome(), edges.detail());
  }
  publication.edges = edges.value();
  return Result<PublicationPayload>::ok(std::move(publication));
}

Status encode_administrative(const AdministrativePayload& payload, ByteVector& out, const Limits& limits) {
  FieldBag bag;
  bag.set_u64(1, payload.key.route.value());
  bag.set_text(2, payload.key.semantic_key);
  bag.set_u64(3, payload.target.value());
  bag.set_u16(4, static_cast<std::uint16_t>(payload.reason));
  bag.set_u16(5, static_cast<std::uint16_t>(payload.source));
  bag.set_digest(6, payload.completion_evidence);
  bag.set_bool(7, payload.allow_non_current_target);
  put_authority(bag, payload.authority, kAuthorityBase);
  put_evidence(bag, payload.evidence, kEvidenceField);
  put_bindings(bag, payload.bindings, kBindingsBase);
  return encode_bag(bag, out, limits);
}

Result<AdministrativePayload> decode_administrative(ByteSpan payload, const Limits& limits) {
  const Result<FieldBag> bag = decode_bag(payload, limits);
  if (!bag.has_value()) {
    return Result<AdministrativePayload>::failure(bag.outcome(), bag.detail());
  }
  const Status fields = check_fields(bag.value(), standard_ranges(limits), {1, 2, 3, 4, 5});
  if (!fields.is_ok()) {
    return Result<AdministrativePayload>::failure(fields.outcome(), fields.detail());
  }
  AdministrativePayload administrative;
  const Result<LineageKey> key = take_key(bag.value(), 1, 2, limits);
  if (!key.has_value()) {
    return Result<AdministrativePayload>::failure(key.outcome(), key.detail());
  }
  administrative.key = key.value();
  administrative.target = ProvenanceNodeId::from_value(bag->u64(3).value_or(0));
  const std::uint16_t reason = bag->u16(4).value_or(0xFFFFU);
  const std::uint16_t source = bag->u16(5).value_or(0xFFFFU);
  administrative.reason = static_cast<ReasonCode>(reason);
  administrative.source = static_cast<SourceClass>(source);
  if (to_string(administrative.reason) == "UNKNOWN" || to_string(administrative.source) == "UNKNOWN") {
    return Result<AdministrativePayload>::failure(Outcome::ProtocolFailure, "unknown administrative enum value");
  }
  administrative.completion_evidence = bag->digest(6).value_or(Digest{});
  administrative.allow_non_current_target = bag->boolean(7).value_or(false);
  const Result<AuthorityContext> authority = take_authority(bag.value(), kAuthorityBase, limits);
  if (!authority.has_value()) {
    return Result<AdministrativePayload>::failure(authority.outcome(), authority.detail());
  }
  administrative.authority = authority.value();
  const Result<EvidenceVector> evidence = take_evidence(bag.value(), kEvidenceField, limits);
  if (!evidence.has_value()) {
    return Result<AdministrativePayload>::failure(evidence.outcome(), evidence.detail());
  }
  administrative.evidence = evidence.value();
  const Result<Bindings> bindings = take_bindings(bag.value(), kBindingsBase);
  if (!bindings.has_value()) {
    return Result<AdministrativePayload>::failure(bindings.outcome(), bindings.detail());
  }
  administrative.bindings = bindings.value();
  return Result<AdministrativePayload>::ok(std::move(administrative));
}

Status encode_correction(const CorrectionPayload& payload, ByteVector& out, const Limits& limits) {
  FieldBag bag;
  bag.set_u64(1, payload.key.route.value());
  bag.set_text(2, payload.key.semantic_key);
  bag.set_u64(3, payload.target.value());
  bag.set_digest(4, payload.route_state_digest);
  bag.set_u16(5, static_cast<std::uint16_t>(payload.source));
  put_authority(bag, payload.authority, kAuthorityBase);
  put_evidence(bag, payload.evidence, kEvidenceField);
  put_bindings(bag, payload.bindings, kBindingsBase);
  return encode_bag(bag, out, limits);
}

Result<CorrectionPayload> decode_correction(ByteSpan payload, const Limits& limits) {
  const Result<FieldBag> bag = decode_bag(payload, limits);
  if (!bag.has_value()) {
    return Result<CorrectionPayload>::failure(bag.outcome(), bag.detail());
  }
  const Status fields =
      check_fields(bag.value(),
                   field_ranges({{1, 5},
                                 {kAuthorityBase, static_cast<std::uint16_t>(kAuthorityBase + 7)},
                                 {kEvidenceField, kEvidenceField},
                                 {kBindingsBase, static_cast<std::uint16_t>(kBindingsBase + 24)}}),
                   {1, 2, 3, 5});
  if (!fields.is_ok()) {
    return Result<CorrectionPayload>::failure(fields.outcome(), fields.detail());
  }
  CorrectionPayload correction;
  const Result<LineageKey> key = take_key(bag.value(), 1, 2, limits);
  if (!key.has_value()) {
    return Result<CorrectionPayload>::failure(key.outcome(), key.detail());
  }
  correction.key = key.value();
  correction.target = ProvenanceNodeId::from_value(bag->u64(3).value_or(0));
  correction.route_state_digest = bag->digest(4).value_or(Digest{});
  const std::uint16_t source = bag->u16(5).value_or(0xFFFFU);
  correction.source = static_cast<SourceClass>(source);
  if (to_string(correction.source) == "UNKNOWN") {
    return Result<CorrectionPayload>::failure(Outcome::ProtocolFailure, "unknown correction source");
  }
  const Result<AuthorityContext> authority = take_authority(bag.value(), kAuthorityBase, limits);
  if (!authority.has_value()) {
    return Result<CorrectionPayload>::failure(authority.outcome(), authority.detail());
  }
  correction.authority = authority.value();
  const Result<EvidenceVector> evidence = take_evidence(bag.value(), kEvidenceField, limits);
  if (!evidence.has_value()) {
    return Result<CorrectionPayload>::failure(evidence.outcome(), evidence.detail());
  }
  correction.evidence = evidence.value();
  const Result<Bindings> bindings = take_bindings(bag.value(), kBindingsBase);
  if (!bindings.has_value()) {
    return Result<CorrectionPayload>::failure(bindings.outcome(), bindings.detail());
  }
  correction.bindings = bindings.value();
  return Result<CorrectionPayload>::ok(std::move(correction));
}

Status encode_declaration(const DeclarationPayload& payload, ByteVector& out, const Limits& limits) {
  FieldBag bag;
  bag.set_u64(1, payload.key.route.value());
  bag.set_text(2, payload.key.semantic_key);
  bag.set_u16(3, static_cast<std::uint16_t>(payload.kind));
  bag.set_u64(4, payload.route.value());
  bag.set_u64(5, payload.route_generation.value());
  bag.set_u16(6, static_cast<std::uint16_t>(payload.reason));
  bag.set_u16(7, static_cast<std::uint16_t>(payload.source));
  put_authority(bag, payload.authority, kAuthorityBase);
  put_evidence(bag, payload.evidence, kEvidenceField);
  put_bindings(bag, payload.bindings, kBindingsBase);
  return encode_bag(bag, out, limits);
}

Result<DeclarationPayload> decode_declaration(ByteSpan payload, const Limits& limits) {
  const Result<FieldBag> bag = decode_bag(payload, limits);
  if (!bag.has_value()) {
    return Result<DeclarationPayload>::failure(bag.outcome(), bag.detail());
  }
  const Status fields = check_fields(bag.value(), standard_ranges(limits), {1, 2, 3, 6, 7});
  if (!fields.is_ok()) {
    return Result<DeclarationPayload>::failure(fields.outcome(), fields.detail());
  }
  DeclarationPayload declaration;
  const Result<LineageKey> key = take_key(bag.value(), 1, 2, limits);
  if (!key.has_value()) {
    return Result<DeclarationPayload>::failure(key.outcome(), key.detail());
  }
  declaration.key = key.value();
  const std::uint16_t kind = bag->u16(3).value_or(0xFFFFU);
  const std::uint16_t reason = bag->u16(6).value_or(0xFFFFU);
  const std::uint16_t source = bag->u16(7).value_or(0xFFFFU);
  declaration.kind = static_cast<NodeKind>(kind);
  declaration.reason = static_cast<ReasonCode>(reason);
  declaration.source = static_cast<SourceClass>(source);
  if (to_string(declaration.kind) == "UNKNOWN" || to_string(declaration.reason) == "UNKNOWN" ||
      to_string(declaration.source) == "UNKNOWN") {
    return Result<DeclarationPayload>::failure(Outcome::ProtocolFailure, "unknown declaration enum value");
  }
  declaration.route = RouteId::from_value(bag->u64(4).value_or(0));
  declaration.route_generation = RouteGeneration::from_value(bag->u64(5).value_or(0));
  const Result<AuthorityContext> authority = take_authority(bag.value(), kAuthorityBase, limits);
  if (!authority.has_value()) {
    return Result<DeclarationPayload>::failure(authority.outcome(), authority.detail());
  }
  declaration.authority = authority.value();
  const Result<EvidenceVector> evidence = take_evidence(bag.value(), kEvidenceField, limits);
  if (!evidence.has_value()) {
    return Result<DeclarationPayload>::failure(evidence.outcome(), evidence.detail());
  }
  declaration.evidence = evidence.value();
  const Result<Bindings> bindings = take_bindings(bag.value(), kBindingsBase);
  if (!bindings.has_value()) {
    return Result<DeclarationPayload>::failure(bindings.outcome(), bindings.detail());
  }
  declaration.bindings = bindings.value();
  return Result<DeclarationPayload>::ok(std::move(declaration));
}

Status encode_link(const LinkPayload& payload, ByteVector& out, const Limits& limits) {
  FieldBag bag;
  bag.set_u64(1, payload.key.route.value());
  bag.set_text(2, payload.key.semantic_key);
  bag.set_u16(3, static_cast<std::uint16_t>(payload.type));
  bag.set_u64(4, payload.from.value());
  bag.set_u64(5, payload.to.value());
  bag.set_u16(6, static_cast<std::uint16_t>(payload.reason));
  bag.set_u16(7, static_cast<std::uint16_t>(payload.source));
  put_authority(bag, payload.authority, kAuthorityBase);
  put_evidence(bag, payload.evidence, kEvidenceField);
  return encode_bag(bag, out, limits);
}

Result<LinkPayload> decode_link(ByteSpan payload, const Limits& limits) {
  const Result<FieldBag> bag = decode_bag(payload, limits);
  if (!bag.has_value()) {
    return Result<LinkPayload>::failure(bag.outcome(), bag.detail());
  }
  const Status fields =
      check_fields(bag.value(),
                   field_ranges({{1, 7},
                                 {kAuthorityBase, static_cast<std::uint16_t>(kAuthorityBase + 7)},
                                 {kEvidenceField, kEvidenceField}}),
                   {1, 2, 3, 4, 5, 6, 7});
  if (!fields.is_ok()) {
    return Result<LinkPayload>::failure(fields.outcome(), fields.detail());
  }
  LinkPayload link;
  const Result<LineageKey> key = take_key(bag.value(), 1, 2, limits);
  if (!key.has_value()) {
    return Result<LinkPayload>::failure(key.outcome(), key.detail());
  }
  link.key = key.value();
  const std::uint16_t type = bag->u16(3).value_or(0xFFFFU);
  const std::uint16_t reason = bag->u16(6).value_or(0xFFFFU);
  const std::uint16_t source = bag->u16(7).value_or(0xFFFFU);
  link.type = static_cast<EdgeType>(type);
  link.reason = static_cast<ReasonCode>(reason);
  link.source = static_cast<SourceClass>(source);
  if (to_string(link.type) == "UNKNOWN" || to_string(link.reason) == "UNKNOWN" ||
      to_string(link.source) == "UNKNOWN") {
    return Result<LinkPayload>::failure(Outcome::ProtocolFailure, "unknown link enum value");
  }
  link.from = ProvenanceNodeId::from_value(bag->u64(4).value_or(0));
  link.to = ProvenanceNodeId::from_value(bag->u64(5).value_or(0));
  const Result<AuthorityContext> authority = take_authority(bag.value(), kAuthorityBase, limits);
  if (!authority.has_value()) {
    return Result<LinkPayload>::failure(authority.outcome(), authority.detail());
  }
  link.authority = authority.value();
  const Result<EvidenceVector> evidence = take_evidence(bag.value(), kEvidenceField, limits);
  if (!evidence.has_value()) {
    return Result<LinkPayload>::failure(evidence.outcome(), evidence.detail());
  }
  link.evidence = evidence.value();
  return Result<LinkPayload>::ok(std::move(link));
}

Status encode_dependency(const DependencyPayload& payload, ByteVector& out, const Limits& limits) {
  FieldBag bag;
  bag.set_u16(1, static_cast<std::uint16_t>(payload.notification.kind));
  bag.set_u64(2, payload.notification.path_authority_generation.value());
  bag.set_u64(3, payload.notification.policy_generation.value());
  bag.set_u64(4, payload.notification.evidence_generation.value());
  bag.set_u64(5, payload.notification.plan_generation.value());
  bag.set_u64(6, payload.notification.epoch.value());
  bag.set_u64(7, payload.notification.publisher.value());
  bag.set_u64(8, payload.notification.boot.value());
  put_authority(bag, payload.notification.authority, 100);
  return encode_bag(bag, out, limits);
}

Result<DependencyPayload> decode_dependency(ByteSpan payload, const Limits& limits) {
  const Result<FieldBag> bag = decode_bag(payload, limits);
  if (!bag.has_value()) {
    return Result<DependencyPayload>::failure(bag.outcome(), bag.detail());
  }
  const Status fields = check_fields(bag.value(), field_ranges({{1, 8}, {100, 107}}), {1, 6, 7, 8, 100});
  if (!fields.is_ok()) {
    return Result<DependencyPayload>::failure(fields.outcome(), fields.detail());
  }
  const std::uint16_t kind = bag->u16(1).value_or(0xFFFFU);
  const std::optional<DependencyKind> parsed = parse_dependency_kind(kind);
  if (!parsed.has_value()) {
    return Result<DependencyPayload>::failure(Outcome::ProtocolFailure, "unknown dependency kind");
  }
  DependencyPayload dependency;
  dependency.notification.kind = *parsed;
  dependency.notification.path_authority_generation =
      PathAuthorityGeneration::from_value(bag->u64(2).value_or(0));
  dependency.notification.policy_generation = PolicyGeneration::from_value(bag->u64(3).value_or(0));
  dependency.notification.evidence_generation =
      EvidenceGeneration::from_value(bag->u64(4).value_or(0));
  dependency.notification.plan_generation =
      ConvergencePlanGeneration::from_value(bag->u64(5).value_or(0));
  dependency.notification.epoch = CoordinatorEpoch::from_value(bag->u64(6).value_or(0));
  dependency.notification.publisher = PublisherId::from_value(bag->u64(7).value_or(0));
  dependency.notification.boot = WorkerBootId::from_value(bag->u64(8).value_or(0));
  const Result<AuthorityContext> authority = take_authority(bag.value(), 100, limits);
  if (!authority.has_value()) {
    return Result<DependencyPayload>::failure(authority.outcome(), authority.detail());
  }
  dependency.notification.authority = authority.value();
  return Result<DependencyPayload>::ok(std::move(dependency));
}

// ---------------------------------------------------------------------------
// Response bodies
// ---------------------------------------------------------------------------

void encode_publication_body(const Publication& publication, FieldBag& body) {
  body.set_u64(1, publication.lineage.value());
  body.set_u64(2, publication.node.value());
  body.set_u64(3, publication.lineage_generation.value());
  body.set_u64(4, publication.store_generation.value());
  body.set_u16(5, static_cast<std::uint16_t>(publication.lifecycle));
  body.set_u16(6, static_cast<std::uint16_t>(publication.currentness));
  body.set_u32(7, static_cast<std::uint32_t>(publication.edges.size()));
  codec::Writer writer;
  for (const ProvenanceEdgeId id : publication.edges) {
    writer.u64(id.value());
  }
  body.set_bytes(8, ByteSpan(writer.data().data(), writer.data().size()));
}

Result<Publication> decode_publication_body(const FieldBag& body, const Limits& limits) {
  static_cast<void>(limits);
  const std::optional<std::uint32_t> edge_count = body.u32(7);
  if (!edge_count.has_value() || !body.u64(1).has_value() || !body.u64(2).has_value()) {
    return Result<Publication>::failure(Outcome::ProtocolFailure, "malformed publication body");
  }
  if (*edge_count > 0 && !body.bytes(8).has_value()) {
    return Result<Publication>::failure(Outcome::ProtocolFailure, "publication body is missing its edges");
  }
  Publication publication;
  publication.lineage = RouteLineageId::from_value(body.u64(1).value_or(0));
  publication.node = ProvenanceNodeId::from_value(body.u64(2).value_or(0));
  publication.lineage_generation = LineageGeneration::from_value(body.u64(3).value_or(0));
  publication.store_generation = ProvenanceGeneration::from_value(body.u64(4).value_or(0));
  const std::uint16_t lifecycle = body.u16(5).value_or(0xFFFFU);
  const std::uint16_t currentness = body.u16(6).value_or(0xFFFFU);
  publication.lifecycle = static_cast<NodeLifecycle>(lifecycle);
  publication.currentness = static_cast<Currentness>(currentness);
  if (to_string(publication.lifecycle) == "UNKNOWN" || to_string(publication.currentness) == "UNKNOWN") {
    return Result<Publication>::failure(Outcome::ProtocolFailure, "unknown publication state value");
  }
  if (*edge_count > 0) {
    const std::optional<ByteVector> blob = body.bytes(8);
    if (!blob.has_value() || blob->size() != static_cast<std::size_t>(*edge_count) * 8U) {
      return Result<Publication>::failure(Outcome::ProtocolFailure, "malformed publication edge list");
    }
    const auto* raw = reinterpret_cast<const std::uint8_t*>(blob->data());
    for (std::uint32_t i = 0; i < *edge_count; ++i) {
      publication.edges.push_back(ProvenanceEdgeId::from_value(load_le64(raw + (i * 8U))));
    }
  }
  return Result<Publication>::ok(std::move(publication));
}

void encode_lineage_body(const LineageView& view, FieldBag& body) {
  body.set_u64(1, view.id.value());
  body.set_u64(2, view.key.route.value());
  body.set_text(3, view.key.semantic_key);
  body.set_u16(4, static_cast<std::uint16_t>(view.lifecycle));
  body.set_u64(5, view.current_route_generation.value());
  body.set_u64(6, view.current_node.value());
  body.set_u64(7, view.lineage_generation.value());
  body.set_u64(8, view.authority_generation.value());
  body.set_u64(9, view.node_count);
  body.set_u64(10, view.edge_count);
  body.set_u64(11, view.compacted_node_count);
  body.set_u16(12, static_cast<std::uint16_t>(view.current_currentness));
  body.set_digest(13, view.digest);
}

Result<LineageView> decode_lineage_body(const FieldBag& body, const Limits& limits) {
  const Result<LineageKey> key = take_key(body, 2, 3, limits);
  if (!key.has_value()) {
    return Result<LineageView>::failure(key.outcome(), key.detail());
  }
  LineageView view;
  view.id = RouteLineageId::from_value(body.u64(1).value_or(0));
  view.key = key.value();
  const std::uint16_t lifecycle = body.u16(4).value_or(0xFFFFU);
  const std::uint16_t currentness = body.u16(12).value_or(0xFFFFU);
  view.lifecycle = static_cast<LineageLifecycle>(lifecycle);
  view.current_currentness = static_cast<Currentness>(currentness);
  if (to_string(view.lifecycle) == "UNKNOWN" || to_string(view.current_currentness) == "UNKNOWN") {
    return Result<LineageView>::failure(Outcome::ProtocolFailure, "unknown lineage state value");
  }
  view.current_route_generation = RouteGeneration::from_value(body.u64(5).value_or(0));
  view.current_node = ProvenanceNodeId::from_value(body.u64(6).value_or(0));
  view.lineage_generation = LineageGeneration::from_value(body.u64(7).value_or(0));
  view.authority_generation = AuthorityGeneration::from_value(body.u64(8).value_or(0));
  view.node_count = body.u64(9).value_or(0);
  view.edge_count = body.u64(10).value_or(0);
  view.compacted_node_count = body.u64(11).value_or(0);
  view.digest = body.digest(13).value_or(Digest{});
  return Result<LineageView>::ok(std::move(view));
}

void encode_nodes_body(const std::vector<ProvenanceNode>& nodes, FieldBag& body) {
  body.set_u64(1, nodes.size());
  codec::Writer writer;
  for (const ProvenanceNode& node : nodes) {
    codec::Writer record;
    codec::write_node(record, node);
    writer.u32(static_cast<std::uint32_t>(record.size()));
    writer.bytes(ByteSpan(record.data().data(), record.data().size()));
  }
  body.set_bytes(2, ByteSpan(writer.data().data(), writer.data().size()));
}

Result<std::vector<ProvenanceNode>> decode_nodes_body(const FieldBag& body, const Limits& limits) {
  const std::optional<std::uint64_t> count = body.u64(1);
  if (!count.has_value()) {
    return Result<std::vector<ProvenanceNode>>::failure(Outcome::ProtocolFailure, "malformed node body");
  }
  if (*count > limits.max_query_results) {
    return Result<std::vector<ProvenanceNode>>::failure(Outcome::ResourceLimit, "node body exceeds the bound");
  }
  const std::optional<ByteVector> blob = body.bytes(2);
  if (!blob.has_value()) {
    return Result<std::vector<ProvenanceNode>>::failure(Outcome::ProtocolFailure, "node body is missing records");
  }
  return decode_records(ByteSpan(blob->data(), blob->size()), limits,
                        static_cast<std::uint32_t>(*count));
}

void encode_explanation_body(const Explanation& explanation, FieldBag& body) {
  body.set_u64(1, explanation.subject.value());
  body.set_u16(2, static_cast<std::uint16_t>(explanation.mode));
  body.set_u64(3, explanation.lineage.value());
  body.set_u64(4, explanation.key.route.value());
  body.set_text(5, explanation.key.semantic_key);
  body.set_u16(6, static_cast<std::uint16_t>(explanation.subject_lifecycle));
  body.set_u16(7, static_cast<std::uint16_t>(explanation.subject_currentness));
  body.set_bool(8, explanation.historically_valid);
  body.set_bool(9, explanation.current);
  body.set_bool(10, explanation.truncated);
  body.set_u64(11, explanation.steps.size());
  body.set_digest(12, explanation.digest);
  codec::Writer writer;
  for (const ExplanationStep& step : explanation.steps) {
    codec::Writer record;
    record.u32(step.depth);
    record.u64(step.edge.value());
    record.u16(static_cast<std::uint16_t>(step.type));
    record.u64(step.from.value());
    record.u64(step.to.value());
    record.u16(static_cast<std::uint16_t>(step.kind));
    record.u16(static_cast<std::uint16_t>(step.reason));
    record.u16(static_cast<std::uint16_t>(step.source));
    record.u64(step.route_generation.value());
    record.u16(static_cast<std::uint16_t>(step.lifecycle));
    record.u16(static_cast<std::uint16_t>(step.currentness));
    record.u8(step.historically_valid ? 1U : 0U);
    record.u8(step.current ? 1U : 0U);
    record.u16(0);
    writer.u32(static_cast<std::uint32_t>(record.size()));
    writer.bytes(ByteSpan(record.data().data(), record.data().size()));
  }
  body.set_bytes(13, ByteSpan(writer.data().data(), writer.data().size()));
}

Result<Explanation> decode_explanation_body(const FieldBag& body, const Limits& limits) {
  Explanation explanation;
  explanation.subject = ProvenanceNodeId::from_value(body.u64(1).value_or(0));
  const std::uint16_t mode = body.u16(2).value_or(0xFFFFU);
  const std::optional<ExplainMode> parsed_mode = parse_explain_mode(to_string(static_cast<ExplainMode>(mode)));
  if (!parsed_mode.has_value()) {
    return Result<Explanation>::failure(Outcome::ProtocolFailure, "unknown explanation mode");
  }
  explanation.mode = *parsed_mode;
  explanation.lineage = RouteLineageId::from_value(body.u64(3).value_or(0));
  explanation.key.route = RouteId::from_value(body.u64(4).value_or(0));
  explanation.key.semantic_key = body.text(5).value_or(std::string{});
  const std::uint16_t lifecycle = body.u16(6).value_or(0xFFFFU);
  const std::uint16_t currentness = body.u16(7).value_or(0xFFFFU);
  explanation.subject_lifecycle = static_cast<NodeLifecycle>(lifecycle);
  explanation.subject_currentness = static_cast<Currentness>(currentness);
  if (to_string(explanation.subject_lifecycle) == "UNKNOWN" ||
      to_string(explanation.subject_currentness) == "UNKNOWN") {
    return Result<Explanation>::failure(Outcome::ProtocolFailure, "unknown explanation state value");
  }
  explanation.historically_valid = body.boolean(8).value_or(false);
  explanation.current = body.boolean(9).value_or(false);
  explanation.truncated = body.boolean(10).value_or(false);
  explanation.digest = body.digest(12).value_or(Digest{});
  const std::optional<std::uint64_t> count = body.u64(11);
  if (!count.has_value() || *count > limits.max_explanation_nodes) {
    return Result<Explanation>::failure(Outcome::ResourceLimit, "explanation exceeds the configured bound");
  }
  const std::optional<ByteVector> blob = body.bytes(13);
  if (!blob.has_value()) {
    return Result<Explanation>::failure(Outcome::ProtocolFailure, "explanation is missing its steps");
  }
  codec::Reader reader(reinterpret_cast<const std::uint8_t*>(blob->data()), blob->size());
  for (std::uint64_t i = 0; i < *count; ++i) {
    const std::uint32_t length = reader.u32();
    if (reader.failed() || length > reader.remaining()) {
      return Result<Explanation>::failure(Outcome::ProtocolFailure, "malformed explanation step");
    }
    const ByteSpan record = reader.span(length);
    codec::Reader step(reinterpret_cast<const std::uint8_t*>(record.data()), record.size());
    ExplanationStep parsed;
    parsed.depth = step.u32();
    parsed.edge = ProvenanceEdgeId::from_value(step.u64());
    const std::uint16_t type = step.u16();
    parsed.from = ProvenanceNodeId::from_value(step.u64());
    parsed.to = ProvenanceNodeId::from_value(step.u64());
    const std::uint16_t kind = step.u16();
    const std::uint16_t reason = step.u16();
    const std::uint16_t source = step.u16();
    parsed.route_generation = RouteGeneration::from_value(step.u64());
    const std::uint16_t step_lifecycle = step.u16();
    const std::uint16_t step_currentness = step.u16();
    const std::uint8_t historically_valid = step.u8();
    const std::uint8_t current = step.u8();
    static_cast<void>(step.u16());
    if (step.failed() || !step.at_end()) {
      return Result<Explanation>::failure(Outcome::ProtocolFailure, "malformed explanation step record");
    }
    parsed.type = static_cast<EdgeType>(type);
    parsed.kind = static_cast<NodeKind>(kind);
    parsed.reason = static_cast<ReasonCode>(reason);
    parsed.source = static_cast<SourceClass>(source);
    parsed.lifecycle = static_cast<NodeLifecycle>(step_lifecycle);
    parsed.currentness = static_cast<Currentness>(step_currentness);
    if (to_string(parsed.type) == "UNKNOWN" || to_string(parsed.kind) == "UNKNOWN" ||
        to_string(parsed.reason) == "UNKNOWN" || to_string(parsed.source) == "UNKNOWN" ||
        to_string(parsed.lifecycle) == "UNKNOWN" || to_string(parsed.currentness) == "UNKNOWN") {
      return Result<Explanation>::failure(Outcome::ProtocolFailure, "unknown explanation step enum value");
    }
    parsed.historically_valid = historically_valid == 1U;
    parsed.current = current == 1U;
    explanation.steps.push_back(parsed);
  }
  if (reader.failed() || !reader.at_end()) {
    return Result<Explanation>::failure(Outcome::ProtocolFailure, "explanation steps have trailing bytes");
  }
  return Result<Explanation>::ok(std::move(explanation));
}

void encode_snapshot_body(const Snapshot& snapshot, FieldBag& body) {
  body.set_u64(1, snapshot.lineage.value());
  body.set_u64(2, snapshot.key.route.value());
  body.set_text(3, snapshot.key.semantic_key);
  body.set_u16(4, static_cast<std::uint16_t>(snapshot.lifecycle));
  body.set_u64(5, snapshot.current_route_generation.value());
  body.set_u64(6, snapshot.current_node.value());
  body.set_u64(7, snapshot.lineage_generation.value());
  body.set_u64(8, snapshot.authority_generation.value());
  body.set_u64(9, snapshot.store_generation.value());
  body.set_u64(10, snapshot.coordinator_epoch.value());
  body.set_u16(11, static_cast<std::uint16_t>(snapshot.current_currentness));
  body.set_digest(12, snapshot.digest);
  body.set_bool(13, snapshot.truncated);
  body.set_u64(14, snapshot.nodes.size());
  codec::Writer nodes;
  for (const ProvenanceNode& node : snapshot.nodes) {
    codec::Writer record;
    codec::write_node(record, node);
    nodes.u32(static_cast<std::uint32_t>(record.size()));
    nodes.bytes(ByteSpan(record.data().data(), record.data().size()));
  }
  body.set_bytes(15, ByteSpan(nodes.data().data(), nodes.data().size()));
  body.set_u64(16, snapshot.edges.size());
  codec::Writer edges;
  for (const ProvenanceEdge& edge : snapshot.edges) {
    codec::Writer record;
    codec::write_edge(record, edge);
    edges.u32(static_cast<std::uint32_t>(record.size()));
    edges.bytes(ByteSpan(record.data().data(), record.data().size()));
  }
  body.set_bytes(17, ByteSpan(edges.data().data(), edges.data().size()));
}

Result<Snapshot> decode_snapshot_body(const FieldBag& body, const Limits& limits) {
  Snapshot snapshot;
  snapshot.lineage = RouteLineageId::from_value(body.u64(1).value_or(0));
  snapshot.key.route = RouteId::from_value(body.u64(2).value_or(0));
  snapshot.key.semantic_key = body.text(3).value_or(std::string{});
  const std::uint16_t lifecycle = body.u16(4).value_or(0xFFFFU);
  const std::uint16_t currentness = body.u16(11).value_or(0xFFFFU);
  snapshot.lifecycle = static_cast<LineageLifecycle>(lifecycle);
  snapshot.current_currentness = static_cast<Currentness>(currentness);
  if (to_string(snapshot.lifecycle) == "UNKNOWN" || to_string(snapshot.current_currentness) == "UNKNOWN") {
    return Result<Snapshot>::failure(Outcome::ProtocolFailure, "unknown snapshot state value");
  }
  snapshot.current_route_generation = RouteGeneration::from_value(body.u64(5).value_or(0));
  snapshot.current_node = ProvenanceNodeId::from_value(body.u64(6).value_or(0));
  snapshot.lineage_generation = LineageGeneration::from_value(body.u64(7).value_or(0));
  snapshot.authority_generation = AuthorityGeneration::from_value(body.u64(8).value_or(0));
  snapshot.store_generation = ProvenanceGeneration::from_value(body.u64(9).value_or(0));
  snapshot.coordinator_epoch = CoordinatorEpoch::from_value(body.u64(10).value_or(0));
  snapshot.digest = body.digest(12).value_or(Digest{});
  snapshot.truncated = body.boolean(13).value_or(false);
  const std::optional<std::uint64_t> node_count = body.u64(14);
  const std::optional<std::uint64_t> edge_count = body.u64(16);
  if (!node_count.has_value() || !edge_count.has_value() || *node_count > limits.max_nodes_per_lineage ||
      *edge_count > limits.max_edges_per_lineage) {
    return Result<Snapshot>::failure(Outcome::ResourceLimit, "snapshot exceeds the configured bounds");
  }
  const std::optional<ByteVector> node_blob = body.bytes(15);
  const std::optional<ByteVector> edge_blob = body.bytes(17);
  if (!node_blob.has_value() || !edge_blob.has_value()) {
    return Result<Snapshot>::failure(Outcome::ProtocolFailure, "snapshot is missing its records");
  }
  const Result<std::vector<ProvenanceNode>> nodes =
      decode_records(ByteSpan(node_blob->data(), node_blob->size()), limits,
                     static_cast<std::uint32_t>(*node_count));
  if (!nodes.has_value()) {
    return Result<Snapshot>::failure(nodes.outcome(), nodes.detail());
  }
  const Result<std::vector<ProvenanceEdge>> edges =
      decode_edge_records(ByteSpan(edge_blob->data(), edge_blob->size()), limits,
                          static_cast<std::uint32_t>(*edge_count));
  if (!edges.has_value()) {
    return Result<Snapshot>::failure(edges.outcome(), edges.detail());
  }
  snapshot.nodes = nodes.value();
  snapshot.edges = edges.value();
  snapshot.id = SnapshotId::from_value(derive_id(snapshot.digest));
  return Result<Snapshot>::ok(std::move(snapshot));
}

void encode_watermarks_body(const DependencyWatermarks& marks, FieldBag& body) {
  body.set_u64(1, marks.store_generation.value());
  body.set_u64(2, marks.path_authority_generation.value());
  body.set_u64(3, marks.policy_generation.value());
  body.set_u64(4, marks.evidence_generation.value());
  body.set_u64(5, marks.plan_generation.value());
  body.set_u64(6, marks.epoch.value());
  body.set_digest(7, marks.digest);
}

Result<DependencyWatermarks> decode_watermarks_body(const FieldBag& body) {
  DependencyWatermarks marks;
  marks.store_generation = ProvenanceGeneration::from_value(body.u64(1).value_or(0));
  marks.path_authority_generation = PathAuthorityGeneration::from_value(body.u64(2).value_or(0));
  marks.policy_generation = PolicyGeneration::from_value(body.u64(3).value_or(0));
  marks.evidence_generation = EvidenceGeneration::from_value(body.u64(4).value_or(0));
  marks.plan_generation = ConvergencePlanGeneration::from_value(body.u64(5).value_or(0));
  marks.epoch = CoordinatorEpoch::from_value(body.u64(6).value_or(0));
  marks.digest = body.digest(7).value_or(Digest{});
  return Result<DependencyWatermarks>::ok(marks);
}

Status encode_fence(const FencePayload& payload, ByteVector& out, const Limits& limits) {
  FieldBag bag;
  bag.set_u64(1, payload.publisher.value());
  bag.set_u64(2, payload.boot.value());
  put_authority(bag, payload.authority, 100);
  return encode_bag(bag, out, limits);
}

Result<FencePayload> decode_fence(ByteSpan payload, const Limits& limits) {
  const Result<FieldBag> bag = decode_bag(payload, limits);
  if (!bag.has_value()) {
    return Result<FencePayload>::failure(bag.outcome(), bag.detail());
  }
  const Status fields = check_fields(bag.value(), field_ranges({{1, 2}, {100, 107}}), {1, 2, 100});
  if (!fields.is_ok()) {
    return Result<FencePayload>::failure(fields.outcome(), fields.detail());
  }
  FencePayload fence;
  fence.publisher = PublisherId::from_value(bag->u64(1).value_or(0));
  fence.boot = WorkerBootId::from_value(bag->u64(2).value_or(0));
  const Result<AuthorityContext> authority = take_authority(bag.value(), 100, limits);
  if (!authority.has_value()) {
    return Result<FencePayload>::failure(authority.outcome(), authority.detail());
  }
  fence.authority = authority.value();
  return Result<FencePayload>::ok(std::move(fence));
}

Status encode_query(const QueryPayload& payload, ByteVector& out, const Limits& limits) {
  FieldBag bag;
  bag.set_u64(1, payload.lineage.value());
  bag.set_u64(2, payload.node.value());
  bag.set_u16(3, static_cast<std::uint16_t>(payload.direction));
  bag.set_u32(4, payload.bounds.max_depth);
  bag.set_u32(5, payload.bounds.max_results);
  bag.set_u32(6, payload.bounds.max_visited);
  bag.set_u16(7, static_cast<std::uint16_t>(payload.mode));
  return encode_bag(bag, out, limits);
}

Result<QueryPayload> decode_query(ByteSpan payload, const Limits& limits) {
  const Result<FieldBag> bag = decode_bag(payload, limits);
  if (!bag.has_value()) {
    return Result<QueryPayload>::failure(bag.outcome(), bag.detail());
  }
  const Status fields = check_fields(bag.value(), field_ranges({{1, 7}}), {});
  if (!fields.is_ok()) {
    return Result<QueryPayload>::failure(fields.outcome(), fields.detail());
  }
  QueryPayload query;
  query.lineage = RouteLineageId::from_value(bag->u64(1).value_or(0));
  query.node = ProvenanceNodeId::from_value(bag->u64(2).value_or(0));
  const std::uint16_t direction = bag->u16(3).value_or(0);
  if (direction > 1U) {
    return Result<QueryPayload>::failure(Outcome::ProtocolFailure, "unknown traversal direction");
  }
  query.direction = direction == 0U ? TraversalDirection::Outgoing : TraversalDirection::Incoming;
  query.bounds.max_depth = bag->u32(4).value_or(0);
  query.bounds.max_results = bag->u32(5).value_or(0);
  query.bounds.max_visited = bag->u32(6).value_or(0);
  const std::uint16_t mode = bag->u16(7).value_or(0xFFFFU);
  const std::optional<ExplainMode> parsed =
      parse_explain_mode(to_string(static_cast<ExplainMode>(mode)));
  if (!parsed.has_value()) {
    return Result<QueryPayload>::failure(Outcome::ProtocolFailure, "unknown explanation mode");
  }
  query.mode = *parsed;
  return Result<QueryPayload>::ok(std::move(query));
}

Status encode_response(const ResponsePayload& payload, ByteVector& out, const Limits& limits) {
  FieldBag bag;
  bag.set_u16(1, static_cast<std::uint16_t>(payload.outcome));
  bag.set_text(2, payload.detail);
  bag.set_nested(3, payload.body);
  return encode_bag(bag, out, limits);
}

Result<ResponsePayload> decode_response(ByteSpan payload, const Limits& limits) {
  const Result<FieldBag> bag = decode_bag(payload, limits);
  if (!bag.has_value()) {
    return Result<ResponsePayload>::failure(bag.outcome(), bag.detail());
  }
  const Status fields = check_fields(bag.value(), {1, 2, 3}, {1});
  if (!fields.is_ok()) {
    return Result<ResponsePayload>::failure(fields.outcome(), fields.detail());
  }
  ResponsePayload response;
  const std::uint16_t outcome = bag->u16(1).value_or(0xFFFFU);
  const std::optional<Outcome> parsed = parse_outcome(to_string(static_cast<Outcome>(outcome)));
  if (!parsed.has_value()) {
    return Result<ResponsePayload>::failure(Outcome::ProtocolFailure, "unknown response outcome");
  }
  response.outcome = *parsed;
  response.detail = bag->text(2).value_or(std::string{});
  if (bag->has(3)) {
    const std::optional<FieldBag> body = bag->nested(3, limits);
    if (!body.has_value()) {
      return Result<ResponsePayload>::failure(Outcome::ProtocolFailure, "malformed response body");
    }
    response.body = body.value();
  }
  return Result<ResponsePayload>::ok(std::move(response));
}

}  // namespace route_provenance
