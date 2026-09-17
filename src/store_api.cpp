// Route Provenance - public store API: validation, publication, authority and sessions.
#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "route_provenance/version.hpp"
#include "store_internal.hpp"

namespace route_provenance {
namespace {

[[nodiscard]] Result<NormalizedPublication> fail_normalized(const Status& status) {
  return Result<NormalizedPublication>::failure(status.outcome(), status.detail());
}

[[nodiscard]] Status check_authority_fields(const AuthorityContext& authority) {
  if (!authority.publisher.publisher.valid()) {
    return Status::failure(Outcome::Unauthorized, "publication requires a valid PublisherId");
  }
  if (!authority.publisher.boot.valid()) {
    return Status::failure(Outcome::Unauthorized, "publication requires a valid WorkerBootId");
  }
  if (!authority.publisher.epoch.valid()) {
    return Status::failure(Outcome::Unauthorized, "publication requires a valid CoordinatorEpoch");
  }
  if (!authority.attempt.valid()) {
    return Status::failure(Outcome::Unauthorized, "publication requires a valid MutationAttemptId");
  }
  return Status::ok();
}

[[nodiscard]] Status check_edge_specs(const std::vector<EdgeSpec>& specs) {
  for (const EdgeSpec& spec : specs) {
    if (!spec.target.valid()) {
      return Status::failure(Outcome::MalformedRequest, "derivation edge requires a valid target identity");
    }
  }
  return Status::ok();
}

[[nodiscard]] Status check_reason_matches(PublishKind kind, ReasonCode reason) {
  switch (kind) {
    case PublishKind::Withdrawal:
      if (reason != ReasonCode::AdminWithdrawal) {
        return Status::failure(Outcome::MalformedRequest, "withdrawal requires ADMIN_WITHDRAWAL");
      }
      break;
    case PublishKind::Revocation:
      if (reason != ReasonCode::Revocation) {
        return Status::failure(Outcome::MalformedRequest, "revocation requires REVOCATION");
      }
      break;
    case PublishKind::Retirement:
      if (reason != ReasonCode::Retirement) {
        return Status::failure(Outcome::MalformedRequest, "retirement requires RETIREMENT");
      }
      break;
    case PublishKind::Revalidation:
      if (reason != ReasonCode::RecoveryRevalidation && reason != ReasonCode::PathRevalidated) {
        return Status::failure(Outcome::MalformedRequest,
                               "revalidation requires RECOVERY_REVALIDATION or PATH_REVALIDATED");
      }
      break;
    case PublishKind::Invalidation:
      if (reason != ReasonCode::Invalidation && reason != ReasonCode::PathInvalidation) {
        return Status::failure(Outcome::MalformedRequest,
                               "invalidation requires INVALIDATION or PATH_INVALIDATION");
      }
      break;
    case PublishKind::Correction:
      if (reason != ReasonCode::Correction) {
        return Status::failure(Outcome::MalformedRequest, "correction requires CORRECTION");
      }
      break;
    default:
      break;
  }
  return Status::ok();
}

/// Direction of the edge an administrative action records.
[[nodiscard]] EdgeType action_edge_type(PublishKind kind) noexcept {
  switch (kind) {
    case PublishKind::Withdrawal: return EdgeType::Withdraws;
    case PublishKind::Revocation: return EdgeType::RevokedBy;
    case PublishKind::Retirement: return EdgeType::RetiredBy;
    case PublishKind::Revalidation: return EdgeType::Revalidates;
    case PublishKind::Invalidation: return EdgeType::Invalidates;
    case PublishKind::Correction: return EdgeType::Corrects;
    default: return EdgeType::DerivedFrom;
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

ProvenanceStore::ProvenanceStore(Limits limits) : impl_(std::make_unique<Impl>(limits)) {
  std::string error;
  if (!limits.validate(error)) {
    throw std::invalid_argument("invalid Route Provenance limits: " + error);
  }
}

ProvenanceStore::~ProvenanceStore() = default;

const Limits& ProvenanceStore::limits() const noexcept { return impl_->limits; }

bool ProvenanceStore::recovered() const noexcept { return impl_->recovered; }

// ---------------------------------------------------------------------------
// Publisher authority
// ---------------------------------------------------------------------------

Result<PublisherRecord> ProvenanceStore::register_publisher(PublisherIdentity identity,
                                                            AuthorityScope scope) {
  if (!identity.valid()) {
    return Result<PublisherRecord>::failure(
        Outcome::Unauthorized, "publisher registration requires PublisherId, WorkerBootId and epoch");
  }
  {
    std::unique_lock<std::shared_mutex> lock(impl_->index_mutex);
    if (!impl_->watermarks.epoch.valid()) {
      impl_->watermarks.epoch = identity.epoch;
    } else if (impl_->watermarks.epoch != identity.epoch) {
      // A coordinator that recovered a durable store re-establishes epoch authority exactly
      // once by presenting a strictly greater epoch. Anything else is a stale session.
      const bool bootstrap =
          impl_->recovered && !impl_->epoch_bootstrapped &&
          identity.epoch.value() > impl_->watermarks.epoch.value();
      if (!bootstrap) {
        return Result<PublisherRecord>::failure(
            Outcome::StaleEpoch, "publisher registration epoch is not the current coordinator epoch");
      }
      impl_->watermarks.epoch = identity.epoch;
      impl_->epoch_bootstrapped = true;
    }
  }
  if (scope.is_empty()) {
    return Result<PublisherRecord>::failure(
        Outcome::Unauthorized, "publisher registration requires an explicit authority scope");
  }
  std::vector<WorkerBootId> superseded;
  PublisherRecord record;
  {
    std::lock_guard<std::mutex> lock(impl_->publisher_mutex);
    const auto existing = impl_->publishers.find(PublisherKey{identity.publisher, identity.boot});
    if (existing != impl_->publishers.end() && existing->second.fenced) {
      return Result<PublisherRecord>::failure(
          Outcome::StaleWorker, "worker boot has been fenced and may never publish again");
    }
    if (impl_->publishers.size() >= impl_->limits.max_publishers) {
      return Result<PublisherRecord>::failure(Outcome::ResourceLimit, "max_publishers reached");
    }
    for (auto& entry : impl_->publishers) {
      if (entry.first.publisher == identity.publisher && entry.first.boot != identity.boot &&
          entry.second.live) {
        // A superseded boot is fenced for good: it may never publish again, even though its
        // historical records remain valid.
        entry.second.live = false;
        entry.second.fenced = true;
        superseded.push_back(entry.first.boot);
      }
    }
    record.identity = identity;
    record.scope = scope;
    record.live = true;
    impl_->publishers[PublisherKey{identity.publisher, identity.boot}] = record;
  }
  for (const WorkerBootId& boot : superseded) {
    std::vector<ProvenanceNodeId> affected;
    {
      std::shared_lock<std::shared_mutex> lock(impl_->index_mutex);
      const auto it = impl_->boot_index.find(boot);
      if (it != impl_->boot_index.end()) {
        affected.assign(it->second.begin(), it->second.end());
      }
    }
    impl_->reevaluate_index(affected);
  }
  return Result<PublisherRecord>::ok(record);
}

Result<PublisherRecord> ProvenanceStore::reincarnate_publisher(PublisherId publisher,
                                                               WorkerBootId fresh_boot,
                                                               CoordinatorEpoch epoch,
                                                               AuthorityScope scope) {
  if (!publisher.valid() || !fresh_boot.valid()) {
    return Result<PublisherRecord>::failure(Outcome::MalformedRequest,
                                            "reincarnation requires publisher and fresh boot identities");
  }
  return register_publisher(PublisherIdentity{publisher, fresh_boot, epoch}, scope);
}

Status ProvenanceStore::fence_publisher(PublisherId publisher, WorkerBootId boot,
                                        const AuthorityContext& authority) {
  if (!publisher.valid() || !boot.valid()) {
    return Status::failure(Outcome::MalformedRequest, "fencing requires publisher and boot identities");
  }
  const Status identity = check_authority_fields(authority);
  if (!identity.is_ok()) {
    return identity;
  }
  const DependencyWatermarks marks = impl_->read_watermarks();
  if (!marks.epoch.valid() || authority.publisher.epoch != marks.epoch) {
    return Status::failure(Outcome::StaleEpoch, "fencing epoch is not the current coordinator epoch");
  }
  if (!impl_->publisher_is_live(authority.publisher.publisher, authority.publisher.boot)) {
    return Status::failure(Outcome::StaleWorker, "fencing requires a live administrative session");
  }
  if (authority.scope.kind() != ScopeKind::Fabric) {
    return Status::failure(Outcome::Unauthorized, "fencing requires explicit fabric authority scope");
  }
  bool found = false;
  {
    std::lock_guard<std::mutex> lock(impl_->publisher_mutex);
    const auto it = impl_->publishers.find(PublisherKey{publisher, boot});
    if (it != impl_->publishers.end()) {
      it->second.live = false;
      it->second.fenced = true;
      found = true;
    }
  }
  if (!found) {
    return Status::failure(Outcome::NodeNotFound, "publisher boot is not registered");
  }
  std::vector<ProvenanceNodeId> affected;
  {
    std::shared_lock<std::shared_mutex> lock(impl_->index_mutex);
    const auto it = impl_->boot_index.find(boot);
    if (it != impl_->boot_index.end()) {
      affected.assign(it->second.begin(), it->second.end());
    }
  }
  impl_->reevaluate_index(affected);
  return Status::ok(Outcome::Updated, "publisher boot fenced");
}

Result<std::vector<PublisherRecord>> ProvenanceStore::list_publishers() const {
  std::vector<PublisherRecord> out;
  {
    std::lock_guard<std::mutex> lock(impl_->publisher_mutex);
    out.reserve(impl_->publishers.size());
    for (const auto& entry : impl_->publishers) {
      out.push_back(entry.second);
    }
  }
  std::sort(out.begin(), out.end(), [](const PublisherRecord& left, const PublisherRecord& right) {
    if (left.identity.publisher != right.identity.publisher) {
      return left.identity.publisher < right.identity.publisher;
    }
    return left.identity.boot < right.identity.boot;
  });
  return Result<std::vector<PublisherRecord>>::ok(std::move(out));
}

bool ProvenanceStore::is_publisher_live(PublisherId publisher, WorkerBootId boot) const {
  return impl_->publisher_is_live(publisher, boot);
}

// ---------------------------------------------------------------------------
// Dependency watermarks
// ---------------------------------------------------------------------------

Status ProvenanceStore::notify_dependency(const DependencyNotification& notification) {
  const Status identity = check_authority_fields(notification.authority);
  if (!identity.is_ok()) {
    return identity;
  }
  const DependencyWatermarks marks = impl_->read_watermarks();
  if (!marks.epoch.valid() || notification.authority.publisher.epoch != marks.epoch) {
    return Status::failure(Outcome::StaleEpoch, "dependency notification epoch is not current");
  }
  if (!impl_->publisher_is_live(notification.authority.publisher.publisher,
                                notification.authority.publisher.boot)) {
    return Status::failure(Outcome::StaleWorker, "dependency notification requires a live session");
  }
  if (notification.authority.scope.kind() != ScopeKind::Fabric) {
    return Status::failure(Outcome::Unauthorized,
                           "dependency notifications require explicit fabric authority scope");
  }

  std::vector<ProvenanceNodeId> affected;
  Outcome outcome = Outcome::Updated;
  {
    std::unique_lock<std::shared_mutex> lock(impl_->index_mutex);
    const auto collect = [&affected](const auto& index, const auto& value) {
      for (auto it = index.begin(); it != index.end() && it->first < value; ++it) {
        affected.insert(affected.end(), it->second.begin(), it->second.end());
      }
    };
    switch (notification.kind) {
      case DependencyKind::PathAuthorityAdvance: {
        if (!notification.path_authority_generation.valid()) {
          return Status::failure(Outcome::InvalidSourceGeneration,
                                 "path authority advance requires a valid generation");
        }
        if (impl_->watermarks.path_authority_generation.valid()) {
          if (notification.path_authority_generation == impl_->watermarks.path_authority_generation) {
            return Status::ok(Outcome::Idempotent, "path authority generation unchanged");
          }
          if (notification.path_authority_generation.value() <
              impl_->watermarks.path_authority_generation.value()) {
            return Status::failure(Outcome::InvalidSourceGeneration,
                                   "path authority generation would decrease");
          }
        }
        collect(impl_->path_authority_index, notification.path_authority_generation);
        impl_->watermarks.path_authority_generation = notification.path_authority_generation;
        break;
      }
      case DependencyKind::PolicyAdvance: {
        if (!notification.policy_generation.valid()) {
          return Status::failure(Outcome::InvalidSourceGeneration,
                                 "policy advance requires a valid generation");
        }
        if (impl_->watermarks.policy_generation.valid()) {
          if (notification.policy_generation == impl_->watermarks.policy_generation) {
            return Status::ok(Outcome::Idempotent, "policy generation unchanged");
          }
          if (notification.policy_generation.value() < impl_->watermarks.policy_generation.value()) {
            return Status::failure(Outcome::InvalidSourceGeneration, "policy generation would decrease");
          }
        }
        collect(impl_->policy_index, notification.policy_generation);
        impl_->watermarks.policy_generation = notification.policy_generation;
        break;
      }
      case DependencyKind::EvidenceAdvance: {
        if (!notification.evidence_generation.valid()) {
          return Status::failure(Outcome::InvalidSourceGeneration,
                                 "evidence advance requires a valid generation");
        }
        if (impl_->watermarks.evidence_generation.valid()) {
          if (notification.evidence_generation == impl_->watermarks.evidence_generation) {
            return Status::ok(Outcome::Idempotent, "evidence generation unchanged");
          }
          if (notification.evidence_generation.value() < impl_->watermarks.evidence_generation.value()) {
            return Status::failure(Outcome::InvalidSourceGeneration, "evidence generation would decrease");
          }
        }
        collect(impl_->evidence_index, notification.evidence_generation);
        impl_->watermarks.evidence_generation = notification.evidence_generation;
        break;
      }
      case DependencyKind::PlanAdvance: {
        if (!notification.plan_generation.valid()) {
          return Status::failure(Outcome::InvalidSourceGeneration,
                                 "plan advance requires a valid generation");
        }
        if (impl_->watermarks.plan_generation.valid()) {
          if (notification.plan_generation == impl_->watermarks.plan_generation) {
            return Status::ok(Outcome::Idempotent, "plan generation unchanged");
          }
          if (notification.plan_generation.value() < impl_->watermarks.plan_generation.value()) {
            return Status::failure(Outcome::InvalidSourceGeneration, "plan generation would decrease");
          }
        }
        impl_->watermarks.plan_generation = notification.plan_generation;
        break;
      }
      case DependencyKind::EpochAdvance: {
        if (!notification.epoch.valid()) {
          return Status::failure(Outcome::InvalidSourceGeneration, "epoch advance requires a valid epoch");
        }
        if (notification.epoch.value() <= impl_->watermarks.epoch.value()) {
          return Status::failure(Outcome::InvalidSourceGeneration, "coordinator epoch must advance");
        }
        impl_->watermarks.epoch = notification.epoch;
        break;
      }
      case DependencyKind::RouteAdvance: {
        return Status::failure(
            Outcome::MalformedRequest,
            "route advance is recorded by publishing the route generation, not by notification");
      }
      case DependencyKind::WorkerFence: {
        if (!notification.publisher.valid() || !notification.boot.valid()) {
          return Status::failure(Outcome::MalformedRequest, "worker fence requires publisher and boot");
        }
        break;
      }
    }
    bool advanced = true;
    static_cast<void>(impl_->next_store_generation(advanced));
    if (!advanced) {
      return Status::failure(Outcome::ResourceLimit, "store generation exhausted");
    }
  }

  if (notification.kind == DependencyKind::EpochAdvance ||
      notification.kind == DependencyKind::WorkerFence) {
    if (notification.kind == DependencyKind::WorkerFence) {
      bool found = false;
      {
        std::lock_guard<std::mutex> lock(impl_->publisher_mutex);
        const auto it = impl_->publishers.find(PublisherKey{notification.publisher, notification.boot});
        if (it != impl_->publishers.end()) {
          it->second.live = false;
          found = true;
        }
      }
      if (!found) {
        return Status::failure(Outcome::NodeNotFound, "publisher boot is not registered");
      }
    }
    // Every record whose liveness depended on the old epoch or on the fenced boot is
    // re-evaluated. Records of other publishers and epochs are untouched.
    std::shared_lock<std::shared_mutex> lock(impl_->index_mutex);
    if (notification.kind == DependencyKind::EpochAdvance) {
      for (const auto& entry : impl_->node_owner) {
        affected.push_back(entry.first);
      }
    } else {
      const auto it = impl_->boot_index.find(notification.boot);
      if (it != impl_->boot_index.end()) {
        affected.assign(it->second.begin(), it->second.end());
      }
    }
  }
  impl_->reevaluate_index(affected);
  return Status::ok(outcome, "dependency watermark updated");
}

Status ProvenanceStore::advance_epoch(CoordinatorEpoch epoch, const AuthorityContext& authority) {
  DependencyNotification notification;
  notification.kind = DependencyKind::EpochAdvance;
  notification.epoch = epoch;
  notification.authority = authority;
  return notify_dependency(notification);
}

Result<DependencyWatermarks> ProvenanceStore::watermarks() const {
  DependencyWatermarks marks = impl_->read_watermarks();
  CanonicalEncoder encoder;
  encoder.add_u32(1, kGraphEncodingVersion);
  encoder.add_u64(2, marks.store_generation.value());
  encoder.add_u64(3, marks.path_authority_generation.value());
  encoder.add_u64(4, marks.policy_generation.value());
  encoder.add_u64(5, marks.evidence_generation.value());
  encoder.add_u64(6, marks.plan_generation.value());
  encoder.add_u64(7, marks.epoch.value());
  marks.digest = encoder.digest("rp.watermarks.v1");
  return Result<DependencyWatermarks>::ok(marks);
}

// ---------------------------------------------------------------------------
// Request normalization
// ---------------------------------------------------------------------------

namespace {

[[nodiscard]] Result<NormalizedPublication> normalize_route(const PublishRouteRequest& request,
                                                            const Limits& limits) {
  const Status key = check_lineage_key(request.key, limits);
  if (!key.is_ok()) {
    return fail_normalized(key);
  }
  if (!request.route_generation.valid()) {
    return Result<NormalizedPublication>::failure(Outcome::InvalidSourceGeneration,
                                                  "route generation must be >= 1");
  }
  if (request.route_state_digest.is_zero()) {
    return Result<NormalizedPublication>::failure(Outcome::InvalidDerivation,
                                                  "route-state digest is required");
  }
  const Status bindings = validate_bindings(request.reason, request.bindings);
  if (!bindings.is_ok()) {
    return fail_normalized(bindings);
  }
  const Status specs = check_edge_specs(request.edges);
  if (!specs.is_ok()) {
    return fail_normalized(specs);
  }
  NormalizedPublication normalized;
  normalized.kind = PublishKind::RouteState;
  normalized.key = request.key;
  normalized.explicit_lineage = request.explicit_lineage;
  normalized.node_kind = NodeKind::RouteGeneration;
  normalized.route = request.key.route;
  normalized.route_generation = request.route_generation;
  normalized.route_state_digest = request.route_state_digest;
  normalized.reason = request.reason;
  normalized.source = request.source;
  normalized.root_reason = request.root_reason;
  normalized.evidence = request.evidence;
  normalized.authority = request.authority;
  normalized.bindings = request.bindings;
  normalized.edges = request.edges;
  return Result<NormalizedPublication>::ok(std::move(normalized));
}

[[nodiscard]] Result<NormalizedPublication> normalize_declaration(const DeclarationRequest& request,
                                                                  const Limits& limits) {
  const Status key = check_lineage_key(request.key, limits);
  if (!key.is_ok()) {
    return fail_normalized(key);
  }
  if (!is_declaration_kind(request.kind)) {
    return Result<NormalizedPublication>::failure(
        Outcome::MalformedRequest, "declaration requires a declaration record kind");
  }
  const Status declared = check_declaration_bindings(request.kind, request.bindings);
  if (!declared.is_ok()) {
    return fail_normalized(declared);
  }
  const Status bindings = validate_bindings(request.reason, request.bindings);
  if (!bindings.is_ok()) {
    return fail_normalized(bindings);
  }
  const Status authority = check_authority_fields(request.authority);
  if (!authority.is_ok()) {
    return fail_normalized(authority);
  }
  if (request.route_generation.valid() && !request.route.valid()) {
    return Result<NormalizedPublication>::failure(
        Outcome::MalformedRequest, "declaration binds a route generation without a route identity");
  }
  NormalizedPublication normalized;
  normalized.kind = PublishKind::Declaration;
  normalized.key = request.key;
  normalized.node_kind = request.kind;
  normalized.route = request.route;
  normalized.route_generation = request.route_generation;
  normalized.reason = request.reason;
  normalized.source = request.source;
  normalized.evidence = request.evidence;
  normalized.authority = request.authority;
  normalized.bindings = request.bindings;
  return Result<NormalizedPublication>::ok(std::move(normalized));
}

[[nodiscard]] Result<NormalizedPublication> normalize_administrative(const AdministrativeRequest& request,
                                                                    PublishKind kind,
                                                                    const Limits& limits) {
  const Status key = check_lineage_key(request.key, limits);
  if (!key.is_ok()) {
    return fail_normalized(key);
  }
  const Status authority = check_authority_fields(request.authority);
  if (!authority.is_ok()) {
    return fail_normalized(authority);
  }
  if (!request.target.valid()) {
    return Result<NormalizedPublication>::failure(Outcome::MalformedRequest,
                                                  "administrative action requires a target record");
  }
  const Status reason = check_reason_matches(kind, request.reason);
  if (!reason.is_ok()) {
    return fail_normalized(reason);
  }
  const Status bindings = validate_bindings(request.reason, request.bindings);
  if (!bindings.is_ok()) {
    return fail_normalized(bindings);
  }
  NormalizedPublication normalized;
  normalized.kind = kind;
  normalized.key = request.key;
  normalized.node_kind = NodeKind::AdministrativeAction;
  normalized.target = request.target;
  normalized.reason = request.reason;
  normalized.source = request.source;
  normalized.evidence = request.evidence;
  normalized.authority = request.authority;
  normalized.bindings = request.bindings;
  normalized.completion_evidence = request.completion_evidence;
  normalized.allow_non_current_target = request.allow_non_current_target;
  EdgeSpec spec;
  spec.type = action_edge_type(kind);
  spec.target = request.target;
  spec.reason = request.reason;
  spec.source = request.source;
  spec.evidence = request.evidence;
  normalized.edges.push_back(std::move(spec));
  return Result<NormalizedPublication>::ok(std::move(normalized));
}

[[nodiscard]] Result<NormalizedPublication> normalize_correction(const CorrectionRequest& request,
                                                                 const Limits& limits) {
  const Status key = check_lineage_key(request.key, limits);
  if (!key.is_ok()) {
    return fail_normalized(key);
  }
  const Status authority = check_authority_fields(request.authority);
  if (!authority.is_ok()) {
    return fail_normalized(authority);
  }
  if (!request.target.valid()) {
    return Result<NormalizedPublication>::failure(Outcome::MalformedRequest,
                                                  "correction requires a target record");
  }
  const Status reason = check_reason_matches(PublishKind::Correction, request.reason);
  if (!reason.is_ok()) {
    return fail_normalized(reason);
  }
  const Status bindings = validate_bindings(request.reason, request.bindings);
  if (!bindings.is_ok()) {
    return fail_normalized(bindings);
  }
  NormalizedPublication normalized;
  normalized.kind = PublishKind::Correction;
  normalized.key = request.key;
  normalized.node_kind = NodeKind::RouteGeneration;
  normalized.target = request.target;
  normalized.route_state_digest = request.route_state_digest;
  normalized.reason = request.reason;
  normalized.source = request.source;
  normalized.evidence = request.evidence;
  normalized.authority = request.authority;
  normalized.bindings = request.bindings;
  EdgeSpec spec;
  spec.type = EdgeType::Corrects;
  spec.target = request.target;
  spec.reason = request.reason;
  spec.source = request.source;
  spec.evidence = request.evidence;
  normalized.edges.push_back(std::move(spec));
  return Result<NormalizedPublication>::ok(std::move(normalized));
}

[[nodiscard]] bool link_type_is_supported(EdgeType type) noexcept {
  switch (type) {
    case EdgeType::AuthorizedBy:
    case EdgeType::ComputedFrom:
    case EdgeType::SelectedFrom:
    case EdgeType::AdaptedFrom:
    case EdgeType::TransitionedBy:
    case EdgeType::DerivedFrom:
      return true;
    default:
      return false;
  }
}

[[nodiscard]] Result<NormalizedPublication> normalize_link(const LinkDerivationRequest& request,
                                                           const Limits& limits) {
  const Status key = check_lineage_key(request.key, limits);
  if (!key.is_ok()) {
    return fail_normalized(key);
  }
  const Status authority = check_authority_fields(request.authority);
  if (!authority.is_ok()) {
    return fail_normalized(authority);
  }
  if (!request.from.valid() || !request.to.valid() || request.from == request.to) {
    return Result<NormalizedPublication>::failure(
        Outcome::MalformedRequest, "link requires two distinct record identities");
  }
  if (!link_type_is_supported(request.type)) {
    return Result<NormalizedPublication>::failure(
        Outcome::MalformedRequest, "unsupported link relation for LINK_DERIVATION");
  }
  NormalizedPublication normalized;
  normalized.kind = PublishKind::Link;
  normalized.key = request.key;
  normalized.link_type = request.type;
  normalized.link_from = request.from;
  normalized.target = request.to;
  normalized.reason = request.reason;
  normalized.source = request.source;
  normalized.evidence = request.evidence;
  normalized.authority = request.authority;
  return Result<NormalizedPublication>::ok(std::move(normalized));
}

}  // namespace

// ---------------------------------------------------------------------------
// Publication entry points
// ---------------------------------------------------------------------------

Result<Publication> ProvenanceStore::publish_route(const PublishRouteRequest& request) {
  const Result<NormalizedPublication> normalized = normalize_route(request, impl_->limits);
  if (!normalized.has_value()) {
    return Result<Publication>::failure(normalized.outcome(), normalized.detail());
  }
  return impl_->commit(normalized.value());
}

Result<Publication> ProvenanceStore::declare(const DeclarationRequest& request) {
  const Result<NormalizedPublication> normalized = normalize_declaration(request, impl_->limits);
  if (!normalized.has_value()) {
    return Result<Publication>::failure(normalized.outcome(), normalized.detail());
  }
  return impl_->commit(normalized.value());
}

Result<Publication> ProvenanceStore::link_derivation(const LinkDerivationRequest& request) {
  const Result<NormalizedPublication> normalized = normalize_link(request, impl_->limits);
  if (!normalized.has_value()) {
    return Result<Publication>::failure(normalized.outcome(), normalized.detail());
  }
  return impl_->commit(normalized.value());
}

Result<Publication> ProvenanceStore::withdraw(const AdministrativeRequest& request) {
  const Result<NormalizedPublication> normalized =
      normalize_administrative(request, PublishKind::Withdrawal, impl_->limits);
  if (!normalized.has_value()) {
    return Result<Publication>::failure(normalized.outcome(), normalized.detail());
  }
  return impl_->commit(normalized.value());
}

Result<Publication> ProvenanceStore::revoke(const AdministrativeRequest& request) {
  const Result<NormalizedPublication> normalized =
      normalize_administrative(request, PublishKind::Revocation, impl_->limits);
  if (!normalized.has_value()) {
    return Result<Publication>::failure(normalized.outcome(), normalized.detail());
  }
  return impl_->commit(normalized.value());
}

Result<Publication> ProvenanceStore::retire(const AdministrativeRequest& request) {
  const Result<NormalizedPublication> normalized =
      normalize_administrative(request, PublishKind::Retirement, impl_->limits);
  if (!normalized.has_value()) {
    return Result<Publication>::failure(normalized.outcome(), normalized.detail());
  }
  return impl_->commit(normalized.value());
}

Result<Publication> ProvenanceStore::revalidate(const AdministrativeRequest& request) {
  const Result<NormalizedPublication> normalized =
      normalize_administrative(request, PublishKind::Revalidation, impl_->limits);
  if (!normalized.has_value()) {
    return Result<Publication>::failure(normalized.outcome(), normalized.detail());
  }
  return impl_->commit(normalized.value());
}

Result<Publication> ProvenanceStore::invalidate(const AdministrativeRequest& request) {
  const Result<NormalizedPublication> normalized =
      normalize_administrative(request, PublishKind::Invalidation, impl_->limits);
  if (!normalized.has_value()) {
    return Result<Publication>::failure(normalized.outcome(), normalized.detail());
  }
  return impl_->commit(normalized.value());
}

Result<Publication> ProvenanceStore::correct(const CorrectionRequest& request) {
  const Result<NormalizedPublication> normalized = normalize_correction(request, impl_->limits);
  if (!normalized.has_value()) {
    return Result<Publication>::failure(normalized.outcome(), normalized.detail());
  }
  return impl_->commit(normalized.value());
}

// ---------------------------------------------------------------------------
// Two-phase publication
// ---------------------------------------------------------------------------

Result<PublicationSession> ProvenanceStore::begin_publication(const PublishRouteRequest& request) {
  const Result<NormalizedPublication> normalized = normalize_route(request, impl_->limits);
  if (!normalized.has_value()) {
    return Result<PublicationSession>::failure(normalized.outcome(), normalized.detail());
  }
  const DependencyWatermarks marks = impl_->read_watermarks();
  DependencySnapshot snapshot;
  snapshot.store_generation = marks.store_generation;
  snapshot.path_authority_generation = marks.path_authority_generation;
  snapshot.policy_generation = marks.policy_generation;
  snapshot.evidence_generation = marks.evidence_generation;
  snapshot.plan_generation = marks.plan_generation;
  snapshot.epoch = marks.epoch;
  snapshot.publisher_boot = request.authority.publisher.boot;
  const std::shared_ptr<Lineage> lineage = impl_->find_lineage(derive_lineage_id(request.key));
  if (lineage != nullptr) {
    std::shared_lock<std::shared_mutex> lock(lineage->mutex);
    snapshot.lineage_generation = lineage->state.lineage_generation;
    snapshot.route_generation = lineage->state.current_route_generation;
  }
  CanonicalEncoder encoder;
  encoder.add_u32(1, kGraphEncodingVersion);
  encoder.add_u64(2, snapshot.store_generation.value());
  encoder.add_u64(3, snapshot.lineage_generation.value());
  encoder.add_u64(4, snapshot.route_generation.value());
  encoder.add_u64(5, snapshot.path_authority_generation.value());
  encoder.add_u64(6, snapshot.policy_generation.value());
  encoder.add_u64(7, snapshot.evidence_generation.value());
  encoder.add_u64(8, snapshot.plan_generation.value());
  encoder.add_u64(9, snapshot.epoch.value());
  encoder.add_u64(10, snapshot.publisher_boot.value());
  snapshot.digest = encoder.digest("rp.dependency.snapshot.v1");

  auto state = std::make_unique<PublicationSessionState>();
  state->request = request;
  state->normalized = normalized.value();
  return Result<PublicationSession>::ok(
      PublicationSession(this, std::move(state), snapshot));
}

Result<Publication> ProvenanceStore::commit_session(const DependencySnapshot& snapshot,
                                                    const NormalizedPublication& request) {
  const DependencyWatermarks marks = impl_->read_watermarks();
  const std::shared_ptr<Lineage> lineage = impl_->find_lineage(derive_lineage_id(request.key));
  if (lineage != nullptr) {
    std::shared_lock<std::shared_mutex> lock(lineage->mutex);
    if (request.kind == PublishKind::RouteState &&
        lineage->state.current_route_generation != snapshot.route_generation) {
      return Result<Publication>::failure(
          Outcome::StaleRoute, "route generation advanced while the derivation was being built");
    }
  } else if (snapshot.lineage_generation.valid()) {
    return Result<Publication>::failure(Outcome::StaleLineageGeneration,
                                        "lineage disappeared while the derivation was being built");
  }
  if (marks.path_authority_generation != snapshot.path_authority_generation) {
    return Result<Publication>::failure(
        Outcome::StalePathAuthority, "path authority advanced while the derivation was being built");
  }
  if (marks.policy_generation != snapshot.policy_generation) {
    return Result<Publication>::failure(Outcome::StalePolicy,
                                        "policy advanced while the derivation was being built");
  }
  if (marks.evidence_generation != snapshot.evidence_generation) {
    return Result<Publication>::failure(Outcome::StaleEvidence,
                                        "evidence advanced while the derivation was being built");
  }
  if (marks.plan_generation != snapshot.plan_generation) {
    return Result<Publication>::failure(Outcome::StalePlan,
                                        "convergence plan advanced while the derivation was being built");
  }
  if (lineage != nullptr) {
    std::shared_lock<std::shared_mutex> lock(lineage->mutex);
    if (lineage->state.lineage_generation != snapshot.lineage_generation) {
      return Result<Publication>::failure(
          Outcome::StaleLineageGeneration, "lineage state advanced while the derivation was being built");
    }
  }
  if (marks.epoch != snapshot.epoch) {
    return Result<Publication>::failure(Outcome::StaleEpoch,
                                        "coordinator epoch advanced while the derivation was being built");
  }
  if (marks.store_generation != snapshot.store_generation) {
    return Result<Publication>::failure(
        Outcome::StaleStoreGeneration, "store state advanced while the derivation was being built");
  }
  return impl_->commit(request);
}

PublicationSession::PublicationSession(ProvenanceStore* store,
                                       std::unique_ptr<PublicationSessionState> state,
                                       DependencySnapshot snapshot)
    : store_(store), state_(std::move(state)), snapshot_(snapshot) {}

PublicationSession::~PublicationSession() = default;
PublicationSession::PublicationSession(PublicationSession&& other) noexcept
    : store_(other.store_), state_(std::move(other.state_)), snapshot_(other.snapshot_),
      committed_(other.committed_) {
  other.store_ = nullptr;
  other.committed_ = true;
}

PublicationSession& PublicationSession::operator=(PublicationSession&& other) noexcept {
  if (this != &other) {
    store_ = other.store_;
    state_ = std::move(other.state_);
    snapshot_ = other.snapshot_;
    committed_ = other.committed_;
    other.store_ = nullptr;
    other.committed_ = true;
  }
  return *this;
}

const PublishRouteRequest& PublicationSession::request() const noexcept { return state_->request; }

Result<Publication> PublicationSession::commit() {
  if (store_ == nullptr || state_ == nullptr) {
    return Result<Publication>::failure(Outcome::MalformedRequest, "publication session is not usable");
  }
  if (committed_) {
    return Result<Publication>::failure(Outcome::MalformedRequest,
                                        "publication session has already been committed");
  }
  committed_ = true;
  return store_->commit_session(snapshot_, state_->normalized);
}

}  // namespace route_provenance