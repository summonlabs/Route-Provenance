// Route Provenance - the provenance runtime.
//
// ProvenanceStore owns route lineage identity, provenance nodes, typed derivations, evidence
// binding, currentness, bounded history and durable persistence. It never creates, installs,
// withdraws or mutates route state, never decides path legality and never executes
// convergence steps.
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "route_provenance/authority.hpp"
#include "route_provenance/bindings.hpp"
#include "route_provenance/digest.hpp"
#include "route_provenance/enums.hpp"
#include "route_provenance/evidence.hpp"
#include "route_provenance/explanation.hpp"
#include "route_provenance/graph.hpp"
#include "route_provenance/id.hpp"
#include "route_provenance/limits.hpp"
#include "route_provenance/lineage.hpp"
#include "route_provenance/node.hpp"
#include "route_provenance/result.hpp"
#include "route_provenance/snapshot.hpp"

namespace route_provenance {

/// Structured image of a persisted store (defined in persistence.hpp).
struct StoreImage;
/// Internal request form produced by request-level validation. Not part of the public API.
struct NormalizedPublication;
/// Internal state of a two-phase publication session. Not part of the public API.
struct PublicationSessionState;

/// One typed link to an existing provenance node.
struct EdgeSpec {
  EdgeType type = EdgeType::DerivedFrom;
  ProvenanceNodeId target;
  ReasonCode reason = ReasonCode::InitialRoute;
  SourceClass source = SourceClass::RouteFabric;
  EvidenceVector evidence;
};

/// Publication of an authoritative route generation, with its typed derivation edges.
struct PublishRouteRequest {
  LineageKey key;
  RouteGeneration route_generation;
  Digest route_state_digest;
  ReasonCode reason = ReasonCode::InitialRoute;
  SourceClass source = SourceClass::RouteFabric;
  std::optional<RootReason> root_reason;
  EvidenceVector evidence;
  AuthorityContext authority;
  Bindings bindings;
  std::vector<EdgeSpec> edges;

  /// Replaces the identity of the lineage when set (imported/recovered state only). The value
  /// must equal derive_lineage_id(key) for the request to be accepted.
  std::optional<RouteLineageId> explicit_lineage;
};

/// Declaration of an upstream authority for a route lineage. Declared records explain nothing
/// until a route-state derivation links them, at which point they are promoted to CURRENT.
struct DeclarationRequest {
  LineageKey key;
  NodeKind kind = NodeKind::PathAuthorization;
  RouteId route;
  RouteGeneration route_generation;
  ReasonCode reason = ReasonCode::Declaration;
  SourceClass source = SourceClass::PathAuthority;
  EvidenceVector evidence;
  AuthorityContext authority;
  Bindings bindings;
};

/// Administrative action against an existing record (withdrawal, revocation, retirement,
/// revalidation, invalidation).
struct AdministrativeRequest {
  LineageKey key;
  ProvenanceNodeId target;
  ReasonCode reason = ReasonCode::AdminWithdrawal;
  SourceClass source = SourceClass::Administrative;
  EvidenceVector evidence;
  AuthorityContext authority;
  Bindings bindings;
  Digest completion_evidence;
  /// Required for revalidation: the record being revalidated must be the lineage's current
  /// route generation unless this is explicitly true.
  bool allow_non_current_target = false;
};

/// Typed link between two existing records of one lineage. Used to bind a route state to a
/// declared upstream authority (AUTHORIZED_BY, SELECTED_FROM, COMPUTED_FROM, ADAPTED_FROM,
/// TRANSITIONED_BY). Linking promotes a declared record to current authority.
struct LinkDerivationRequest {
  LineageKey key;
  EdgeType type = EdgeType::AuthorizedBy;
  ProvenanceNodeId from;
  ProvenanceNodeId to;
  ReasonCode reason = ReasonCode::Declaration;
  SourceClass source = SourceClass::PathAuthority;
  EvidenceVector evidence;
  AuthorityContext authority;
};

/// Explicit correction of an accepted record. The corrected record stays visible; the
/// replacement becomes the authoritative explanation.
struct CorrectionRequest {
  LineageKey key;
  ProvenanceNodeId target;
  ReasonCode reason = ReasonCode::Correction;
  SourceClass source = SourceClass::Administrative;
  Digest route_state_digest;
  EvidenceVector evidence;
  AuthorityContext authority;
  Bindings bindings;
};

struct Publication {
  RouteLineageId lineage;
  ProvenanceNodeId node;
  std::vector<ProvenanceEdgeId> edges;
  LineageGeneration lineage_generation;
  ProvenanceGeneration store_generation;
  NodeLifecycle lifecycle = NodeLifecycle::Declared;
  Currentness currentness = Currentness::HistoricalOnly;
};

/// Frozen dependency state captured when a two-phase publication begins.
struct DependencySnapshot {
  ProvenanceGeneration store_generation;
  LineageGeneration lineage_generation;
  RouteGeneration route_generation;
  PathAuthorityGeneration path_authority_generation;
  PolicyGeneration policy_generation;
  EvidenceGeneration evidence_generation;
  ConvergencePlanGeneration plan_generation;
  CoordinatorEpoch epoch;
  WorkerBootId publisher_boot;
  Digest digest;
};

/// Two-phase publication: capture dependencies, build and validate the record, reacquire,
/// verify that the bindings are still current, then commit. No broad lock is held across the
/// build phase, so an external dependency advance cannot be blocked by a slow derivation.
class PublicationSession {
 public:
  PublicationSession() = delete;
  ~PublicationSession();
  PublicationSession(const PublicationSession&) = delete;
  PublicationSession& operator=(const PublicationSession&) = delete;
  PublicationSession(PublicationSession&& other) noexcept;
  PublicationSession& operator=(PublicationSession&& other) noexcept;

  [[nodiscard]] const DependencySnapshot& snapshot() const noexcept { return snapshot_; }
  [[nodiscard]] const PublishRouteRequest& request() const noexcept;
  [[nodiscard]] bool committed() const noexcept { return committed_; }

  /// Reacquires the lineage and commits if every captured dependency is still current.
  [[nodiscard]] Result<Publication> commit();

 private:
  friend class ProvenanceStore;
  PublicationSession(ProvenanceStore* store, std::unique_ptr<PublicationSessionState> state,
                     DependencySnapshot snapshot);

  ProvenanceStore* store_ = nullptr;
  std::unique_ptr<PublicationSessionState> state_;
  DependencySnapshot snapshot_;
  bool committed_ = false;
};

/// Upstream dependency notification. Notifications are mutations: they carry authority, and a
/// stale epoch or stale worker cannot advance a watermark.
struct DependencyNotification {
  DependencyKind kind = DependencyKind::PathAuthorityAdvance;
  PathAuthorityGeneration path_authority_generation;
  PolicyGeneration policy_generation;
  EvidenceGeneration evidence_generation;
  ConvergencePlanGeneration plan_generation;
  CoordinatorEpoch epoch;
  PublisherId publisher;
  WorkerBootId boot;
  AuthorityContext authority;
};

struct DependencyWatermarks {
  ProvenanceGeneration store_generation;
  PathAuthorityGeneration path_authority_generation;
  PolicyGeneration policy_generation;
  EvidenceGeneration evidence_generation;
  ConvergencePlanGeneration plan_generation;
  CoordinatorEpoch epoch;
  Digest digest;
};

struct StoreStats {
  std::uint64_t lineage_count = 0;
  std::uint64_t node_count = 0;
  std::uint64_t edge_count = 0;
  std::uint64_t current_node_count = 0;
  std::uint64_t historical_node_count = 0;
  std::uint64_t invalid_node_count = 0;
  std::uint64_t compacted_node_count = 0;
  std::uint64_t publisher_count = 0;
  std::uint64_t live_publisher_count = 0;
  std::uint64_t route_index_entries = 0;
  std::uint64_t path_index_entries = 0;
  std::uint64_t policy_index_entries = 0;
  std::uint64_t publisher_index_entries = 0;
  ProvenanceGeneration store_generation;
  CoordinatorEpoch epoch;
};

/// Bounded-history compaction request.
struct CompactOptions {
  /// Ancestors of the current route node within this depth are never pruned.
  std::uint32_t retain_explanation_depth = 8;
  /// Maximum number of records to compact in one call.
  std::uint32_t max_compactions = 0;  ///< 0 means "use Limits::max_batch_size".
};

struct CompactResult {
  std::uint64_t compacted = 0;
  std::vector<ProvenanceNodeId> tombstones;
  LineageGeneration lineage_generation;
  ProvenanceGeneration store_generation;
};

class ProvenanceStore {
 public:
  explicit ProvenanceStore(Limits limits = Limits::defaults());
  ~ProvenanceStore();
  ProvenanceStore(const ProvenanceStore&) = delete;
  ProvenanceStore& operator=(const ProvenanceStore&) = delete;

  [[nodiscard]] const Limits& limits() const noexcept;

  // ---- publisher authority -------------------------------------------------
  [[nodiscard]] Result<PublisherRecord> register_publisher(PublisherIdentity identity,
                                                           AuthorityScope scope);
  [[nodiscard]] Result<PublisherRecord> reincarnate_publisher(PublisherId publisher,
                                                              WorkerBootId fresh_boot,
                                                              CoordinatorEpoch epoch,
                                                              AuthorityScope scope);
  /// Fences a publisher boot. Requires live coordinator authority with fabric scope.
  [[nodiscard]] Status fence_publisher(PublisherId publisher, WorkerBootId boot,
                                       const AuthorityContext& authority);
  [[nodiscard]] Result<std::vector<PublisherRecord>> list_publishers() const;
  [[nodiscard]] bool is_publisher_live(PublisherId publisher, WorkerBootId boot) const;

  // ---- dependency watermarks ----------------------------------------------
  [[nodiscard]] Status notify_dependency(const DependencyNotification& notification);
  [[nodiscard]] Result<DependencyWatermarks> watermarks() const;
  /// Advances the coordinator epoch and demotes currentness that depended on the old epoch.
  [[nodiscard]] Status advance_epoch(CoordinatorEpoch epoch, const AuthorityContext& authority);

  // ---- publication ---------------------------------------------------------
  [[nodiscard]] Result<Publication> publish_route(const PublishRouteRequest& request);
  [[nodiscard]] Result<Publication> declare(const DeclarationRequest& request);
  [[nodiscard]] Result<Publication> withdraw(const AdministrativeRequest& request);
  [[nodiscard]] Result<Publication> revoke(const AdministrativeRequest& request);
  [[nodiscard]] Result<Publication> retire(const AdministrativeRequest& request);
  [[nodiscard]] Result<Publication> revalidate(const AdministrativeRequest& request);
  [[nodiscard]] Result<Publication> invalidate(const AdministrativeRequest& request);
  [[nodiscard]] Result<Publication> correct(const CorrectionRequest& request);
  [[nodiscard]] Result<Publication> link_derivation(const LinkDerivationRequest& request);
  [[nodiscard]] Result<PublicationSession> begin_publication(const PublishRouteRequest& request);

  // ---- queries -------------------------------------------------------------
  [[nodiscard]] Result<LineageView> lineage(RouteLineageId id) const;
  [[nodiscard]] Result<LineageView> lineage_for_route(RouteId route) const;
  [[nodiscard]] Result<std::vector<LineageView>> list_lineages() const;
  [[nodiscard]] Result<ProvenanceNode> node(ProvenanceNodeId id) const;
  [[nodiscard]] Result<ProvenanceNode> route_node(RouteId route, RouteGeneration generation) const;
  [[nodiscard]] Result<std::vector<ProvenanceEdge>> parents(ProvenanceNodeId id) const;
  [[nodiscard]] Result<std::vector<ProvenanceEdge>> children(ProvenanceNodeId id) const;
  [[nodiscard]] Result<TraversalResult> ancestors(ProvenanceNodeId id, TraversalBounds bounds) const;
  [[nodiscard]] Result<TraversalResult> descendants(ProvenanceNodeId id, TraversalBounds bounds) const;
  [[nodiscard]] Result<TraversalResult> predecessor_chain(ProvenanceNodeId id,
                                                          TraversalBounds bounds) const;
  [[nodiscard]] Result<TraversalResult> successor_chain(ProvenanceNodeId id,
                                                        TraversalBounds bounds) const;
  [[nodiscard]] Result<std::vector<ProvenanceNode>> causes(ProvenanceNodeId id,
                                                           TraversalBounds bounds) const;
  [[nodiscard]] Result<Explanation> explain(const ExplainRequest& request) const;
  [[nodiscard]] Result<std::vector<ProvenanceNode>> routes_derived_from_path(
      PathId path, TraversalBounds bounds) const;
  [[nodiscard]] Result<std::vector<ProvenanceNode>> routes_derived_from_policy(
      PolicyGeneration generation, TraversalBounds bounds) const;
  [[nodiscard]] Result<std::vector<ProvenanceNode>> publications_by_publisher_boot(
      WorkerBootId boot, TraversalBounds bounds) const;
  [[nodiscard]] Result<std::vector<ProvenanceNode>> routes_for_path_authority(
      PathAuthorityGeneration generation, TraversalBounds bounds) const;
  [[nodiscard]] Result<Snapshot> snapshot(RouteLineageId id, SnapshotOptions options = {}) const;
  [[nodiscard]] Result<Diff> diff(const Snapshot& before, const Snapshot& after) const;
  [[nodiscard]] Result<StoreStats> stats() const;

  // ---- maintenance ---------------------------------------------------------
  /// Bounded-history compaction. Records that the current explanation still needs are never
  /// pruned; every pruned record leaves a tombstone that preserves its identity, route
  /// generation and semantic digest, so predecessor and successor chains stay intact.
  [[nodiscard]] Result<CompactResult> compact(RouteLineageId id, const AuthorityContext& authority,
                                              CompactOptions options = {});

  // ---- persistence ---------------------------------------------------------
  /// Captures a globally consistent image of the store. Every lineage is read under its own
  /// lock, so no mutation can interleave with the capture.
  [[nodiscard]] Result<StoreImage> export_image() const;
  [[nodiscard]] Status save(const std::string& path) const;
  /// Replaces the store contents with a persisted image and applies conservative recovery:
  /// historical provenance survives, live publisher authority does not, and every record whose
  /// currentness depended on live process state requires revalidation.
  [[nodiscard]] Status load(const std::string& path);
  [[nodiscard]] bool recovered() const noexcept;

 private:
  friend class PublicationSession;

  [[nodiscard]] Result<Publication> commit_session(const DependencySnapshot& snapshot,
                                                   const NormalizedPublication& request);

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace route_provenance
