// Route Provenance - closed enumerations with stable numeric values.
//
// Every enumeration used on the wire or in the persistence format carries explicit stable
// numeric values. Unknown or out-of-range values are rejected on decode rather than being
// coerced to a default.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace route_provenance {

/// What a provenance node represents in the causal graph.
enum class NodeKind : std::uint16_t {
  RouteGeneration = 1,      ///< An authoritative Route Fabric route generation.
  PathAuthorization = 2,    ///< A Path Authority authorization outcome.
  PlannerCandidate = 3,     ///< A Path Planner candidate/selection record.
  AdaptiveDecision = 4,     ///< An Adaptive Routing Fabric decision.
  ConvergencePlan = 5,      ///< A Route Convergence plan/step record.
  PolicyDecision = 6,       ///< A policy-driven decision binding.
  AdministrativeAction = 7, ///< Withdrawal, revocation, retirement, revalidation, correction.
  CompactedSummary = 8,     ///< Tombstone left by bounded-history compaction.
};

/// Typed derivation edge. The direction is fixed per type and documented in the README.
enum class EdgeType : std::uint16_t {
  DerivedFrom = 1,      ///< from is derived from to.
  Supersedes = 2,       ///< from supersedes to.
  Replaces = 3,         ///< from replaces to.
  Withdraws = 4,        ///< from (action) withdraws to (route state).
  Revalidates = 5,      ///< from (action) revalidates to.
  AuthorizedBy = 6,     ///< from is authorized by to.
  ComputedFrom = 7,     ///< from was computed from to.
  SelectedFrom = 8,     ///< from was selected from to.
  AdaptedFrom = 9,      ///< from was adapted from to.
  TransitionedBy = 10,  ///< from transitioned by to.
  RolledBackFrom = 11,  ///< from rolled back from to.
  RevokedBy = 12,       ///< from was revoked by to (action).
  RetiredBy = 13,       ///< from was retired by to (action).
  Corrects = 14,        ///< from corrects to.
  Invalidates = 15,     ///< from (action) invalidates to.
};

/// Explicit provenance source class. Never inferred from free text.
enum class SourceClass : std::uint16_t {
  Administrative = 1,
  RouteFabric = 2,
  PathAuthority = 3,
  PathPlanner = 4,
  AdaptiveRouting = 5,
  RouteConvergence = 6,
  Imported = 7,
  Recovery = 8,
};

/// Structured derivation reason. Free text is never the authoritative reason.
enum class ReasonCode : std::uint16_t {
  InitialRoute = 1,
  PathRevalidated = 2,
  RouteReplaced = 3,
  AdminWithdrawal = 4,
  PolicyChange = 5,
  AdaptiveChange = 6,
  EcmpChange = 7,
  WeightChange = 8,
  PathInvalidation = 9,
  ConvergenceComplete = 10,
  Rollback = 11,
  RecoveryRevalidation = 12,
  Revocation = 13,
  Retirement = 14,
  Correction = 15,
  Invalidation = 16,
  Declaration = 17,
  HistoryCompaction = 18,
  Import = 19,
};

/// Why a lineage root exists. A root without an explicit reason is rejected.
enum class RootReason : std::uint16_t {
  InitialPublication = 1,
  ImportedAdministrativeState = 2,
  RecoveredDurableState = 3,
  OperatorCreate = 4,
};

/// Lifecycle of an individual provenance record.
enum class NodeLifecycle : std::uint16_t {
  Declared = 1,
  Current = 2,
  Historical = 3,
  RevalidationRequired = 4,
  Superseded = 5,
  Revoked = 6,
  Retired = 7,
  Invalid = 8,
};

/// Whether a record is still live evidence for present authority. Distinct from historical
/// validity: a record can be historically valid and not current.
enum class Currentness : std::uint16_t {
  Current = 1,
  StaleRoute = 2,
  StalePathAuthority = 3,
  StalePolicy = 4,
  StaleEvidence = 5,
  StaleEpoch = 6,
  FencedPublisher = 7,
  HistoricalOnly = 8,
  RevalidationRequired = 9,
};

/// Lifecycle of a whole route lineage.
enum class LineageLifecycle : std::uint16_t {
  Active = 1,
  Withdrawn = 2,
  Revoked = 3,
  Retired = 4,
};

/// Structured operation outcome. Route Provenance never reports success or failure as bool.
enum class Outcome : std::uint16_t {
  Created = 1,
  Linked = 2,
  Updated = 3,
  Idempotent = 4,
  StaleRoute = 5,
  StalePathAuthority = 6,
  StalePolicy = 7,
  StalePlan = 8,
  StaleEpoch = 9,
  StaleWorker = 10,
  Duplicate = 11,
  Conflict = 12,
  CycleDetected = 13,
  MissingParent = 14,
  InvalidDerivation = 15,
  InvalidSourceGeneration = 16,
  Unauthorized = 17,
  RevalidationRequired = 18,
  Revoked = 19,
  Retired = 20,
  ResourceLimit = 21,
  MalformedRequest = 22,
  LineageNotFound = 23,
  NodeNotFound = 24,
  StoreCorrupt = 25,
  WireIntegrityFailure = 26,
  UnsupportedVersion = 27,
  IoFailure = 28,
  ProtocolFailure = 29,
  SessionRejected = 30,
  Ok = 31,
  StaleLineageGeneration = 32,
  StaleStoreGeneration = 33,
  StaleEvidence = 34,
};

/// Explanation traversal modes. Callers never have to walk the graph by hand.
enum class ExplainMode : std::uint16_t {
  ImmediateCause = 1,
  FullAncestry = 2,
  AuthorityOnly = 3,
  PolicyOnly = 4,
  PathOnly = 5,
  MutationLineage = 6,
};

/// Stable wire message identifiers.
enum class MessageId : std::uint16_t {
  Hello = 1,
  HelloAck = 2,
  RegisterPublisher = 3,
  PublishProvenance = 4,
  LinkDerivation = 5,
  Supersede = 6,
  Withdraw = 7,
  Revoke = 8,
  Retire = 9,
  Correct = 10,
  QueryLineage = 11,
  QueryCause = 12,
  QueryAncestry = 13,
  SnapshotRequest = 14,
  SnapshotResponse = 15,
  FenceNotice = 16,
  Result = 17,
  Error = 18,
  NotifyDependency = 19,
  Revalidate = 20,
  Invalidate = 21,
  DeclareSource = 22,
  Ping = 23,
  Pong = 24,
  Bye = 25,
  QueryWatermarks = 26,
};

/// Upstream dependency advance notifications.
enum class DependencyKind : std::uint16_t {
  RouteAdvance = 1,
  PathAuthorityAdvance = 2,
  PolicyAdvance = 3,
  EvidenceAdvance = 4,
  PlanAdvance = 5,
  EpochAdvance = 6,
  WorkerFence = 7,
};

[[nodiscard]] std::string_view to_string(NodeKind value) noexcept;
[[nodiscard]] std::string_view to_string(EdgeType value) noexcept;
[[nodiscard]] std::string_view to_string(SourceClass value) noexcept;
[[nodiscard]] std::string_view to_string(ReasonCode value) noexcept;
[[nodiscard]] std::string_view to_string(RootReason value) noexcept;
[[nodiscard]] std::string_view to_string(NodeLifecycle value) noexcept;
[[nodiscard]] std::string_view to_string(Currentness value) noexcept;
[[nodiscard]] std::string_view to_string(LineageLifecycle value) noexcept;
[[nodiscard]] std::string_view to_string(Outcome value) noexcept;
[[nodiscard]] std::string_view to_string(ExplainMode value) noexcept;
[[nodiscard]] std::string_view to_string(MessageId value) noexcept;
[[nodiscard]] std::string_view to_string(DependencyKind value) noexcept;

[[nodiscard]] std::optional<NodeKind> parse_node_kind(std::string_view text) noexcept;
[[nodiscard]] std::optional<EdgeType> parse_edge_type(std::string_view text) noexcept;
[[nodiscard]] std::optional<SourceClass> parse_source_class(std::string_view text) noexcept;
[[nodiscard]] std::optional<ReasonCode> parse_reason_code(std::string_view text) noexcept;
[[nodiscard]] std::optional<RootReason> parse_root_reason(std::string_view text) noexcept;
[[nodiscard]] std::optional<NodeLifecycle> parse_node_lifecycle(std::string_view text) noexcept;
[[nodiscard]] std::optional<Currentness> parse_currentness(std::string_view text) noexcept;
[[nodiscard]] std::optional<LineageLifecycle> parse_lineage_lifecycle(std::string_view text) noexcept;
[[nodiscard]] std::optional<Outcome> parse_outcome(std::string_view text) noexcept;
[[nodiscard]] std::optional<ExplainMode> parse_explain_mode(std::string_view text) noexcept;
[[nodiscard]] std::optional<MessageId> parse_message_id(std::uint16_t raw) noexcept;
[[nodiscard]] std::optional<DependencyKind> parse_dependency_kind(std::uint16_t raw) noexcept;

/// True for outcomes that represent committed or already-committed semantic state.
[[nodiscard]] bool outcome_is_commit(Outcome outcome) noexcept;
/// True for outcomes that mean "the request was valid but the world moved".
[[nodiscard]] bool outcome_is_stale(Outcome outcome) noexcept;
/// True for outcomes that are neither commits nor staleness (rejections and errors).
[[nodiscard]] bool outcome_is_rejection(Outcome outcome) noexcept;

}  // namespace route_provenance
