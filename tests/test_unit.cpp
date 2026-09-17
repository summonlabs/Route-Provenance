// Route Provenance - unit suite: identities, canonical encoding, digests and model rules.
#include <string>
#include <vector>

#include "harness.hpp"
#include "route_provenance/graph.hpp"
#include "route_provenance/version.hpp"
#include "support.hpp"

using namespace rp_test;
using namespace route_provenance;

RP_TEST(unit, strong_identities_reject_invalid_values) {
  RP_EXPECT_FALSE(RouteId{}.valid());
  RP_EXPECT_FALSE(RouteGeneration{}.valid());
  RP_EXPECT_TRUE(RouteId::from_value(1).valid());
  RP_EXPECT_TRUE(RouteGeneration::from_value(1).valid());
  RP_EXPECT_FALSE(RouteGeneration::parse("0").has_value());
  RP_EXPECT_FALSE(RouteGeneration::parse("-1").has_value());
  RP_EXPECT_FALSE(RouteGeneration::parse(" 1").has_value());
  RP_EXPECT_FALSE(RouteGeneration::parse("1 ").has_value());
  RP_EXPECT_FALSE(RouteGeneration::parse("abc").has_value());
  RP_EXPECT_FALSE(RouteGeneration::parse("").has_value());
  RP_EXPECT_FALSE(RouteGeneration::parse("99999999999999999999999").has_value());
  const auto parsed = RouteGeneration::parse("42");
  RP_REQUIRE_TRUE(parsed.has_value());
  RP_EXPECT_EQ(parsed->value(), 42ULL);
  RP_EXPECT_STREQ(parsed->to_string(), "42");
}

RP_TEST(unit, generations_never_wrap) {
  const RouteGeneration maximum = RouteGeneration::from_value(0xFFFF'FFFF'FFFF'FFFFULL);
  RP_EXPECT_FALSE(maximum.try_next().has_value());
  const RouteGeneration first = RouteGeneration::from_value(1);
  RP_REQUIRE_TRUE(first.try_next().has_value());
  RP_EXPECT_EQ(first.try_next()->value(), 2ULL);
  // A counter that has never advanced advances to one, never to zero.
  RP_REQUIRE_TRUE(RouteGeneration{}.try_next().has_value());
  RP_EXPECT_EQ(RouteGeneration{}.try_next()->value(), 1ULL);
}

RP_TEST(unit, evidence_canonicalisation_is_order_independent) {
  std::vector<EvidenceEntry> first{{EvidenceField::PathAuthorityGeneration, 12},
                                   {EvidenceField::LinkStateGeneration, 5},
                                   {EvidenceField::FabricEpoch, 3}};
  std::vector<EvidenceEntry> second{{EvidenceField::FabricEpoch, 3},
                                    {EvidenceField::PathAuthorityGeneration, 12},
                                    {EvidenceField::LinkStateGeneration, 5}};
  const Result<EvidenceVector> a = EvidenceVector::create(first, Limits::defaults());
  const Result<EvidenceVector> b = EvidenceVector::create(second, Limits::defaults());
  RP_REQUIRE_HAS_VALUE(a);
  RP_REQUIRE_HAS_VALUE(b);
  RP_EXPECT_EQ(a.value().digest(), b.value().digest());
  RP_EXPECT_TRUE(a.value() == b.value());
  RP_EXPECT_EQ(a.value().size(), 3U);
  RP_EXPECT_EQ(a.value().entries().front().field, EvidenceField::LinkStateGeneration);
}

RP_TEST(unit, evidence_rejects_zero_and_conflicting_entries) {
  const Result<EvidenceVector> zero =
      EvidenceVector::create({{EvidenceField::PathAuthorityGeneration, 0}}, Limits::defaults());
  RP_EXPECT_EQ(zero.outcome(), Outcome::InvalidSourceGeneration);
  const Result<EvidenceVector> conflict =
      EvidenceVector::create({{EvidenceField::FabricEpoch, 2}, {EvidenceField::FabricEpoch, 3}},
                             Limits::defaults());
  RP_EXPECT_EQ(conflict.outcome(), Outcome::MalformedRequest);
  const Result<EvidenceVector> duplicate =
      EvidenceVector::create({{EvidenceField::FabricEpoch, 2}, {EvidenceField::FabricEpoch, 2}},
                             Limits::defaults());
  RP_REQUIRE_HAS_VALUE(duplicate);
  RP_EXPECT_EQ(duplicate.value().size(), 1U);
  Limits tiny = Limits::defaults();
  tiny.max_evidence_entries = 1;
  const Result<EvidenceVector> bounded = EvidenceVector::create(
      {{EvidenceField::FabricEpoch, 2}, {EvidenceField::PlannerGeneration, 3}}, tiny);
  RP_EXPECT_EQ(bounded.outcome(), Outcome::ResourceLimit);
}

RP_TEST(unit, digest_encoding_is_stable_and_hex_round_trips) {
  const Digest empty = Digest::hash("");
  RP_EXPECT_STREQ(empty.hex(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  const Digest abc = Digest::hash("abc");
  RP_EXPECT_STREQ(abc.hex(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  const auto parsed = Digest::from_hex(abc.hex());
  RP_REQUIRE_TRUE(parsed.has_value());
  RP_EXPECT_EQ(*parsed, abc);
  RP_EXPECT_FALSE(Digest::from_hex("00").has_value());
  RP_EXPECT_FALSE(Digest::from_hex(std::string(63, 'a')).has_value());
  RP_EXPECT_FALSE(Digest::from_hex(std::string(64, 'z')).has_value());
  RP_EXPECT_TRUE(Digest{}.is_zero());
  RP_EXPECT_FALSE(abc.is_zero());
}

RP_TEST(unit, canonical_encoder_separates_domains_and_fields) {
  CanonicalEncoder first;
  first.add_u64(1, 7);
  CanonicalEncoder second;
  second.add_u64(2, 7);
  RP_EXPECT_NE(first.digest("rp.test.v1"), second.digest("rp.test.v1"));
  RP_EXPECT_NE(first.digest("rp.test.v1"), first.digest("rp.test.v2"));
  CanonicalEncoder third;
  third.add_u64(1, 7);
  RP_EXPECT_EQ(first.digest("rp.test.v1"), third.digest("rp.test.v1"));
  RP_EXPECT_NE(derive_id(first.digest("rp.test.v1")), 0ULL);
}

RP_TEST(unit, lineage_identity_is_stable_for_a_semantic_route) {
  LineageKey key;
  key.route = RouteId::from_value(9);
  key.semantic_key = "fabric/route-a";
  const RouteLineageId first = derive_lineage_id(key);
  const RouteLineageId second = derive_lineage_id(key);
  RP_EXPECT_EQ(first, second);
  RP_EXPECT_TRUE(first.valid());
  LineageKey other = key;
  other.semantic_key = "fabric/route-b";
  RP_EXPECT_NE(derive_lineage_id(other), first);
  LineageKey other_route = key;
  other_route.route = RouteId::from_value(10);
  RP_EXPECT_NE(derive_lineage_id(other_route), first);
}

RP_TEST(unit, node_identity_is_content_addressed) {
  ProvenanceNode first;
  first.lineage = RouteLineageId::from_value(5);
  first.kind = NodeKind::RouteGeneration;
  first.route = RouteId::from_value(2);
  first.route_generation = RouteGeneration::from_value(3);
  first.route_state_digest = Digest::hash("state");
  first.authority.scope = AuthorityScope::fabric();
  first.authority.attempt = MutationAttemptId::from_value(1);
  first.authority.publisher = PublisherIdentity{PublisherId::from_value(1), WorkerBootId::from_value(1),
                                                CoordinatorEpoch::from_value(1)};
  first.lifecycle = NodeLifecycle::Current;
  ProvenanceNode second = first;
  finalize_node(first);
  finalize_node(second);
  RP_EXPECT_EQ(first.id, second.id);
  // Record state is not part of identity.
  second.lifecycle = NodeLifecycle::Historical;
  second.currentness = Currentness::HistoricalOnly;
  finalize_node(second);
  RP_EXPECT_EQ(first.id, second.id);
  RP_EXPECT_NE(first.digest(), second.digest());
  // Content changes change identity.
  ProvenanceNode third = first;
  third.route_generation = RouteGeneration::from_value(4);
  finalize_node(third);
  RP_EXPECT_NE(first.id, third.id);
}

RP_TEST(unit, derivation_and_edge_identity_are_distinct_and_stable) {
  ProvenanceEdge edge;
  edge.lineage = RouteLineageId::from_value(1);
  edge.type = EdgeType::Supersedes;
  edge.from = ProvenanceNodeId::from_value(10);
  edge.to = ProvenanceNodeId::from_value(11);
  edge.predecessor_route_generation = RouteGeneration::from_value(1);
  edge.successor_route_generation = RouteGeneration::from_value(2);
  edge.authority.scope = AuthorityScope::fabric();
  edge.authority.attempt = MutationAttemptId::from_value(1);
  edge.authority.publisher = PublisherIdentity{PublisherId::from_value(1), WorkerBootId::from_value(1),
                                              CoordinatorEpoch::from_value(1)};
  finalize_edge(edge);
  RP_EXPECT_TRUE(edge.derivation.valid());
  RP_EXPECT_TRUE(edge.id.valid());
  RP_EXPECT_NE(edge.derivation.value(), edge.id.value());
  ProvenanceEdge copy = edge;
  finalize_edge(copy);
  RP_EXPECT_EQ(copy.derivation, edge.derivation);
  RP_EXPECT_EQ(copy.id, edge.id);
}

RP_TEST(unit, successor_relations_require_increasing_generations) {
  ProvenanceEdge edge;
  edge.lineage = RouteLineageId::from_value(1);
  edge.type = EdgeType::Supersedes;
  edge.from = ProvenanceNodeId::from_value(10);
  edge.to = ProvenanceNodeId::from_value(11);
  edge.predecessor_route_generation = RouteGeneration::from_value(4);
  edge.successor_route_generation = RouteGeneration::from_value(4);
  RP_EXPECT_EQ(validate_edge_consistency(edge).outcome(), Outcome::InvalidDerivation);
  edge.successor_route_generation = RouteGeneration::from_value(5);
  RP_EXPECT_TRUE(validate_edge_consistency(edge).is_ok());
  edge.from = edge.to;
  RP_EXPECT_EQ(validate_edge_consistency(edge).outcome(), Outcome::CycleDetected);
}

RP_TEST(unit, lifecycle_transitions_reject_impossible_states) {
  RP_EXPECT_TRUE(is_valid_lifecycle_transition(NodeLifecycle::Current, NodeLifecycle::Historical));
  RP_EXPECT_TRUE(is_valid_lifecycle_transition(NodeLifecycle::Current, NodeLifecycle::Revoked));
  RP_EXPECT_TRUE(is_valid_lifecycle_transition(NodeLifecycle::RevalidationRequired, NodeLifecycle::Current));
  RP_EXPECT_FALSE(is_valid_lifecycle_transition(NodeLifecycle::Invalid, NodeLifecycle::Current));
  RP_EXPECT_FALSE(is_valid_lifecycle_transition(NodeLifecycle::Retired, NodeLifecycle::Current));
  RP_EXPECT_FALSE(is_valid_lifecycle_transition(NodeLifecycle::Revoked, NodeLifecycle::Current));
  RP_EXPECT_TRUE(is_valid_lifecycle_transition(NodeLifecycle::Historical, NodeLifecycle::Invalid));
}

RP_TEST(unit, authority_scope_defaults_to_deny) {
  const AuthorityScope empty;
  RP_EXPECT_TRUE(empty.is_empty());
  const ScopeTarget target{RoutingNamespaceId{}, RouteLineageId::from_value(4), RouteId::from_value(9)};
  RP_EXPECT_FALSE(empty.permits(target));
  RP_EXPECT_TRUE(AuthorityScope::fabric().permits(target));
  RP_EXPECT_TRUE(AuthorityScope::lineage(RouteLineageId::from_value(4)).permits(target));
  RP_EXPECT_FALSE(AuthorityScope::lineage(RouteLineageId::from_value(5)).permits(target));
  RP_EXPECT_TRUE(AuthorityScope::route(RouteId::from_value(9)).permits(target));
  RP_EXPECT_FALSE(AuthorityScope::route(RouteId::from_value(8)).permits(target));
  RP_EXPECT_TRUE(AuthorityScope::routing_namespace(RoutingNamespaceId::from_value(7))
                     .permits(ScopeTarget{RoutingNamespaceId::from_value(7), {}, {}}));
}

RP_TEST(unit, outcome_classification_partitions_the_enumeration) {
  const Outcome all[] = {
      Outcome::Created,        Outcome::Linked,          Outcome::Updated,
      Outcome::Idempotent,     Outcome::StaleRoute,      Outcome::StalePathAuthority,
      Outcome::StalePolicy,    Outcome::StalePlan,       Outcome::StaleEpoch,
      Outcome::StaleWorker,    Outcome::Duplicate,       Outcome::Conflict,
      Outcome::CycleDetected,  Outcome::MissingParent,   Outcome::InvalidDerivation,
      Outcome::InvalidSourceGeneration, Outcome::Unauthorized, Outcome::RevalidationRequired,
      Outcome::Revoked,        Outcome::Retired,         Outcome::ResourceLimit,
      Outcome::MalformedRequest, Outcome::LineageNotFound, Outcome::NodeNotFound,
      Outcome::StoreCorrupt,   Outcome::WireIntegrityFailure, Outcome::UnsupportedVersion,
      Outcome::IoFailure,      Outcome::ProtocolFailure, Outcome::SessionRejected,
      Outcome::Ok,             Outcome::StaleLineageGeneration, Outcome::StaleStoreGeneration,
      Outcome::StaleEvidence};
  for (const Outcome outcome : all) {
    const int classes = (outcome_is_commit(outcome) ? 1 : 0) + (outcome_is_stale(outcome) ? 1 : 0) +
                        (outcome_is_rejection(outcome) ? 1 : 0);
    RP_EXPECT_EQ(classes, outcome == Outcome::Ok ? 0 : 1);
    RP_EXPECT_FALSE(to_string(outcome) == "UNKNOWN");
    RP_REQUIRE_TRUE(parse_outcome(to_string(outcome)).has_value());
    RP_EXPECT_EQ(*parse_outcome(to_string(outcome)), outcome);
  }
}

RP_TEST(unit, every_enumeration_value_round_trips_through_its_name) {
  const NodeKind kinds[] = {NodeKind::RouteGeneration, NodeKind::PathAuthorization,
                            NodeKind::PlannerCandidate, NodeKind::AdaptiveDecision,
                            NodeKind::ConvergencePlan, NodeKind::PolicyDecision,
                            NodeKind::AdministrativeAction, NodeKind::CompactedSummary};
  for (const NodeKind kind : kinds) {
    RP_REQUIRE_TRUE(parse_node_kind(to_string(kind)).has_value());
    RP_EXPECT_EQ(*parse_node_kind(to_string(kind)), kind);
  }
  const EdgeType edges[] = {EdgeType::DerivedFrom, EdgeType::Supersedes, EdgeType::Replaces,
                            EdgeType::Withdraws, EdgeType::Revalidates, EdgeType::AuthorizedBy,
                            EdgeType::ComputedFrom, EdgeType::SelectedFrom, EdgeType::AdaptedFrom,
                            EdgeType::TransitionedBy, EdgeType::RolledBackFrom, EdgeType::RevokedBy,
                            EdgeType::RetiredBy, EdgeType::Corrects, EdgeType::Invalidates};
  for (const EdgeType type : edges) {
    RP_REQUIRE_TRUE(parse_edge_type(to_string(type)).has_value());
    RP_EXPECT_EQ(*parse_edge_type(to_string(type)), type);
    const bool classified = edge_type_is_successor_relation(type) ||
                            edge_type_is_evidence_relation(type) || edge_type_is_action_relation(type);
    RP_EXPECT_TRUE(classified);
  }
  RP_EXPECT_FALSE(parse_node_kind("NOT_A_KIND").has_value());
  RP_EXPECT_FALSE(parse_reason_code("NOT_A_REASON").has_value());
  RP_EXPECT_FALSE(parse_message_id(0xFFFFU).has_value());
  RP_EXPECT_FALSE(parse_dependency_kind(0xFFFFU).has_value());
  // The candidate list of reason codes is entirely live.
  const ReasonCode reasons[] = {
      ReasonCode::InitialRoute,     ReasonCode::PathRevalidated, ReasonCode::RouteReplaced,
      ReasonCode::AdminWithdrawal,  ReasonCode::PolicyChange,    ReasonCode::AdaptiveChange,
      ReasonCode::EcmpChange,       ReasonCode::WeightChange,    ReasonCode::PathInvalidation,
      ReasonCode::ConvergenceComplete, ReasonCode::Rollback,     ReasonCode::RecoveryRevalidation,
      ReasonCode::Revocation,       ReasonCode::Retirement,      ReasonCode::Correction,
      ReasonCode::Invalidation,     ReasonCode::Declaration,     ReasonCode::HistoryCompaction,
      ReasonCode::Import};
  for (const ReasonCode reason : reasons) {
    RP_EXPECT_FALSE(to_string(reason) == "UNKNOWN");
  }
}

RP_TEST(unit, limits_validation_rejects_inconsistent_configuration) {
  std::string error;
  RP_EXPECT_TRUE(Limits::defaults().validate(error));
  Limits zero = Limits::defaults();
  zero.max_lineages = 0;
  RP_EXPECT_FALSE(zero.validate(error));
  Limits inverted = Limits::defaults();
  inverted.max_history_nodes_per_lineage = inverted.max_nodes_per_lineage + 1;
  RP_EXPECT_FALSE(inverted.validate(error));
  Limits nodes = Limits::defaults();
  nodes.max_nodes_per_lineage = nodes.max_persistence_nodes + 1;
  RP_EXPECT_FALSE(nodes.validate(error));
  Limits queries = Limits::defaults();
  queries.max_query_results = queries.max_visited_nodes + 1;
  RP_EXPECT_FALSE(queries.validate(error));
}

RP_TEST(unit, bindings_require_the_generation_that_justifies_the_reason) {
  Bindings empty;
  RP_EXPECT_EQ(validate_bindings(ReasonCode::EcmpChange, empty).outcome(), Outcome::InvalidDerivation);
  RP_EXPECT_EQ(validate_bindings(ReasonCode::WeightChange, empty).outcome(), Outcome::InvalidDerivation);
  RP_EXPECT_EQ(validate_bindings(ReasonCode::AdaptiveChange, empty).outcome(), Outcome::InvalidDerivation);
  RP_EXPECT_EQ(validate_bindings(ReasonCode::PolicyChange, empty).outcome(), Outcome::InvalidDerivation);
  RP_EXPECT_EQ(validate_bindings(ReasonCode::PathRevalidated, empty).outcome(), Outcome::InvalidDerivation);
  RP_EXPECT_EQ(validate_bindings(ReasonCode::ConvergenceComplete, empty).outcome(),
               Outcome::InvalidDerivation);
  RP_EXPECT_EQ(validate_bindings(ReasonCode::Rollback, empty).outcome(), Outcome::InvalidDerivation);

  Bindings path;
  PathBinding path_binding;
  path_binding.path = PathId::from_value(3);
  path_binding.generation = PathAuthorityGeneration::from_value(7);
  path.path = path_binding;
  RP_EXPECT_TRUE(validate_bindings(ReasonCode::PathRevalidated, path).is_ok());
  RP_EXPECT_EQ(validate_bindings(ReasonCode::PathRevalidated, path).outcome(), Outcome::Ok);

  Bindings broken = path;
  broken.path->generation = PathAuthorityGeneration{};
  RP_EXPECT_EQ(validate_bindings(ReasonCode::PathRevalidated, broken).outcome(),
               Outcome::InvalidSourceGeneration);
}

RP_TEST(unit, graph_traversal_is_bounded_and_ordered) {
  ProvenanceGraph graph;
  Limits limits = Limits::defaults();
  std::vector<ProvenanceNodeId> ids;
  for (std::uint64_t index = 1; index <= 8; ++index) {
    ProvenanceNode node;
    node.lineage = RouteLineageId::from_value(1);
    node.kind = NodeKind::RouteGeneration;
    node.route = RouteId::from_value(1);
    node.route_generation = RouteGeneration::from_value(index);
    node.route_state_digest = Digest::hash("state" + std::to_string(index));
    node.lifecycle = NodeLifecycle::Current;
    node.authority.scope = AuthorityScope::fabric();
    node.authority.attempt = MutationAttemptId::from_value(index);
    node.authority.publisher = PublisherIdentity{PublisherId::from_value(1), WorkerBootId::from_value(1),
                                                CoordinatorEpoch::from_value(1)};
    finalize_node(node);
    RP_REQUIRE_TRUE(graph.add_node(node, limits).is_ok());
    ids.push_back(node.id);
  }
  for (std::size_t index = 1; index < ids.size(); ++index) {
    ProvenanceEdge edge;
    edge.lineage = RouteLineageId::from_value(1);
    edge.type = EdgeType::Supersedes;
    edge.from = ids[index];
    edge.to = ids[index - 1];
    edge.predecessor_route_generation = RouteGeneration::from_value(index);
    edge.successor_route_generation = RouteGeneration::from_value(index + 1);
    edge.authority.scope = AuthorityScope::fabric();
    edge.authority.attempt = MutationAttemptId::from_value(100 + index);
    edge.authority.publisher = PublisherIdentity{PublisherId::from_value(1), WorkerBootId::from_value(1),
                                                CoordinatorEpoch::from_value(1)};
    finalize_edge(edge);
    RP_REQUIRE_TRUE(graph.add_edge(edge, limits).is_ok());
  }
  RP_EXPECT_TRUE(graph.validate_structure().is_ok());
  RP_EXPECT_EQ(graph.node_count(), 8U);
  RP_EXPECT_EQ(graph.edge_count(), 7U);

  TraversalResult full;
  RP_REQUIRE_TRUE(
      graph.traverse(ids.back(), TraversalDirection::Outgoing, TraversalBounds{}, limits, full).is_ok());
  RP_EXPECT_EQ(full.nodes.size(), 8U);
  RP_EXPECT_EQ(full.max_depth_reached, 7U);
  for (std::size_t index = 1; index < full.nodes.size(); ++index) {
    RP_EXPECT_LE(full.nodes[index - 1].depth, full.nodes[index].depth);
    if (full.nodes[index - 1].depth == full.nodes[index].depth) {
      RP_EXPECT_LT(full.nodes[index - 1].node.id, full.nodes[index].node.id);
    }
  }

  TraversalBounds shallow;
  shallow.max_depth = 2;
  TraversalResult limited;
  RP_REQUIRE_TRUE(
      graph.traverse(ids.back(), TraversalDirection::Outgoing, shallow, limits, limited).is_ok());
  RP_EXPECT_EQ(limited.nodes.size(), 3U);

  TraversalBounds tiny;
  tiny.max_results = 2;
  TraversalResult truncated;
  RP_EXPECT_EQ(
      graph.traverse(ids.back(), TraversalDirection::Outgoing, tiny, limits, truncated).outcome(),
      Outcome::ResourceLimit);

  // A topological order places every record after the record it derives from. Because a
  // successor points at its predecessor, the newest record comes first.
  const auto order = graph.topological_order();
  RP_REQUIRE_TRUE(order.has_value());
  RP_EXPECT_EQ(order->size(), 8U);
  RP_EXPECT_EQ(order->front(), ids.back());
  RP_EXPECT_EQ(order->back(), ids.front());
}

RP_TEST(unit, graph_rejects_cycles_and_self_edges) {
  ProvenanceGraph graph;
  Limits limits = Limits::defaults();
  ProvenanceNode first;
  first.lineage = RouteLineageId::from_value(1);
  first.kind = NodeKind::RouteGeneration;
  first.route = RouteId::from_value(1);
  first.route_generation = RouteGeneration::from_value(1);
  first.route_state_digest = Digest::hash("a");
  first.lifecycle = NodeLifecycle::Current;
  first.authority.scope = AuthorityScope::fabric();
  first.authority.attempt = MutationAttemptId::from_value(1);
  first.authority.publisher = PublisherIdentity{PublisherId::from_value(1), WorkerBootId::from_value(1),
                                               CoordinatorEpoch::from_value(1)};
  finalize_node(first);
  ProvenanceNode second = first;
  second.route_generation = RouteGeneration::from_value(2);
  second.route_state_digest = Digest::hash("b");
  finalize_node(second);
  RP_REQUIRE_TRUE(graph.add_node(first, limits).is_ok());
  RP_REQUIRE_TRUE(graph.add_node(second, limits).is_ok());

  RP_EXPECT_EQ(graph.check_add_edge(second.id, second.id, limits).outcome(), Outcome::CycleDetected);
  // Absence of an endpoint is not a cycle check concern: the store validates membership and
  // ProvenanceGraph::add_edge requires both endpoints to exist.
  RP_EXPECT_TRUE(graph.check_add_edge(second.id, ProvenanceNodeId::from_value(999), limits).is_ok());
  RP_EXPECT_TRUE(graph.check_add_edge(second.id, first.id, limits).is_ok());
  ProvenanceEdge chain;
  chain.lineage = RouteLineageId::from_value(1);
  chain.type = EdgeType::Supersedes;
  chain.from = second.id;
  chain.to = first.id;
  chain.predecessor_route_generation = RouteGeneration::from_value(1);
  chain.successor_route_generation = RouteGeneration::from_value(2);
  chain.authority.scope = AuthorityScope::fabric();
  chain.authority.attempt = MutationAttemptId::from_value(5);
  chain.authority.publisher = PublisherIdentity{PublisherId::from_value(1), WorkerBootId::from_value(1),
                                               CoordinatorEpoch::from_value(1)};
  finalize_edge(chain);
  RP_REQUIRE_TRUE(graph.add_edge(chain, limits).is_ok());
  RP_EXPECT_EQ(graph.check_add_edge(first.id, second.id, limits).outcome(), Outcome::CycleDetected);
  ProvenanceEdge reverse = chain;
  reverse.from = first.id;
  reverse.to = second.id;
  reverse.predecessor_route_generation = RouteGeneration::from_value(2);
  reverse.successor_route_generation = RouteGeneration::from_value(3);
  finalize_edge(reverse);
  RP_EXPECT_EQ(graph.add_edge(reverse, limits).outcome(), Outcome::CycleDetected);
}

RP_TEST(unit, version_reporting_is_coherent) {
  RP_EXPECT_STREQ(version_string(), "1.0.0");
  RP_EXPECT_EQ(kVersionMajor, 1U);
  const std::string report = version_report();
  RP_EXPECT_TRUE(report.find("version: 1.0.0") != std::string::npos);
  RP_EXPECT_TRUE(report.find("wire_protocol_version: 1") != std::string::npos);
  RP_EXPECT_TRUE(report.find("persistence_format_version: 1") != std::string::npos);
  RP_EXPECT_TRUE(report.find("reason_code_semantics_version: 1") != std::string::npos);
  RP_EXPECT_TRUE(report.find("Copyright 2026 Summon Software Labs.") != std::string::npos);
}
