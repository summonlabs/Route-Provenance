// Route Provenance - store suite: publication semantics, currentness, lineage and limits.
#include <algorithm>
#include <string>
#include <vector>

#include "harness.hpp"
#include "route_provenance/wire.hpp"
#include "support.hpp"

using namespace rp_test;
using namespace route_provenance;

namespace {

[[nodiscard]] Bindings path_bindings(std::uint64_t path, std::uint64_t generation) {
  Bindings bindings;
  PathBinding binding;
  binding.path = PathId::from_value(path);
  binding.generation = PathAuthorityGeneration::from_value(generation);
  binding.decision_digest = Digest::hash("path-decision:" + std::to_string(path) + ":" +
                                         std::to_string(generation));
  bindings.path = binding;
  return bindings;
}

[[nodiscard]] Bindings policy_bindings(std::uint64_t generation) {
  Bindings bindings;
  PolicyBinding binding;
  binding.generation = PolicyGeneration::from_value(generation);
  bindings.policy = binding;
  return bindings;
}

[[nodiscard]] Bindings adaptation_bindings(std::uint64_t decision, std::uint64_t generation,
                                           std::uint64_t policy, std::uint64_t evidence) {
  Bindings bindings;
  AdaptationBinding binding;
  binding.decision = AdaptationDecisionId::from_value(decision);
  binding.generation = AdaptationGeneration::from_value(generation);
  binding.policy = PolicyGeneration::from_value(policy);
  binding.evidence = EvidenceGeneration::from_value(evidence);
  binding.decision_digest = Digest::hash("adaptation:" + std::to_string(decision));
  bindings.adaptation = binding;
  return bindings;
}

[[nodiscard]] Bindings convergence_bindings(std::uint64_t plan, std::uint64_t generation,
                                            std::uint64_t step) {
  Bindings bindings;
  ConvergenceBinding binding;
  binding.plan = ConvergencePlanId::from_value(plan);
  binding.generation = ConvergencePlanGeneration::from_value(generation);
  binding.step = ConvergenceStepId::from_value(step);
  binding.completion_evidence = Digest::hash("convergence:" + std::to_string(plan));
  bindings.convergence = binding;
  return bindings;
}

[[nodiscard]] DependencyNotification notification(DependencyKind kind, const AuthorityContext& authority) {
  DependencyNotification notice;
  notice.kind = kind;
  notice.authority = authority;
  notice.authority.scope = AuthorityScope::fabric();
  return notice;
}

}  // namespace

RP_TEST(store, root_requires_an_explicit_reason_and_a_successor_requires_a_predecessor) {
  Fixture fixture;
  const auto without_root = fixture.publish(11, "route/one", 1, ReasonCode::InitialRoute);
  RP_EXPECT_EQ(without_root.outcome(), Outcome::InvalidDerivation);

  const auto root = fixture.publish_root(11, "route/one");
  RP_REQUIRE_HAS_VALUE(root);
  RP_EXPECT_EQ(root.outcome(), Outcome::Created);
  RP_EXPECT_EQ(root.value().currentness, Currentness::Current);
  RP_EXPECT_EQ(root.value().lifecycle, NodeLifecycle::Current);

  // A successor without a causal predecessor is rejected rather than inferred.
  const auto orphan = fixture.publish(11, "route/one", 2, ReasonCode::RouteReplaced);
  RP_EXPECT_EQ(orphan.outcome(), Outcome::InvalidDerivation);

  // A root declared in a lineage that already has route state is rejected.
  const auto second_root =
      fixture.publish(11, "route/one", 2, ReasonCode::InitialRoute, RootReason::InitialPublication);
  RP_EXPECT_EQ(second_root.outcome(), Outcome::InvalidDerivation);

  // A root that also carries a successor relation is rejected.
  EdgeSpec edge;
  edge.type = EdgeType::Supersedes;
  edge.target = root.value().node;
  const auto contradictory =
      fixture.publish(11, "route/one", 2, ReasonCode::InitialRoute, RootReason::InitialPublication,
                      std::vector<EdgeSpec>{edge});
  RP_EXPECT_EQ(contradictory.outcome(), Outcome::InvalidDerivation);
}

RP_TEST(store, missing_parent_and_cross_lineage_edges_are_rejected) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(21, "route/two"));
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(22, "route/other"));

  EdgeSpec missing;
  missing.type = EdgeType::Supersedes;
  missing.target = ProvenanceNodeId::from_value(123456);
  const auto absent = fixture.publish(21, "route/two", 2, ReasonCode::RouteReplaced, std::nullopt,
                                      std::vector<EdgeSpec>{missing});
  RP_EXPECT_EQ(absent.outcome(), Outcome::MissingParent);

  const auto other_lineage = fixture.current_node(22, "route/other");
  RP_REQUIRE_HAS_VALUE(other_lineage);
  EdgeSpec foreign;
  foreign.type = EdgeType::Supersedes;
  foreign.target = other_lineage.value().id;
  const auto crossed = fixture.publish(21, "route/two", 2, ReasonCode::RouteReplaced, std::nullopt,
                                       std::vector<EdgeSpec>{foreign});
  RP_EXPECT_EQ(crossed.outcome(), Outcome::InvalidDerivation);
}

RP_TEST(store, supersession_records_typed_lineage_and_chains) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(31, "route/three"));
  RP_REQUIRE_HAS_VALUE(fixture.publish_successor(31, "route/three", 2, ReasonCode::RouteReplaced));
  RP_REQUIRE_HAS_VALUE(fixture.publish_successor(31, "route/three", 3, ReasonCode::RouteReplaced));

  const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(31));
  RP_REQUIRE_HAS_VALUE(lineage);
  RP_EXPECT_EQ(lineage.value().current_route_generation.value(), 3ULL);
  RP_EXPECT_EQ(lineage.value().node_count, 3ULL);
  RP_EXPECT_EQ(lineage.value().edge_count, 2ULL);

  const auto current = fixture.store.node(lineage.value().current_node);
  RP_REQUIRE_HAS_VALUE(current);
  RP_EXPECT_EQ(current.value().lifecycle, NodeLifecycle::Current);

  // The predecessor chain walks to the root through successor relations only.
  const auto chain = fixture.store.predecessor_chain(current.value().id, TraversalBounds{});
  RP_REQUIRE_HAS_VALUE(chain);
  RP_EXPECT_EQ(chain.value().nodes.size(), 3U);
  RP_EXPECT_EQ(chain.value().nodes.front().node.route_generation.value(), 3ULL);
  RP_EXPECT_EQ(chain.value().nodes.back().node.route_generation.value(), 1ULL);
  RP_EXPECT_EQ(chain.value().nodes.back().node.lifecycle, NodeLifecycle::Superseded);
  RP_EXPECT_EQ(chain.value().nodes.back().node.currentness, Currentness::HistoricalOnly);

  // The superseded record is historically valid but no longer current evidence.
  RP_EXPECT_TRUE(node_is_historically_valid(chain.value().nodes.back().node));
  RP_EXPECT_FALSE(chain.value().nodes.back().node.currentness == Currentness::Current);

  // Exactly one provenance node is current in the lineage.
  const auto stats = fixture.store.stats();
  RP_REQUIRE_HAS_VALUE(stats);
  RP_EXPECT_EQ(stats.value().current_node_count, 1ULL);
}

RP_TEST(store, exact_replay_is_idempotent_and_conflicting_replay_is_rejected) {
  Fixture fixture;
  route_provenance::PublishRouteRequest request =
      fixture.route_request(41, "route/four", 1, ReasonCode::InitialRoute);
  request.root_reason = RootReason::InitialPublication;
  const auto first = fixture.store.publish_route(request);
  RP_REQUIRE_HAS_VALUE(first);
  RP_EXPECT_EQ(first.outcome(), Outcome::Created);

  const auto before = fixture.store.stats();
  RP_REQUIRE_HAS_VALUE(before);

  const auto replay = fixture.store.publish_route(request);
  RP_EXPECT_EQ(replay.outcome(), Outcome::Idempotent);
  RP_EXPECT_TRUE(replay.has_value());
  RP_EXPECT_EQ(replay.value().node, first.value().node);

  const auto after = fixture.store.stats();
  RP_REQUIRE_HAS_VALUE(after);
  RP_EXPECT_EQ(after.value().node_count, before.value().node_count);
  RP_EXPECT_EQ(after.value().store_generation, before.value().store_generation);

  route_provenance::PublishRouteRequest conflicting = request;
  conflicting.route_state_digest = Digest::hash("different-state");
  const auto conflict = fixture.store.publish_route(conflicting);
  RP_EXPECT_EQ(conflict.outcome(), Outcome::Conflict);

  // A different attempt identifier with identical content is a duplicate, not a second record:
  // provenance identity is content addressed, so a later arrival cannot duplicate graph state.
  route_provenance::PublishRouteRequest duplicate = request;
  duplicate.authority.attempt = fixture.next_attempt();
  const auto duplicated = fixture.store.publish_route(duplicate);
  RP_EXPECT_EQ(duplicated.outcome(), Outcome::Duplicate);
  RP_EXPECT_TRUE(duplicated.has_value());
  RP_EXPECT_EQ(duplicated.value().node, first.value().node);
  const auto final_stats = fixture.store.stats();
  RP_REQUIRE_HAS_VALUE(final_stats);
  RP_EXPECT_EQ(final_stats.value().node_count, before.value().node_count);
}

RP_TEST(store, stale_route_generation_cannot_become_current_provenance) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(51, "route/five"));
  RP_REQUIRE_HAS_VALUE(fixture.publish_successor(51, "route/five", 2, ReasonCode::RouteReplaced));
  const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(51));
  RP_REQUIRE_HAS_VALUE(lineage);
  const auto stale = fixture.publish(51, "route/five", 1, ReasonCode::RouteReplaced,
                                           std::nullopt,
                                           std::vector<EdgeSpec>{});
  RP_EXPECT_EQ(stale.outcome(), Outcome::StaleRoute);
}

RP_TEST(store, expected_generation_conflicts_are_reported) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(61, "route/six"));
  route_provenance::PublishRouteRequest request =
      fixture.route_request(61, "route/six", 2, ReasonCode::RouteReplaced);
  const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(61));
  RP_REQUIRE_HAS_VALUE(lineage);
  EdgeSpec edge;
  edge.type = EdgeType::Supersedes;
  edge.target = lineage.value().current_node;
  request.edges.push_back(edge);
  request.authority.expected_lineage_generation = LineageGeneration::from_value(999);
  const auto mismatch = fixture.store.publish_route(request);
  RP_EXPECT_EQ(mismatch.outcome(), Outcome::StaleLineageGeneration);

  request.authority.expected_lineage_generation = lineage.value().lineage_generation;
  request.authority.expected_provenance_generation = ProvenanceGeneration::from_value(9999);
  const auto store_mismatch = fixture.store.publish_route(request);
  RP_EXPECT_EQ(store_mismatch.outcome(), Outcome::StaleStoreGeneration);
}

RP_TEST(store, historical_validity_survives_path_authority_supersession) {
  Fixture fixture;
  const auto notice = notification(DependencyKind::PathAuthorityAdvance, fixture.context());
  DependencyNotification path_notice = notice;
  path_notice.path_authority_generation = PathAuthorityGeneration::from_value(12);
  RP_EXPECT_TRUE(fixture.store.notify_dependency(path_notice).outcome() != Outcome::MalformedRequest);

  RP_REQUIRE_HAS_VALUE(fixture.publish(71, "route/seven", 1, ReasonCode::InitialRoute,
                                       RootReason::InitialPublication, std::vector<EdgeSpec>{},
                                       path_bindings(5, 12)));
  const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(71));
  RP_REQUIRE_HAS_VALUE(lineage);
  const auto node = fixture.store.node(lineage.value().current_node);
  RP_REQUIRE_HAS_VALUE(node);
  RP_EXPECT_EQ(node.value().currentness, Currentness::Current);

  DependencyNotification supersede = notice;
  supersede.path_authority_generation = PathAuthorityGeneration::from_value(13);
  RP_EXPECT_TRUE(!outcome_is_rejection(fixture.store.notify_dependency(supersede).outcome()));

  const auto demoted = fixture.store.node(lineage.value().current_node);
  RP_REQUIRE_HAS_VALUE(demoted);
  RP_EXPECT_EQ(demoted.value().currentness, Currentness::StalePathAuthority);
  RP_EXPECT_EQ(demoted.value().lifecycle, NodeLifecycle::Current);
  RP_EXPECT_TRUE(node_is_historically_valid(demoted.value()));

  const ExplainRequest request{demoted.value().id, ExplainMode::PathOnly, 0, 0};
  const auto explanation = fixture.store.explain(request);
  RP_REQUIRE_HAS_VALUE(explanation);
  RP_EXPECT_FALSE(explanation.value().current);
  RP_EXPECT_TRUE(explanation.value().historically_valid);
  RP_EXPECT_EQ(explanation.value().subject_currentness, Currentness::StalePathAuthority);

  // A binding ahead of the announced authority is rejected outright.
  EdgeSpec successor;
  successor.type = EdgeType::Supersedes;
  successor.target = lineage.value().current_node;
  const auto future = fixture.publish(71, "route/seven", 2, ReasonCode::RouteReplaced, std::nullopt,
                                      std::vector<EdgeSpec>{successor}, path_bindings(5, 99));
  RP_EXPECT_EQ(future.outcome(), Outcome::InvalidSourceGeneration);
}

RP_TEST(store, policy_and_evidence_advances_demote_dependent_records) {
  Fixture fixture;
  DependencyNotification policy = notification(DependencyKind::PolicyAdvance, fixture.context());
  policy.policy_generation = PolicyGeneration::from_value(3);
  RP_EXPECT_TRUE(!outcome_is_rejection(fixture.store.notify_dependency(policy).outcome()));
  DependencyNotification evidence = notification(DependencyKind::EvidenceAdvance, fixture.context());
  evidence.evidence_generation = EvidenceGeneration::from_value(4);
  RP_EXPECT_TRUE(!outcome_is_rejection(fixture.store.notify_dependency(evidence).outcome()));

  RP_REQUIRE_HAS_VALUE(fixture.publish(81, "route/eight", 1, ReasonCode::AdaptiveChange,
                                       RootReason::InitialPublication, std::vector<EdgeSpec>{},
                                       adaptation_bindings(9, 2, 3, 4)));
  const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(81));
  RP_REQUIRE_HAS_VALUE(lineage);
  const auto fresh = fixture.store.node(lineage.value().current_node);
  RP_REQUIRE_HAS_VALUE(fresh);
  RP_EXPECT_EQ(fresh.value().currentness, Currentness::Current);

  // The evidence advance is the earliest staleness the record is exposed to, so it is reported
  // first; the policy advance takes precedence once the bound policy generation is superseded.
  DependencyNotification evidence_advance = evidence;
  evidence_advance.evidence_generation = EvidenceGeneration::from_value(5);
  RP_EXPECT_TRUE(!outcome_is_rejection(fixture.store.notify_dependency(evidence_advance).outcome()));
  const auto evidence_stale = fixture.store.node(lineage.value().current_node);
  RP_REQUIRE_HAS_VALUE(evidence_stale);
  RP_EXPECT_EQ(evidence_stale.value().currentness, Currentness::StaleEvidence);

  DependencyNotification policy_advance = policy;
  policy_advance.policy_generation = PolicyGeneration::from_value(4);
  RP_EXPECT_TRUE(!outcome_is_rejection(fixture.store.notify_dependency(policy_advance).outcome()));
  const auto policy_stale = fixture.store.node(lineage.value().current_node);
  RP_REQUIRE_HAS_VALUE(policy_stale);
  RP_EXPECT_EQ(policy_stale.value().currentness, Currentness::StalePolicy);

  // Watermarks never move backwards and identical advances are idempotent.
  DependencyNotification backwards = policy;
  backwards.policy_generation = PolicyGeneration::from_value(1);
  RP_EXPECT_EQ(fixture.store.notify_dependency(backwards).outcome(), Outcome::InvalidSourceGeneration);
  DependencyNotification repeat = policy_advance;
  RP_EXPECT_EQ(fixture.store.notify_dependency(repeat).outcome(), Outcome::Idempotent);
}

RP_TEST(store, withdrawal_preserves_history_and_is_not_deletion) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(91, "route/nine"));
  RP_REQUIRE_HAS_VALUE(fixture.publish_successor(91, "route/nine", 2, ReasonCode::RouteReplaced));
  const auto before = fixture.current_node(91, "route/nine");
  RP_REQUIRE_HAS_VALUE(before);

  const auto withdrawn = fixture.store.withdraw(
      fixture.administrative(91, "route/nine", before.value().id, ReasonCode::AdminWithdrawal));
  RP_REQUIRE_HAS_VALUE(withdrawn);

  const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(91));
  RP_REQUIRE_HAS_VALUE(lineage);
  RP_EXPECT_EQ(lineage.value().lifecycle, LineageLifecycle::Withdrawn);
  RP_EXPECT_EQ(lineage.value().node_count, 3ULL);
  const auto record = fixture.store.node(before.value().id);
  RP_REQUIRE_HAS_VALUE(record);
  RP_EXPECT_EQ(record.value().lifecycle, NodeLifecycle::Historical);
  RP_EXPECT_EQ(record.value().currentness, Currentness::HistoricalOnly);
  RP_EXPECT_TRUE(node_is_historically_valid(record.value()));

  // The withdrawal action is a typed record with a WITHDRAWS edge.
  const auto action = fixture.store.node(withdrawn.value().node);
  RP_REQUIRE_HAS_VALUE(action);
  RP_EXPECT_EQ(action.value().kind, NodeKind::AdministrativeAction);
  RP_EXPECT_EQ(action.value().reason, ReasonCode::AdminWithdrawal);
  const auto parents = fixture.store.parents(action.value().id);
  RP_REQUIRE_HAS_VALUE(parents);
  RP_EXPECT_EQ(parents.value().size(), 1U);
  RP_EXPECT_EQ(parents.value().front().type, EdgeType::Withdraws);

  // A withdrawn lineage may be published into again with an explicit predecessor.
  const auto resumed = fixture.publish(91, "route/nine", 3, ReasonCode::RouteReplaced,
                                             std::nullopt, std::vector<EdgeSpec>{});
  RP_EXPECT_EQ(resumed.outcome(), Outcome::InvalidDerivation);
  const auto reauthorized = fixture.publish_successor(91, "route/nine", 3, ReasonCode::RouteReplaced);
  RP_REQUIRE_HAS_VALUE(reauthorized);
  const auto reactivated = fixture.store.lineage_for_route(RouteId::from_value(91));
  RP_REQUIRE_HAS_VALUE(reactivated);
  RP_EXPECT_EQ(reactivated.value().lifecycle, LineageLifecycle::Active);
}

RP_TEST(store, revocation_differs_from_invalidation_and_prevents_new_publication) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(101, "route/ten"));
  const auto node = fixture.current_node(101, "route/ten");
  RP_REQUIRE_HAS_VALUE(node);

  const auto invalidated = fixture.store.invalidate(
      fixture.administrative(101, "route/ten", node.value().id, ReasonCode::Invalidation));
  RP_REQUIRE_HAS_VALUE(invalidated);
  auto record = fixture.store.node(node.value().id);
  RP_REQUIRE_HAS_VALUE(record);
  RP_EXPECT_EQ(record.value().lifecycle, NodeLifecycle::Invalid);
  RP_EXPECT_FALSE(node_is_historically_valid(record.value()));
  auto lineage = fixture.store.lineage_for_route(RouteId::from_value(101));
  RP_REQUIRE_HAS_VALUE(lineage);
  RP_EXPECT_EQ(lineage.value().lifecycle, LineageLifecycle::Active);

  // Evidence-driven invalidation does not end the lineage: a corrected record restores authority.
  route_provenance::CorrectionRequest correction;
  correction.key = fixture.key(101, "route/ten");
  correction.target = node.value().id;
  correction.authority = fixture.context();
  correction.source = SourceClass::Administrative;
  const auto corrected = fixture.store.correct(correction);
  RP_REQUIRE_HAS_VALUE(corrected);
  lineage = fixture.store.lineage_for_route(RouteId::from_value(101));
  RP_REQUIRE_HAS_VALUE(lineage);
  RP_EXPECT_EQ(lineage.value().current_node, corrected.value().node);

  // Administrative revocation ends the lineage for new publications.
  const auto revoked = fixture.store.revoke(
      fixture.administrative(101, "route/ten", corrected.value().node, ReasonCode::Revocation));
  RP_REQUIRE_HAS_VALUE(revoked);
  lineage = fixture.store.lineage_for_route(RouteId::from_value(101));
  RP_REQUIRE_HAS_VALUE(lineage);
  RP_EXPECT_EQ(lineage.value().lifecycle, LineageLifecycle::Revoked);
  const auto blocked = fixture.publish(101, "route/ten", 2, ReasonCode::RouteReplaced,
                                       std::nullopt, std::vector<EdgeSpec>{});
  RP_EXPECT_EQ(blocked.outcome(), Outcome::Revoked);
}

RP_TEST(store, retirement_prevents_resurrection_by_late_events) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(111, "route/eleven"));
  RP_REQUIRE_HAS_VALUE(fixture.publish_successor(111, "route/eleven", 2, ReasonCode::RouteReplaced));
  const auto node = fixture.current_node(111, "route/eleven");
  RP_REQUIRE_HAS_VALUE(node);

  const auto retired = fixture.store.retire(
      fixture.administrative(111, "route/eleven", node.value().id, ReasonCode::Retirement));
  RP_REQUIRE_HAS_VALUE(retired);
  auto lineage = fixture.store.lineage_for_route(RouteId::from_value(111));
  RP_REQUIRE_HAS_VALUE(lineage);
  RP_EXPECT_EQ(lineage.value().lifecycle, LineageLifecycle::Retired);
  const LineageGeneration frozen = lineage.value().lineage_generation;

  // Late supersession, revalidation, correction and replay all fail with RETIRED, and the
  // lineage stays retired with every record demoted to historical-only.
  const auto late_supersession = fixture.publish(111, "route/eleven", 3, ReasonCode::RouteReplaced,
                                                 std::nullopt, std::vector<EdgeSpec>{});
  RP_EXPECT_EQ(late_supersession.outcome(), Outcome::Retired);
  const auto late_revalidation = fixture.store.revalidate(
      fixture.administrative(111, "route/eleven", node.value().id, ReasonCode::RecoveryRevalidation));
  RP_EXPECT_EQ(late_revalidation.outcome(), Outcome::Retired);
  route_provenance::CorrectionRequest correction;
  correction.key = fixture.key(111, "route/eleven");
  correction.target = node.value().id;
  correction.authority = fixture.context();
  RP_EXPECT_EQ(fixture.store.correct(correction).outcome(), Outcome::Retired);

  route_provenance::PublishRouteRequest replay =
      fixture.route_request(111, "route/eleven", 1, ReasonCode::InitialRoute);
  replay.authority.attempt = MutationAttemptId::from_value(1);
  RP_EXPECT_EQ(fixture.store.publish_route(replay).outcome(), Outcome::Retired);

  lineage = fixture.store.lineage_for_route(RouteId::from_value(111));
  RP_REQUIRE_HAS_VALUE(lineage);
  RP_EXPECT_EQ(lineage.value().lifecycle, LineageLifecycle::Retired);
  RP_EXPECT_EQ(lineage.value().lineage_generation, frozen);
  const auto records = fixture.store.snapshot(lineage.value().id);
  RP_REQUIRE_HAS_VALUE(records);
  for (const ProvenanceNode& record : records.value().nodes) {
    RP_EXPECT_NE(record.currentness, Currentness::Current);
    RP_EXPECT_TRUE(node_is_historically_valid(record));
  }
}

RP_TEST(store, rollback_preserves_the_failed_branch) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(121, "route/twelve"));
  RP_REQUIRE_HAS_VALUE(fixture.publish_successor(121, "route/twelve", 2, ReasonCode::RouteReplaced));
  const auto failed = fixture.current_node(121, "route/twelve");
  RP_REQUIRE_HAS_VALUE(failed);
  const LineageKey key = fixture.key(121, "route/twelve");
  const auto view = fixture.store.lineage(derive_lineage_id(key));
  RP_REQUIRE_HAS_VALUE(view);
  const auto root_node = fixture.store.node(view.value().current_node);
  RP_REQUIRE_HAS_VALUE(root_node);

  // Roll back to the first generation: the abandoned branch stays visible.
  EdgeSpec rollback;
  rollback.type = EdgeType::RolledBackFrom;
  rollback.target = failed.value().id;
  rollback.reason = ReasonCode::Rollback;
  route_provenance::PublishRouteRequest request =
      fixture.route_request(121, "route/twelve", 3, ReasonCode::Rollback);
  request.edges.push_back(rollback);
  request.bindings = convergence_bindings(4, 1, 2);
  const auto rolled_back = fixture.store.publish_route(request);
  RP_REQUIRE_HAS_VALUE(rolled_back);
  RP_EXPECT_EQ(rolled_back.value().currentness, Currentness::Current);

  const auto abandoned = fixture.store.node(failed.value().id);
  RP_REQUIRE_HAS_VALUE(abandoned);
  RP_EXPECT_EQ(abandoned.value().lifecycle, NodeLifecycle::Historical);
  RP_EXPECT_TRUE(node_is_historically_valid(abandoned.value()));

  const auto chain = fixture.store.predecessor_chain(rolled_back.value().node, TraversalBounds{});
  RP_REQUIRE_HAS_VALUE(chain);
  RP_EXPECT_EQ(chain.value().nodes.size(), 3U);
  RP_EXPECT_EQ(chain.value().nodes[1].node.id, failed.value().id);
}

RP_TEST(store, correction_is_explicit_and_history_is_not_rewritten) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(131, "route/thirteen"));
  const auto original = fixture.current_node(131, "route/thirteen");
  RP_REQUIRE_HAS_VALUE(original);
  const Digest original_digest = original.value().digest();

  route_provenance::CorrectionRequest correction;
  correction.key = fixture.key(131, "route/thirteen");
  correction.target = original.value().id;
  correction.authority = fixture.context();
  correction.source = SourceClass::Administrative;
  correction.evidence = EvidenceVector{};
  const auto corrected = fixture.store.correct(correction);
  RP_REQUIRE_HAS_VALUE(corrected);
  RP_EXPECT_NE(corrected.value().node, original.value().id);

  const auto original_after = fixture.store.node(original.value().id);
  RP_REQUIRE_HAS_VALUE(original_after);
  RP_EXPECT_EQ(original_after.value().lifecycle, NodeLifecycle::Invalid);
  RP_EXPECT_FALSE(node_is_historically_valid(original_after.value()));
  RP_REQUIRE_TRUE(original_after.value().corrected_by.has_value());
  RP_EXPECT_EQ(*original_after.value().corrected_by, corrected.value().node);
  // The original record's immutable content is untouched: corrections never rewrite history.
  RP_EXPECT_EQ(original_after.value().core_digest(), original.value().core_digest());

  const auto replacement = fixture.store.node(corrected.value().node);
  RP_REQUIRE_HAS_VALUE(replacement);
  RP_EXPECT_EQ(replacement.value().reason, ReasonCode::Correction);
  RP_REQUIRE_TRUE(replacement.value().corrects.has_value());
  RP_EXPECT_EQ(*replacement.value().corrects, original.value().id);
  RP_EXPECT_EQ(replacement.value().currentness, Currentness::Current);

  const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(131));
  RP_REQUIRE_HAS_VALUE(lineage);
  RP_EXPECT_EQ(lineage.value().current_node, corrected.value().node);
  RP_EXPECT_NE(original_digest, replacement.value().digest());
}

RP_TEST(store, branching_lineage_stays_acyclic) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(141, "route/fourteen"));
  const auto root = fixture.current_node(141, "route/fourteen");
  RP_REQUIRE_HAS_VALUE(root);

  // Two successors of the same predecessor: a superseded candidate branch and a rollback branch.
  EdgeSpec supersede;
  supersede.type = EdgeType::Supersedes;
  supersede.target = root.value().id;
  route_provenance::PublishRouteRequest candidate =
      fixture.route_request(141, "route/fourteen", 2, ReasonCode::RouteReplaced);
  candidate.edges.push_back(supersede);
  const auto branch = fixture.store.publish_route(candidate);
  RP_REQUIRE_HAS_VALUE(branch);

  EdgeSpec rollback;
  rollback.type = EdgeType::RolledBackFrom;
  rollback.target = root.value().id;
  route_provenance::PublishRouteRequest rollback_request =
      fixture.route_request(141, "route/fourteen", 3, ReasonCode::Rollback);
  rollback_request.edges.push_back(rollback);
  rollback_request.bindings = convergence_bindings(9, 1, 5);
  const auto rolled_back = fixture.store.publish_route(rollback_request);
  RP_REQUIRE_HAS_VALUE(rolled_back);

  const auto descendants = fixture.store.descendants(root.value().id, TraversalBounds{});
  RP_REQUIRE_HAS_VALUE(descendants);
  RP_EXPECT_EQ(descendants.value().nodes.size(), 3U);
  const auto ancestors = fixture.store.ancestors(rolled_back.value().node, TraversalBounds{});
  RP_REQUIRE_HAS_VALUE(ancestors);
  RP_EXPECT_EQ(ancestors.value().nodes.size(), 2U);
  // Both branches remain visible: one superseded, one current.
  const auto candidate_record = fixture.store.node(branch.value().node);
  RP_REQUIRE_HAS_VALUE(candidate_record);
  RP_EXPECT_EQ(candidate_record.value().lifecycle, NodeLifecycle::Historical);
}

RP_TEST(store, declared_authorities_are_promoted_when_linked) {
  Fixture fixture;
  route_provenance::DeclarationRequest declaration =
      fixture.declaration(151, "route/fifteen", NodeKind::PathAuthorization);
  declaration.bindings = path_bindings(7, 1);
  const auto declared = fixture.store.declare(declaration);
  RP_REQUIRE_HAS_VALUE(declared);
  auto record = fixture.store.node(declared.value().node);
  RP_REQUIRE_HAS_VALUE(record);
  RP_EXPECT_EQ(record.value().lifecycle, NodeLifecycle::Declared);
  RP_EXPECT_FALSE(node_is_historically_valid(record.value()));

  // A declaration without the binding that identifies its authority is rejected.
  route_provenance::DeclarationRequest malformed =
      fixture.declaration(151, "route/fifteen", NodeKind::PathAuthorization);
  RP_EXPECT_EQ(fixture.store.declare(malformed).outcome(), Outcome::MalformedRequest);

  // A route record authorized by that declaration promotes it to current authority.
  route_provenance::PublishRouteRequest request =
      fixture.route_request(151, "route/fifteen", 1, ReasonCode::PathRevalidated);
  request.root_reason = RootReason::InitialPublication;
  request.bindings = path_bindings(7, 1);
  EdgeSpec authorization;
  authorization.type = EdgeType::AuthorizedBy;
  authorization.target = declared.value().node;
  authorization.reason = ReasonCode::PathRevalidated;
  request.edges.push_back(authorization);
  const auto published = fixture.store.publish_route(request);
  RP_REQUIRE_HAS_VALUE(published);
  record = fixture.store.node(declared.value().node);
  RP_REQUIRE_HAS_VALUE(record);
  RP_EXPECT_EQ(record.value().lifecycle, NodeLifecycle::Current);

  // Reverse indexes answer exact questions without scanning.
  const auto by_path = fixture.store.routes_derived_from_path(PathId::from_value(7), TraversalBounds{});
  RP_REQUIRE_HAS_VALUE(by_path);
  RP_EXPECT_EQ(by_path.value().size(), 2U);
  const auto by_authority =
      fixture.store.routes_for_path_authority(PathAuthorityGeneration::from_value(1), TraversalBounds{});
  RP_REQUIRE_HAS_VALUE(by_authority);
  RP_EXPECT_EQ(by_authority.value().size(), 2U);
  const auto by_boot = fixture.store.publications_by_publisher_boot(fixture.boot, TraversalBounds{});
  RP_REQUIRE_HAS_VALUE(by_boot);
  RP_EXPECT_EQ(by_boot.value().size(), 2U);
}

RP_TEST(store, publisher_fencing_demotes_only_that_boot) {
  Fixture fixture;
  const auto other = fixture.store.register_publisher(
      PublisherIdentity{PublisherId::from_value(2), WorkerBootId::from_value(2), fixture.epoch},
      AuthorityScope::fabric());
  RP_REQUIRE_HAS_VALUE(other);

  route_provenance::PublishRouteRequest first =
      fixture.route_request(161, "route/sixteen", 1, ReasonCode::InitialRoute);
  first.root_reason = RootReason::InitialPublication;
  RP_REQUIRE_HAS_VALUE(fixture.store.publish_route(first));

  route_provenance::PublishRouteRequest second =
      fixture.route_request(162, "route/seventeen", 1, ReasonCode::InitialRoute);
  second.root_reason = RootReason::InitialPublication;
  second.authority = fixture.other_context(PublisherId::from_value(2), WorkerBootId::from_value(2),
                                           fixture.epoch);
  RP_REQUIRE_HAS_VALUE(fixture.store.publish_route(second));

  const auto fenced = fixture.store.fence_publisher(fixture.publisher, fixture.boot,
                                                    fixture.context());
  RP_EXPECT_TRUE(!outcome_is_rejection(fenced.outcome()));

  const auto first_lineage = fixture.store.lineage_for_route(RouteId::from_value(161));
  RP_REQUIRE_HAS_VALUE(first_lineage);
  const auto demoted = fixture.store.node(first_lineage.value().current_node);
  RP_REQUIRE_HAS_VALUE(demoted);
  RP_EXPECT_EQ(demoted.value().currentness, Currentness::FencedPublisher);
  RP_EXPECT_TRUE(node_is_historically_valid(demoted.value()));

  const auto second_lineage = fixture.store.lineage_for_route(RouteId::from_value(162));
  RP_REQUIRE_HAS_VALUE(second_lineage);
  const auto untouched = fixture.store.node(second_lineage.value().current_node);
  RP_REQUIRE_HAS_VALUE(untouched);
  RP_EXPECT_EQ(untouched.value().currentness, Currentness::Current);

  // A fenced boot may never publish current provenance again.
  route_provenance::PublishRouteRequest blocked =
      fixture.route_request(163, "route/eighteen", 1, ReasonCode::InitialRoute);
  blocked.root_reason = RootReason::InitialPublication;
  RP_EXPECT_EQ(fixture.store.publish_route(blocked).outcome(), Outcome::StaleWorker);
}

RP_TEST(store, stale_epoch_cannot_mutate) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(171, "route/nineteen"));
  const auto advanced = fixture.store.advance_epoch(CoordinatorEpoch::from_value(2), fixture.context());
  RP_EXPECT_TRUE(!outcome_is_rejection(advanced.outcome()));

  route_provenance::PublishRouteRequest stale =
      fixture.route_request(172, "route/twenty", 1, ReasonCode::InitialRoute);
  stale.root_reason = RootReason::InitialPublication;
  RP_EXPECT_EQ(fixture.store.publish_route(stale).outcome(), Outcome::StaleEpoch);

  const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(171));
  RP_REQUIRE_HAS_VALUE(lineage);
  const auto demoted = fixture.store.node(lineage.value().current_node);
  RP_REQUIRE_HAS_VALUE(demoted);
  RP_EXPECT_EQ(demoted.value().currentness, Currentness::StaleEpoch);
}

RP_TEST(store, deterministic_rejection_precedence_for_multi_defect_requests) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(181, "route/twentyone"));
  const auto current = fixture.current_node(181, "route/twentyone");
  RP_REQUIRE_HAS_VALUE(current);
  const LineageKey key = fixture.key(181, "route/twentyone");
  const RouteLineageId lineage_id = derive_lineage_id(key);
  const auto view = fixture.store.lineage(lineage_id);
  RP_REQUIRE_HAS_VALUE(view);

  RP_REQUIRE_HAS_VALUE(fixture.store.retire(
      fixture.administrative(181, "route/twentyone", current.value().id, ReasonCode::Retirement)));

  // Identity is missing, the epoch is stale, the scope is empty, the lineage is retired and the
  // generation is stale: identity is the first defect the pipeline reports.
  route_provenance::PublishRouteRequest request = fixture.route_request(181, "route/twentyone", 1,
                                                                      ReasonCode::RouteReplaced);
  request.authority = AuthorityContext{};
  RP_EXPECT_EQ(fixture.store.publish_route(request).outcome(), Outcome::Unauthorized);

  // With identity present, the epoch is checked next.
  request.authority = fixture.context();
  request.authority.publisher.epoch = CoordinatorEpoch::from_value(99);
  RP_EXPECT_EQ(fixture.store.publish_route(request).outcome(), Outcome::StaleEpoch);

  // With a current epoch, an empty scope is unauthorized before the retired lineage is reported.
  request.authority = fixture.context();
  request.authority.scope = AuthorityScope::none();
  RP_EXPECT_EQ(fixture.store.publish_route(request).outcome(), Outcome::Unauthorized);

  // With a valid scope the retired lineage is reported before the stale generation.
  request.authority = fixture.context();
  request.authority.scope = AuthorityScope::fabric();
  RP_EXPECT_EQ(fixture.store.publish_route(request).outcome(), Outcome::Retired);

  // Malformed input is rejected before any authority check.
  route_provenance::PublishRouteRequest malformed = fixture.route_request(181, "route/twentyone", 1,
                                                                       ReasonCode::RouteReplaced);
  malformed.key.semantic_key.clear();
  RP_EXPECT_EQ(fixture.store.publish_route(malformed).outcome(), Outcome::MalformedRequest);

  // A declaration with the wrong binding is malformed regardless of authority.
  route_provenance::DeclarationRequest declaration =
      fixture.declaration(181, "route/twentyone", NodeKind::ConvergencePlan);
  declaration.authority = AuthorityContext{};
  RP_EXPECT_EQ(fixture.store.declare(declaration).outcome(), Outcome::MalformedRequest);
}

RP_TEST(store, every_configured_limit_is_consulted) {
  // max_lineages
  {
    Limits limits = Limits::defaults();
    limits.max_lineages = 1;
    Fixture fixture(limits);
    RP_REQUIRE_HAS_VALUE(fixture.publish_root(1, "route/a"));
    const auto rejected = fixture.publish_root(2, "route/b");
    RP_EXPECT_EQ(rejected.outcome(), Outcome::ResourceLimit);
  }
  // max_nodes_per_lineage
  {
    Limits limits = Limits::defaults();
    limits.max_nodes_per_lineage = 2;
    limits.max_history_nodes_per_lineage = 2;
    Fixture fixture(limits);
    RP_REQUIRE_HAS_VALUE(fixture.publish_root(3, "route/c"));
    RP_REQUIRE_HAS_VALUE(fixture.publish_successor(3, "route/c", 2, ReasonCode::RouteReplaced));
    const auto rejected = fixture.publish_successor(3, "route/c", 3, ReasonCode::RouteReplaced);
    RP_EXPECT_TRUE(rejected.outcome() == Outcome::ResourceLimit);
  }
  // max_history_nodes_per_lineage
  {
    Limits limits = Limits::defaults();
    limits.max_history_nodes_per_lineage = 1;
    Fixture fixture(limits);
    RP_REQUIRE_HAS_VALUE(fixture.publish_root(4, "route/d"));
    RP_REQUIRE_HAS_VALUE(fixture.publish_successor(4, "route/d", 2, ReasonCode::RouteReplaced));
    const auto rejected = fixture.publish_successor(4, "route/d", 3, ReasonCode::RouteReplaced);
    RP_EXPECT_EQ(rejected.outcome(), Outcome::ResourceLimit);
  }
  // max_edges_per_lineage
  {
    Limits limits = Limits::defaults();
    limits.max_edges_per_lineage = 1;
    limits.max_parents_per_node = 1;
    limits.max_children_per_node = 1;
    Fixture fixture(limits);
    RP_REQUIRE_HAS_VALUE(fixture.publish_root(5, "route/e"));
    RP_REQUIRE_HAS_VALUE(fixture.publish_successor(5, "route/e", 2, ReasonCode::RouteReplaced));
    const auto rejected = fixture.publish_successor(5, "route/e", 3, ReasonCode::RouteReplaced);
    RP_EXPECT_EQ(rejected.outcome(), Outcome::ResourceLimit);
  }
  // max_parents_per_node
  {
    Limits limits = Limits::defaults();
    limits.max_parents_per_node = 1;
    Fixture fixture(limits);
    RP_REQUIRE_HAS_VALUE(fixture.publish_root(6, "route/f"));
    RP_REQUIRE_HAS_VALUE(fixture.publish_root(7, "route/g"));
    const auto first = fixture.current_node(6, "route/f");
    const auto second = fixture.current_node(7, "route/g");
    RP_REQUIRE_HAS_VALUE(first);
    RP_REQUIRE_HAS_VALUE(second);
    EdgeSpec edge;
    edge.type = EdgeType::Supersedes;
    edge.target = first.value().id;
    route_provenance::PublishRouteRequest request =
        fixture.route_request(6, "route/f", 2, ReasonCode::RouteReplaced);
    request.edges.push_back(edge);
    RP_REQUIRE_HAS_VALUE(fixture.store.publish_route(request));
    EdgeSpec second_edge;
    second_edge.type = EdgeType::Supersedes;
    route_provenance::PublishRouteRequest again =
        fixture.route_request(6, "route/f", 3, ReasonCode::RouteReplaced);
    again.edges.push_back(second_edge);
    again.edges.front().target = second.value().id;
    const auto rejected = fixture.store.publish_route(again);
    RP_EXPECT_TRUE(rejected.outcome() == Outcome::InvalidDerivation ||
                   rejected.outcome() == Outcome::MissingParent);
  }
  // max_batch_size
  {
    Limits limits = Limits::defaults();
    limits.max_batch_size = 1;
    Fixture fixture(limits);
    RP_REQUIRE_HAS_VALUE(fixture.publish_root(8, "route/h"));
    const auto node = fixture.current_node(8, "route/h");
    RP_REQUIRE_HAS_VALUE(node);
    EdgeSpec first_edge;
    first_edge.type = EdgeType::Supersedes;
    first_edge.target = node.value().id;
    EdgeSpec second_edge = first_edge;
    route_provenance::PublishRouteRequest request =
        fixture.route_request(8, "route/h", 2, ReasonCode::RouteReplaced);
    request.edges.push_back(first_edge);
    request.edges.push_back(second_edge);
    RP_EXPECT_EQ(fixture.store.publish_route(request).outcome(), Outcome::ResourceLimit);
  }
  // max_attempts_per_lineage
  {
    Limits limits = Limits::defaults();
    limits.max_attempts_per_lineage = 2;
    Fixture fixture(limits);
    RP_REQUIRE_HAS_VALUE(fixture.publish_root(9, "route/i"));
    RP_REQUIRE_HAS_VALUE(fixture.publish_successor(9, "route/i", 2, ReasonCode::RouteReplaced));
    const auto rejected = fixture.publish_successor(9, "route/i", 3, ReasonCode::RouteReplaced);
    RP_EXPECT_EQ(rejected.outcome(), Outcome::ResourceLimit);
  }
  // max_query_results
  {
    Limits limits = Limits::defaults();
    limits.max_query_results = 1;
    limits.max_visited_nodes = 8;
    limits.max_explanation_nodes = 1;
    Fixture fixture(limits);
    RP_REQUIRE_HAS_VALUE(fixture.publish_root(10, "route/j"));
    RP_REQUIRE_HAS_VALUE(fixture.publish_successor(10, "route/j", 2, ReasonCode::RouteReplaced));
    const auto ancestors = fixture.store.ancestors(
        fixture.store.lineage_for_route(RouteId::from_value(10)).value().current_node,
        TraversalBounds{});
    RP_EXPECT_EQ(ancestors.outcome(), Outcome::ResourceLimit);
  }
  // max_explanation_nodes
  {
    Limits limits = Limits::defaults();
    limits.max_explanation_nodes = 1;
    Fixture fixture(limits);
    RP_REQUIRE_HAS_VALUE(fixture.publish_root(11, "route/k"));
    RP_REQUIRE_HAS_VALUE(fixture.publish_successor(11, "route/k", 2, ReasonCode::RouteReplaced));
    RP_REQUIRE_HAS_VALUE(fixture.publish_successor(11, "route/k", 3, ReasonCode::RouteReplaced));
    const auto node = fixture.current_node(11, "route/k");
    RP_REQUIRE_HAS_VALUE(node);
    const ExplainRequest request{node.value().id, ExplainMode::FullAncestry, 0, 0};
    const auto explanation = fixture.store.explain(request);
    RP_REQUIRE_HAS_VALUE(explanation);
    RP_EXPECT_TRUE(explanation.value().truncated);
    RP_EXPECT_EQ(explanation.value().steps.size(), 1U);
  }
  // max_semantic_key_bytes
  {
    Limits limits = Limits::defaults();
    limits.max_semantic_key_bytes = 4;
    Fixture fixture(limits);
    const auto rejected = fixture.publish_root(12, "route/too-long");
    RP_EXPECT_EQ(rejected.outcome(), Outcome::ResourceLimit);
  }
  // max_evidence_entries is enforced when a vector is built.
  {
    Limits limits = Limits::defaults();
    limits.max_evidence_entries = 1;
    const auto rejected =
        EvidenceVector::create({{EvidenceField::FabricEpoch, 1}, {EvidenceField::PortGeneration, 1}},
                               limits);
    RP_EXPECT_EQ(rejected.outcome(), Outcome::ResourceLimit);
  }
  // max_publishers
  {
    Limits limits = Limits::defaults();
    limits.max_publishers = 1;
    ProvenanceStore limited(limits);
    RP_REQUIRE_TRUE(limited
                        .register_publisher(PublisherIdentity{PublisherId::from_value(1),
                                                              WorkerBootId::from_value(1),
                                                              CoordinatorEpoch::from_value(1)},
                                            AuthorityScope::fabric())
                        .has_value());
    const auto rejected = limited.register_publisher(
        PublisherIdentity{PublisherId::from_value(2), WorkerBootId::from_value(2),
                          CoordinatorEpoch::from_value(1)},
        AuthorityScope::fabric());
    RP_EXPECT_EQ(rejected.outcome(), Outcome::ResourceLimit);
  }
  // max_frame_bytes is consulted by the wire layer and by the store's payload bound.
  {
    Limits limits = Limits::defaults();
    limits.max_frame_bytes = 64;
    const auto rejected = EvidenceVector::create({}, limits);
    RP_EXPECT_TRUE(rejected.has_value());
    const ByteVector payload;
    ByteVector frame_bytes;
    const auto frame =
        encode_frame(FrameHeader{}, ByteSpan(payload.data(), payload.size()), limits, frame_bytes);
    RP_EXPECT_EQ(frame.outcome(), Outcome::ResourceLimit);
  }
}

RP_TEST(store, snapshot_and_diff_are_deterministic) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(191, "route/twentytwo"));
  const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(191));
  RP_REQUIRE_HAS_VALUE(lineage);
  const auto before = fixture.store.snapshot(lineage.value().id);
  RP_REQUIRE_HAS_VALUE(before);
  RP_REQUIRE_HAS_VALUE(fixture.publish_successor(191, "route/twentytwo", 2, ReasonCode::RouteReplaced));
  const auto after = fixture.store.snapshot(lineage.value().id);
  RP_REQUIRE_HAS_VALUE(after);
  RP_EXPECT_NE(before.value().digest, after.value().digest);

  const auto diff = fixture.store.diff(before.value(), after.value());
  RP_REQUIRE_HAS_VALUE(diff);
  RP_EXPECT_TRUE(diff.value().entries.size() >= 3U);
  const auto repeated = fixture.store.diff(before.value(), after.value());
  RP_REQUIRE_HAS_VALUE(repeated);
  RP_EXPECT_EQ(diff.value().digest, repeated.value().digest);
  for (std::size_t index = 1; index < diff.value().entries.size(); ++index) {
    const DiffEntry& previous = diff.value().entries[index - 1];
    const DiffEntry& current = diff.value().entries[index];
    RP_EXPECT_TRUE(static_cast<std::uint16_t>(previous.kind) <=
                   static_cast<std::uint16_t>(current.kind));
  }

  // A snapshot from another lineage cannot be diffed.
  const auto other_lineage = fixture.store.lineage_for_route(RouteId::from_value(192));
  RP_EXPECT_EQ(fixture.store.diff(before.value(), Snapshot{}).outcome(), Outcome::MalformedRequest);
  static_cast<void>(other_lineage);
}

RP_TEST(store, compaction_preserves_the_current_explanation) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(201, "route/twentythree"));
  for (std::uint64_t generation = 2; generation <= 6; ++generation) {
    RP_REQUIRE_HAS_VALUE(
        fixture.publish_successor(201, "route/twentythree", generation, ReasonCode::RouteReplaced));
  }
  const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(201));
  RP_REQUIRE_HAS_VALUE(lineage);
  const auto before = fixture.store.snapshot(lineage.value().id);
  RP_REQUIRE_HAS_VALUE(before);
  RP_EXPECT_EQ(before.value().nodes.size(), 6U);

  CompactOptions options;
  options.retain_explanation_depth = 2;
  const auto compacted = fixture.store.compact(lineage.value().id, fixture.context(), options);
  RP_REQUIRE_HAS_VALUE(compacted);
  RP_EXPECT_GT(compacted.value().compacted, 0ULL);

  const auto after = fixture.store.snapshot(lineage.value().id);
  RP_REQUIRE_HAS_VALUE(after);
  RP_EXPECT_EQ(after.value().nodes.size(), before.value().nodes.size());
  // Identity and all edges survive compaction; only record detail is summarised.
  RP_EXPECT_EQ(after.value().edges.size(), before.value().edges.size());
  for (const ProvenanceNodeId id : compacted.value().tombstones) {
    const auto record = fixture.store.node(id);
    RP_REQUIRE_HAS_VALUE(record);
    RP_EXPECT_EQ(record.value().kind, NodeKind::CompactedSummary);
    RP_REQUIRE_TRUE(record.value().compacted_digest.has_value());
    RP_EXPECT_TRUE(node_is_historically_valid(record.value()));
  }
  // The current explanation still reaches the protected ancestry.
  const auto chain = fixture.store.predecessor_chain(after.value().current_node, TraversalBounds{});
  RP_REQUIRE_HAS_VALUE(chain);
  RP_EXPECT_EQ(chain.value().nodes.size(), 6U);
  for (const TraversalEntry& entry : chain.value().nodes) {
    RP_EXPECT_TRUE(entry.node.kind == NodeKind::RouteGeneration ||
                   entry.node.kind == NodeKind::CompactedSummary);
  }
  // A route generation that was compacted is no longer a route-state record, so its detail is
  // represented by the summary and never by stale content.
  const auto compacted_record = fixture.store.node(compacted.value().tombstones.front());
  RP_REQUIRE_HAS_VALUE(compacted_record);
  RP_EXPECT_FALSE(compacted_record.value().kind == NodeKind::RouteGeneration);
}

RP_TEST(store, store_statistics_match_the_graph_state) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(211, "route/twentyfour"));
  RP_REQUIRE_HAS_VALUE(fixture.publish_successor(211, "route/twentyfour", 2, ReasonCode::RouteReplaced));
  const auto stats = fixture.store.stats();
  RP_REQUIRE_HAS_VALUE(stats);
  RP_EXPECT_EQ(stats.value().lineage_count, 1ULL);
  RP_EXPECT_EQ(stats.value().node_count, 2ULL);
  RP_EXPECT_EQ(stats.value().edge_count, 1ULL);
  RP_EXPECT_EQ(stats.value().current_node_count, 1ULL);
  RP_EXPECT_EQ(stats.value().historical_node_count, 1ULL);
  RP_EXPECT_EQ(stats.value().live_publisher_count, 1ULL);
  const auto lineages = fixture.store.list_lineages();
  RP_REQUIRE_HAS_VALUE(lineages);
  RP_EXPECT_EQ(lineages.value().size(), 1U);
  RP_EXPECT_EQ(lineages.value().front().node_count, 2ULL);
}
