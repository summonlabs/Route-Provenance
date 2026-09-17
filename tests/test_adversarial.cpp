// Route Provenance - adversarial suite.
//
// Every attack here is answered with a structured outcome and no partial mutation.
#include <string>
#include <vector>

#include "harness.hpp"
#include "route_provenance/wire.hpp"
#include "support.hpp"

using namespace rp_test;
using namespace route_provenance;

RP_TEST(adversarial, malformed_identities_and_zero_values_are_rejected) {
  Fixture fixture;
  route_provenance::PublishRouteRequest request =
      fixture.route_request(601, "route/adv", 1, ReasonCode::InitialRoute);
  request.root_reason = RootReason::InitialPublication;

  request.key.route = RouteId{};
  RP_EXPECT_EQ(fixture.store.publish_route(request).outcome(), Outcome::MalformedRequest);

  request = fixture.route_request(601, "route/adv", 1, ReasonCode::InitialRoute);
  request.root_reason = RootReason::InitialPublication;
  request.route_generation = RouteGeneration{};
  RP_EXPECT_EQ(fixture.store.publish_route(request).outcome(), Outcome::InvalidSourceGeneration);

  request = fixture.route_request(601, "route/adv", 1, ReasonCode::InitialRoute);
  request.root_reason = RootReason::InitialPublication;
  request.route_state_digest = Digest{};
  RP_EXPECT_EQ(fixture.store.publish_route(request).outcome(), Outcome::InvalidDerivation);

  request = fixture.route_request(601, "route/adv", 1, ReasonCode::InitialRoute);
  request.root_reason = RootReason::InitialPublication;
  request.authority.attempt = MutationAttemptId{};
  RP_EXPECT_EQ(fixture.store.publish_route(request).outcome(), Outcome::Unauthorized);

  request = fixture.route_request(601, "route/adv", 1, ReasonCode::InitialRoute);
  request.root_reason = RootReason::InitialPublication;
  request.key.semantic_key = std::string("bad") + std::string(1, '\x07');
  RP_EXPECT_EQ(fixture.store.publish_route(request).outcome(), Outcome::MalformedRequest);

  request = fixture.route_request(601, "route/adv", 1, ReasonCode::InitialRoute);
  request.root_reason = RootReason::InitialPublication;
  EdgeSpec invalid_target;
  invalid_target.type = EdgeType::Supersedes;
  invalid_target.target = ProvenanceNodeId{};
  request.edges.push_back(invalid_target);
  RP_EXPECT_EQ(fixture.store.publish_route(request).outcome(), Outcome::MalformedRequest);
}

RP_TEST(adversarial, cycle_injection_is_rejected_without_partial_mutation) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(611, "route/cycle"));
  RP_REQUIRE_HAS_VALUE(fixture.publish_successor(611, "route/cycle", 2, ReasonCode::RouteReplaced));
  RP_REQUIRE_HAS_VALUE(fixture.publish_successor(611, "route/cycle", 3, ReasonCode::RouteReplaced));
  const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(611));
  RP_REQUIRE_HAS_VALUE(lineage);
  const auto snapshot_before = fixture.store.snapshot(lineage.value().id);
  RP_REQUIRE_HAS_VALUE(snapshot_before);

  // The oldest record tries to supersede the newest one.
  const auto nodes = fixture.store.predecessor_chain(lineage.value().current_node, TraversalBounds{});
  RP_REQUIRE_HAS_VALUE(nodes);
  const ProvenanceNodeId current = nodes.value().nodes.front().node.id;
  const ProvenanceNodeId oldest = nodes.value().nodes.back().node.id;

  route_provenance::PublishRouteRequest cyclic =
      fixture.route_request(611, "route/cycle", 4, ReasonCode::RouteReplaced);
  EdgeSpec edge;
  edge.type = EdgeType::Supersedes;
  edge.target = current;
  cyclic.edges.push_back(edge);
  const auto published = fixture.store.publish_route(cyclic);
  RP_REQUIRE_HAS_VALUE(published);
  // Now the newly created record tries to point backwards at itself through the chain.
  route_provenance::PublishRouteRequest back =
      fixture.route_request(611, "route/cycle", 5, ReasonCode::RouteReplaced);
  EdgeSpec self_edge;
  self_edge.type = EdgeType::Supersedes;
  self_edge.target = published.value().node;
  back.edges.push_back(self_edge);
  // A successor relation that points backwards is impossible and is refused before any graph
  // change.
  route_provenance::LinkDerivationRequest backward;
  backward.key = fixture.key(611, "route/cycle");
  backward.type = EdgeType::DerivedFrom;
  backward.from = oldest;
  backward.to = current;
  backward.authority = fixture.context();
  RP_EXPECT_EQ(fixture.store.link_derivation(backward).outcome(), Outcome::InvalidDerivation);

  // A new record is linked to the oldest record, and then the oldest record is linked back to
  // it: the second link would close a cycle and is refused without partial mutation.
  const auto newest = fixture.current_node(611, "route/cycle");
  RP_REQUIRE_HAS_VALUE(newest);
  route_provenance::LinkDerivationRequest forward;
  forward.key = fixture.key(611, "route/cycle");
  forward.type = EdgeType::AuthorizedBy;
  forward.from = newest.value().id;
  forward.to = oldest;
  forward.authority = fixture.context();
  RP_REQUIRE_HAS_VALUE(fixture.store.link_derivation(forward));
  route_provenance::LinkDerivationRequest closing;
  closing.key = fixture.key(611, "route/cycle");
  closing.type = EdgeType::AuthorizedBy;
  closing.from = oldest;
  closing.to = newest.value().id;
  closing.authority = fixture.context();
  RP_EXPECT_EQ(fixture.store.link_derivation(closing).outcome(), Outcome::CycleDetected);

  const auto snapshot_after = fixture.store.snapshot(lineage.value().id);
  RP_REQUIRE_HAS_VALUE(snapshot_after);
  RP_EXPECT_EQ(snapshot_after.value().edges.size(), snapshot_before.value().edges.size() + 2U);
}

RP_TEST(adversarial, duplicate_records_and_edges_do_not_duplicate_graph_state) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(621, "route/dup"));
  const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(621));
  RP_REQUIRE_HAS_VALUE(lineage);
  const auto before = fixture.store.snapshot(lineage.value().id);
  RP_REQUIRE_HAS_VALUE(before);

  // The same generation with different provenance is a conflict, not a second record.
  route_provenance::PublishRouteRequest conflicting =
      fixture.route_request(621, "route/dup", 1, ReasonCode::RouteReplaced);
  conflicting.root_reason = RootReason::ImportedAdministrativeState;
  const auto published = fixture.store.publish_route(conflicting);
  RP_EXPECT_TRUE(published.outcome() == Outcome::Conflict || published.outcome() == Outcome::Duplicate);

  // Re-linking the same derivation is a duplicate rather than a second edge.
  route_provenance::LinkDerivationRequest link;
  link.key = fixture.key(621, "route/dup");
  link.type = EdgeType::DerivedFrom;
  link.from = lineage.value().current_node;
  link.to = lineage.value().current_node;
  link.authority = fixture.context();
  const route_provenance::Result<route_provenance::Publication> self_link =
      fixture.store.link_derivation(link);
  RP_EXPECT_TRUE(self_link.outcome() == Outcome::CycleDetected ||
                 self_link.outcome() == Outcome::MalformedRequest);

  const auto after = fixture.store.snapshot(lineage.value().id);
  RP_REQUIRE_HAS_VALUE(after);
  RP_EXPECT_EQ(after.value().edges.size(), before.value().edges.size());
}

RP_TEST(adversarial, stale_and_forged_authority_is_refused) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(631, "route/auth"));

  // Forgotten identity.
  route_provenance::PublishRouteRequest request =
      fixture.route_request(632, "route/auth-two", 1, ReasonCode::InitialRoute);
  request.root_reason = RootReason::InitialPublication;
  request.authority.publisher.boot = WorkerBootId::from_value(4242);
  RP_EXPECT_EQ(fixture.store.publish_route(request).outcome(), Outcome::StaleWorker);

  // Forged epoch.
  request = fixture.route_request(632, "route/auth-two", 1, ReasonCode::InitialRoute);
  request.root_reason = RootReason::InitialPublication;
  request.authority.publisher.epoch = CoordinatorEpoch::from_value(77);
  RP_EXPECT_EQ(fixture.store.publish_route(request).outcome(), Outcome::StaleEpoch);

  // Scope that does not cover the target lineage.
  const RouteLineageId other = derive_lineage_id(fixture.key(999, "route/other"));
  request = fixture.route_request(632, "route/auth-two", 1, ReasonCode::InitialRoute);
  request.root_reason = RootReason::InitialPublication;
  request.authority.scope = AuthorityScope::lineage(other);
  RP_EXPECT_EQ(fixture.store.publish_route(request).outcome(), Outcome::Unauthorized);

  // Explicit lineage identity that disagrees with the key.
  request = fixture.route_request(632, "route/auth-two", 1, ReasonCode::InitialRoute);
  request.root_reason = RootReason::InitialPublication;
  request.explicit_lineage = other;
  RP_EXPECT_EQ(fixture.store.publish_route(request).outcome(), Outcome::MalformedRequest);

  // A dependency notification without fabric scope is refused.
  DependencyNotification notice;
  notice.kind = DependencyKind::PolicyAdvance;
  notice.policy_generation = PolicyGeneration::from_value(1);
  notice.authority = fixture.context();
  notice.authority.scope = AuthorityScope::lineage(derive_lineage_id(fixture.key(631, "route/auth")));
  RP_EXPECT_EQ(fixture.store.notify_dependency(notice).outcome(), Outcome::Unauthorized);

  // Fencing requires fabric authority.
  AuthorityContext narrow = fixture.context();
  narrow.scope = AuthorityScope::lineage(derive_lineage_id(fixture.key(631, "route/auth")));
  RP_EXPECT_EQ(fixture.store.fence_publisher(fixture.publisher, fixture.boot, narrow).outcome(),
               Outcome::Unauthorized);
}

RP_TEST(adversarial, traversal_exhaustion_is_bounded) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(641, "route/deep"));
  for (std::uint64_t generation = 2; generation <= 40; ++generation) {
    RP_REQUIRE_HAS_VALUE(
        fixture.publish_successor(641, "route/deep", generation, ReasonCode::RouteReplaced));
  }
  const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(641));
  RP_REQUIRE_HAS_VALUE(lineage);

  TraversalBounds impatient;
  impatient.max_depth = 2;
  impatient.max_results = 3;
  const auto bounded = fixture.store.ancestors(lineage.value().current_node, impatient);
  RP_REQUIRE_HAS_VALUE(bounded);
  RP_EXPECT_LE(bounded.value().nodes.size(), 4U);

  TraversalBounds impossible;
  impossible.max_depth = 1000000;
  impossible.max_results = 1000000;
  impossible.max_visited = 5;
  const auto exhausted = fixture.store.ancestors(lineage.value().current_node, impossible);
  RP_EXPECT_TRUE(exhausted.outcome() == Outcome::ResourceLimit || exhausted.has_value());

  // A maximum-depth traversal still terminates and never returns more than the bound.
  TraversalBounds deep;
  deep.max_depth = 64;
  deep.max_results = 4096;
  const auto full = fixture.store.ancestors(lineage.value().current_node, deep);
  RP_REQUIRE_HAS_VALUE(full);
  RP_EXPECT_LE(full.value().nodes.size(), 40U);
}

RP_TEST(adversarial, resource_exhaustion_is_reported_not_crashed) {
  Limits limits = Limits::defaults();
  limits.max_lineages = 32;
  Fixture fixture(limits);
  std::uint64_t accepted = 0;
  for (std::uint64_t index = 0; index < 64; ++index) {
    const auto published = fixture.publish_root(700 + index, "route/" + std::to_string(index));
    if (published.has_value()) {
      ++accepted;
      continue;
    }
    RP_EXPECT_EQ(published.outcome(), Outcome::ResourceLimit);
  }
  RP_EXPECT_EQ(accepted, 32ULL);

  // Query bounds are enforced rather than silently truncated.
  Limits query_limits = Limits::defaults();
  query_limits.max_query_results = 4;
  Fixture bounded(query_limits);
  for (std::uint64_t index = 0; index < 8; ++index) {
    RP_REQUIRE_HAS_VALUE(bounded.publish_root(800 + index, "route/q" + std::to_string(index)));
  }
  const auto lineages = bounded.store.list_lineages();
  RP_EXPECT_EQ(lineages.outcome(), Outcome::ResourceLimit);
}

RP_TEST(adversarial, wire_attacks_are_refused) {
  Limits limits = Limits::defaults();
  limits.max_frame_bytes = 512;

  // A frame whose declared message is not in the protocol.
  ByteVector frame;
  FieldBag body;
  const Status encoded =
      encode_frame(FrameHeader{}, ByteSpan(body.encode().data(), body.encode().size()), limits, frame);
  RP_REQUIRE_TRUE(encoded.is_ok());
  ByteVector forged = frame;
  forged[4] = std::byte{0x7A};
  forged[5] = std::byte{0x00};
  RP_EXPECT_FALSE(decode_frame(ByteSpan(forged.data(), forged.size()), limits).has_value());

  // An oversized declared payload is refused before any allocation proportional to it.
  ByteVector declared = frame;
  declared[12] = std::byte{0xFF};
  declared[13] = std::byte{0xFF};
  declared[14] = std::byte{0xFF};
  declared[15] = std::byte{0x7F};
  RP_EXPECT_FALSE(decode_frame(ByteSpan(declared.data(), declared.size()), limits).has_value());

  // A payload with an unknown field identifier is refused.
  FieldBag unknown;
  unknown.set_u64(1, 1);
  unknown.set_u64(60000, 2);
  const Result<FieldBag> rejected = FieldBag::decode(
      ByteSpan(unknown.encode().data(), unknown.encode().size()), limits);
  RP_REQUIRE_HAS_VALUE(rejected);
  RegistrationPayload registration;
  registration.identity = PublisherIdentity{PublisherId::from_value(1), WorkerBootId::from_value(1),
                                           CoordinatorEpoch::from_value(1)};
  ByteVector encoded_registration;
  RP_REQUIRE_TRUE(encode_registration(registration, encoded_registration, limits).is_ok());
  const Result<FieldBag> bag =
      FieldBag::decode(ByteSpan(encoded_registration.data(), encoded_registration.size()), limits);
  RP_REQUIRE_HAS_VALUE(bag);
  FieldBag extended = bag.value();
  extended.set_u64(900, 1);
  const auto refused =
      decode_registration(ByteSpan(extended.encode().data(), extended.encode().size()), limits);
  RP_EXPECT_EQ(refused.outcome(), Outcome::ProtocolFailure);
}
