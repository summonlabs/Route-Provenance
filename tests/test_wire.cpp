// Route Provenance - wire suite: framing, integrity, bounds and payload strictness.
#include <string>
#include <vector>

#include "harness.hpp"
#include "route_provenance/wire.hpp"
#include "support.hpp"

using namespace rp_test;
using namespace route_provenance;

namespace {

[[nodiscard]] ByteVector encode_or_fail(const FrameHeader& header, const FieldBag& body,
                                        const Limits& limits) {
  ByteVector frame;
  const Status status = encode_frame(header, ByteSpan(body.encode().data(), body.encode().size()),
                                     limits, frame);
  static_cast<void>(status);
  return frame;
}

[[nodiscard]] Limits small_limits() {
  Limits limits = Limits::defaults();
  limits.max_frame_bytes = 1024;
  return limits;
}

}  // namespace

RP_TEST(wire, frames_round_trip_and_detect_tampering) {
  const Limits limits = small_limits();
  FieldBag body;
  body.set_u64(1, 42);
  body.set_text(2, "payload");
  FrameHeader header;
  header.message = MessageId::PublishProvenance;
  header.epoch = CoordinatorEpoch::from_value(3);
  header.publisher = PublisherId::from_value(4);
  header.boot = WorkerBootId::from_value(5);
  header.attempt = MutationAttemptId::from_value(6);
  const ByteVector frame = encode_or_fail(header, body, limits);
  RP_EXPECT_GT(frame.size(), kFrameHeaderBytes + kFrameTrailerBytes);

  const auto decoded = decode_frame(ByteSpan(frame.data(), frame.size()), limits);
  RP_REQUIRE_HAS_VALUE(decoded);
  RP_EXPECT_EQ(decoded.value().header.message, MessageId::PublishProvenance);
  RP_EXPECT_EQ(decoded.value().header.epoch.value(), 3ULL);
  RP_EXPECT_EQ(decoded.value().header.publisher.value(), 4ULL);
  RP_EXPECT_EQ(decoded.value().header.boot.value(), 5ULL);
  RP_EXPECT_EQ(decoded.value().header.attempt.value(), 6ULL);
  const Result<FieldBag> round_tripped =
      FieldBag::decode(ByteSpan(decoded.value().payload.data(), decoded.value().payload.size()), limits);
  RP_REQUIRE_HAS_VALUE(round_tripped);
  RP_EXPECT_EQ(round_tripped.value().u64(1).value_or(0), 42ULL);
  RP_EXPECT_STREQ(round_tripped.value().text(2).value_or(""), "payload");

  // Tampering anywhere in the frame is detected.
  for (std::size_t index : {std::size_t{0}, std::size_t{2}, std::size_t{5}, std::size_t{17},
                            std::size_t{30}, frame.size() - 1}) {
    ByteVector tampered = frame;
    tampered[index] = static_cast<std::byte>(std::to_integer<std::uint8_t>(tampered[index]) ^ 0x01U);
    const auto result = decode_frame(ByteSpan(tampered.data(), tampered.size()), limits);
    RP_EXPECT_FALSE(result.has_value());
  }

  // Trailing bytes are rejected.
  ByteVector extended = frame;
  extended.push_back(std::byte{0});
  RP_EXPECT_FALSE(decode_frame(ByteSpan(extended.data(), extended.size()), limits).has_value());
  // Truncation is rejected.
  const ByteVector truncated(frame.begin(), frame.end() - 1);
  RP_EXPECT_FALSE(decode_frame(ByteSpan(truncated.data(), truncated.size()), limits).has_value());
}

RP_TEST(wire, frames_reject_unknown_messages_versions_and_oversized_payloads) {
  const Limits limits = small_limits();
  FieldBag body;
  FrameHeader header;
  header.message = MessageId::Ping;
  ByteVector frame = encode_or_fail(header, body, limits);

  // Unknown message identifier.
  ByteVector unknown = frame;
  unknown[4] = std::byte{0xFF};
  unknown[5] = std::byte{0xFF};
  // Keep the integrity trailer valid so the failure is attributed to the message identifier.
  const FrameHeader unknown_header{[] {
    FrameHeader copy;
    copy.message = MessageId::Ping;
    return copy;
  }()};
  static_cast<void>(unknown_header);
  RP_EXPECT_FALSE(decode_frame(ByteSpan(unknown.data(), unknown.size()), limits).has_value());

  // Unsupported protocol version.
  ByteVector version = frame;
  version[2] = std::byte{0x09};
  RP_EXPECT_FALSE(decode_frame(ByteSpan(version.data(), version.size()), limits).has_value());

  // Oversized payload.
  FieldBag large;
  large.set_bytes(1, ByteVector(2048, std::byte{0x41}));
  ByteVector oversized;
  const Status status =
      encode_frame(header, ByteSpan(large.encode().data(), large.encode().size()), limits, oversized);
  RP_EXPECT_EQ(status.outcome(), Outcome::ResourceLimit);

  // Header size and reserved fields are validated.
  ByteVector header_mismatch = frame;
  header_mismatch[8] = std::byte{0x41};
  RP_EXPECT_FALSE(decode_frame(ByteSpan(header_mismatch.data(), header_mismatch.size()), limits).has_value());
  ByteVector reserved = frame;
  reserved[48] = std::byte{0x01};
  RP_EXPECT_FALSE(decode_frame(ByteSpan(reserved.data(), reserved.size()), limits).has_value());
}

RP_TEST(wire, field_bags_reject_structural_abuse) {
  const Limits limits = small_limits();
  FieldBag bag;
  bag.set_u64(1, 7);
  bag.set_u64(2, 8);
  const ByteVector encoded = bag.encode();

  // Duplicate field identifier.
  ByteVector duplicated = encoded;
  duplicated.insert(duplicated.end(), encoded.begin(), encoded.begin() + 6);
  duplicated.insert(duplicated.end(), encoded.end() - 8, encoded.end());
  const auto duplicate_result = FieldBag::decode(ByteSpan(duplicated.data(), duplicated.size()), limits);
  RP_EXPECT_FALSE(duplicate_result.has_value());

  // Truncated field body.
  const ByteVector truncated(encoded.begin(), encoded.end() - 3);
  RP_EXPECT_FALSE(FieldBag::decode(ByteSpan(truncated.data(), truncated.size()), limits).has_value());

  // Wrong payload length in a field header.
  ByteVector wrong_length = encoded;
  wrong_length[3] = std::byte{0x40};
  RP_EXPECT_FALSE(
      FieldBag::decode(ByteSpan(wrong_length.data(), wrong_length.size()), limits).has_value());

  // Typed accessors reject length mismatches instead of coercing.
  const auto decoded = FieldBag::decode(ByteSpan(encoded.data(), encoded.size()), limits);
  RP_REQUIRE_HAS_VALUE(decoded);
  RP_EXPECT_FALSE(decoded.value().u16(1).has_value());
  RP_EXPECT_FALSE(decoded.value().boolean(1).has_value());
  RP_EXPECT_EQ(decoded.value().u64(1).value_or(0), 7ULL);
}

RP_TEST(wire, message_payloads_round_trip) {
  const Limits limits = Limits::defaults();
  Fixture fixture;
  route_provenance::PublishRouteRequest request =
      fixture.route_request(401, "route/wire", 1, ReasonCode::InitialRoute);
  request.root_reason = RootReason::InitialPublication;

  PublicationPayload publication;
  publication.key = request.key;
  publication.route_generation = request.route_generation;
  publication.route_state_digest = request.route_state_digest;
  publication.reason = request.reason;
  publication.source = request.source;
  publication.root_reason = request.root_reason;
  publication.authority = request.authority;
  ByteVector encoded;
  RP_REQUIRE_TRUE(encode_publication(publication, encoded, limits).is_ok());
  const auto decoded = decode_publication(ByteSpan(encoded.data(), encoded.size()), limits);
  RP_REQUIRE_HAS_VALUE(decoded);
  RP_EXPECT_EQ(decoded.value().key.semantic_key, publication.key.semantic_key);
  RP_EXPECT_EQ(decoded.value().route_generation, publication.route_generation);
  RP_EXPECT_EQ(decoded.value().route_state_digest, publication.route_state_digest);
  RP_EXPECT_EQ(decoded.value().reason, publication.reason);
  RP_EXPECT_EQ(decoded.value().authority.publisher.publisher, publication.authority.publisher.publisher);
  RP_EXPECT_EQ(decoded.value().authority.scope.kind(), ScopeKind::Fabric);

  // Unknown field identifiers inside a payload are rejected.
  FieldBag extended;
  const auto bag = FieldBag::decode(ByteSpan(encoded.data(), encoded.size()), limits);
  RP_REQUIRE_HAS_VALUE(bag);
  extended = bag.value();
  extended.set_u64(4000, 1);
  const auto rejected =
      decode_publication(ByteSpan(extended.encode().data(), extended.encode().size()), limits);
  RP_EXPECT_EQ(rejected.outcome(), Outcome::ProtocolFailure);

  // Malformed enumeration values are rejected.
  FieldBag malformed = bag.value();
  malformed.set_u16(5, 0x7FFFU);
  const auto bad_reason =
      decode_publication(ByteSpan(malformed.encode().data(), malformed.encode().size()), limits);
  RP_EXPECT_EQ(bad_reason.outcome(), Outcome::ProtocolFailure);

  // Registration and acknowledgements round trip as well.
  RegistrationPayload registration;
  registration.role = 1;
  registration.identity = PublisherIdentity{PublisherId::from_value(2), WorkerBootId::from_value(3),
                                           CoordinatorEpoch::from_value(1)};
  registration.scope = AuthorityScope::lineage(RouteLineageId::from_value(9));
  ByteVector registration_bytes;
  RP_REQUIRE_TRUE(encode_registration(registration, registration_bytes, limits).is_ok());
  const auto registration_decoded =
      decode_registration(ByteSpan(registration_bytes.data(), registration_bytes.size()), limits);
  RP_REQUIRE_HAS_VALUE(registration_decoded);
  RP_EXPECT_EQ(registration_decoded.value().role, 1);
  RP_EXPECT_EQ(registration_decoded.value().scope.kind(), ScopeKind::Lineage);
  RP_EXPECT_EQ(registration_decoded.value().scope.subject(), 9ULL);

  HelloAckPayload ack;
  ack.epoch = CoordinatorEpoch::from_value(2);
  ack.accepted = true;
  ack.max_frame_bytes = 4096;
  ack.detail = "registered";
  ByteVector ack_bytes;
  RP_REQUIRE_TRUE(encode_hello_ack(ack, ack_bytes, limits).is_ok());
  const auto ack_decoded = decode_hello_ack(ByteSpan(ack_bytes.data(), ack_bytes.size()), limits);
  RP_REQUIRE_HAS_VALUE(ack_decoded);
  RP_EXPECT_TRUE(ack_decoded.value().accepted);
  RP_EXPECT_EQ(ack_decoded.value().max_frame_bytes, 4096U);
  RP_EXPECT_STREQ(ack_decoded.value().detail, "registered");
}

RP_TEST(wire, response_bodies_round_trip) {
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(411, "route/body"));
  const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(411));
  RP_REQUIRE_HAS_VALUE(lineage);
  const auto snapshot = fixture.store.snapshot(lineage.value().id);
  RP_REQUIRE_HAS_VALUE(snapshot);
  const auto view = fixture.store.lineage(lineage.value().id);
  RP_REQUIRE_HAS_VALUE(view);
  const auto node = fixture.store.node(lineage.value().current_node);
  RP_REQUIRE_HAS_VALUE(node);
  const ExplainRequest request{node.value().id, ExplainMode::FullAncestry, 0, 0};
  const auto explanation = fixture.store.explain(request);
  RP_REQUIRE_HAS_VALUE(explanation);

  const Limits limits = Limits::defaults();
  FieldBag lineage_body;
  encode_lineage_body(view.value(), lineage_body);
  const auto lineage_decoded = decode_lineage_body(lineage_body, limits);
  RP_REQUIRE_HAS_VALUE(lineage_decoded);
  RP_EXPECT_EQ(lineage_decoded.value().id, view.value().id);
  RP_EXPECT_EQ(lineage_decoded.value().digest, view.value().digest);

  FieldBag snapshot_body;
  encode_snapshot_body(snapshot.value(), snapshot_body);
  const auto snapshot_decoded = decode_snapshot_body(snapshot_body, limits);
  RP_REQUIRE_HAS_VALUE(snapshot_decoded);
  RP_EXPECT_EQ(snapshot_decoded.value().nodes.size(), snapshot.value().nodes.size());
  RP_EXPECT_EQ(snapshot_decoded.value().edges.size(), snapshot.value().edges.size());
  RP_EXPECT_EQ(snapshot_decoded.value().digest, snapshot.value().digest);

  FieldBag explanation_body;
  encode_explanation_body(explanation.value(), explanation_body);
  const auto explanation_decoded = decode_explanation_body(explanation_body, limits);
  RP_REQUIRE_HAS_VALUE(explanation_decoded);
  RP_EXPECT_EQ(explanation_decoded.value().subject, explanation.value().subject);
  RP_EXPECT_EQ(explanation_decoded.value().steps.size(), explanation.value().steps.size());

  FieldBag nodes_body;
  encode_nodes_body(snapshot.value().nodes, nodes_body);
  const auto nodes_decoded = decode_nodes_body(nodes_body, limits);
  RP_REQUIRE_HAS_VALUE(nodes_decoded);
  RP_EXPECT_EQ(nodes_decoded.value().size(), snapshot.value().nodes.size());
  RP_EXPECT_EQ(nodes_decoded.value().front().core_digest(), snapshot.value().nodes.front().core_digest());

  const auto watermarks = fixture.store.watermarks();
  RP_REQUIRE_HAS_VALUE(watermarks);
  FieldBag watermarks_body;
  encode_watermarks_body(watermarks.value(), watermarks_body);
  const auto watermarks_decoded = decode_watermarks_body(watermarks_body);
  RP_REQUIRE_HAS_VALUE(watermarks_decoded);
  RP_EXPECT_EQ(watermarks_decoded.value().store_generation, watermarks.value().store_generation);
  RP_EXPECT_EQ(watermarks_decoded.value().epoch, watermarks.value().epoch);
}
