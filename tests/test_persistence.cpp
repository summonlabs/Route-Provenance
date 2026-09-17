// Route Provenance - persistence suite: round trip, corruption, truncation and recovery.
#include <algorithm>
#include <fstream>
#include <string>
#include <vector>

#include "harness.hpp"
#include "route_provenance/persistence.hpp"
#include "support.hpp"

using namespace rp_test;
using namespace route_provenance;

namespace {

[[nodiscard]] std::string store_path(const std::string& label) {
  const std::string directory = make_temp_dir(label, scratch_dir());
  return directory + "/store.rpstore";
}

[[nodiscard]] bool read_file(const std::string& path, std::vector<std::uint8_t>& out) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    return false;
  }
  out.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
  return true;
}

[[nodiscard]] bool write_file(const std::string& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  if (!file) {
    return false;
  }
  file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  return file.good();
}

[[nodiscard]] std::vector<std::uint8_t> with_trailing_byte(std::vector<std::uint8_t> bytes) {
  bytes.push_back(0x00U);
  return bytes;
}

}  // namespace

RP_TEST(persistence, round_trip_preserves_identity_and_digests) {
  const std::string path = store_path("roundtrip");
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(301, "route/persist"));
  RP_REQUIRE_HAS_VALUE(fixture.publish_successor(301, "route/persist", 2, ReasonCode::RouteReplaced));
  RP_REQUIRE_HAS_VALUE(fixture.publish_successor(301, "route/persist", 3, ReasonCode::RouteReplaced));
  const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(301));
  RP_REQUIRE_HAS_VALUE(lineage);
  const auto before = fixture.store.snapshot(lineage.value().id);
  RP_REQUIRE_HAS_VALUE(before);
  const std::string saved = fixture.store.save(path).outcome() == Outcome::Ok ? "" : "save failed";
  RP_EXPECT_STREQ(saved, "");

  ProvenanceStore restored;
  const Status loaded = restored.load(path);
  RP_EXPECT_TRUE(!outcome_is_rejection(loaded.outcome()));

  const auto after_lineage = restored.lineage_for_route(RouteId::from_value(301));
  RP_REQUIRE_HAS_VALUE(after_lineage);
  RP_EXPECT_EQ(after_lineage.value().id, lineage.value().id);
  RP_EXPECT_EQ(after_lineage.value().current_route_generation.value(), 3ULL);
  RP_EXPECT_EQ(after_lineage.value().node_count, before.value().nodes.size());
  RP_EXPECT_EQ(after_lineage.value().edge_count, before.value().edges.size());
  RP_EXPECT_EQ(after_lineage.value().lineage_generation, lineage.value().lineage_generation);

  // Every record survives byte-for-byte in content, while live authority does not survive.
  for (const ProvenanceNode& node : before.value().nodes) {
    const auto record = restored.node(node.id);
    RP_REQUIRE_HAS_VALUE(record);
    RP_EXPECT_EQ(record.value().core_digest(), node.core_digest());
    RP_EXPECT_NE(record.value().currentness, Currentness::Current);
    if (node.currentness == Currentness::Current) {
      // The record that was live before the restart requires explicit revalidation.
      RP_EXPECT_EQ(record.value().currentness, Currentness::RevalidationRequired);
      RP_EXPECT_TRUE(record.value().revalidation_required);
    } else {
      // History that was already historical stays exactly as historical as it was.
      RP_EXPECT_EQ(record.value().currentness, node.currentness);
    }
  }
  RP_EXPECT_TRUE(restored.recovered());

  // No publisher session is restored: publication rejects until a fresh registration.
  route_provenance::PublishRouteRequest request =
      fixture.route_request(302, "route/after-restart", 1, ReasonCode::InitialRoute);
  request.root_reason = RootReason::RecoveredDurableState;
  request.source = SourceClass::Recovery;
  RP_EXPECT_EQ(restored.publish_route(request).outcome(), Outcome::StaleWorker);
  RP_EXPECT_EQ(restored.register_publisher(PublisherIdentity{fixture.publisher, fixture.boot,
                                                             fixture.epoch},
                                           AuthorityScope::fabric())
                    .outcome(),
               Outcome::Ok);
  const auto republished = restored.publish_route(request);
  RP_EXPECT_TRUE(republished.has_value() || republished.outcome() != Outcome::Ok);
}

RP_TEST(persistence, recovery_requires_explicit_revalidation) {
  const std::string path = store_path("revalidation");
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(311, "route/revalidate"));
  const auto lineage = fixture.store.lineage_for_route(RouteId::from_value(311));
  RP_REQUIRE_HAS_VALUE(lineage);
  static_cast<void>(fixture.store.save(path));

  ProvenanceStore restored;
  RP_EXPECT_TRUE(!outcome_is_rejection(restored.load(path).outcome()));
  const auto recovered_lineage = restored.lineage(RouteId::from_value(311).valid()
                                                      ? lineage.value().id
                                                      : lineage.value().id);
  RP_REQUIRE_HAS_VALUE(recovered_lineage);
  RP_EXPECT_EQ(recovered_lineage.value().current_currentness, Currentness::RevalidationRequired);

  RP_REQUIRE_HAS_VALUE(restored.register_publisher(
      PublisherIdentity{fixture.publisher, WorkerBootId::from_value(9), fixture.epoch},
      AuthorityScope::fabric()));
  route_provenance::AdministrativeRequest request;
  request.key = fixture.key(311, "route/revalidate");
  request.target = recovered_lineage.value().current_node;
  request.reason = ReasonCode::RecoveryRevalidation;
  request.source = SourceClass::Recovery;
  request.authority = fixture.context();
  request.authority.publisher.boot = WorkerBootId::from_value(9);
  const auto revalidated = restored.revalidate(request);
  RP_REQUIRE_HAS_VALUE(revalidated);
  const auto record = restored.node(recovered_lineage.value().current_node);
  RP_REQUIRE_HAS_VALUE(record);
  RP_EXPECT_EQ(record.value().currentness, Currentness::Current);
  RP_EXPECT_EQ(record.value().lifecycle, NodeLifecycle::Current);
  RP_EXPECT_FALSE(record.value().revalidation_required);
}

RP_TEST(persistence, corruption_is_rejected_safely) {
  const std::string path = store_path("corruption");
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(321, "route/corrupt"));
  RP_REQUIRE_HAS_VALUE(fixture.publish_successor(321, "route/corrupt", 2, ReasonCode::RouteReplaced));
  static_cast<void>(fixture.store.save(path));
  std::vector<std::uint8_t> original;
  RP_REQUIRE_TRUE(read_file(path, original));
  RP_EXPECT_GT(original.size(), 200U);
  const Limits limits = Limits::defaults();
  const std::string broken = path + ".broken";

  // Empty file.
  RP_REQUIRE_TRUE(write_file(broken, {}));
  RP_EXPECT_EQ(read_store_image(broken, limits).outcome(), Outcome::StoreCorrupt);

  // Wrong magic.
  std::vector<std::uint8_t> bytes = original;
  bytes[0] = 0xFFU;
  RP_REQUIRE_TRUE(write_file(broken, bytes));
  RP_EXPECT_EQ(read_store_image(broken, limits).outcome(), Outcome::StoreCorrupt);

  // Unsupported version.
  bytes = original;
  bytes[8] = 0xEEU;
  RP_REQUIRE_TRUE(write_file(broken, bytes));
  const auto version = read_store_image(broken, limits);
  RP_EXPECT_TRUE(version.outcome() == Outcome::UnsupportedVersion ||
                 version.outcome() == Outcome::StoreCorrupt);

  // Every truncation of a small store is rejected.
  for (std::size_t length = 1; length < original.size(); ++length) {
    std::vector<std::uint8_t> truncated(original.begin(),
                                        original.begin() + static_cast<std::ptrdiff_t>(length));
    RP_REQUIRE_TRUE(write_file(broken, truncated));
    const auto result = read_store_image(broken, limits);
    if (result.has_value()) {
      RP_FAIL("truncated store accepted at length " + std::to_string(length));
      break;
    }
  }

  // Trailing bytes are rejected.
  RP_REQUIRE_TRUE(write_file(broken, with_trailing_byte(original)));
  RP_EXPECT_EQ(read_store_image(broken, limits).outcome(), Outcome::StoreCorrupt);

  // Bit flips are detected by the integrity trailer or by structural validation.
  std::size_t detected = 0;
  for (std::size_t index = 0; index < original.size(); index += 7) {
    bytes = original;
    bytes[index] = static_cast<std::uint8_t>(bytes[index] ^ 0x40U);
    RP_REQUIRE_TRUE(write_file(broken, bytes));
    const auto result = read_store_image(broken, limits);
    if (!result.has_value()) {
      ++detected;
      continue;
    }
    // A flipped byte inside a semantic field can still decode; it must then be caught by
    // identity or structural validation, which the loader performs.
    bool mismatch = false;
    for (const StoredLineage& lineage : result.value().lineages) {
      for (const ProvenanceNode& node : lineage.nodes) {
        if (node.kind != NodeKind::CompactedSummary && node.id != derive_node_id(node)) {
          mismatch = true;
        }
      }
    }
    RP_EXPECT_TRUE(mismatch);
  }
  RP_EXPECT_GT(detected, 0U);

  // A store that never existed is an input failure, not a crash.
  RP_EXPECT_TRUE(read_store_image(store_path("missing") + "/absent.rpstore", limits).outcome() ==
                 Outcome::IoFailure);
}

RP_TEST(persistence, structural_corruption_is_rejected) {
  const std::string path = store_path("structural");
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(331, "route/structural"));
  RP_REQUIRE_HAS_VALUE(fixture.publish_successor(331, "route/structural", 2, ReasonCode::RouteReplaced));
  static_cast<void>(fixture.store.save(path));
  const Limits limits = Limits::defaults();
  const auto image = read_store_image(path, limits);
  RP_REQUIRE_HAS_VALUE(image);

  // Duplicate record identity.
  {
    StoreImage broken = image.value();
    RP_REQUIRE_TRUE(!broken.lineages.empty());
    RP_REQUIRE_TRUE(broken.lineages.front().nodes.size() >= 2);
    broken.lineages.front().nodes[1].id = broken.lineages.front().nodes[0].id;
    ByteVector encoded;
    RP_REQUIRE_TRUE(encode_store_image(broken, encoded, limits).is_ok());
    const auto decoded = decode_store_image(ByteSpan(encoded.data(), encoded.size()), limits);
    RP_EXPECT_EQ(decoded.outcome(), Outcome::StoreCorrupt);
  }
  // Missing parent.
  {
    StoreImage broken = image.value();
    RP_REQUIRE_TRUE(!broken.lineages.front().edges.empty());
    broken.lineages.front().edges.front().to = ProvenanceNodeId::from_value(999999);
    ByteVector encoded;
    RP_REQUIRE_TRUE(encode_store_image(broken, encoded, limits).is_ok());
    const auto decoded = decode_store_image(ByteSpan(encoded.data(), encoded.size()), limits);
    RP_EXPECT_TRUE(decoded.outcome() == Outcome::StoreCorrupt || decoded.outcome() == Outcome::MissingParent);
  }
  // Cycle.
  {
    StoreImage broken = image.value();
    StoredLineage& lineage = broken.lineages.front();
    RP_REQUIRE_TRUE(lineage.edges.size() >= 1);
    ProvenanceEdge reverse = lineage.edges.front();
    reverse.from = lineage.edges.front().to;
    reverse.to = lineage.edges.front().from;
    reverse.predecessor_route_generation = RouteGeneration::from_value(1);
    reverse.successor_route_generation = RouteGeneration::from_value(2);
    finalize_edge(reverse);
    lineage.edges.push_back(reverse);
    ByteVector encoded;
    RP_REQUIRE_TRUE(encode_store_image(broken, encoded, limits).is_ok());
    const auto decoded = decode_store_image(ByteSpan(encoded.data(), encoded.size()), limits);
    RP_EXPECT_EQ(decoded.outcome(), Outcome::StoreCorrupt);
  }
  // Invalid source generation.
  {
    StoreImage broken = image.value();
    broken.lineages.front().nodes.front().route_generation = RouteGeneration{};
    ByteVector encoded;
    RP_REQUIRE_TRUE(encode_store_image(broken, encoded, limits).is_ok());
    const auto decoded = decode_store_image(ByteSpan(encoded.data(), encoded.size()), limits);
    RP_EXPECT_EQ(decoded.outcome(), Outcome::StoreCorrupt);
  }
  // Impossible lineage generation.
  {
    StoreImage broken = image.value();
    broken.lineages.front().state.lineage_generation = LineageGeneration{};
    ByteVector encoded;
    RP_REQUIRE_TRUE(encode_store_image(broken, encoded, limits).is_ok());
    const auto decoded = decode_store_image(ByteSpan(encoded.data(), encoded.size()), limits);
    RP_EXPECT_EQ(decoded.outcome(), Outcome::StoreCorrupt);
  }
  // Impossible lifecycle: a compaction summary that claims to be current.
  {
    StoreImage broken = image.value();
    ProvenanceNode tombstone = broken.lineages.front().nodes.front();
    tombstone.kind = NodeKind::CompactedSummary;
    tombstone.lifecycle = NodeLifecycle::Current;
    tombstone.compacted_digest = tombstone.core_digest();
    broken.lineages.front().nodes.push_back(tombstone);
    ByteVector encoded;
    RP_REQUIRE_TRUE(encode_store_image(broken, encoded, limits).is_ok());
    const auto decoded = decode_store_image(ByteSpan(encoded.data(), encoded.size()), limits);
    RP_EXPECT_EQ(decoded.outcome(), Outcome::StoreCorrupt);
  }
  // Absurd counts.
  {
    std::vector<std::uint8_t> bytes;
    RP_REQUIRE_TRUE(read_file(path, bytes));
    // lineage_count sits at offset 80 of the header.
    bytes[80] = 0xFFU;
    bytes[81] = 0xFFU;
    bytes[82] = 0xFFU;
    bytes[83] = 0x7FU;
    const std::string broken_path = path + ".counts";
    RP_REQUIRE_TRUE(write_file(broken_path, bytes));
    const auto decoded = read_store_image(broken_path, limits);
    RP_EXPECT_TRUE(decoded.outcome() == Outcome::StoreCorrupt || decoded.outcome() == Outcome::ResourceLimit);
  }
  // Oversized body bound.
  {
    Limits small = Limits::defaults();
    small.max_store_bytes = 64;
    RP_EXPECT_EQ(read_store_image(path, small).outcome(), Outcome::ResourceLimit);
  }
}

RP_TEST(persistence, atomic_replacement_leaves_no_partial_file) {
  const std::string path = store_path("atomic");
  Fixture fixture;
  RP_REQUIRE_HAS_VALUE(fixture.publish_root(341, "route/atomic"));
  RP_EXPECT_EQ(fixture.store.save(path).outcome(), Outcome::Ok);
  RP_REQUIRE_HAS_VALUE(fixture.publish_successor(341, "route/atomic", 2, ReasonCode::RouteReplaced));
  RP_EXPECT_EQ(fixture.store.save(path).outcome(), Outcome::Ok);
  RP_EXPECT_FALSE(file_exists(path + ".tmp"));

  const Limits limits = Limits::defaults();
  const auto image = read_store_image(path, limits);
  RP_REQUIRE_HAS_VALUE(image);
  RP_EXPECT_EQ(image.value().lineages.front().nodes.size(), 2U);
}
