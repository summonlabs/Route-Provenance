// Route Provenance - core value types, canonical encoding and deterministic digests.
#include <algorithm>
#include <array>
#include <cstring>
#include <string>

#include "route_provenance/authority.hpp"
#include "route_provenance/bindings.hpp"
#include "route_provenance/digest.hpp"
#include "route_provenance/enums.hpp"
#include "route_provenance/evidence.hpp"
#include "route_provenance/limits.hpp"
#include "route_provenance/node.hpp"
#include "route_provenance/version.hpp"

#if defined(_MSC_VER)
#define RP_COMPILER_NAME "MSVC"
#define RP_COMPILER_VERSION_STRING RP_STRINGIFY(_MSC_VER)
#define RP_STRINGIFY_IMPL(x) #x
#define RP_STRINGIFY(x) RP_STRINGIFY_IMPL(x)
#elif defined(__clang__)
#define RP_COMPILER_NAME "Clang"
#define RP_COMPILER_VERSION_STRING RP_STRINGIFY(__clang_major__)
#define RP_STRINGIFY_IMPL(x) #x
#define RP_STRINGIFY(x) RP_STRINGIFY_IMPL(x)
#elif defined(__GNUC__)
#define RP_COMPILER_NAME "GCC"
#define RP_COMPILER_VERSION_STRING RP_STRINGIFY(__GNUC__)
#define RP_STRINGIFY_IMPL(x) #x
#define RP_STRINGIFY(x) RP_STRINGIFY_IMPL(x)
#else
#define RP_COMPILER_NAME "unknown"
#define RP_COMPILER_VERSION_STRING "unknown"
#endif

namespace route_provenance {
namespace {

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

constexpr std::array<std::uint32_t, 64> kSha256K = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
    0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
    0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
    0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
    0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
    0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
    0xc67178f2U};

[[nodiscard]] constexpr std::uint32_t rotr(std::uint32_t value, unsigned count) noexcept {
  return (value >> count) | (value << (32U - count));
}

// ---------------------------------------------------------------------------
// Enumeration name tables
// ---------------------------------------------------------------------------

template <class Enum, class Entry, std::size_t N>
[[nodiscard]] std::string_view lookup_name(const Entry (&table)[N], Enum value) noexcept {
  for (const Entry& entry : table) {
    if (entry.value == value) {
      return entry.name;
    }
  }
  return std::string_view{"UNKNOWN"};
}

template <class Enum, class Entry, std::size_t N>
[[nodiscard]] std::optional<Enum> lookup_value(const Entry (&table)[N], std::string_view text) noexcept {
  for (const Entry& entry : table) {
    if (entry.name == text) {
      return entry.value;
    }
  }
  return std::nullopt;
}

struct NodeKindEntry { NodeKind value; std::string_view name; };
constexpr NodeKindEntry kNodeKinds[] = {
    {NodeKind::RouteGeneration, "ROUTE_GENERATION"},
    {NodeKind::PathAuthorization, "PATH_AUTHORIZATION"},
    {NodeKind::PlannerCandidate, "PLANNER_CANDIDATE"},
    {NodeKind::AdaptiveDecision, "ADAPTIVE_DECISION"},
    {NodeKind::ConvergencePlan, "CONVERGENCE_PLAN"},
    {NodeKind::PolicyDecision, "POLICY_DECISION"},
    {NodeKind::AdministrativeAction, "ADMINISTRATIVE_ACTION"},
    {NodeKind::CompactedSummary, "COMPACTED_SUMMARY"},
};

struct EdgeTypeEntry { EdgeType value; std::string_view name; };
constexpr EdgeTypeEntry kEdgeTypes[] = {
    {EdgeType::DerivedFrom, "DERIVED_FROM"},
    {EdgeType::Supersedes, "SUPERSEDES"},
    {EdgeType::Replaces, "REPLACES"},
    {EdgeType::Withdraws, "WITHDRAWS"},
    {EdgeType::Revalidates, "REVALIDATES"},
    {EdgeType::AuthorizedBy, "AUTHORIZED_BY"},
    {EdgeType::ComputedFrom, "COMPUTED_FROM"},
    {EdgeType::SelectedFrom, "SELECTED_FROM"},
    {EdgeType::AdaptedFrom, "ADAPTED_FROM"},
    {EdgeType::TransitionedBy, "TRANSITIONED_BY"},
    {EdgeType::RolledBackFrom, "ROLLED_BACK_FROM"},
    {EdgeType::RevokedBy, "REVOKED_BY"},
    {EdgeType::RetiredBy, "RETIRED_BY"},
    {EdgeType::Corrects, "CORRECTS"},
    {EdgeType::Invalidates, "INVALIDATES"},
};

struct SourceClassEntry { SourceClass value; std::string_view name; };
constexpr SourceClassEntry kSourceClasses[] = {
    {SourceClass::Administrative, "ADMINISTRATIVE"},
    {SourceClass::RouteFabric, "ROUTE_FABRIC"},
    {SourceClass::PathAuthority, "PATH_AUTHORITY"},
    {SourceClass::PathPlanner, "PATH_PLANNER"},
    {SourceClass::AdaptiveRouting, "ADAPTIVE_ROUTING"},
    {SourceClass::RouteConvergence, "ROUTE_CONVERGENCE"},
    {SourceClass::Imported, "IMPORTED"},
    {SourceClass::Recovery, "RECOVERY"},
};

struct ReasonCodeEntry { ReasonCode value; std::string_view name; };
constexpr ReasonCodeEntry kReasonCodes[] = {
    {ReasonCode::InitialRoute, "INITIAL_ROUTE"},
    {ReasonCode::PathRevalidated, "PATH_REVALIDATED"},
    {ReasonCode::RouteReplaced, "ROUTE_REPLACED"},
    {ReasonCode::AdminWithdrawal, "ADMIN_WITHDRAWAL"},
    {ReasonCode::PolicyChange, "POLICY_CHANGE"},
    {ReasonCode::AdaptiveChange, "ADAPTIVE_CHANGE"},
    {ReasonCode::EcmpChange, "ECMP_CHANGE"},
    {ReasonCode::WeightChange, "WEIGHT_CHANGE"},
    {ReasonCode::PathInvalidation, "PATH_INVALIDATION"},
    {ReasonCode::ConvergenceComplete, "CONVERGENCE_COMPLETE"},
    {ReasonCode::Rollback, "ROLLBACK"},
    {ReasonCode::RecoveryRevalidation, "RECOVERY_REVALIDATION"},
    {ReasonCode::Revocation, "REVOCATION"},
    {ReasonCode::Retirement, "RETIREMENT"},
    {ReasonCode::Correction, "CORRECTION"},
    {ReasonCode::Invalidation, "INVALIDATION"},
    {ReasonCode::Declaration, "DECLARATION"},
    {ReasonCode::HistoryCompaction, "HISTORY_COMPACTION"},
    {ReasonCode::Import, "IMPORT"},
};

struct RootReasonEntry { RootReason value; std::string_view name; };
constexpr RootReasonEntry kRootReasons[] = {
    {RootReason::InitialPublication, "INITIAL_PUBLICATION"},
    {RootReason::ImportedAdministrativeState, "IMPORTED_ADMINISTRATIVE_STATE"},
    {RootReason::RecoveredDurableState, "RECOVERED_DURABLE_STATE"},
    {RootReason::OperatorCreate, "OPERATOR_CREATE"},
};

struct NodeLifecycleEntry { NodeLifecycle value; std::string_view name; };
constexpr NodeLifecycleEntry kNodeLifecycles[] = {
    {NodeLifecycle::Declared, "DECLARED"},
    {NodeLifecycle::Current, "CURRENT"},
    {NodeLifecycle::Historical, "HISTORICAL"},
    {NodeLifecycle::RevalidationRequired, "REVALIDATION_REQUIRED"},
    {NodeLifecycle::Superseded, "SUPERSEDED"},
    {NodeLifecycle::Revoked, "REVOKED"},
    {NodeLifecycle::Retired, "RETIRED"},
    {NodeLifecycle::Invalid, "INVALID"},
};

struct CurrentnessEntry { Currentness value; std::string_view name; };
constexpr CurrentnessEntry kCurrentnesses[] = {
    {Currentness::Current, "CURRENT"},
    {Currentness::StaleRoute, "STALE_ROUTE"},
    {Currentness::StalePathAuthority, "STALE_PATH_AUTHORITY"},
    {Currentness::StalePolicy, "STALE_POLICY"},
    {Currentness::StaleEvidence, "STALE_EVIDENCE"},
    {Currentness::StaleEpoch, "STALE_EPOCH"},
    {Currentness::FencedPublisher, "FENCED_PUBLISHER"},
    {Currentness::HistoricalOnly, "HISTORICAL_ONLY"},
    {Currentness::RevalidationRequired, "REVALIDATION_REQUIRED"},
};

struct LineageLifecycleEntry { LineageLifecycle value; std::string_view name; };
constexpr LineageLifecycleEntry kLineageLifecycles[] = {
    {LineageLifecycle::Active, "ACTIVE"},
    {LineageLifecycle::Withdrawn, "WITHDRAWN"},
    {LineageLifecycle::Revoked, "REVOKED"},
    {LineageLifecycle::Retired, "RETIRED"},
};

struct OutcomeEntry { Outcome value; std::string_view name; };
constexpr OutcomeEntry kOutcomes[] = {
    {Outcome::Created, "CREATED"},
    {Outcome::Linked, "LINKED"},
    {Outcome::Updated, "UPDATED"},
    {Outcome::Idempotent, "IDEMPOTENT"},
    {Outcome::StaleRoute, "STALE_ROUTE"},
    {Outcome::StalePathAuthority, "STALE_PATH_AUTHORITY"},
    {Outcome::StalePolicy, "STALE_POLICY"},
    {Outcome::StalePlan, "STALE_PLAN"},
    {Outcome::StaleEpoch, "STALE_EPOCH"},
    {Outcome::StaleWorker, "STALE_WORKER"},
    {Outcome::Duplicate, "DUPLICATE"},
    {Outcome::Conflict, "CONFLICT"},
    {Outcome::CycleDetected, "CYCLE_DETECTED"},
    {Outcome::MissingParent, "MISSING_PARENT"},
    {Outcome::InvalidDerivation, "INVALID_DERIVATION"},
    {Outcome::InvalidSourceGeneration, "INVALID_SOURCE_GENERATION"},
    {Outcome::Unauthorized, "UNAUTHORIZED"},
    {Outcome::RevalidationRequired, "REVALIDATION_REQUIRED"},
    {Outcome::Revoked, "REVOKED"},
    {Outcome::Retired, "RETIRED"},
    {Outcome::ResourceLimit, "RESOURCE_LIMIT"},
    {Outcome::MalformedRequest, "MALFORMED_REQUEST"},
    {Outcome::LineageNotFound, "LINEAGE_NOT_FOUND"},
    {Outcome::NodeNotFound, "NODE_NOT_FOUND"},
    {Outcome::StoreCorrupt, "STORE_CORRUPT"},
    {Outcome::WireIntegrityFailure, "WIRE_INTEGRITY_FAILURE"},
    {Outcome::UnsupportedVersion, "UNSUPPORTED_VERSION"},
    {Outcome::IoFailure, "IO_FAILURE"},
    {Outcome::ProtocolFailure, "PROTOCOL_FAILURE"},
    {Outcome::SessionRejected, "SESSION_REJECTED"},
    {Outcome::Ok, "OK"},
    {Outcome::StaleLineageGeneration, "STALE_LINEAGE_GENERATION"},
    {Outcome::StaleStoreGeneration, "STALE_STORE_GENERATION"},
    {Outcome::StaleEvidence, "STALE_EVIDENCE"},
};

struct ExplainModeEntry { ExplainMode value; std::string_view name; };
constexpr ExplainModeEntry kExplainModes[] = {
    {ExplainMode::ImmediateCause, "IMMEDIATE_CAUSE"},
    {ExplainMode::FullAncestry, "FULL_ANCESTRY"},
    {ExplainMode::AuthorityOnly, "AUTHORITY_ONLY"},
    {ExplainMode::PolicyOnly, "POLICY_ONLY"},
    {ExplainMode::PathOnly, "PATH_ONLY"},
    {ExplainMode::MutationLineage, "MUTATION_LINEAGE"},
};

struct MessageIdEntry { MessageId value; std::string_view name; };
constexpr MessageIdEntry kMessageIds[] = {
    {MessageId::Hello, "HELLO"},
    {MessageId::HelloAck, "HELLO_ACK"},
    {MessageId::RegisterPublisher, "REGISTER_PUBLISHER"},
    {MessageId::PublishProvenance, "PUBLISH_PROVENANCE"},
    {MessageId::LinkDerivation, "LINK_DERIVATION"},
    {MessageId::Supersede, "SUPERSEDE"},
    {MessageId::Withdraw, "WITHDRAW"},
    {MessageId::Revoke, "REVOKE"},
    {MessageId::Retire, "RETIRE"},
    {MessageId::Correct, "CORRECT"},
    {MessageId::QueryLineage, "QUERY_LINEAGE"},
    {MessageId::QueryCause, "QUERY_CAUSE"},
    {MessageId::QueryAncestry, "QUERY_ANCESTRY"},
    {MessageId::SnapshotRequest, "SNAPSHOT_REQUEST"},
    {MessageId::SnapshotResponse, "SNAPSHOT_RESPONSE"},
    {MessageId::FenceNotice, "FENCE_NOTICE"},
    {MessageId::Result, "RESULT"},
    {MessageId::Error, "ERROR"},
    {MessageId::NotifyDependency, "NOTIFY_DEPENDENCY"},
    {MessageId::Revalidate, "REVALIDATE"},
    {MessageId::Invalidate, "INVALIDATE"},
    {MessageId::DeclareSource, "DECLARE_SOURCE"},
    {MessageId::Ping, "PING"},
    {MessageId::Pong, "PONG"},
    {MessageId::Bye, "BYE"},
    {MessageId::QueryWatermarks, "QUERY_WATERMARKS"},
};

struct DependencyKindEntry { DependencyKind value; std::string_view name; };
constexpr DependencyKindEntry kDependencyKinds[] = {
    {DependencyKind::RouteAdvance, "ROUTE_ADVANCE"},
    {DependencyKind::PathAuthorityAdvance, "PATH_AUTHORITY_ADVANCE"},
    {DependencyKind::PolicyAdvance, "POLICY_ADVANCE"},
    {DependencyKind::EvidenceAdvance, "EVIDENCE_ADVANCE"},
    {DependencyKind::PlanAdvance, "PLAN_ADVANCE"},
    {DependencyKind::EpochAdvance, "EPOCH_ADVANCE"},
    {DependencyKind::WorkerFence, "WORKER_FENCE"},
};

}  // namespace

// ---------------------------------------------------------------------------
// Hasher
// ---------------------------------------------------------------------------

Hasher::Hasher() noexcept
    : state_{0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
             0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U} {}

void Hasher::compress(const std::uint8_t* block) noexcept {
  std::uint32_t w[64];
  for (std::size_t i = 0; i < 16; ++i) {
    const std::size_t base = i * 4;
    w[i] = (static_cast<std::uint32_t>(block[base]) << 24) |
           (static_cast<std::uint32_t>(block[base + 1]) << 16) |
           (static_cast<std::uint32_t>(block[base + 2]) << 8) |
           static_cast<std::uint32_t>(block[base + 3]);
  }
  for (std::size_t i = 16; i < 64; ++i) {
    const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t i = 0; i < 64; ++i) {
    const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const std::uint32_t ch = (e & f) ^ (~e & g);
    const std::uint32_t temp1 = h + s1 + ch + kSha256K[i] + w[i];
    const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Hasher::feed(const std::uint8_t* data, std::size_t size) noexcept {
  std::size_t remaining = size;
  const std::uint8_t* cursor = data;
  while (remaining > 0) {
    const std::size_t space = buffer_.size() - buffered_;
    const std::size_t take = remaining < space ? remaining : space;
    std::memcpy(buffer_.data() + buffered_, cursor, take);
    buffered_ += take;
    cursor += take;
    remaining -= take;
    if (buffered_ == buffer_.size()) {
      compress(buffer_.data());
      buffered_ = 0;
    }
  }
}

void Hasher::update(ByteSpan data) noexcept {
  if (finished_) {
    return;
  }
  total_bytes_ += static_cast<std::uint64_t>(data.size());
  feed(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

void Hasher::update(std::string_view text) noexcept {
  update(ByteSpan(reinterpret_cast<const std::byte*>(text.data()), text.size()));
}

void Hasher::update_u8(std::uint8_t value) noexcept {
  const std::uint8_t raw[1] = {value};
  update(ByteSpan(reinterpret_cast<const std::byte*>(raw), 1));
}

void Hasher::update_u16(std::uint16_t value) noexcept {
  std::uint8_t raw[2];
  store_le16(raw, value);
  update(ByteSpan(reinterpret_cast<const std::byte*>(raw), 2));
}

void Hasher::update_u32(std::uint32_t value) noexcept {
  std::uint8_t raw[4];
  store_le32(raw, value);
  update(ByteSpan(reinterpret_cast<const std::byte*>(raw), 4));
}

void Hasher::update_u64(std::uint64_t value) noexcept {
  std::uint8_t raw[8];
  store_le64(raw, value);
  update(ByteSpan(reinterpret_cast<const std::byte*>(raw), 8));
}

Digest Hasher::finish() noexcept {
  if (finished_) {
    return Digest(result_);
  }
  const std::uint64_t bit_length = total_bytes_ * 8U;
  const std::size_t rem = static_cast<std::size_t>(total_bytes_ % buffer_.size());
  std::uint8_t tail[128];
  std::size_t tail_length = 0;
  tail[tail_length++] = 0x80U;
  // After the 0x80 byte the message length field must begin at byte 56 of a block, so the
  // number of zero bytes is (55 - rem) for the common case and (119 - rem) otherwise.
  const std::size_t zero_count = (rem < 56U) ? (55U - rem) : (119U - rem);
  for (std::size_t i = 0; i < zero_count; ++i) {
    tail[tail_length++] = 0x00U;
  }
  for (int i = 7; i >= 0; --i) {
    tail[tail_length++] = static_cast<std::uint8_t>((bit_length >> (static_cast<unsigned>(i) * 8U)) & 0xFFU);
  }
  feed(tail, tail_length);
  for (std::size_t i = 0; i < 8; ++i) {
    const std::uint32_t word = state_[i];
    result_[i * 4 + 0] = static_cast<std::uint8_t>((word >> 24) & 0xFFU);
    result_[i * 4 + 1] = static_cast<std::uint8_t>((word >> 16) & 0xFFU);
    result_[i * 4 + 2] = static_cast<std::uint8_t>((word >> 8) & 0xFFU);
    result_[i * 4 + 3] = static_cast<std::uint8_t>(word & 0xFFU);
  }
  finished_ = true;
  return Digest(result_);
}

// ---------------------------------------------------------------------------
// Digest
// ---------------------------------------------------------------------------

Digest Digest::from_bytes(ByteSpan bytes) noexcept {
  bytes_type out{};
  const std::size_t count = bytes.size() < out.size() ? bytes.size() : out.size();
  for (std::size_t i = 0; i < count; ++i) {
    out[i] = std::to_integer<std::uint8_t>(bytes[i]);
  }
  return Digest(out);
}

Digest Digest::hash(ByteSpan bytes) noexcept {
  Hasher hasher;
  hasher.update(bytes);
  return hasher.finish();
}

Digest Digest::hash(std::string_view text) noexcept {
  Hasher hasher;
  hasher.update(text);
  return hasher.finish();
}

std::optional<Digest> Digest::from_hex(std::string_view hex) noexcept {
  if (hex.size() != kSize * 2U) {
    return std::nullopt;
  }
  bytes_type out{};
  for (std::size_t i = 0; i < kSize; ++i) {
    const auto decode = [](char ch) -> int {
      if (ch >= '0' && ch <= '9') {
        return ch - '0';
      }
      if (ch >= 'a' && ch <= 'f') {
        return 10 + (ch - 'a');
      }
      if (ch >= 'A' && ch <= 'F') {
        return 10 + (ch - 'A');
      }
      return -1;
    };
    const int high = decode(hex[i * 2]);
    const int low = decode(hex[i * 2 + 1]);
    if (high < 0 || low < 0) {
      return std::nullopt;
    }
    out[i] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return Digest(out);
}

std::string Digest::hex() const {
  static constexpr char kHexDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(kSize * 2U);
  for (const std::uint8_t byte : bytes_) {
    out.push_back(kHexDigits[byte >> 4]);
    out.push_back(kHexDigits[byte & 0x0FU]);
  }
  return out;
}

bool Digest::is_zero() const noexcept {
  for (const std::uint8_t byte : bytes_) {
    if (byte != 0) {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------

void CanonicalEncoder::add_raw(ByteSpan value) {
  const std::size_t base = bytes_.size();
  bytes_.resize(base + value.size());
  if (!value.empty()) {
    std::memcpy(bytes_.data() + base, value.data(), value.size());
  }
}

void CanonicalEncoder::add_field(std::uint16_t field, ByteSpan payload) {
  const std::size_t base = bytes_.size();
  bytes_.resize(base + 6U + payload.size());
  std::uint8_t* header = reinterpret_cast<std::uint8_t*>(bytes_.data()) + base;
  store_le16(header, field);
  store_le32(header + 2U, static_cast<std::uint32_t>(payload.size()));
  if (!payload.empty()) {
    std::memcpy(bytes_.data() + base + 6U, payload.data(), payload.size());
  }
}

void CanonicalEncoder::add_bool(std::uint16_t field, bool value) {
  const std::uint8_t raw = value ? 1U : 0U;
  add_field(field, ByteSpan(reinterpret_cast<const std::byte*>(&raw), 1));
}

void CanonicalEncoder::add_u16(std::uint16_t field, std::uint16_t value) {
  std::uint8_t raw[2];
  store_le16(raw, value);
  add_field(field, ByteSpan(reinterpret_cast<const std::byte*>(raw), 2));
}

void CanonicalEncoder::add_u32(std::uint16_t field, std::uint32_t value) {
  std::uint8_t raw[4];
  store_le32(raw, value);
  add_field(field, ByteSpan(reinterpret_cast<const std::byte*>(raw), 4));
}

void CanonicalEncoder::add_u64(std::uint16_t field, std::uint64_t value) {
  std::uint8_t raw[8];
  store_le64(raw, value);
  add_field(field, ByteSpan(reinterpret_cast<const std::byte*>(raw), 8));
}

void CanonicalEncoder::add_digest(std::uint16_t field, const Digest& value) {
  add_field(field, ByteSpan(reinterpret_cast<const std::byte*>(value.bytes().data()),
                           value.bytes().size()));
}

void CanonicalEncoder::add_bytes(std::uint16_t field, ByteSpan value) { add_field(field, value); }

void CanonicalEncoder::add_string(std::uint16_t field, std::string_view value) {
  add_field(field, ByteSpan(reinterpret_cast<const std::byte*>(value.data()), value.size()));
}

void CanonicalEncoder::add_nested(std::uint16_t field, const CanonicalEncoder& nested) {
  add_field(field, ByteSpan(nested.bytes_.data(), nested.bytes_.size()));
}

Digest CanonicalEncoder::digest(std::string_view domain) const noexcept {
  Hasher hasher;
  hasher.update(domain);
  hasher.update_u32(static_cast<std::uint32_t>(bytes_.size()));
  hasher.update(ByteSpan(bytes_.data(), bytes_.size()));
  return hasher.finish();
}

std::uint64_t derive_id(const Digest& digest) noexcept {
  const std::uint8_t* data = digest.data();
  for (std::size_t offset = 0; offset < Digest::kSize; offset += 8U) {
    const std::uint64_t candidate = load_le64(data + offset);
    if (candidate != 0) {
      return candidate;
    }
  }
  return 1;
}

std::uint64_t derive_id(std::string_view domain, const CanonicalEncoder& encoder) noexcept {
  return derive_id(encoder.digest(domain));
}

std::uint16_t load_le16(const std::uint8_t* data) noexcept {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[0]) |
                                    (static_cast<std::uint16_t>(data[1]) << 8));
}

std::uint32_t load_le32(const std::uint8_t* data) noexcept {
  return static_cast<std::uint32_t>(data[0]) | (static_cast<std::uint32_t>(data[1]) << 8) |
         (static_cast<std::uint32_t>(data[2]) << 16) | (static_cast<std::uint32_t>(data[3]) << 24);
}

std::uint64_t load_le64(const std::uint8_t* data) noexcept {
  std::uint64_t value = 0;
  for (int i = 7; i >= 0; --i) {
    value = (value << 8) | static_cast<std::uint64_t>(data[i]);
  }
  return value;
}

void store_le16(std::uint8_t* out, std::uint16_t value) noexcept {
  out[0] = static_cast<std::uint8_t>(value & 0xFFU);
  out[1] = static_cast<std::uint8_t>((value >> 8) & 0xFFU);
}

void store_le32(std::uint8_t* out, std::uint32_t value) noexcept {
  for (int i = 0; i < 4; ++i) {
    out[i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFU);
  }
}

void store_le64(std::uint8_t* out, std::uint64_t value) noexcept {
  for (int i = 0; i < 8; ++i) {
    out[i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFU);
  }
}

// ---------------------------------------------------------------------------
// Enumeration conversions
// ---------------------------------------------------------------------------

std::string_view to_string(NodeKind value) noexcept { return lookup_name(kNodeKinds, value); }
std::string_view to_string(EdgeType value) noexcept { return lookup_name(kEdgeTypes, value); }
std::string_view to_string(SourceClass value) noexcept { return lookup_name(kSourceClasses, value); }
std::string_view to_string(ReasonCode value) noexcept { return lookup_name(kReasonCodes, value); }
std::string_view to_string(RootReason value) noexcept { return lookup_name(kRootReasons, value); }
std::string_view to_string(NodeLifecycle value) noexcept { return lookup_name(kNodeLifecycles, value); }
std::string_view to_string(Currentness value) noexcept { return lookup_name(kCurrentnesses, value); }
std::string_view to_string(LineageLifecycle value) noexcept { return lookup_name(kLineageLifecycles, value); }
std::string_view to_string(Outcome value) noexcept { return lookup_name(kOutcomes, value); }
std::string_view to_string(ExplainMode value) noexcept { return lookup_name(kExplainModes, value); }
std::string_view to_string(MessageId value) noexcept { return lookup_name(kMessageIds, value); }
std::string_view to_string(DependencyKind value) noexcept { return lookup_name(kDependencyKinds, value); }

std::optional<NodeKind> parse_node_kind(std::string_view text) noexcept { return lookup_value<NodeKind>(kNodeKinds, text); }
std::optional<EdgeType> parse_edge_type(std::string_view text) noexcept { return lookup_value<EdgeType>(kEdgeTypes, text); }
std::optional<SourceClass> parse_source_class(std::string_view text) noexcept { return lookup_value<SourceClass>(kSourceClasses, text); }
std::optional<ReasonCode> parse_reason_code(std::string_view text) noexcept { return lookup_value<ReasonCode>(kReasonCodes, text); }
std::optional<RootReason> parse_root_reason(std::string_view text) noexcept { return lookup_value<RootReason>(kRootReasons, text); }
std::optional<NodeLifecycle> parse_node_lifecycle(std::string_view text) noexcept { return lookup_value<NodeLifecycle>(kNodeLifecycles, text); }
std::optional<Currentness> parse_currentness(std::string_view text) noexcept { return lookup_value<Currentness>(kCurrentnesses, text); }
std::optional<LineageLifecycle> parse_lineage_lifecycle(std::string_view text) noexcept { return lookup_value<LineageLifecycle>(kLineageLifecycles, text); }
std::optional<Outcome> parse_outcome(std::string_view text) noexcept { return lookup_value<Outcome>(kOutcomes, text); }
std::optional<ExplainMode> parse_explain_mode(std::string_view text) noexcept { return lookup_value<ExplainMode>(kExplainModes, text); }

std::optional<MessageId> parse_message_id(std::uint16_t raw) noexcept {
  for (const MessageIdEntry& entry : kMessageIds) {
    if (static_cast<std::uint16_t>(entry.value) == raw) {
      return entry.value;
    }
  }
  return std::nullopt;
}

std::optional<DependencyKind> parse_dependency_kind(std::uint16_t raw) noexcept {
  for (const DependencyKindEntry& entry : kDependencyKinds) {
    if (static_cast<std::uint16_t>(entry.value) == raw) {
      return entry.value;
    }
  }
  return std::nullopt;
}

bool outcome_is_commit(Outcome outcome) noexcept {
  switch (outcome) {
    case Outcome::Created:
    case Outcome::Linked:
    case Outcome::Updated:
    case Outcome::Idempotent:
      return true;
    default:
      return false;
  }
}

bool outcome_is_stale(Outcome outcome) noexcept {
  switch (outcome) {
    case Outcome::StaleRoute:
    case Outcome::StalePathAuthority:
    case Outcome::StalePolicy:
    case Outcome::StalePlan:
    case Outcome::StaleEpoch:
    case Outcome::StaleWorker:
    case Outcome::StaleEvidence:
    case Outcome::StaleLineageGeneration:
    case Outcome::StaleStoreGeneration:
    case Outcome::RevalidationRequired:
      return true;
    default:
      return false;
  }
}

bool outcome_is_rejection(Outcome outcome) noexcept {
  if (outcome == Outcome::Ok || outcome_is_commit(outcome) || outcome_is_stale(outcome)) {
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

bool Limits::validate(std::string& error) const {
  const auto fail = [&error](std::string message) {
    error = std::move(message);
    return false;
  };
  if (max_lineages == 0 || max_nodes_per_lineage == 0 || max_edges_per_lineage == 0 ||
      max_history_nodes_per_lineage == 0 || max_attempts_per_lineage == 0 ||
      max_traversal_depth == 0 || max_query_results == 0 || max_visited_nodes == 0 ||
      max_explanation_nodes == 0 || max_batch_size == 0 || max_evidence_entries == 0 ||
      max_semantic_key_bytes == 0 || max_frame_bytes == 0 || max_publishers == 0 ||
      max_sessions == 0 || max_persistence_record_bytes == 0 || max_persistence_nodes == 0 ||
      max_persistence_edges == 0 || max_frame_assembly_ms == 0 || max_store_bytes == 0) {
    return fail("limits must be non-zero");
  }
  if (max_nodes_per_lineage > max_persistence_nodes) {
    return fail("max_nodes_per_lineage exceeds max_persistence_nodes");
  }
  if (max_edges_per_lineage > max_persistence_edges) {
    return fail("max_edges_per_lineage exceeds max_persistence_edges");
  }
  if (max_parents_per_node == 0 || max_children_per_node == 0) {
    return fail("per-node degree limits must be non-zero");
  }
  if (max_parents_per_node > max_edges_per_lineage || max_children_per_node > max_edges_per_lineage) {
    return fail("per-node degree limit exceeds per-lineage edge limit");
  }
  if (max_history_nodes_per_lineage > max_nodes_per_lineage) {
    return fail("max_history_nodes_per_lineage exceeds max_nodes_per_lineage");
  }
  if (max_query_results > max_visited_nodes || max_explanation_nodes > max_visited_nodes) {
    return fail("result limits exceed max_visited_nodes");
  }
  if (max_evidence_entries > 1024) {
    return fail("max_evidence_entries is unreasonably large");
  }
  return true;
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

std::string_view to_string(EvidenceField field) noexcept {
  switch (field) {
    case EvidenceField::TopologyGeneration: return "TOPOLOGY_GENERATION";
    case EvidenceField::LinkStateGeneration: return "LINK_STATE_GENERATION";
    case EvidenceField::PortGeneration: return "PORT_GENERATION";
    case EvidenceField::CapabilityGeneration: return "CAPABILITY_GENERATION";
    case EvidenceField::FailureDomainGeneration: return "FAILURE_DOMAIN_GENERATION";
    case EvidenceField::FabricEpoch: return "FABRIC_EPOCH";
    case EvidenceField::PathAuthorityGeneration: return "PATH_AUTHORITY_GENERATION";
    case EvidenceField::PlannerGeneration: return "PLANNER_GENERATION";
    case EvidenceField::AdaptivePolicyGeneration: return "ADAPTIVE_POLICY_GENERATION";
    case EvidenceField::ConvergencePlanGeneration: return "CONVERGENCE_PLAN_GENERATION";
    case EvidenceField::RouteGeneration: return "ROUTE_GENERATION";
    case EvidenceField::PublisherGeneration: return "PUBLISHER_GENERATION";
  }
  return "UNKNOWN";
}

std::optional<EvidenceField> parse_evidence_field(std::string_view text) noexcept {
  static constexpr EvidenceField kAll[] = {
      EvidenceField::TopologyGeneration,      EvidenceField::LinkStateGeneration,
      EvidenceField::PortGeneration,          EvidenceField::CapabilityGeneration,
      EvidenceField::FailureDomainGeneration, EvidenceField::FabricEpoch,
      EvidenceField::PathAuthorityGeneration, EvidenceField::PlannerGeneration,
      EvidenceField::AdaptivePolicyGeneration, EvidenceField::ConvergencePlanGeneration,
      EvidenceField::RouteGeneration,         EvidenceField::PublisherGeneration};
  for (const EvidenceField field : kAll) {
    if (to_string(field) == text) {
      return field;
    }
  }
  return std::nullopt;
}

Result<EvidenceVector> EvidenceVector::create(std::vector<EvidenceEntry> entries, const Limits& limits) {
  if (entries.size() > limits.max_evidence_entries) {
    return Result<EvidenceVector>::failure(Outcome::ResourceLimit, "evidence vector exceeds max_evidence_entries");
  }
  std::sort(entries.begin(), entries.end(), [](const EvidenceEntry& left, const EvidenceEntry& right) {
    return static_cast<std::uint16_t>(left.field) < static_cast<std::uint16_t>(right.field);
  });
  EvidenceVector vector;
  for (const EvidenceEntry& entry : entries) {
    if (entry.value == 0) {
      return Result<EvidenceVector>::failure(
          Outcome::InvalidSourceGeneration,
          std::string("evidence field ") + std::string(to_string(entry.field)) + " has an invalid generation");
    }
    if (!vector.entries_.empty() && vector.entries_.back().field == entry.field) {
      if (vector.entries_.back().value != entry.value) {
        return Result<EvidenceVector>::failure(
            Outcome::MalformedRequest,
            std::string("conflicting evidence values for field ") + std::string(to_string(entry.field)));
      }
      continue;
    }
    vector.entries_.push_back(entry);
  }
  return Result<EvidenceVector>::ok(std::move(vector));
}

bool EvidenceVector::contains(EvidenceField field) const noexcept {
  for (const EvidenceEntry& entry : entries_) {
    if (entry.field == field) {
      return true;
    }
  }
  return false;
}

std::optional<std::uint64_t> EvidenceVector::get(EvidenceField field) const noexcept {
  for (const EvidenceEntry& entry : entries_) {
    if (entry.field == field) {
      return entry.value;
    }
  }
  return std::nullopt;
}

Digest EvidenceVector::digest() const noexcept {
  CanonicalEncoder encoder;
  encode(encoder, 1);
  return encoder.digest("rp.evidence.v1");
}

void EvidenceVector::encode(CanonicalEncoder& encoder, std::uint16_t field) const {
  CanonicalEncoder nested;
  nested.add_u32(1, static_cast<std::uint32_t>(entries_.size()));
  for (const EvidenceEntry& entry : entries_) {
    nested.add_u64(static_cast<std::uint16_t>(entry.field), entry.value);
  }
  encoder.add_nested(field, nested);
}

// ---------------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------------

std::string PublisherIdentity::describe() const {
  return "publisher=" + publisher.to_string() + " boot=" + boot.to_string() +
         " epoch=" + epoch.to_string();
}

AuthorityScope AuthorityScope::fabric() noexcept {
  AuthorityScope scope;
  scope.kind_ = ScopeKind::Fabric;
  scope.subject_ = 0;
  return scope;
}

AuthorityScope AuthorityScope::routing_namespace(RoutingNamespaceId id) noexcept {
  AuthorityScope scope;
  if (id.valid()) {
    scope.kind_ = ScopeKind::RoutingNamespace;
    scope.subject_ = id.value();
  }
  return scope;
}

AuthorityScope AuthorityScope::lineage(RouteLineageId id) noexcept {
  AuthorityScope scope;
  if (id.valid()) {
    scope.kind_ = ScopeKind::Lineage;
    scope.subject_ = id.value();
  }
  return scope;
}

AuthorityScope AuthorityScope::route(RouteId id) noexcept {
  AuthorityScope scope;
  if (id.valid()) {
    scope.kind_ = ScopeKind::Route;
    scope.subject_ = id.value();
  }
  return scope;
}

bool AuthorityScope::permits(const ScopeTarget& target) const noexcept {
  switch (kind_) {
    case ScopeKind::None:
      return false;
    case ScopeKind::Fabric:
      return true;
    case ScopeKind::RoutingNamespace:
      return subject_ != 0 && target.routing_namespace.valid() &&
             subject_ == target.routing_namespace.value();
    case ScopeKind::Lineage:
      return subject_ != 0 && target.lineage.valid() && subject_ == target.lineage.value();
    case ScopeKind::Route:
      return subject_ != 0 && target.route.valid() && subject_ == target.route.value();
  }
  return false;
}

std::string_view to_string(ScopeKind kind) noexcept {
  switch (kind) {
    case ScopeKind::None: return "NONE";
    case ScopeKind::Fabric: return "FABRIC";
    case ScopeKind::RoutingNamespace: return "ROUTING_NAMESPACE";
    case ScopeKind::Lineage: return "LINEAGE";
    case ScopeKind::Route: return "ROUTE";
  }
  return "UNKNOWN";
}

std::optional<ScopeKind> parse_scope_kind(std::string_view text) noexcept {
  static constexpr ScopeKind kAll[] = {ScopeKind::None, ScopeKind::Fabric, ScopeKind::RoutingNamespace,
                                       ScopeKind::Lineage, ScopeKind::Route};
  for (const ScopeKind kind : kAll) {
    if (to_string(kind) == text) {
      return kind;
    }
  }
  return std::nullopt;
}

std::string AuthorityScope::describe() const {
  switch (kind_) {
    case ScopeKind::None:
      return "scope=NONE";
    case ScopeKind::Fabric:
      return "scope=FABRIC";
    case ScopeKind::RoutingNamespace:
      return "scope=ROUTING_NAMESPACE:" + std::to_string(subject_);
    case ScopeKind::Lineage:
      return "scope=LINEAGE:" + std::to_string(subject_);
    case ScopeKind::Route:
      return "scope=ROUTE:" + std::to_string(subject_);
  }
  return "scope=UNKNOWN";
}

void AuthorityScope::encode(CanonicalEncoder& encoder, std::uint16_t field) const {
  CanonicalEncoder nested;
  nested.add_u16(1, static_cast<std::uint16_t>(kind_));
  nested.add_u64(2, subject_);
  encoder.add_nested(field, nested);
}

void AuthorityContext::encode(CanonicalEncoder& encoder, std::uint16_t field) const {
  CanonicalEncoder nested;
  nested.add_u64(1, publisher.publisher.value());
  nested.add_u64(2, publisher.boot.value());
  nested.add_u64(3, publisher.epoch.value());
  nested.add_u64(4, attempt.value());
  scope.encode(nested, 5);
  nested.add_u64(6, expected_lineage_generation.has_value() ? expected_lineage_generation->value() : 0);
  nested.add_u64(7, expected_provenance_generation.has_value() ? expected_provenance_generation->value() : 0);
  encoder.add_nested(field, nested);
}

Digest AuthorityContext::digest() const noexcept {
  CanonicalEncoder encoder;
  encode(encoder, 1);
  return encoder.digest("rp.authority.v1");
}

// ---------------------------------------------------------------------------
// Bindings
// ---------------------------------------------------------------------------

bool Bindings::empty() const noexcept {
  return !path.has_value() && !planner.has_value() && !ecmp.has_value() && !weighted.has_value() &&
         !adaptation.has_value() && !convergence.has_value() && !policy.has_value();
}

namespace {

[[nodiscard]] Status require_generation(std::uint64_t value, std::string_view name) {
  if (value == 0) {
    return Status::failure(Outcome::InvalidSourceGeneration,
                           std::string(name) + " must be a valid generation");
  }
  return Status::ok();
}

}  // namespace

Status validate_bindings(ReasonCode reason, const Bindings& bindings) {
  if (bindings.path.has_value()) {
    if (!bindings.path->path.valid()) {
      return Status::failure(Outcome::MalformedRequest, "path binding requires a valid PathId");
    }
    const Status status = require_generation(bindings.path->generation.value(), "PathAuthorityGeneration");
    if (!status.is_ok()) {
      return status;
    }
  }
  if (bindings.planner.has_value()) {
    if (!bindings.planner->request.valid() || !bindings.planner->selected_path.valid()) {
      return Status::failure(Outcome::MalformedRequest, "planner binding requires request and selected PathId");
    }
    const Status status = require_generation(bindings.planner->generation.value(), "PlannerGeneration");
    if (!status.is_ok()) {
      return status;
    }
  }
  if (bindings.ecmp.has_value()) {
    if (!bindings.ecmp->group.valid()) {
      return Status::failure(Outcome::MalformedRequest, "ECMP binding requires a valid EcmpGroupId");
    }
    Status status = require_generation(bindings.ecmp->membership.value(), "MembershipGeneration");
    if (!status.is_ok()) {
      return status;
    }
    status = require_generation(bindings.ecmp->assignment.value(), "AssignmentGeneration");
    if (!status.is_ok()) {
      return status;
    }
  }
  if (bindings.weighted.has_value()) {
    if (!bindings.weighted->set.valid()) {
      return Status::failure(Outcome::MalformedRequest, "weighted binding requires a valid WeightedPathSetId");
    }
    Status status = require_generation(bindings.weighted->policy.value(), "WeightPolicyGeneration");
    if (!status.is_ok()) {
      return status;
    }
    status = require_generation(bindings.weighted->assignment.value(), "AssignmentGeneration");
    if (!status.is_ok()) {
      return status;
    }
  }
  if (bindings.adaptation.has_value()) {
    if (!bindings.adaptation->decision.valid()) {
      return Status::failure(Outcome::MalformedRequest, "adaptation binding requires a valid AdaptationDecisionId");
    }
    Status status = require_generation(bindings.adaptation->generation.value(), "AdaptationGeneration");
    if (!status.is_ok()) {
      return status;
    }
    status = require_generation(bindings.adaptation->policy.value(), "PolicyGeneration");
    if (!status.is_ok()) {
      return status;
    }
    status = require_generation(bindings.adaptation->evidence.value(), "EvidenceGeneration");
    if (!status.is_ok()) {
      return status;
    }
  }
  if (bindings.convergence.has_value()) {
    if (!bindings.convergence->plan.valid()) {
      return Status::failure(Outcome::MalformedRequest, "convergence binding requires a valid ConvergencePlanId");
    }
    const Status status = require_generation(bindings.convergence->generation.value(), "ConvergencePlanGeneration");
    if (!status.is_ok()) {
      return status;
    }
  }
  if (bindings.policy.has_value()) {
    const Status status = require_generation(bindings.policy->generation.value(), "PolicyGeneration");
    if (!status.is_ok()) {
      return status;
    }
  }

  switch (reason) {
    case ReasonCode::EcmpChange:
      if (!bindings.ecmp.has_value()) {
        return Status::failure(Outcome::InvalidDerivation, "ECMP_CHANGE requires an ECMP binding");
      }
      break;
    case ReasonCode::WeightChange:
      if (!bindings.weighted.has_value()) {
        return Status::failure(Outcome::InvalidDerivation, "WEIGHT_CHANGE requires a weighted-path binding");
      }
      break;
    case ReasonCode::AdaptiveChange:
      if (!bindings.adaptation.has_value()) {
        return Status::failure(Outcome::InvalidDerivation, "ADAPTIVE_CHANGE requires an adaptation binding");
      }
      break;
    case ReasonCode::PathInvalidation:
    case ReasonCode::PathRevalidated:
      if (!bindings.path.has_value()) {
        return Status::failure(Outcome::InvalidDerivation, "path reason requires a path binding");
      }
      break;
    case ReasonCode::ConvergenceComplete:
    case ReasonCode::Rollback:
      if (!bindings.convergence.has_value()) {
        return Status::failure(Outcome::InvalidDerivation, "convergence reason requires a convergence binding");
      }
      break;
    case ReasonCode::PolicyChange:
      if (!bindings.policy.has_value()) {
        return Status::failure(Outcome::InvalidDerivation, "POLICY_CHANGE requires a policy binding");
      }
      break;
    default:
      break;
  }
  return Status::ok();
}

void encode_bindings(const Bindings& bindings, CanonicalEncoder& encoder, std::uint16_t field) {
  CanonicalEncoder nested;
  if (bindings.path.has_value()) {
    CanonicalEncoder path;
    path.add_u64(1, bindings.path->path.value());
    path.add_u64(2, bindings.path->generation.value());
    path.add_digest(3, bindings.path->decision_digest);
    nested.add_nested(1, path);
  }
  if (bindings.planner.has_value()) {
    CanonicalEncoder planner;
    planner.add_u64(1, bindings.planner->request.value());
    planner.add_u64(2, bindings.planner->generation.value());
    planner.add_u32(3, bindings.planner->candidate_rank);
    planner.add_digest(4, bindings.planner->plan_digest);
    planner.add_u64(5, bindings.planner->selected_path.value());
    nested.add_nested(2, planner);
  }
  if (bindings.ecmp.has_value()) {
    CanonicalEncoder ecmp;
    ecmp.add_u64(1, bindings.ecmp->group.value());
    ecmp.add_u64(2, bindings.ecmp->membership.value());
    ecmp.add_u64(3, bindings.ecmp->assignment.value());
    nested.add_nested(3, ecmp);
  }
  if (bindings.weighted.has_value()) {
    CanonicalEncoder weighted;
    weighted.add_u64(1, bindings.weighted->set.value());
    weighted.add_u64(2, bindings.weighted->policy.value());
    weighted.add_u64(3, bindings.weighted->assignment.value());
    nested.add_nested(4, weighted);
  }
  if (bindings.adaptation.has_value()) {
    CanonicalEncoder adaptation;
    adaptation.add_u64(1, bindings.adaptation->decision.value());
    adaptation.add_u64(2, bindings.adaptation->generation.value());
    adaptation.add_u64(3, bindings.adaptation->policy.value());
    adaptation.add_u64(4, bindings.adaptation->evidence.value());
    adaptation.add_digest(5, bindings.adaptation->decision_digest);
    nested.add_nested(5, adaptation);
  }
  if (bindings.convergence.has_value()) {
    CanonicalEncoder convergence;
    convergence.add_u64(1, bindings.convergence->plan.value());
    convergence.add_u64(2, bindings.convergence->generation.value());
    convergence.add_u64(3, bindings.convergence->step.value());
    convergence.add_digest(4, bindings.convergence->completion_evidence);
    nested.add_nested(6, convergence);
  }
  if (bindings.policy.has_value()) {
    CanonicalEncoder policy;
    policy.add_u64(1, bindings.policy->generation.value());
    nested.add_nested(7, policy);
  }
  encoder.add_nested(field, nested);
}

// ---------------------------------------------------------------------------
// Lineage identity
// ---------------------------------------------------------------------------

RouteLineageId derive_lineage_id(const LineageKey& key) noexcept {
  CanonicalEncoder encoder;
  encoder.add_u32(1, kGraphEncodingVersion);
  encoder.add_u64(2, key.route.value());
  encoder.add_string(3, key.semantic_key);
  return derive_strong_id<RouteLineageId>(encoder.digest("rp.lineage.v1"));
}

// ---------------------------------------------------------------------------
// Node and edge identity
// ---------------------------------------------------------------------------

Digest node_core_digest(const ProvenanceNode& node) noexcept {
  CanonicalEncoder encoder;
  encoder.add_u32(1, kGraphEncodingVersion);
  encoder.add_u64(2, node.lineage.value());
  encoder.add_u16(3, static_cast<std::uint16_t>(node.kind));
  encoder.add_u64(4, node.route.value());
  encoder.add_u64(5, node.route_generation.value());
  encoder.add_digest(6, node.route_state_digest);
  encoder.add_u16(7, static_cast<std::uint16_t>(node.reason));
  encoder.add_u16(8, static_cast<std::uint16_t>(node.source));
  encoder.add_u16(9, node.root_reason.has_value() ? static_cast<std::uint16_t>(*node.root_reason) : 0);
  node.evidence.encode(encoder, 10);
  node.authority.encode(encoder, 11);
  encode_bindings(node.bindings, encoder, 12);
  encoder.add_u64(13, node.corrects.has_value() ? node.corrects->value() : 0);
  encoder.add_digest(14, node.compacted_digest.value_or(Digest{}));
  return encoder.digest("rp.node.core.v1");
}

Digest node_digest(const ProvenanceNode& node) noexcept {
  CanonicalEncoder encoder;
  encoder.add_digest(1, node_core_digest(node));
  encoder.add_u64(2, node.id.value());
  encoder.add_u16(3, static_cast<std::uint16_t>(node.lifecycle));
  encoder.add_u16(4, static_cast<std::uint16_t>(node.currentness));
  encoder.add_bool(5, node.revalidation_required);
  encoder.add_u64(6, node.corrected_by.has_value() ? node.corrected_by->value() : 0);
  encoder.add_bool(7, node.revalidated);
  return encoder.digest("rp.node.v1");
}

Digest ProvenanceNode::core_digest() const noexcept { return node_core_digest(*this); }
Digest ProvenanceNode::digest() const noexcept { return node_digest(*this); }

DerivationId compute_derivation_id(const ProvenanceEdge& edge) noexcept {
  CanonicalEncoder encoder;
  encoder.add_u32(1, kGraphEncodingVersion);
  encoder.add_u64(2, edge.lineage.value());
  encoder.add_u16(3, static_cast<std::uint16_t>(edge.type));
  encoder.add_u64(4, edge.from.value());
  encoder.add_u64(5, edge.to.value());
  encoder.add_u64(6, edge.predecessor_route_generation.value());
  encoder.add_u64(7, edge.successor_route_generation.value());
  encoder.add_u16(8, static_cast<std::uint16_t>(edge.reason));
  encoder.add_u16(9, static_cast<std::uint16_t>(edge.source));
  edge.evidence.encode(encoder, 10);
  edge.authority.encode(encoder, 11);
  return derive_strong_id<DerivationId>(encoder.digest("rp.derivation.v1"));
}

ProvenanceEdgeId compute_edge_id(const ProvenanceEdge& edge) noexcept {
  CanonicalEncoder encoder;
  encoder.add_u32(1, kGraphEncodingVersion);
  encoder.add_u64(2, edge.lineage.value());
  encoder.add_u64(3, edge.derivation.value());
  encoder.add_u16(4, static_cast<std::uint16_t>(edge.type));
  encoder.add_u64(5, edge.from.value());
  encoder.add_u64(6, edge.to.value());
  return derive_strong_id<ProvenanceEdgeId>(encoder.digest("rp.edge.v1"));
}

void finalize_edge(ProvenanceEdge& edge) noexcept {
  edge.derivation = compute_derivation_id(edge);
  edge.id = compute_edge_id(edge);
}

ProvenanceNodeId derive_node_id(const ProvenanceNode& node) noexcept {
  return derive_strong_id<ProvenanceNodeId>(node_core_digest(node));
}

void finalize_node(ProvenanceNode& node) noexcept { node.id = derive_node_id(node); }

Digest ProvenanceEdge::core_digest() const noexcept {
  CanonicalEncoder encoder;
  encoder.add_u32(1, kGraphEncodingVersion);
  encoder.add_u64(2, lineage.value());
  encoder.add_u64(3, derivation.value());
  encoder.add_u16(4, static_cast<std::uint16_t>(type));
  encoder.add_u64(5, from.value());
  encoder.add_u64(6, to.value());
  return encoder.digest("rp.edge.v1");
}

bool edge_type_is_successor_relation(EdgeType type) noexcept {
  switch (type) {
    case EdgeType::Supersedes:
    case EdgeType::Replaces:
    case EdgeType::DerivedFrom:
    case EdgeType::RolledBackFrom:
      return true;
    default:
      return false;
  }
}

bool edge_type_is_evidence_relation(EdgeType type) noexcept {
  switch (type) {
    case EdgeType::AuthorizedBy:
    case EdgeType::ComputedFrom:
    case EdgeType::SelectedFrom:
    case EdgeType::AdaptedFrom:
    case EdgeType::TransitionedBy:
      return true;
    default:
      return false;
  }
}

bool edge_type_is_action_relation(EdgeType type) noexcept {
  switch (type) {
    case EdgeType::Withdraws:
    case EdgeType::RevokedBy:
    case EdgeType::RetiredBy:
    case EdgeType::Revalidates:
    case EdgeType::Corrects:
    case EdgeType::Invalidates:
      return true;
    default:
      return false;
  }
}

bool is_valid_lifecycle_transition(NodeLifecycle from, NodeLifecycle to) noexcept {
  if (from == to) {
    return true;
  }
  switch (from) {
    case NodeLifecycle::Declared:
      return to == NodeLifecycle::Current || to == NodeLifecycle::Historical ||
             to == NodeLifecycle::Invalid || to == NodeLifecycle::Superseded;
    case NodeLifecycle::Current:
      return to == NodeLifecycle::Historical || to == NodeLifecycle::Superseded ||
             to == NodeLifecycle::Revoked || to == NodeLifecycle::Retired ||
             to == NodeLifecycle::Invalid || to == NodeLifecycle::RevalidationRequired;
    case NodeLifecycle::RevalidationRequired:
      return to == NodeLifecycle::Current || to == NodeLifecycle::Historical ||
             to == NodeLifecycle::Superseded || to == NodeLifecycle::Revoked ||
             to == NodeLifecycle::Retired || to == NodeLifecycle::Invalid;
    case NodeLifecycle::Historical:
      return to == NodeLifecycle::Invalid || to == NodeLifecycle::Revoked ||
             to == NodeLifecycle::Retired || to == NodeLifecycle::Superseded;
    case NodeLifecycle::Superseded:
      return to == NodeLifecycle::Invalid || to == NodeLifecycle::Revoked ||
             to == NodeLifecycle::Retired;
    case NodeLifecycle::Revoked:
      return to == NodeLifecycle::Retired || to == NodeLifecycle::Invalid;
    case NodeLifecycle::Retired:
      return to == NodeLifecycle::Invalid;
    case NodeLifecycle::Invalid:
      return false;
  }
  return false;
}

bool node_is_history_record(const ProvenanceNode& node) noexcept {
  if (node.kind == NodeKind::CompactedSummary) {
    return false;
  }
  switch (node.lifecycle) {
    case NodeLifecycle::Historical:
    case NodeLifecycle::Superseded:
    case NodeLifecycle::Invalid:
      return true;
    default:
      return false;
  }
}

Status validate_node_consistency(const ProvenanceNode& node) {
  if (!node.lineage.valid()) {
    return Status::failure(Outcome::MalformedRequest, "node requires a valid RouteLineageId");
  }
  if (!node.authority.has_identity()) {
    return Status::failure(Outcome::Unauthorized, "node requires a full publisher/boot/epoch/attempt identity");
  }
  if (node.kind == NodeKind::RouteGeneration) {
    if (!node.route.valid() || !node.route_generation.valid()) {
      return Status::failure(Outcome::InvalidDerivation,
                             "route-state node requires a valid RouteId and RouteGeneration");
    }
    if (node.route_state_digest.is_zero()) {
      return Status::failure(Outcome::InvalidDerivation, "route-state node requires a route-state digest");
    }
    if (node.lifecycle == NodeLifecycle::Declared) {
      return Status::failure(Outcome::InvalidDerivation, "route-state node cannot be DECLARED");
    }
  } else if (node.kind == NodeKind::CompactedSummary) {
    if (!node.route_generation.valid() || !node.compacted_digest.has_value()) {
      return Status::failure(Outcome::InvalidDerivation, "compaction summary requires generation and digest");
    }
    if (node.lifecycle == NodeLifecycle::Current || node.lifecycle == NodeLifecycle::Declared) {
      return Status::failure(Outcome::InvalidDerivation, "compaction summary cannot be current");
    }
  }
  if (node.root_reason.has_value() && node.kind != NodeKind::RouteGeneration) {
    return Status::failure(Outcome::InvalidDerivation, "only route-state roots carry a root reason");
  }
  if (node.corrects.has_value() && node.reason != ReasonCode::Correction) {
    return Status::failure(Outcome::InvalidDerivation, "only correction records carry a correction target");
  }
  return Status::ok();
}

Status validate_edge_consistency(const ProvenanceEdge& edge) {
  if (!edge.lineage.valid()) {
    return Status::failure(Outcome::MalformedRequest, "edge requires a valid RouteLineageId");
  }
  if (!edge.from.valid() || !edge.to.valid()) {
    return Status::failure(Outcome::MalformedRequest, "edge requires valid endpoints");
  }
  if (edge.from == edge.to) {
    return Status::failure(Outcome::CycleDetected, "self edge rejected");
  }
  if (edge_type_is_successor_relation(edge.type)) {
    if (!edge.predecessor_route_generation.valid() || !edge.successor_route_generation.valid()) {
      return Status::failure(Outcome::InvalidDerivation,
                             "successor relation requires predecessor and successor route generations");
    }
    if (edge.predecessor_route_generation.value() >= edge.successor_route_generation.value()) {
      return Status::failure(Outcome::InvalidDerivation,
                             "successor relation requires strictly increasing route generations");
    }
  }
  return Status::ok();
}

// ---------------------------------------------------------------------------
// Version reporting
// ---------------------------------------------------------------------------

std::string version_string() { return std::string(kVersionString); }

std::string build_info() {
  return std::string(RP_COMPILER_NAME) + " " + RP_COMPILER_VERSION_STRING + " " +
         std::to_string(sizeof(void*) * 8U) + "-bit C++" + std::to_string(__cplusplus / 100 % 100);
}

std::string version_report() {
  std::string report;
  report += "product: ";
  report += kProductName;
  report += "\nversion: ";
  report += kVersionString;
  report += "\nwire_protocol_version: ";
  report += std::to_string(kWireProtocolVersion);
  report += "\npersistence_format_version: ";
  report += std::to_string(kPersistenceFormatVersion);
  report += "\ngraph_encoding_version: ";
  report += std::to_string(kGraphEncodingVersion);
  report += "\ndigest_encoding_version: ";
  report += std::to_string(kDigestEncodingVersion);
  report += "\nreason_code_semantics_version: ";
  report += std::to_string(kReasonCodeSemanticsVersion);
  report += "\nbuild: ";
  report += build_info();
  report += "\nnotice: ";
  report += kCopyrightNotice;
  report += "\n";
  return report;
}

}  // namespace route_provenance
