// Route Provenance - canonical encoding and deterministic digests.
//
// Every digest in Route Provenance is computed over a canonical, length-prefixed,
// field-tagged little-endian encoding. Nothing that is not semantic provenance state may
// enter an encoding: no timestamps, addresses, thread ids, handles, iteration order or
// diagnostic counters.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "route_provenance/id.hpp"

namespace route_provenance {

using ByteSpan = std::span<const std::byte>;
using ByteVector = std::vector<std::byte>;

/// SHA-256 digest value.
class Digest {
 public:
  using bytes_type = std::array<std::uint8_t, 32>;
  static constexpr std::size_t kSize = 32;

  constexpr Digest() noexcept = default;
  explicit constexpr Digest(bytes_type bytes) noexcept : bytes_(bytes) {}

  [[nodiscard]] static Digest from_bytes(ByteSpan bytes) noexcept;
  [[nodiscard]] static std::optional<Digest> from_hex(std::string_view hex) noexcept;
  [[nodiscard]] static Digest hash(ByteSpan bytes) noexcept;
  [[nodiscard]] static Digest hash(std::string_view text) noexcept;

  [[nodiscard]] const bytes_type& bytes() const noexcept { return bytes_; }
  [[nodiscard]] const std::uint8_t* data() const noexcept { return bytes_.data(); }
  [[nodiscard]] std::string hex() const;
  [[nodiscard]] bool is_zero() const noexcept;

  friend bool operator==(const Digest&, const Digest&) noexcept = default;
  friend std::strong_ordering operator<=>(const Digest&, const Digest&) noexcept = default;

 private:
  bytes_type bytes_{};
};

/// Incremental SHA-256 hasher. State is held inline; no allocation, no hidden globals.
class Hasher {
 public:
  Hasher() noexcept;
  Hasher(const Hasher&) = delete;
  Hasher& operator=(const Hasher&) = delete;
  ~Hasher() = default;

  void update(ByteSpan data) noexcept;
  void update(std::string_view text) noexcept;
  void update_u8(std::uint8_t value) noexcept;
  void update_u16(std::uint16_t value) noexcept;
  void update_u32(std::uint32_t value) noexcept;
  void update_u64(std::uint64_t value) noexcept;

  /// Finalises the hash. Calling finish() twice returns the same value.
  [[nodiscard]] Digest finish() noexcept;

 private:
  void compress(const std::uint8_t* block) noexcept;
  void feed(const std::uint8_t* data, std::size_t size) noexcept;

  std::array<std::uint32_t, 8> state_{};
  std::array<std::uint8_t, 64> buffer_{};
  std::uint64_t total_bytes_ = 0;
  std::size_t buffered_ = 0;
  bool finished_ = false;
  Digest::bytes_type result_{};
};

/// Canonical field encoder. Field identifiers are fixed by the encoding version; each field
/// is written as (u16 id, u32 byte-length, payload) so that no two distinct field sets can
/// produce the same byte string.
class CanonicalEncoder {
 public:
  CanonicalEncoder() = default;

  void add_bool(std::uint16_t field, bool value);
  void add_u16(std::uint16_t field, std::uint16_t value);
  void add_u32(std::uint16_t field, std::uint32_t value);
  void add_u64(std::uint16_t field, std::uint64_t value);
  void add_id(std::uint16_t field, std::uint64_t value) { add_u64(field, value); }
  void add_digest(std::uint16_t field, const Digest& value);
  void add_bytes(std::uint16_t field, ByteSpan value);
  void add_string(std::uint16_t field, std::string_view value);
  void add_nested(std::uint16_t field, const CanonicalEncoder& nested);
  void add_raw(ByteSpan value);

  [[nodiscard]] const ByteVector& bytes() const noexcept { return bytes_; }
  [[nodiscard]] bool empty() const noexcept { return bytes_.empty(); }
  [[nodiscard]] std::size_t size() const noexcept { return bytes_.size(); }

  /// Digest of (domain tag, encoded fields).
  [[nodiscard]] Digest digest(std::string_view domain) const noexcept;

 private:
  void add_field(std::uint16_t field, ByteSpan payload);

  ByteVector bytes_;
};

/// Derives a stable non-zero 64-bit identity from a digest. The derivation is deterministic;
/// a digest of all zeroes cannot occur for real content, and is folded to a non-zero value
/// so that "zero is never a valid identity" holds unconditionally.
[[nodiscard]] std::uint64_t derive_id(const Digest& digest) noexcept;
[[nodiscard]] std::uint64_t derive_id(std::string_view domain, const CanonicalEncoder& encoder) noexcept;

template <class Id>
[[nodiscard]] Id derive_strong_id(const Digest& digest) noexcept {
  return Id::from_value(derive_id(digest));
}

// Fixed-width little-endian primitives shared by the persistence and wire encodings.
[[nodiscard]] std::uint16_t load_le16(const std::uint8_t* data) noexcept;
[[nodiscard]] std::uint32_t load_le32(const std::uint8_t* data) noexcept;
[[nodiscard]] std::uint64_t load_le64(const std::uint8_t* data) noexcept;
void store_le16(std::uint8_t* out, std::uint16_t value) noexcept;
void store_le32(std::uint8_t* out, std::uint32_t value) noexcept;
void store_le64(std::uint8_t* out, std::uint64_t value) noexcept;

}  // namespace route_provenance
