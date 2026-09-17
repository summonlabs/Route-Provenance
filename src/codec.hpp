// Route Provenance - shared canonical binary codec for model objects.
//
// The persistence format and the wire protocol share one deterministic encoding of evidence
// vectors, authority contexts, bindings, provenance records, typed derivations and mutation
// attempts. Sharing the codec is deliberate: a value that round-trips through persistence is
// byte-for-byte the value that travels on the wire.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "route_provenance/digest.hpp"
#include "route_provenance/evidence.hpp"
#include "route_provenance/limits.hpp"
#include "route_provenance/node.hpp"
#include "route_provenance/persistence.hpp"

namespace route_provenance {
namespace codec {

class Writer {
 public:
  void u8(std::uint8_t value) { bytes_.push_back(static_cast<std::byte>(value)); }
  void u16(std::uint16_t value) {
    std::uint8_t raw[2];
    store_le16(raw, value);
    raw_bytes(raw, 2);
  }
  void u32(std::uint32_t value) {
    std::uint8_t raw[4];
    store_le32(raw, value);
    raw_bytes(raw, 4);
  }
  void u64(std::uint64_t value) {
    std::uint8_t raw[8];
    store_le64(raw, value);
    raw_bytes(raw, 8);
  }
  void digest(const Digest& value) { raw_bytes(value.data(), Digest::kSize); }
  void bytes(ByteSpan value) {
    bytes_.insert(bytes_.end(), value.begin(), value.end());
  }
  void text(const std::string& value) {
    u32(static_cast<std::uint32_t>(value.size()));
    const auto* raw = reinterpret_cast<const std::byte*>(value.data());
    bytes_.insert(bytes_.end(), raw, raw + value.size());
  }

  [[nodiscard]] const ByteVector& data() const noexcept { return bytes_; }
  [[nodiscard]] std::size_t size() const noexcept { return bytes_.size(); }
  void patch_u32(std::size_t offset, std::uint32_t value) {
    std::uint8_t raw[4];
    store_le32(raw, value);
    for (std::size_t i = 0; i < 4; ++i) {
      bytes_[offset + i] = static_cast<std::byte>(raw[i]);
    }
  }
  void patch_u64(std::size_t offset, std::uint64_t value) {
    std::uint8_t raw[8];
    store_le64(raw, value);
    for (std::size_t i = 0; i < 8; ++i) {
      bytes_[offset + i] = static_cast<std::byte>(raw[i]);
    }
  }

 private:
  void raw_bytes(const std::uint8_t* raw, std::size_t size) {
    for (std::size_t i = 0; i < size; ++i) {
      bytes_.push_back(static_cast<std::byte>(raw[i]));
    }
  }

  ByteVector bytes_;
};

class Reader {
 public:
  Reader(const std::uint8_t* data, std::size_t size) : data_(data), size_(size) {}

  [[nodiscard]] bool failed() const noexcept { return failed_; }
  [[nodiscard]] bool at_end() const noexcept { return cursor_ == size_; }
  [[nodiscard]] std::size_t remaining() const noexcept { return size_ - cursor_; }
  [[nodiscard]] std::size_t cursor() const noexcept { return cursor_; }

  [[nodiscard]] std::uint8_t u8() {
    if (!ensure(1)) {
      return 0;
    }
    return data_[cursor_++];
  }
  [[nodiscard]] std::uint16_t u16() {
    if (!ensure(2)) {
      return 0;
    }
    const std::uint16_t value = load_le16(data_ + cursor_);
    cursor_ += 2;
    return value;
  }
  [[nodiscard]] std::uint32_t u32() {
    if (!ensure(4)) {
      return 0;
    }
    const std::uint32_t value = load_le32(data_ + cursor_);
    cursor_ += 4;
    return value;
  }
  [[nodiscard]] std::uint64_t u64() {
    if (!ensure(8)) {
      return 0;
    }
    const std::uint64_t value = load_le64(data_ + cursor_);
    cursor_ += 8;
    return value;
  }
  [[nodiscard]] Digest digest() {
    if (!ensure(Digest::kSize)) {
      return Digest{};
    }
    const Digest value = Digest::from_bytes(
        ByteSpan(reinterpret_cast<const std::byte*>(data_ + cursor_), Digest::kSize));
    cursor_ += Digest::kSize;
    return value;
  }
  [[nodiscard]] std::string text(std::uint32_t max_length) {
    const std::uint32_t length = u32();
    if (failed_ || length > max_length || !ensure(length)) {
      failed_ = true;
      return std::string{};
    }
    std::string value(reinterpret_cast<const char*>(data_ + cursor_), length);
    cursor_ += length;
    return value;
  }
  [[nodiscard]] ByteSpan span(std::size_t length) {
    if (!ensure(length)) {
      return ByteSpan{};
    }
    const ByteSpan value(reinterpret_cast<const std::byte*>(data_ + cursor_), length);
    cursor_ += length;
    return value;
  }
  void skip(std::size_t length) {
    if (ensure(length)) {
      cursor_ += length;
    }
  }
  void fail() noexcept { failed_ = true; }

 private:
  [[nodiscard]] bool ensure(std::size_t length) {
    if (failed_ || length > remaining()) {
      failed_ = true;
      return false;
    }
    return true;
  }

  const std::uint8_t* data_;
  std::size_t size_;
  std::size_t cursor_ = 0;
  bool failed_ = false;
};

[[nodiscard]] bool is_known(NodeKind value) noexcept;
[[nodiscard]] bool is_known(EdgeType value) noexcept;
[[nodiscard]] bool is_known(ReasonCode value) noexcept;
[[nodiscard]] bool is_known(SourceClass value) noexcept;
[[nodiscard]] bool is_known(NodeLifecycle value) noexcept;
[[nodiscard]] bool is_known(Currentness value) noexcept;
[[nodiscard]] bool is_known(LineageLifecycle value) noexcept;
[[nodiscard]] bool is_known(Outcome value) noexcept;
[[nodiscard]] bool is_known(RootReason value) noexcept;

void write_evidence(Writer& writer, const EvidenceVector& evidence);
[[nodiscard]] bool read_evidence(Reader& reader, EvidenceVector& out, const Limits& limits);
void write_authority(Writer& writer, const AuthorityContext& authority);
[[nodiscard]] bool read_authority(Reader& reader, AuthorityContext& out);
void write_bindings(Writer& writer, const Bindings& bindings);
[[nodiscard]] bool read_bindings(Reader& reader, Bindings& out);
void write_node(Writer& writer, const ProvenanceNode& node);
[[nodiscard]] bool read_node(Reader& reader, ProvenanceNode& out, const Limits& limits);
void write_edge(Writer& writer, const ProvenanceEdge& edge);
[[nodiscard]] bool read_edge(Reader& reader, ProvenanceEdge& out, const Limits& limits);
void write_attempt(Writer& writer, const StoredAttempt& attempt);
[[nodiscard]] bool read_attempt(Reader& reader, StoredAttempt& out, const Limits& limits);

}  // namespace codec
}  // namespace route_provenance
