// Route Provenance - version and compatibility surface.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace route_provenance {

/// Library version (semantic versioning).
inline constexpr std::uint32_t kVersionMajor = 1;
inline constexpr std::uint32_t kVersionMinor = 0;
inline constexpr std::uint32_t kVersionPatch = 0;
inline constexpr std::string_view kVersionString = "1.0.0";
inline constexpr std::string_view kProductName = "Route Provenance";
inline constexpr std::string_view kCopyrightNotice = "Copyright 2026 Summon Software Labs.";

/// Independently versioned compatibility surfaces. Each of these may advance without a
/// library version change, and each is rejected on mismatch where compatibility matters.
inline constexpr std::uint16_t kWireProtocolVersion = 1;
inline constexpr std::uint32_t kPersistenceFormatVersion = 1;
inline constexpr std::uint32_t kGraphEncodingVersion = 1;
inline constexpr std::uint32_t kDigestEncodingVersion = 1;
inline constexpr std::uint32_t kReasonCodeSemanticsVersion = 1;

/// "1.0.0"
[[nodiscard]] std::string version_string();

/// Compiler and language facts for the build that produced this binary.
[[nodiscard]] std::string build_info();

/// Deterministic multi-line report used by the CLI \c version command.
[[nodiscard]] std::string version_report();

}  // namespace route_provenance
