// Route Provenance - self-contained test harness.
//
// Bounded waits exist so that a stuck system reports an explicit failure rather than hanging.
// There are no test timeouts anywhere: exceeding a bound is itself the failure. Every child
// process is created inside a job object that kills it when this process exits, so a failing
// test cannot leave an orphan behind.
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "route_provenance/enums.hpp"

namespace rp_test {

using TestFn = void (*)();

void register_test(const char* suite, const char* name, TestFn fn);

struct Registrar {
  Registrar(const char* suite, const char* name, TestFn fn);
};

/// Thrown by RP_REQUIRE_* so that dependent checks do not cascade.
class TestAborted {};

void report_failure(const char* file, int line, const std::string& message);
[[nodiscard]] bool current_test_failed();
[[nodiscard]] std::string describe(const char* value);
[[nodiscard]] std::string describe(char* value);

/// Generic value rendering used by the equality assertions. Strongly typed identities render
/// their canonical text form, enumerations render their stable name and digests render hex.
template <class T>
[[nodiscard]] std::string describe(const T& value) {
  using Decayed = std::decay_t<T>;
  if constexpr (std::is_same_v<Decayed, std::string>) {
    return value;
  } else if constexpr (std::is_same_v<Decayed, bool>) {
    return value ? std::string("true") : std::string("false");
  } else if constexpr (std::is_enum_v<Decayed>) {
    if constexpr (requires(Decayed candidate) { route_provenance::to_string(candidate); }) {
      return std::string(route_provenance::to_string(value));
    } else {
      return "<enum:" + std::to_string(static_cast<long long>(value)) + ">";
    }
  } else if constexpr (std::is_arithmetic_v<Decayed>) {
    return std::to_string(value);
  } else if constexpr (requires(const Decayed& candidate) { candidate.to_string(); }) {
    return value.to_string();
  } else if constexpr (requires(const Decayed& candidate) { candidate.hex(); }) {
    return value.hex();
  } else {
    return std::string("<value>");
  }
}

int run_all(int argc, char** argv);

/// Real child process control.
class ChildProcess {
 public:
  ChildProcess() = default;
  ~ChildProcess();
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;
  ChildProcess(ChildProcess&& other) noexcept;
  ChildProcess& operator=(ChildProcess&& other) noexcept;

  /// Launches exe with args. stdout and stderr are redirected into a private capture file in
  /// capture_dir. Returns nullopt and fills error on failure.
  static std::optional<ChildProcess> launch(const std::string& exe,
                                            const std::vector<std::string>& args,
                                            const std::string& capture_dir, std::string& error);

  [[nodiscard]] bool running();
  [[nodiscard]] bool wait_for_exit(unsigned milliseconds);
  [[nodiscard]] bool wait_for_exit_code(unsigned milliseconds, unsigned long& code);
  void terminate();
  [[nodiscard]] unsigned long exit_code() const;
  [[nodiscard]] std::uint32_t process_id() const;
  [[nodiscard]] std::string captured_output();
  [[nodiscard]] bool wait_for_output(const std::string& needle, unsigned milliseconds);
  /// True when the process is alive and its captured output does not contain the needle.
  [[nodiscard]] bool write_stdin(const std::string& text);

 private:
  struct Impl;
  Impl* impl_ = nullptr;
};

[[nodiscard]] std::string make_temp_dir(const std::string& label, const std::string& root = {});
void remove_dir(const std::string& path);
[[nodiscard]] bool file_exists(const std::string& path);
[[nodiscard]] bool wait_until(unsigned milliseconds, const std::function<bool()>& predicate);

/// Paths injected by the build system.
[[nodiscard]] std::string scratch_dir();
[[nodiscard]] std::string coordinator_exe();
[[nodiscard]] std::string publisher_exe();

}  // namespace rp_test

#define RP_TEST(suite, name)                                                          \
  static void rp_test_##suite##_##name();                                             \
  static const ::rp_test::Registrar rp_test_registrar_##suite##_##name(               \
      #suite, #name, &rp_test_##suite##_##name);                                      \
  static void rp_test_##suite##_##name()

#define RP_EXPECT_TRUE(expr)                                                          \
  do {                                                                                \
    if (!(expr)) {                                                                    \
      ::rp_test::report_failure(__FILE__, __LINE__, "expected true: " #expr);         \
    }                                                                                 \
  } while (false)

#define RP_EXPECT_FALSE(expr)                                                         \
  do {                                                                                \
    if ((expr)) {                                                                     \
      ::rp_test::report_failure(__FILE__, __LINE__, "expected false: " #expr);        \
    }                                                                                 \
  } while (false)

#define RP_EXPECT_EQ(a, b)                                                            \
  do {                                                                                \
    const auto& rp_left = (a);                                                        \
    const auto& rp_right = (b);                                                       \
    if (!(rp_left == rp_right)) {                                                     \
      ::rp_test::report_failure(__FILE__, __LINE__,                                   \
                                std::string("expected " #a " == " #b " but got ") +   \
                                    ::rp_test::describe(rp_left) + " vs " +           \
                                    ::rp_test::describe(rp_right));                    \
    }                                                                                 \
  } while (false)

#define RP_EXPECT_NE(a, b)                                                            \
  do {                                                                                \
    const auto& rp_left = (a);                                                        \
    const auto& rp_right = (b);                                                       \
    if (rp_left == rp_right) {                                                        \
      ::rp_test::report_failure(__FILE__, __LINE__, "expected " #a " != " #b);        \
    }                                                                                 \
  } while (false)

#define RP_EXPECT_LT(a, b)                                                            \
  do {                                                                                \
    if (!((a) < (b))) {                                                               \
      ::rp_test::report_failure(__FILE__, __LINE__, "expected " #a " < " #b);         \
    }                                                                                 \
  } while (false)

#define RP_EXPECT_LE(a, b)                                                            \
  do {                                                                                \
    if (!((a) <= (b))) {                                                              \
      ::rp_test::report_failure(__FILE__, __LINE__, "expected " #a " <= " #b);        \
    }                                                                                 \
  } while (false)

#define RP_EXPECT_GE(a, b)                                                            \
  do {                                                                                \
    if (!((a) >= (b))) {                                                              \
      ::rp_test::report_failure(__FILE__, __LINE__, "expected " #a " >= " #b);        \
    }                                                                                 \
  } while (false)

#define RP_EXPECT_GT(a, b)                                                            \
  do {                                                                                \
    if (!((a) > (b))) {                                                               \
      ::rp_test::report_failure(__FILE__, __LINE__, "expected " #a " > " #b);         \
    }                                                                                 \
  } while (false)

#define RP_EXPECT_STREQ(a, b)                                                         \
  do {                                                                                \
    const std::string rp_left = std::string(a);                                       \
    const std::string rp_right = std::string(b);                                      \
    if (rp_left != rp_right) {                                                        \
      ::rp_test::report_failure(__FILE__, __LINE__,                                   \
                                std::string("expected string equality: ") + rp_left + \
                                    " vs " + rp_right);                               \
    }                                                                                 \
  } while (false)

#define RP_FAIL(message) ::rp_test::report_failure(__FILE__, __LINE__, (message))

#define RP_REQUIRE_TRUE(expr)                                                         \
  do {                                                                                \
    if (!(expr)) {                                                                    \
      ::rp_test::report_failure(__FILE__, __LINE__, "required true: " #expr);         \
      throw ::rp_test::TestAborted{};                                                 \
    }                                                                                 \
  } while (false)

#define RP_REQUIRE_EQ(a, b)                                                           \
  do {                                                                                \
    const auto& rp_left = (a);                                                        \
    const auto& rp_right = (b);                                                       \
    if (!(rp_left == rp_right)) {                                                     \
      ::rp_test::report_failure(__FILE__, __LINE__,                                   \
                                std::string("required " #a " == " #b " but got ") +   \
                                    ::rp_test::describe(rp_left) + " vs " +           \
                                    ::rp_test::describe(rp_right));                    \
      throw ::rp_test::TestAborted{};                                                 \
    }                                                                                 \
  } while (false)

#define RP_REQUIRE_HAS_VALUE(result)                                                  \
  do {                                                                                \
    if (!(result).has_value()) {                                                      \
      ::rp_test::report_failure(__FILE__, __LINE__,                                   \
                                std::string("required a value but got outcome ") +    \
                                    std::string(::route_provenance::to_string(        \
                                        (result).outcome())) +                        \
                                    " " + (result).detail());                         \
      throw ::rp_test::TestAborted{};                                                 \
    }                                                                                 \
  } while (false)

#define RP_TEST_MAIN() \
  int main(int argc, char** argv) { return ::rp_test::run_all(argc, argv); }
