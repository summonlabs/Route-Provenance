// Route Provenance - structured results.
//
// No Route Provenance operation reports success or failure as bool. Every entry point
// returns a structured Outcome plus, where meaningful, a value.
#pragma once

#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include "route_provenance/enums.hpp"

namespace route_provenance {

/// Empty value type used by operations that produce no payload.
struct Unit {
  friend bool operator==(Unit, Unit) noexcept = default;
};

template <class T>
class Result {
 public:
  Result() = delete;

  Result(Outcome outcome, std::optional<T> value, std::string detail)
      : outcome_(outcome), value_(std::move(value)), detail_(std::move(detail)) {}

  [[nodiscard]] static Result ok(T value) {
    return Result(Outcome::Ok, std::optional<T>(std::move(value)), std::string{});
  }
  [[nodiscard]] static Result failure(Outcome outcome, std::string detail = {}) {
    return Result(outcome, std::nullopt, std::move(detail));
  }

  [[nodiscard]] bool has_value() const noexcept { return value_.has_value(); }
  [[nodiscard]] bool is_ok() const noexcept { return outcome_ == Outcome::Ok; }
  [[nodiscard]] Outcome outcome() const noexcept { return outcome_; }
  [[nodiscard]] const std::string& detail() const noexcept { return detail_; }

  /// Precondition: has_value(). Throws std::logic_error otherwise, which indicates a caller
  /// bug rather than an operational failure.
  [[nodiscard]] const T& value() const {
    if (!value_.has_value()) {
      throw std::logic_error("route_provenance::Result::value() on a failed result: " +
                             std::string(to_string(outcome_)) + " " + detail_);
    }
    return *value_;
  }
  [[nodiscard]] T& value() {
    if (!value_.has_value()) {
      throw std::logic_error("route_provenance::Result::value() on a failed result: " +
                             std::string(to_string(outcome_)) + " " + detail_);
    }
    return *value_;
  }
  [[nodiscard]] const T* operator->() const { return &value(); }
  [[nodiscard]] T* operator->() { return &value(); }
  [[nodiscard]] const T& operator*() const { return value(); }
  [[nodiscard]] T& operator*() { return value(); }
  [[nodiscard]] T value_or(T fallback) const { return value_.has_value() ? *value_ : std::move(fallback); }

 private:
  Outcome outcome_;
  std::optional<T> value_;
  std::string detail_;
};

template <>
class Result<void> {
 public:
  Result() = delete;
  Result(Outcome outcome, std::string detail) : outcome_(outcome), detail_(std::move(detail)) {}

  [[nodiscard]] static Result ok() { return Result(Outcome::Ok, std::string{}); }
  [[nodiscard]] static Result ok(Outcome outcome, std::string detail = {}) {
    return Result(outcome, std::move(detail));
  }
  [[nodiscard]] static Result failure(Outcome outcome, std::string detail = {}) {
    return Result(outcome, std::move(detail));
  }

  [[nodiscard]] bool is_ok() const noexcept { return outcome_ == Outcome::Ok; }
  [[nodiscard]] bool has_value() const noexcept { return outcome_ == Outcome::Ok; }
  [[nodiscard]] Outcome outcome() const noexcept { return outcome_; }
  [[nodiscard]] const std::string& detail() const noexcept { return detail_; }

 private:
  Outcome outcome_;
  std::string detail_;
};

using Status = Result<void>;

}  // namespace route_provenance
