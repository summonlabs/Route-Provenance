// Route Provenance - independent small-state graph oracle.
//
// This is a deliberately separate implementation used to cross-check the production graph.
// It shares no code with the runtime: adjacency is a plain map, cycle detection is a fresh
// depth-first search and topological order is a from-scratch Kahn implementation.
#pragma once

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <vector>

namespace rp_test {

/// True when the oracle's own self-check passed at start-up.
[[nodiscard]] bool oracle_is_verified();

class GraphOracle {
 public:
  void add_node(std::uint64_t id) { nodes_.insert(id); }

  [[nodiscard]] bool has_node(std::uint64_t id) const { return nodes_.find(id) != nodes_.end(); }

  /// Returns false when an endpoint is unknown or the edge would close a cycle.
  bool add_edge(std::uint64_t from, std::uint64_t to) {
    if (!has_node(from) || !has_node(to) || from == to) {
      return false;
    }
    if (reaches(to, from)) {
      return false;
    }
    edges_[from].push_back(to);
    reverse_[to].push_back(from);
    return true;
  }

  /// True when target is reachable from origin by following edges.
  [[nodiscard]] bool reaches(std::uint64_t origin, std::uint64_t target) const {
    std::vector<std::uint64_t> stack{origin};
    std::set<std::uint64_t> seen{origin};
    while (!stack.empty()) {
      const std::uint64_t current = stack.back();
      stack.pop_back();
      if (current == target) {
        return true;
      }
      const auto adjacency = edges_.find(current);
      if (adjacency == edges_.end()) {
        continue;
      }
      for (const std::uint64_t next : adjacency->second) {
        if (seen.insert(next).second) {
          stack.push_back(next);
        }
      }
    }
    return false;
  }

  [[nodiscard]] bool has_cycle() const {
    std::set<std::uint64_t> done;
    for (const std::uint64_t node : nodes_) {
      std::set<std::uint64_t> path;
      if (visit(node, path, done)) {
        return true;
      }
    }
    return false;
  }

  /// Causal ancestry: every record this one derives from, found by following derivation edges
  /// outward. This matches the runtime's documented convention, where an edge points from a
  /// record towards the records that caused it.
  [[nodiscard]] std::vector<std::uint64_t> ancestors(std::uint64_t id) const {
    return closure(id, false);
  }

  /// Causal descendants: every record that derives from this one.
  [[nodiscard]] std::vector<std::uint64_t> descendants(std::uint64_t id) const {
    return closure(id, true);
  }

  /// Deterministic topological order: repeatedly take the smallest node with no remaining
  /// predecessor. An empty result means the graph has a cycle.
  [[nodiscard]] std::vector<std::uint64_t> topological() const {
    std::map<std::uint64_t, std::size_t> incoming;
    for (const std::uint64_t node : nodes_) {
      incoming[node] = 0;
    }
    for (const auto& entry : edges_) {
      for (const std::uint64_t target : entry.second) {
        incoming[target] += 1;
      }
    }
    std::vector<std::uint64_t> order;
    std::set<std::uint64_t> ready;
    for (const auto& entry : incoming) {
      if (entry.second == 0) {
        ready.insert(entry.first);
      }
    }
    while (!ready.empty()) {
      const std::uint64_t current = *ready.begin();
      ready.erase(ready.begin());
      order.push_back(current);
      const auto adjacency = edges_.find(current);
      if (adjacency == edges_.end()) {
        continue;
      }
      for (const std::uint64_t next : adjacency->second) {
        incoming[next] -= 1;
        if (incoming[next] == 0) {
          ready.insert(next);
        }
      }
    }
    if (order.size() != nodes_.size()) {
      return std::vector<std::uint64_t>{};
    }
    return order;
  }

 private:
  [[nodiscard]] bool visit(std::uint64_t node, std::set<std::uint64_t>& path,
                           std::set<std::uint64_t>& done) const {
    if (done.find(node) != done.end()) {
      return false;
    }
    if (!path.insert(node).second) {
      return true;
    }
    const auto adjacency = edges_.find(node);
    if (adjacency != edges_.end()) {
      for (const std::uint64_t next : adjacency->second) {
        if (visit(next, path, done)) {
          return true;
        }
      }
    }
    path.erase(node);
    done.insert(node);
    return false;
  }

  [[nodiscard]] std::vector<std::uint64_t> closure(std::uint64_t id, bool upwards) const {
    std::vector<std::uint64_t> result;
    std::set<std::uint64_t> seen;
    std::vector<std::uint64_t> stack{id};
    while (!stack.empty()) {
      const std::uint64_t current = stack.back();
      stack.pop_back();
      const auto& adjacency = upwards ? reverse_ : edges_;  // upwards walks against the arrows
      const auto entry = adjacency.find(current);
      if (entry == adjacency.end()) {
        continue;
      }
      for (const std::uint64_t next : entry->second) {
        if (seen.insert(next).second) {
          result.push_back(next);
          stack.push_back(next);
        }
      }
    }
    std::sort(result.begin(), result.end());
    return result;
  }

  std::set<std::uint64_t> nodes_;
  std::map<std::uint64_t, std::vector<std::uint64_t>> edges_;
  std::map<std::uint64_t, std::vector<std::uint64_t>> reverse_;
};

}  // namespace rp_test
