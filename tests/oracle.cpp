// Route Provenance - oracle translation unit.
//
// The oracle is header-only; this unit exists so that the oracle participates in the build and
// cannot silently rot when the runtime changes.
#include "oracle.hpp"

namespace rp_test {
namespace {

[[nodiscard]] bool oracle_self_check() {
  GraphOracle oracle;
  oracle.add_node(1);
  oracle.add_node(2);
  oracle.add_node(3);
  return oracle.add_edge(1, 2) && oracle.add_edge(2, 3) && !oracle.add_edge(3, 1) &&
         !oracle.has_cycle() &&
         // Edge 1 -> 2 means "1 derives from 2", so 1's ancestry is {2, 3} and 3's causal
         // descendants are {1, 2}.
         oracle.ancestors(1).size() == 2 && oracle.descendants(3).size() == 2 &&
         oracle.ancestors(3).empty() && oracle.descendants(1).empty() &&
         oracle.topological().size() == 3;
}
const bool kOracleVerified = oracle_self_check();
}  // namespace

[[nodiscard]] bool oracle_is_verified() { return kOracleVerified; }

}  // namespace rp_test
