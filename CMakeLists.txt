cmake_minimum_required(VERSION 3.24)

project(RouteProvenance
  VERSION 1.0.0
  DESCRIPTION "Route Provenance - authoritative route-lineage, derivation-history and evidence-binding runtime"
  HOMEPAGE_URL "https://github.com/summonlabs/Route-Provenance"
  LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(RP_BUILD_TOOLS "Build the coordinator, publisher and rpctl command line tools" ON)
option(RP_BUILD_EXAMPLES "Build the public-API examples" ON)
option(RP_BUILD_TESTS "Build the validation suites" ON)
option(RP_BUILD_BENCHMARKS "Build the benchmark harness" ON)
option(RP_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)
option(RP_ENABLE_ANALYZE "Enable the MSVC static analyzer for first-party targets" OFF)
option(RP_ENABLE_ASAN "Enable AddressSanitizer when the toolchain supports it" OFF)

if(RP_ENABLE_ANALYZE AND NOT MSVC)
  message(FATAL_ERROR "RP_ENABLE_ANALYZE requires MSVC")
endif()

# ---------------------------------------------------------------------------
# First-party compile settings. Every target in this project is first-party, so the warning
# policy is applied uniformly: no target opts out of warnings.
# ---------------------------------------------------------------------------
function(rp_configure_target target)
  target_compile_features(${target} PRIVATE cxx_std_20)
  set_target_properties(${target} PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc)
    if(RP_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
    if(RP_ENABLE_ANALYZE)
      # Every translation unit in this project is first-party, so no external-header
      # suppression is needed and none is configured.
      target_compile_options(${target} PRIVATE /analyze)
    endif()
    if(RP_ENABLE_ASAN)
      target_compile_options(${target} PRIVATE /fsanitize=address)
      target_link_options(${target} PRIVATE /fsanitize=address)
    endif()
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    if(RP_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
set(RP_LIBRARY_SOURCES
  src/core.cpp
  src/graph.cpp
  src/store.cpp
  src/store_api.cpp
  src/store_query.cpp
  src/persistence.cpp
  src/codec.cpp
  src/wire.cpp
  src/net.cpp)

add_library(route_provenance ${RP_LIBRARY_SOURCES})
add_library(SummonSoftwareLabs::RouteProvenance ALIAS route_provenance)
rp_configure_target(route_provenance)

set_target_properties(route_provenance PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  # Alias targets are not exported, so the installed target name is set explicitly. Consumers
  # link ${namespace}RouteProvenance in both the build tree and the installed package.
  EXPORT_NAME RouteProvenance)

target_include_directories(route_provenance
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

if(WIN32)
  target_link_libraries(route_provenance PRIVATE ws2_32)
endif()

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
set(RP_TOOL_TARGETS "")
if(RP_BUILD_TOOLS)
  foreach(tool rp_coordinator rp_publisher rpctl)
    add_executable(${tool} tools/${tool}.cpp)
    rp_configure_target(${tool})
    target_link_libraries(${tool} PRIVATE SummonSoftwareLabs::RouteProvenance)
    list(APPEND RP_TOOL_TARGETS ${tool})
  endforeach()
endif()

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------
set(RP_EXAMPLE_TARGETS "")
if(RP_BUILD_EXAMPLES)
  set(RP_EXAMPLES
    ex_initial_lineage
    ex_supersession
    ex_path_authority
    ex_adaptive_decision
    ex_convergence
    ex_rollback
    ex_historical_currentness
    ex_worker_reincarnation
    ex_coordinator_restart)
  foreach(example ${RP_EXAMPLES})
    add_executable(${example} examples/${example}.cpp)
    rp_configure_target(${example})
    target_link_libraries(${example} PRIVATE SummonSoftwareLabs::RouteProvenance)
    list(APPEND RP_EXAMPLE_TARGETS ${example})
  endforeach()
endif()

# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------
if(RP_BUILD_BENCHMARKS)
  add_executable(rp_bench benchmarks/rp_bench.cpp)
  rp_configure_target(rp_bench)
  target_compile_definitions(rp_bench PRIVATE
    RP_BENCH_SCRATCH_FILE="${CMAKE_CURRENT_BINARY_DIR}/bench-store.rpstore")
  target_link_libraries(rp_bench PRIVATE SummonSoftwareLabs::RouteProvenance)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(RP_BUILD_TESTS)
  enable_testing()
  add_executable(rp_tests
    tests/harness.cpp
    tests/test_unit.cpp
    tests/test_store.cpp
    tests/test_persistence.cpp
    tests/test_wire.cpp
    tests/test_race.cpp
    tests/test_property.cpp
    tests/test_adversarial.cpp
    tests/test_oracle.cpp
    tests/test_scale.cpp
    tests/test_distributed.cpp
    tests/oracle.cpp
    tests/main.cpp)
  rp_configure_target(rp_tests)
  target_include_directories(rp_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
  target_link_libraries(rp_tests PRIVATE SummonSoftwareLabs::RouteProvenance)
  target_compile_definitions(rp_tests PRIVATE
    RP_TEST_SCRATCH_DIR="${CMAKE_CURRENT_BINARY_DIR}/test-scratch"
    RP_TEST_BINARY_DIR="${CMAKE_CURRENT_BINARY_DIR}")
  if(RP_BUILD_TOOLS)
    target_compile_definitions(rp_tests PRIVATE
      RP_COORDINATOR_EXE="$<TARGET_FILE:rp_coordinator>"
      RP_PUBLISHER_EXE="$<TARGET_FILE:rp_publisher>")
  endif()

  # No test timeout is configured anywhere: a hang is a defect, and every bounded wait inside
  # the suites fails explicitly instead.
  set(RP_SUITES unit store persistence wire race property adversarial oracle scale distributed)
  foreach(suite ${RP_SUITES})
    add_test(NAME rp_${suite} COMMAND rp_tests --suite ${suite})
  endforeach()
  if(RP_BUILD_BENCHMARKS)
    add_test(NAME rp_benchmarks COMMAND rp_bench --small)
  endif()
  foreach(example ${RP_EXAMPLE_TARGETS})
    add_test(NAME ${example} COMMAND ${example})
  endforeach()
endif()

# ---------------------------------------------------------------------------
# Install and package export
# ---------------------------------------------------------------------------
install(TARGETS route_provenance
  EXPORT RouteProvenanceTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(RP_TOOL_TARGETS)
  install(TARGETS ${RP_TOOL_TARGETS} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(DIRECTORY include/route_provenance DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT RouteProvenanceTargets
  FILE RouteProvenanceTargets.cmake
  NAMESPACE SummonSoftwareLabs::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/RouteProvenance)

configure_package_config_file(
  cmake/RouteProvenanceConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/RouteProvenanceConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/RouteProvenance)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/RouteProvenanceConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/RouteProvenanceConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/RouteProvenanceConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/RouteProvenance)

install(FILES LICENSE README.md DESTINATION ${CMAKE_INSTALL_DATADIR}/RouteProvenance)
