# Route Provenance validation report

This report records what was actually executed and observed for Route Provenance 1.0.0. Every
figure below was produced by the commands shown, on the host described. Nothing in this report is
a projection.

## Environment

| Item | Value |
| --- | --- |
| Operating system | Windows 11 (10.0.26200), x64 |
| CPU | AMD Ryzen 7 9800X3D, 8 cores / 16 threads |
| Compiler | MSVC 19.44.35207 (Visual Studio 2022 17.14) |
| CMake | 4.3.2 |
| Transport | loopback TCP (Winsock2) |

## Build matrix

| Configuration | Flags | Result |
| --- | --- | --- |
| Release | `/W4 /WX /permissive- /Zc:__cplusplus /utf-8` | clean, zero first-party warnings |
| Debug | same, plus the debug runtime checks | clean, zero first-party warnings |
| Release + `/analyze` | `RP_ENABLE_ANALYZE=ON` | zero first-party analyzer findings |
| Release + ASan | `RP_ENABLE_ASAN=ON` | not supported on this host, see below |

## Test results

`ctest -C Release` and `ctest -C Debug`: **20 of 20 tests pass** in both configurations.

The twenty tests are the ten validation suites plus the nine examples and the benchmark harness.

| Suite | Tests | What it proves |
| --- | --- | --- |
| unit | 19 | identity validity and non-wrapping, canonical encoding, SHA-256 vectors, evidence canonicalisation, content-addressed record and derivation identity, lifecycle transitions, scope default-deny, outcome classification, bounded traversal, limits validation |
| store | 22 | root and predecessor rules, supersession lineage, replay idempotency, conflicting replay, duplicate record detection, stale route and expected-generation rejections, path/policy/evidence demotion, withdrawal, revocation versus invalidation, retirement, rollback, correction, declared authorities, fencing, epoch staleness, deterministic rejection precedence, every configured limit, snapshots and diffs, compaction, statistics |
| persistence | 5 | round trip, conservative recovery, revalidation, corruption matrix (empty, bad magic, unsupported version, every-byte truncation, trailing bytes, bit flips), structural corruption (duplicate record, missing endpoint, cycle, invalid generation, impossible lifecycle, absurd counts), atomic replacement |
| wire | 5 | frame round trip, tamper detection, unknown message/version/oversize/header/reserved rejection, field-bag structural abuse, message codecs, response bodies |
| race | 7 | route advance versus late completion, path invalidation versus late completion, epoch advance versus late completion, fence versus publication, retirement versus publication, queries during correction, persistence snapshot versus mutation |
| property | 3 | seeded randomised schedules with invariants, replay never advances generations, insertion order independence |
| adversarial | 7 | malformed and zero identities, cycle injection without partial mutation, duplicate records and edges, forged and stale authority, traversal exhaustion, resource exhaustion, wire attacks |
| oracle | 2 | differential agreement with an independent graph implementation (acceptance, ancestry, descendants, topological order) |
| scale | 3 | 1,000 lineages with round trip, 10,000 lineages with exact reverse-index answers, 400-generation deep chain and a broad DAG |
| distributed | 5 | real OS processes: worker death with fencing and reincarnation, coordinator restart with monotonic epochs, partial and malformed peers, session limits and clean shutdown, wire-enforced query bounds |

## Real-process proofs

All of these ran with real coordinator and publisher processes over loopback TCP.

* **Worker death**: a publisher published route generations 1 and 2, was confirmed alive, was
  terminated with a real OS kill, and the coordinator fenced the boot through its independent
  liveness probe. The lineage's currentness moved to `FENCED_PUBLISHER`, both historical records
  remained historically valid, the fenced boot was permanently refused a new registration, a
  fresh boot for the same publisher was accepted and published generation 3, the fenced boot
  stayed fenced, and an unrelated live publisher was unaffected.
* **Coordinator restart**: the lineage was published, persisted and the coordinator was
  hard-killed. The restarted coordinator loaded the store, advanced the epoch monotonically,
  reproduced the lineage exactly (identity, record identity, counts, generation), refused an
  old-epoch registration, required explicit revalidation before records were current again, and
  extended the lineage afterwards. Two consecutive restarts were performed.
* **Partial frame**: a peer that sent an incomplete frame was disconnected inside the configured
  assembly budget (400 ms in the test); a peer that sent garbage was disconnected as well; the
  coordinator kept serving real clients afterwards.
* **Session limit**: a third session beyond `--max-sessions 2` was refused, and a clean shutdown
  exited with status 0 and a persisted store.

## AddressSanitizer diagnosis

Genuine x64 MSVC AddressSanitizer is **not available** in this environment. The evidence:

```
> cl /std:c++20 /EHsc /Zi /fsanitize=address probe.cpp
LINK : fatal error LNK1104: cannot open file 'clang_rt.asan_static_runtime_thunk-x86_64.lib'
```

A recursive search of the Visual Studio installation found only the i386 sanitizer runtime
(`clang_rt.asan_dynamic-i386.dll`, `clang_rt.asan_dynamic-i386.lib`,
`clang_rt.asan_static_runtime_thunk-i386.lib`); no `x86_64` runtime, static or dynamic, is
installed, and no `clang-cl`, GCC or Clang toolchain is present on the host. The
`RP_ENABLE_ASAN` option exists, forwards `/fsanitize=address` to the compiler and linker, and
fails at link time on this host for exactly this reason.

As a compensating control the Debug configuration was used, which enables the MSVC debug runtime
checks (stack frame checks, uninitialised-variable checks and iterator debugging) and all twenty
tests pass under it.

## Scale figures

The scale suite and the benchmark harness label their workloads as synthetic. They are evidence
about provenance volume and graph shape, not about any physical network. Representative
observations from the small benchmark mode (1,000 lineages, 64-generation chain):

```
publication_initial      operations=1000  total_ms=9     us_per_operation=9
publication_supersession operations=63    total_ms=9     us_per_operation=150
explanation_deep_chain   operations=63    total_ms=0     us_per_operation=2
ancestry_query           operations=64    total_ms=0     us_per_operation=1
snapshot_and_digest      operations=1     total_ms=0     us_per_operation=214
persistence_save         operations=1     total_ms=7     us_per_operation=7592
persistence_load         operations=1     total_ms=19    us_per_operation=19070
```

These numbers are machine-specific observations of completed operations, not guarantees.

## Installed package

`cmake --install` produces a package whose exported target is
`SummonSoftwareLabs::RouteProvenance` together with `RouteProvenanceConfig.cmake` and a version
file reporting 1.0.0. An independent consumer project outside the source tree configures,
compiles and links against the installed package, creates a route lineage (generation 1 initial,
generation 2 derived from generation 1, generation 3 superseding generation 2), queries the
ancestry, verifies the exact structured reason `SUPERSEDES:ROUTE_REPLACED` and verifies that the
snapshot digest is deterministic, then exits 0.

During this validation the package export was found to be missing the documented target name:
alias targets are not exported by CMake, so the first consumer attempt failed to link
`SummonSoftwareLabs::RouteProvenance`. The library target now sets `EXPORT_NAME RouteProvenance`
and the installed package exports exactly that name.

## Not supported

Physical switch programming, physical packet tracing, cryptographically attested or signed
provenance, multi-host consensus, split-brain prevention and any integration with a provider that
is not present in this repository are **not implemented**. Route Provenance makes no claim about
them. Provenance integrity is checked with SHA-256 content digests; it is not cryptographically
authenticated against a hostile publisher.
