# Relinker fuzzing archive, 2026-11-19

This orphan branch only stores fuzzing results. It shares no history with `main` and must not be merged into it or included in a pull request.

## Provenance

| Item | Value |
| --- | --- |
| Upstream base | `boykopovar/AnyPS5` `main` at `74f685158e104f717fd267a6a25a28909b70f3b7` |
| Code under test | `e32764d9ed` (part A, extended options) and `6179877ab5` (part B, guest modules) on `claude/fervent-ptolemy-bjhil3` |
| Host | Linux 6.18 x86-64 container, 4 cores, no GPU |
| Toolchain | Ubuntu clang 18.1.3, `libclang-rt-18-dev`, LLVM 18.1.3 (`llvm-profdata`, `llvm-cov`), GCC 13.3.0, CMake 3.28.3, Ninja, Python 3.13 |
| Inputs | Synthetic executables and modules built by the relinker's Python tests (`tools/relinker_fuzz_seeds.py`); no game files |

## Contents

| Path | What it is |
| --- | --- |
| `corpora/corpus-conversion-min.tar.xz` | `relinker_conversion_fuzzer` corpus after both A campaigns, minimized with `-merge=1` (2,491 files) |
| `corpora/corpus-guest-min.tar.xz` | `relinker_guest_module_fuzzer` corpus after campaign B, minimized with `-merge=1` (1,325 files) |
| `corpora/seeds-conversion-extended.tar.xz` | Seeds of campaign A after: `relinker_fuzz_seeds.py --extended-options` (2,160 files) |
| `corpora/seeds-guest.tar.xz` | Seeds of campaign B: `relinker_fuzz_seeds.py --guest-modules --extended-options` (440 files) |
| `logs/campaign-*.log.xz` | libFuzzer output of the three 20-minute campaigns |
| `coverage/coverage-*.txt.xz` | `llvm-cov report` per source file (see below) |
| `tests/ctest-*.log.xz` | Full CTest runs: GCC on `main`, GCC on the branch, Clang ASan/UBSan on the branch |
| `patches/*.patch` | `git format-patch` of the two commits |
| `SHA256SUMS` | SHA-256 of every other file; check with `sha256sum -c SHA256SUMS` |

## Results

| Campaign | Fuzzer | Executions | libFuzzer coverage | Crashes / timeouts / OOMs |
| --- | --- | ---: | ---: | --- |
| A before | `main` | 1,602,172 | 19,814 | 0 / 0 / 0 |
| A after | branch, extended options | 1,166,057 | 25,012 | 0 / 0 / 0 |
| B | branch, guest modules | 2,050,091 | 20,975 | 0 / 0 / 0 |

| llvm-cov report | Lines | Functions | Branches |
| --- | ---: | ---: | ---: |
| `coverage-before` (old fuzzer, A-before corpus) | 45.76 % | 45.45 % | 35.42 % |
| `coverage-after` (new fuzzer, A-after corpus) | 54.37 % | 54.74 % | 41.06 % |
| `coverage-guest-after` (guest fuzzer, B corpus) | 51.27 % | 51.48 % | 34.45 % |
| A and B profiles merged | 63.29 % | 61.15 % | 48.67 % |

`coverage-legacy-old` and `coverage-legacy-new` replay the 2,768 A-before inputs whose first byte keeps its old meaning through the old and the new fuzzer; they are identical file by file. `coverage-compat` replays the whole A-before corpus through the new fuzzer: 178 mutated inputs whose first byte was already 24 or more are decoded with extended options, hence 45.00 %. `coverage-guest-seeds` replays only the B seeds.

## Reproduce

```sh
git clone https://github.com/mkr2tl-hue/AnyPS5 anyps5 && cd anyps5
git checkout 6179877ab5
cmake -S . -B build-fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DANYPS5_RELINKER_ONLY=ON -DANYPS5_BUILD_FUZZERS=ON -DBUILD_TESTING=ON -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
cmake --build build-fuzz --parallel
git fetch origin archive/relinker-fuzzing-2026-11-19
git worktree add ../fuzz-archive FETCH_HEAD
(cd ../fuzz-archive && sha256sum -c SHA256SUMS)
mkdir -p ../fuzz-run && tar -xJf ../fuzz-archive/corpora/corpus-conversion-min.tar.xz -C ../fuzz-run && tar -xJf ../fuzz-archive/corpora/corpus-guest-min.tar.xz -C ../fuzz-run
build-fuzz/tests/relinker_conversion_fuzzer -runs=0 ../fuzz-run/min-conversion
build-fuzz/tests/relinker_guest_module_fuzzer -runs=0 ../fuzz-run/min-guest
```

Campaigns, run from an empty working directory so findings land there:

```sh
build-fuzz/tests/relinker_conversion_fuzzer ../fuzz-run/min-conversion -fork=4 -max_total_time=1200 -timeout=20 -rss_limit_mb=3000 -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1
build-fuzz/tests/relinker_guest_module_fuzzer ../fuzz-run/min-guest -fork=4 -max_total_time=1200 -timeout=20 -rss_limit_mb=3000 -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1
```

Fresh seeds instead of the archived corpora:

```sh
python3 tools/relinker_fuzz_seeds.py seeds-conversion --extended-options
python3 tools/relinker_fuzz_seeds.py seeds-guest --guest-modules --extended-options
```

Line coverage: configure a second tree with `-DBUILD_TESTING=OFF "-DCMAKE_CXX_FLAGS=-fprofile-instr-generate -fcoverage-mapping" -DCMAKE_EXE_LINKER_FLAGS=-fprofile-instr-generate`, build the fuzzer target, then:

```sh
LLVM_PROFILE_FILE=run-%p.profraw build-cov/tests/relinker_conversion_fuzzer -runs=0 ../fuzz-run/min-conversion
llvm-profdata merge -sparse run-*.profraw -o run.profdata
llvm-cov report build-cov/tests/relinker_conversion_fuzzer -instr-profile=run.profdata -ignore-filename-regex='(/usr/|3rdparty|/fuzz/)'
```

The archived minimized corpora merge both A campaigns, so replaying them does not reproduce the per-campaign figures above exactly; the per-campaign reports are in `coverage/`.

## Limits

No campaign found a crash, timeout or out-of-memory input, so these results fix no bug. Game patches, icons and runtime directories are not fuzzed. The fuzzers run only on Linux with Clang. Each campaign ran 20 minutes on 4 cores.
