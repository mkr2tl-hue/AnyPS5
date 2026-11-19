Title: test(relinker): fuzz the conversion options the command line and web converter reach

### What

`relinker_conversion_fuzzer` only varied the target system, `--to-intel` and the `unused-filter` level. The other conversion options were never fuzzed, including `--windows-diagnostics`, which the web converter sets for every Windows conversion.

- `core/relinker/fuzz/FuzzOptions.hpp` decodes the input. The first byte keeps its meaning. When the byte shifted right by 3 is 3 or more, two more bytes select `--to-rosetta`, `--to-avx`, `--frame-red-zone`, `--lazy-binding`, `--skip-syscall-check`, `--trap-sdk-syscall-stubs`, `--function-symbol-roots`, `--omit-unavailable-dependencies`, `--windows-gui`, `--trace-imports`, `--windows-diagnostics` and the target's fixed base. An option that `CliArgs.cpp` refuses with the selected target or another selected option is dropped; `--to-rosetta` and `--to-avx` turn on `--to-intel`, as on the command line.
- `relinker_fuzz_options` checks that the 24 legacy selectors decode as before and that each of the 393,216 extended configurations passes the option checks of `Conversion::Convert`: with an empty executable the only error is `File too small for ELF header`. Removing the macOS-only rule for `--to-avx` makes it fail with the conversion's own message.
- `tools/relinker_fuzz_seeds.py --extended-options` adds one seed per target system and option; the default and `--all-configurations` seeds are unchanged.
- `docs/dev/BUILD.md` describes the input format.

### Tested

Linux x86-64 (4 cores), GCC 13.3.0 and Clang 18.1.3 with `libclang-rt-18-dev`, relinker only.

- GCC Release, `-DANYPS5_RELINKER_ONLY=ON -DBUILD_TESTING=ON`: 1011/1011 on `main` (74f685158e), 1012/1012 with this change. `relinker_fuzz_options` takes 2.4 s.
- Clang fuzzing build (`-DANYPS5_BUILD_FUZZERS=ON`, ASan and UBSan): all CTest cases pass, including `relinker_conversion_fuzzer` and `relinker_fuzz_options` (36 s under ASan).
- 20-minute campaigns, `-fork=4 -timeout=20 -rss_limit_mb=3000`: `main` from 216 seeds made 1,602,172 executions; this change from 2,160 seeds made 1,166,057. No crash, timeout or out-of-memory input in either.
- `llvm-cov` line coverage of the relinker sources (3rdparty, system headers and `core/relinker/fuzz` excluded), replaying each final corpus: 45.76 % on `main`, 54.37 % with this change. Newly reached: `WindowsDependencyStubBuilder.cpp` 0 to 711/711 lines, `RedZoneFramer.cpp` 0 to 187/605, `StrictReachability.cpp` 7 to 182/196, and the Rosetta and AVX lowerings.
- Replaying the 2,768 inputs of the `main` corpus whose first byte keeps its meaning through the old and the new fuzzer gives identical per-file coverage.
- `python3 tools/check_conventions.py --base origin/main` passes.

Corpora, logs and coverage reports: https://github.com/mkr2tl-hue/AnyPS5/tree/archive/relinker-fuzzing-2026-11-19

### Checklist
<!-- Rules behind each item: https://github.com/boykopovar/AnyPS5/blob/main/CONTRIBUTING.md -->
- [x] Based on current `main`; no other open PR implements the same functions
- [x] One topic per PR; follow-ups go in a new PR
- [x] No comments in code except [technical debt](https://github.com/boykopovar/AnyPS5/blob/main/docs/dev/CONVENTIONS.md) and the licence notice of code adapted from upstream (see AGENTS.md)
- [x] Unimplemented paths throw (`NotImplemented_nid_no_patch`); silent stubs are listed under Silent stubs in their library's [technical debt](https://github.com/boykopovar/AnyPS5/tree/main/docs/dev/debt) file
- [x] No notes, investigation `.md` files or images added to the repository (attach them to this PR)
- [x] New third-party code is a submodule built from source
- [x] Generic behaviour, not specific to one title
- [x] Depends on: none
- [x] Fixes: none
- [x] Unblocks: none
- [x] GPUs tested: n/a
- [x] AI-assisted: yes

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01K8jaqaV3jxmjnPFRfdH5uj
