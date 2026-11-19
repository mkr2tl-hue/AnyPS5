Title: test(relinker): fuzz the conversion of guest modules

### What

No fuzzer passed guest modules to the conversion, so `GuestImageReader` and `GuestModuleBuilder` were never fuzzed, although the web converter converts the modules a user selects.

- `relinker_guest_module_fuzzer` decodes the selector and option bytes of `relinker_conversion_fuzzer`, then records of a 4-byte little-endian length and that many bytes: the executable, then up to four pairs of a module file name and the module's bytes, read from `/input/sce_module`. A name that is empty, longer than 64 bytes, `.`, `..` or holds a byte outside `A-Z`, `a-z`, `0-9`, `.`, `_` and `-` becomes `libFuzz<index>.prx`. `--lazy-binding` is dropped, as guest modules require eager binding.
- `relinker_fuzz_options` also checks the record splitting and module names.
- `tools/relinker_fuzz_seeds.py --guest-modules` writes its seeds: an executable that imports the provider of `test_guest_gnu_hash.py`, and the standalone fixture executable with each module the relinker's Python tests build without arguments.
- CTest runs 20000 inputs from an empty corpus as `relinker_guest_module_fuzzer`; `docs/dev/BUILD.md` gives the commands.

### Tested

Linux x86-64 (4 cores), GCC 13.3.0 and Clang 18.1.3 with `libclang-rt-18-dev`, relinker only, on top of the options change.

- GCC Release, `-DANYPS5_RELINKER_ONLY=ON -DBUILD_TESTING=ON`: 1012/1012.
- Clang fuzzing build with ASan and UBSan: 769/769, including both fuzzers.
- 20-minute campaign from 440 seeds, `-fork=4 -timeout=20 -rss_limit_mb=3000`: 2,050,091 executions, no crash, timeout or out-of-memory input.
- `llvm-cov` line coverage: `GuestImageReader.cpp` 0 to 420/514 lines, `GuestModuleBuilder.cpp` 15 to 572/709. With the profile of the options fuzzer merged, the relinker sources reach 63.29 % of lines, from 45.76 % on `main`.
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
- [x] Depends on: #<number of the options PR>
- [x] Fixes: none
- [x] Unblocks: none
- [x] GPUs tested: n/a
- [x] AI-assisted: yes

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01K8jaqaV3jxmjnPFRfdH5uj
