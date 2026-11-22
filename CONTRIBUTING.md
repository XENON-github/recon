# Contributing

Thanks for helping. Recon is a security tool, so the bar is: **correct, bounded, tested, and honest about what it knows.**

## Build and test

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
ctest --test-dir build --output-on-failure
sudo ctest --test-dir build -R '^(syn|cli_e2e)$'     # privileged tests (otherwise they report SKIP)
```

No CMake? `./scripts/install.sh --build-only --test` builds and tests with just a compiler.

Before opening a pull request, also run:

```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DRECON_SANITIZER="address;undefined" && cmake --build build-asan -j && ctest --test-dir build-asan
cmake -S . -B build-tsan -DCMAKE_BUILD_TYPE=Debug -DRECON_SANITIZER=thread               && cmake --build build-tsan -j && ctest --test-dir build-tsan
cmake --build build --target format      # clang-format
```

CI runs GCC and Clang, C++17 and C++20, both sanitizer families, libFuzzer, clang-format and clang-tidy.

## Rules of the road

1. **Every behaviour change has a test, and you should have seen it fail.** Revert your fix locally and confirm the test catches the bug. Several real bugs in this project (endianness, a `strchr` NUL pitfall, TCP self-connect false positives) were only caught this way.
2. **Parsers treat input as hostile.** Pure functions, `string_view` or `detail::Reader`, no raw pointer arithmetic, no `strchr`/`strtok`/`sprintf`. Add a wire-accurate positive test, near-miss rejects, and a truncation test. Add new matchers to `fuzz/fuzz_matchers.cpp`.
3. **No unbounded anything**: sizes, times, queue depths, recursion depth.
4. **RAII for every descriptor, thread and handle.** No raw `new`/`delete`.
5. **Don't overstate.** Output distinguishes what a service *reported* from what recon *guessed*; keep it that way. Never invent a version.
6. **Docs are tested.** `tests/doc_test.py` runs every command line in `docs/MANUAL.md` and checks that every `--help` option is documented in the manual and man page. Update both when you add an option.
7. **Architecture changes go through the map.** The diagram, component tables and flows in `docs/ARCHITECTURE.md` are generated from `docs/architecture.json`. Edit the JSON and run `python3 scripts/gen_architecture.py`; it refuses a map that names a missing source file or an unconnected flow, and `tests/doc_test.py` fails if the document is stale.
8. Don't add dependencies without discussion. The build needs only a C++17 compiler (OpenSSL is optional).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and section 14 of the [manual](docs/MANUAL.md) (including how to add a protocol matcher).

## Reporting bugs and vulnerabilities

Bugs: use the issue templates. **Security issues: see [SECURITY.md](SECURITY.md); do not file them publicly.**

## Responsible use

Contributions must not add exploitation, credential-guessing or evasion features. Recon identifies; it does not attack.
