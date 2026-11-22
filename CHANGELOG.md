# Changelog

All notable changes are documented here. Format based on [Keep a Changelog](https://keepachangelog.com/), versioning by [SemVer](https://semver.org/).

## [2.1.0]

### Added
- Raw-socket **SYN scan** (`-sS`, IPv4) with sequence-number validation of replies.
- **Baseline drift detection** (`--baseline`, exit code 5) backed by a strict, bounded JSON parser; `scripts/drift_cron.sh`.
- `--profile quick|standard|full|stealth`, `-iL` target files, live progress line, colour output (`NO_COLOR` honoured), `--dry-run`.
- `--banner-wait` for slow-greeting servers; RTT-adaptive detection timeouts; `tcpwrapped` detection.
- `scripts/cert_expiry.py`; bash/zsh completions; man page; full user manual (`docs/MANUAL.md`) whose examples are executed by the test suite.
- Install script that needs only a compiler (CMake optional), per-user default prefix, `--install-deps`, `--uninstall`.
- Fuzz targets (matchers, JSON/baseline, input parsers); mutation-checked tests.
- Architecture documentation generated from `docs/architecture.json` (stages, components, flows) and verified against the source tree by the test suite.
- Hardened builds by default (`_GLIBCXX_ASSERTIONS`, fortify, stack protector, PIE, RELRO).

### Security
- `-o` creates files with mode `0600` and refuses symbolic links.
- JSON parser: node-count limit (memory amplification), depth limit, UTF-8 validation.
- `-iL` lines are length-bounded.

### Fixed
- Connect scan reported phantom open ports on loopback (TCP self-connect); now detected and classed closed.
- NUL byte in a banner was accepted as a version character (`strchr` pitfall).
- A connect that completes and is then reset is now correctly `open`.
- Reset-after-handshake is handled consistently by the detector.

## [2.0.0]

### Changed
- Rewritten around an `epoll` reactor with bounded concurrency, timeouts, retries, rate limiting and cancellation.
- Strict protocol parsers with confidence scores; JSON and CSV output; defined exit codes; CMake build; sanitizer-clean test suite.

### Fixed
- Scan was killed by `SIGPIPE` when a service reset a connection (exit 141, no output).
- `-p 80abc` was accepted as port 80.
- Removed a destructive `rm -rf` from the old `install.sh`; removed the claim that TTL can be read from TCP handshakes (Linux does not provide it).

## 1.x

Original implementation (thread-per-connection scanner, banner grabbing, OS guess).
