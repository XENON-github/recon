# Recon

[![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)
[![CodeQL](https://github.com/OWNER/REPO/actions/workflows/codeql.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/codeql.yml)
[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)

A fast, safe-by-default TCP/UDP port, service and OS scanner in modern C++: an `epoll` reactor, a raw-socket SYN scanner,
strict bounds-checked protocol parsers, honest confidence-scored output, and CI-friendly drift detection.

> **Authorization.** Only scan systems you own or have explicit written permission to test. Defaults are conservative
> (500 probes/s, 128 sockets in flight) and a notice is printed on every run.

## Install

Linux only. Pick whichever is easiest; **none of them needs `sudo` unless you ask for a system-wide install.**

| Method | Command | Needs |
|---|---|---|
| **Install script** (recommended) | `./scripts/install.sh` | a C++17 compiler (CMake is used if present, not required) |
| Install script, system-wide | `sudo ./scripts/install.sh` | same |
| Script + missing dependencies | `./scripts/install.sh --install-deps` | asks before using `sudo` for your distro's package manager |
| CMake | `cmake -S . -B build && cmake --build build -j && sudo cmake --install build` | CMake >= 3.16 |
| Docker | `docker build -t recon . && docker run --rm --network host recon <target> -pCT` | Docker |
| Release package | download the `.tar.gz` / `.deb` from the Releases page (checksums and build provenance included) | |

The script installs to `~/.local` for normal users (`/usr/local` as root), runs `recon --version` to verify, warns if the
directory is not on your `PATH`, and installs the man page, manual and shell completions. Useful flags:
`--test` (run the test suite first), `--prefix DIR`, `--no-openssl`, `--build-only`, `--uninstall`, `--deps` (print the
dependency command for your distro). OpenSSL (`libssl-dev`) is optional and adds TLS certificate inspection.
Uninstall removes only the files it installed.

## Quickstart

```bash
recon localhost -pCT                              # common TCP ports + service/version detection
recon 192.168.1.0/24 -pCT --dry-run               # preview: how many hosts and probes, time estimate; sends nothing
recon 192.168.1.0/24 -p 22,80,443 --rate 200     # a subnet, capped rate
recon host -A                                     # + OS inference
recon host --profile stealth                      # slow and quiet (20 probes/s, 8 sockets)
sudo recon host -sS -pAT                          # half-open SYN scan of all ports (or: setcap cap_net_raw+ep)
```

**In CI**: fail the pipeline when something new opens:

```bash
recon prod.example.internal -pCT --json -q -o today.json --baseline last_known_good.json
echo $?        # 0 = no change, 5 = NEW open ports (listed under "drift" in the JSON), 130 = interrupted
```

`./scripts/drift_cron.sh` wraps this for scheduled monitoring, and `./scripts/cert_expiry.py` warns about expiring TLS certificates.

**Documentation:** the [User Manual](docs/MANUAL.md) (also `man recon`) covers every option, output format, recipe, tuning rule,
error message and the exact network traffic recon sends. `recon --help` gives a summary.

## Features

| | |
|---|---|
| **Scan engines** | `epoll` connect scan (default) and raw-socket **SYN scan** (`-sS`, IPv4) with sequence-number validation; UDP scan with ICMP-based closed detection |
| **Safety** | Bounded in-flight sockets, token-bucket rate limit, per-probe deadlines, retries, graceful SIGINT with partial results, adaptive back-off on fd exhaustion, `MSG_NOSIGNAL`, fd-limit clamping, `--dry-run` |
| **Detection** | Passive banner + active probes (HTTP, TLS, Redis, PostgreSQL, SMB2); SSH/FTP/SMTP/POP3/IMAP/MySQL/VNC/Telnet/DNS/NTP/NetBIOS parsers; `tcpwrapped`; RTT-adaptive timeouts; TLS certificate inspection (OpenSSL) |
| **Honest output** | Every service has a `confidence` (0-100) and a `version_quality` of `reported` or `inferred`. A silent port is `unknown`, never a made-up version |
| **Targets** | IPv4, IPv6, hostnames, CIDR (with a host cap), `-iL` target files |
| **Output** | Table (colour on TTY, `NO_COLOR` honoured), strict-UTF-8 JSON, CSV (formula-injection safe), live progress line on stderr; report files are created private (`0600`) |
| **Automation** | Defined exit codes, `--fail-on-open`, `--baseline` drift detection, scan profiles |

### Example output (real run against a local lab with mock services)

```
================================================================================================
TARGET: 127.0.0.1
================================================================================================
PORT       STATE          SERVICE         CONF  VERSION / DETAILS
------------------------------------------------------------------------------------------------
33063/tcp  open           unknown         0     [no banner]
36249/tcp  open           ftp             92    vsftpd 3.0.5
38751/tcp  open           smtp            92    Postfix
39181/tcp  open           unknown         0     [no banner]
43633/tcp  open           http            95    nginx 1.24.0
43867/tcp  open           http            95    Apache 2.4.58 (Ubuntu)
43935/tcp  open           mysql           95    MySQL 8.0.36-0ubuntu0.22.04.1
45577/tcp  open           ssh             98    dropbear 2022.83 (protocol 2.0)
46017/tcp  open           redis           92    Redis 7.0.11
46187/tcp  open           ssh             98    OpenSSH 9.6p1 (protocol 2.0; Ubuntu-3ubuntu13.5)

DRIFT vs baseline baseline.json
  + NEW OPEN   127.0.0.1 33063/tcp (unknown)

================================================================================================
Scan completed in 2.31s | hosts 1 | probes 10 | open 10 | closed 0 | filtered 0 | retries 0
CPU 0.01s, peak RSS 4.06 MiB
Version column shows what the service reports; confidence < 50 marks port-number guesses (?).
```

The two `unknown` rows are open-but-silent mock services: recon says so instead of inventing a version. This run exited with code 5
because `--baseline` was an earlier scan that lacked one of the ports.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | scan completed |
| 1 | open ports found (`--fail-on-open`) |
| 2 | usage error |
| 3 | target could not be resolved or expanded |
| 4 | runtime/I-O error, no raw-socket permission for `-sS`, or every probe errored |
| 5 | new open ports compared with `--baseline` |
| 130 | interrupted; partial results are still written with `status: "cancelled"` |

## Security and quality

Recon treats everything a remote host sends as hostile. See [SECURITY.md](SECURITY.md) for the threat model and how to report a vulnerability privately.

| Area | What |
|---|---|
| Hardened builds | On by default: bounds-checked standard containers, `_FORTIFY_SOURCE`, stack protector, PIE, full RELRO, non-executable stack |
| Parsers | Pure functions over `string_view` with a bounds-checked reader; sanitized, length-capped text; strict JSON with depth and node limits |
| C++ tests | 109 unit and integration tests (CTest): mock servers on loopback, slow-drip/reset/flood peers, fd-leak and cancellation checks, a differential SYN-vs-connect test, forged-reply injection |
| End-to-end | 21 tests drive the real binary against Python mock services, including real TLS 1.2/1.3 servers, drift detection, `--dry-run`, the helper scripts, private output files, exit codes and SIGINT handling |
| Documentation | `tests/doc_test.py` executes every `recon` command line in the manual, requires every `--help` option to be documented in the manual and man page, compares the manual's sample output with the real output, and checks that the architecture map (`docs/architecture.json`) matches the source tree and that `docs/ARCHITECTURE.md` is up to date |
| Sanitizers | Full suite clean under ASan+UBSan and TSan (GCC 13) |
| Fuzzing | 3 targets (protocol matchers, JSON/baseline, input parsers); 400k iterations each clean under ASan+UBSan; libFuzzer jobs in CI |
| Mutation checks | 19 deliberately re-introduced bugs (SIGPIPE, endianness, ignored retries/cancellation, self-connect, unvalidated SYN-ACKs, symlink-following output, missing JSON limits, ...): each caught by the suite |
| CI | GCC/Clang x C++17/20, OpenSSL on/off, sanitizers, libFuzzer, clang-format, clang-tidy, CodeQL; tagged releases are built, tested, checksummed and attested |

### Engineering notes: bugs that tests and fuzzing found

* **SIGPIPE** killed the whole scan when a service reset a connection (exit 141, no output): original code; reproduced, fixed, regression-tested.
* **Endianness**: MySQL packet lengths and SMB2 fields are little-endian; a big-endian reader would have rejected every real MySQL server. Caught by wire-accurate test vectors.
* **`strchr` NUL pitfall**: `strchr(set, '\0')` is non-null, so a NUL byte in a banner counted as a valid version character. Found by the fuzzer, not by hand-written tests.
* **TCP self-connect**: connecting to `127.0.0.1:P` with `P` in the ephemeral range can connect a socket *to itself*, producing phantom "open" ports in full-range loopback sweeps. Reproduced deterministically and fixed.
* **Spoofed SYN-ACKs**: the SYN scanner only believes replies that acknowledge its own random sequence number; tested by flooding forged replies at every source port.
* **Output-file hijacking**: `-o` follows no symlinks and creates `0600` files; tested against a planted symlink.

## Known gaps

* Linux only (`epoll`, raw sockets).
* SYN scan is IPv4 only, does not parse ICMP unreachables (blocked ports time out and are reported `filtered`), and does not drop capabilities after opening its raw sockets. Prefer `setcap cap_net_raw+ep` to running as root; never install it setuid.
* IPv6 parsing and CIDR are unit-tested, but IPv6 *networking* was not exercised end to end.
* TLS certificate inspection (`src/tls_openssl.cpp`) needs OpenSSL. It was type-checked against stub headers but not compiled against real OpenSSL by the author; CI builds it when `libssl-dev` is present.
* SMB2 negotiation is unit-tested against a wire-accurate response but was not checked against a real Windows/Samba server.
* OS detection is evidence aggregation, not fingerprinting (TTL-only evidence is capped at 40-50%); IPv6 hop-limit probing is not implemented.
* UDP closed-port detection depends on ICMP, which Linux rate-limits, so large UDP sweeps under-report `closed`.
* Servers that greet slowly may look silent unless you raise `--banner-wait`.
* The project was developed against GCC 13. Clang builds, the CMake build and the CI/release workflows are validated by CI; the first push may need `cmake --build build --target format` (clang-format was not available during development).

## Roadmap

1. External signature database (YAML/JSON) so probes can be added without recompiling.
2. ICMP unreachable handling in the SYN scanner; BPF receive filter; IPv6 SYN scan; dropping capabilities after raw-socket setup.
3. IPv6 end-to-end CI lab; ICMPv6 OS probing.
4. Host discovery (ARP/ICMP/TCP ping) and scan resume.
5. Published comparisons against other scanners on real multi-host lab topologies.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md): every behaviour change needs a test you have seen fail, parsers treat input as hostile, and docs are tested.
Please report security issues privately as described in [SECURITY.md](SECURITY.md).

## License

GPL-3.0, see [LICENSE](LICENSE). The optional TLS inspection links OpenSSL; OpenSSL 3.x is Apache-2.0 licensed and compatible with the GPL-3.0.
OpenSSL 1.1.x uses a license that is **not** GPL-compatible without an exception, so build with `--no-openssl` (or `-DRECON_WITH_OPENSSL=OFF`) if you target OpenSSL 1.1.
(This is a general note, not legal advice.)
