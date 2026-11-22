# Recon User Manual

**Version 2.1** · TCP/UDP port, service and OS scanner

This manual covers installation, concepts, every command-line option, the output formats, scripting and CI use,
tuning, troubleshooting and the exact network traffic recon generates. Every `recon` command line in it is
executed (with `--dry-run`) by the test suite, so the examples are known to parse.

## Contents

1. [Introduction](#1-introduction)
2. [Installation](#2-installation)
3. [A five-minute tour](#3-a-five-minute-tour)
4. [Concepts](#4-concepts)
5. [Command reference](#5-command-reference)
6. [Output reference](#6-output-reference)
7. [Exit codes and scripting](#7-exit-codes-and-scripting)
8. [Recipes](#8-recipes)
9. [Tuning guide](#9-tuning-guide)
10. [Interpreting results](#10-interpreting-results)
11. [Troubleshooting](#11-troubleshooting)
12. [What recon sends on the network](#12-what-recon-sends-on-the-network)
13. [Handling results safely](#13-handling-results-safely)
14. [Development guide](#14-development-guide)
15. [Limitations](#15-limitations)
- [Appendix A: port lists](#appendix-a-port-lists) · [Appendix B: JSON schema](#appendix-b-json-schema) · [Appendix C: glossary](#appendix-c-glossary) · [Appendix D: legacy flags](#appendix-d-legacy-flags)

---

## 1. Introduction

### 1.1 What recon is

Recon answers three questions about a host or network you are responsible for:

1. **Which TCP/UDP ports are reachable?** (connect scan, or raw-socket SYN scan)
2. **What is listening on them?** (banner grabbing and protocol probes, with an explicit confidence score)
3. **What changed since last time?** (baseline comparison, built for CI and scheduled monitoring)

It is built for **safety and honesty**: conservative default rates, bounded resource use, strict parsing of everything a remote
host sends, and output that distinguishes what a service *reported* from what recon merely *guessed*.

### 1.2 What recon is not

* Not a vulnerability scanner: it does not test for or exploit flaws, and never sends credentials.
* Not a host-discovery tool: it does not ping-sweep. Every target in the list is probed.
* Not a replacement for Nmap's script engine or its decades-old fingerprint database. Recon's signature set is small and deliberately conservative.
* OS detection is **inference from evidence**, not fingerprinting (see [4.7](#47-os-inference)).

### 1.3 Authorization and legal

> **Only scan systems you own or have explicit, written permission to test.** Unauthorized scanning may violate computer-misuse
> laws, acceptable-use policies and cloud-provider terms, and may trigger intrusion-detection responses or abuse reports.

Good practice: record the scope and permission before you start; scan during an agreed window; start with `--profile stealth` or a low
`--rate`; use `--dry-run` to confirm the target list and probe count first; keep results under access control ([section 13](#13-handling-results-safely)).
Recon prints an authorization reminder on stderr on every run (suppress with `-q` once you have read it).

### 1.4 Conventions

* `recon` is the installed binary. If you have not installed it, use `build/recon`.
* `<angle brackets>` are placeholders; `[square brackets]` are optional.
* Commands marked with `sudo` need root or the `cap_net_raw` capability.
* Hostnames such as `example.internal` and `app.example.lan` are placeholders for hosts in *your* environment.

---

## 2. Installation

### 2.1 Requirements

| Requirement | Notes |
|---|---|
| Linux | `epoll` and Linux socket semantics are required. macOS/BSD/Windows are not supported. |
| C++17 compiler | GCC 9+ or Clang 10+ recommended (developed with GCC 13). C++20 is also supported and enables `std::jthread`. |
| CMake ≥ 3.16 | |
| Python 3 | Optional. Used by the end-to-end tests, the manual's doc-test and the helper script `scripts/cert_expiry.py`; not needed to build or run recon. |
| OpenSSL headers | **Optional**. `libssl-dev` (Debian/Ubuntu), `openssl-devel` (Fedora/RHEL), `openssl` (Arch). Adds TLS certificate inspection. |

### 2.2 Quick install

```bash
./scripts/install.sh                          # build, then install to /usr/local (sudo only for the install step)
./scripts/install.sh --prefix ~/.local --test # no root needed; run the tests first
./scripts/install.sh --deps                   # print the package-manager command for your distro, then exit
```

| Script option | Effect |
|---|---|
| `--prefix <dir>` | Install location (default `/usr/local`). |
| `--no-openssl` | Build without TLS certificate inspection. |
| `--std 17\|20` | C++ standard (default 17). |
| `--test` | Run `ctest` before installing. |
| `--deps` | Print the dependency-install command and exit. |

The script builds in `./build`, installs under the prefix, and never deletes anything outside `./build`.

### 2.3 Manual CMake build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
sudo cmake --install build
```

| CMake option | Default | Purpose |
|---|---|---|
| `RECON_CXX_STANDARD` | `17` | `17` or `20` (`std::jthread` is used when available). |
| `RECON_WITH_OPENSSL` | `AUTO` | `ON` fails if OpenSSL is missing, `OFF` never uses it, `AUTO` uses it if found. |
| `RECON_BUILD_TESTS` | `ON` | Build the test suite. |
| `RECON_SANITIZER` | empty | `"address;undefined"` or `"thread"` (use with `-DCMAKE_BUILD_TYPE=Debug`). |
| `RECON_WARNINGS_AS_ERRORS` | `OFF` | Used by CI. |
| `RECON_BUILD_FUZZERS` | `OFF` | Build the fuzz targets (libFuzzer under Clang, a standalone driver otherwise). |

The configure step prints whether OpenSSL was found, e.g. `recon: C++17, OpenSSL TLS inspection: ON`.

### 2.4 Verify the installation

```bash
recon --version
recon localhost -p 22,80 --dry-run
recon localhost -p 22,80
```

`--dry-run` proves the binary starts and parses your options without sending a single packet. The last command performs a real scan of your own machine.

### 2.5 Privileges

Recon works **without privileges** for connect scans (the default). Two optional features need more:

| Feature | Needs | How to grant |
|---|---|---|
| `-sS` SYN scan | `CAP_NET_RAW` | Run as root, or once: `sudo setcap cap_net_raw+ep "$(command -v recon)"` |
| ICMP echo for OS inference (`-O`) | Your group in `net.ipv4.ping_group_range` | `sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"` (persist in `/etc/sysctl.d/`) |

Without them recon degrades gracefully: `-sS` exits with code 4 and a clear message; `-O` simply has no TTL evidence and says so.

### 2.6 Packaging, completions, uninstall

* **Packages:** `cpack -G TGZ` or `cpack -G DEB` from the build directory (the DEB metadata is minimal; review before distributing).
* **Shell completion:** installed to `share/bash-completion/completions/recon` and `share/zsh/site-functions/_recon`. Completes options, profile names and file arguments.
* **Man page:** `man/recon.1` is installed to `share/man/man1`.
* **Uninstall:** `xargs rm < build/install_manifest.txt` (run with the same privileges as the install). Recon keeps no config files or state.

---

## 3. A five-minute tour

**Scan your own machine** with the common-port list and service detection:

```bash
recon localhost -pCT
```

**Preview before you send anything:**

```bash
recon 192.168.1.0/28 -pCT --dry-run
```

```
Dry run: nothing was sent.
  targets:   16 host(s): 192.168.1.0, 192.168.1.1, 192.168.1.2, 192.168.1.3, 192.168.1.4, ...
  scan:      connect (TCP 68 ports, UDP 0 ports) -> 1088 probes
  detection: on (intensity 5), OS inference off
  pacing:    500 probes/s, 128 in flight, timeout 1500 ms, 1 retries
  estimate:  >= 2.176 s of probing (lower bound; excludes timeouts, retries and service detection)
```

**Choose ports:** `-p 22,80,443`, `-p 8000-8100`, `-pCT` (68 common TCP ports), `-pAT` (all 65535), `-pCU` / `-pAU` (UDP).

**Get machine-readable output:**

```bash
recon app.example.lan -p 22,443 --json -o scan.json
```

**Detect changes between runs** (exit code 5 if something new opened):

```bash
recon app.example.lan -p 22,443 --json -o today.json --baseline scan.json
```

**Read a result.** A line from the table output:

```
PORT       STATE          SERVICE         CONF  VERSION / DETAILS
45019/tcp  open           ssh             98    OpenSSH 9.6p1 (protocol 2.0; Ubuntu-3ubuntu13.5)
```

`CONF 98` means the response passed strict SSH validation. `9.6p1` is what the service *reports* (a banner can be altered). A line such as
`http?  25` means only a guess from the port number ([section 10](#10-interpreting-results)).

---

## 4. Concepts

### 4.1 Targets

A target is any of:

| Form | Example | Notes |
|---|---|---|
| IPv4 address | `192.168.1.10` | |
| IPv6 address | `fd00::10`, `::1` | No brackets, no zone id. |
| Hostname | `app.example.lan` | Resolved with the system resolver. IPv4 is preferred; `-6` forces IPv6, `-4` forces IPv4. The name is kept as the `hostname` label and used for the HTTP `Host` header and TLS SNI. |
| CIDR | `10.0.0.0/24`, `fd00::/120` | Expanded to **every** address in the block, including network/broadcast. Capped by `--max-hosts` (default 1024). |
| Alias | `localhost`, `me` | Map to `127.0.0.1` (or `::1` with `-6`). |

Give several targets positionally, repeat `-t`, or read a file with `-iL` (one per line, `#` comments, `-` for stdin). Duplicates are removed
(first occurrence wins). A block larger than `--max-hosts` is refused with exit code 3 rather than scanned: raise the limit deliberately.

### 4.2 Ports

`-p` takes comma-separated numbers and ranges: `22`, `22,80,443`, `8000-8100`, `22,80,8000-8100`. Parsing is strict: `80abc`, `0`, `65536`, `443-80`,
`80,,443` and empty items are errors (exit 2). Results are sorted and de-duplicated. `-p` combines with `-pCT`/`-pCU` (the union is scanned).

| Selector | Meaning |
|---|---|
| `-pCT` | 68 commonly used TCP ports ([Appendix A](#appendix-a-port-lists)) |
| `-pAT` | all 65535 TCP ports |
| `-pCU` | 13 commonly used UDP ports |
| `-pAU` | all 65535 UDP ports (slow: see [4.3](#43-scan-types)) |
| `-p <list>` | your list (TCP) |

Probes are issued in **port-major order**: all hosts for port 1, then all hosts for port 2, ... so load is spread across hosts rather than hammering one.

### 4.3 Scan types

| Type | Flag | Privileges | How it works | Best for |
|---|---|---|---|---|
| **Connect** | `-sT` (default) | none | Non-blocking `connect()`; the kernel completes the handshake, recon closes the socket. | Everyday use, IPv6, unprivileged accounts. |
| **SYN** | `-sS` | `CAP_NET_RAW` | Sends a crafted SYN; a SYN-ACK means open, RST means closed. The kernel resets the half-open connection, so no connection ever reaches the application. | Faster, quieter in application logs, full-range sweeps. IPv4 only. |
| **UDP** | `-pCU` / `-pAU` | none | Sends a protocol-appropriate datagram per port. A reply means `open`; an ICMP "port unreachable" means `closed`; silence means `open\|filtered`. | DNS, NTP, NetBIOS and similar services. |

Connect and SYN scans can be combined with UDP in one run. Service detection (4.5) always uses ordinary connections, even after a SYN scan.

**Why UDP is slow and imprecise.** A closed UDP port is only revealed by an ICMP error, and Linux rate-limits those (by default roughly one per second per destination after a small burst),
so a large sweep reports many `closed` ports as `open|filtered`. Treat `open|filtered` as "unknown", not as "probably open". Use the default 13-port list unless you have
a reason to sweep everything.

### 4.4 Port states

| State | Meaning | Typical cause |
|---|---|---|
| `open` | Something accepted the connection (or answered the UDP probe). | A listening service. |
| `closed` | The host actively refused. | No listener; host reachable. |
| `filtered` | No answer within the timeout, after retries, or the network reported the destination unreachable. | Firewall dropping packets, host down, no route. |
| `open\|filtered` | UDP only: no reply and no ICMP error. | Open but silent, or filtered, or ICMP rate-limited. |
| `error` | The probe could not be sent. | Local resource problem, unexpected socket error. |

Only `open` ports (and, with `--show-open-filtered`, UDP `open|filtered`) are listed individually. Closed, filtered and error counts appear in the summary, so a 65535-port scan
does not store 65535 records.

Two details that prevent false results: a connect that succeeds but is then **reset** counts as `open` (the handshake completed), and a connection from a socket to **itself**
(a Linux loopback quirk when source and destination ports coincide) is classed `closed`, never `open`.

### 4.5 Service detection

For every `open` TCP port recon opens a new connection and identifies the service.

**The pipeline**

1. **Passive wait.** Many protocols speak first (SSH, FTP, SMTP, POP3, IMAP, MySQL, VNC, Telnet). Recon waits briefly (automatically ≤ 400 ms; set it with `--banner-wait`) and tries each matcher on what arrives. A match ends detection.
2. **`tcpwrapped` shortcut.** If the peer closes or resets *before sending anything and before recon sent anything*, the port is reported as `tcpwrapped` (confidence 60) and no probes are sent. This is the classic TCP-wrapper/filtering-proxy signature.
3. **Unrecognised greeting.** If the service spoke but nothing matched, recon reports `unknown` with the sanitized banner and stops (unless intensity ≥ 7).
4. **Active probes.** For silent ports recon sends protocol probes on fresh connections, ports hinted for that probe first, then by rarity, until one matches ([4.5.1](#451-intensity)).
5. **TLS follow-up.** If a probe identifies TLS and OpenSSL is available, recon completes a handshake to read the certificate and issues an HTTP request over it.
6. **Fallback.** If nothing matched, a port-number guess is reported with confidence 25 and `version_quality: inferred` (never a version). Ports with no well-known name stay `unknown`.

Each port has a hard budget of 8 seconds, and responses are size-capped, so a hostile or broken service cannot stall or exhaust a scan.

#### 4.5.1 Intensity

`--intensity 0-9` (default 5) controls how many probe types may be sent. A probe runs if its *rarity* is ≤ the intensity, **or** the port is one of the probe's usual ports (when intensity ≥ 1).

| Probe | Rarity | Usual ports | Runs on any open silent port at intensity |
|---|---|---|---|
| passive banner | 0 | all | always |
| HTTP `GET /` | 1 | 80, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9090 | ≥ 1 |
| TLS ClientHello | 2 | 443, 465, 636, 993, 995, 4443, 8443, 9443 | ≥ 2 |
| Redis `INFO server` | 6 | 6379 | ≥ 6 |
| PostgreSQL `SSLRequest` | 6 | 5432 | ≥ 6 |
| SMB2 `NEGOTIATE` | 7 | 139, 445 | ≥ 7 |

So at the default intensity a Redis on port 6379 is identified, but a Redis on port 6700 is reported `unknown`; raise to 6 to find it. At **0** recon only listens and never sends application data.
At ≥ 7 it keeps probing even after an unrecognised greeting. Higher intensity finds more but is noisier and slower.

#### 4.5.2 Confidence and version quality

`confidence` (0-100) scores whether the **service name** is right, not the version.

| Range | Meaning | Examples |
|---|---|---|
| 90-100 | The response passed strict protocol validation. | SSH identification string, MySQL handshake, TLS ServerHello, DNS reply with matching id. |
| 50-89 | Partial or ambiguous evidence. | `220` greeting on port 21 with no product keyword; TLS alert; `tcpwrapped` (60). |
| 1-49 | A guess. | Name taken from the port number (25). Unrecognised banner (10). |
| 0 | Nothing learned. | A silent port with no well-known name. |

`version_quality` is separate:

| Value | Meaning |
|---|---|
| `reported` | Parsed from a protocol-defined field of a validated response. It is what the service **claims**. |
| `inferred` | A guess. Never carries a version number. |
| `none` | No version information. |

Nothing a banner-grabber can see can *verify* a version: administrators can hide or alter banners, and some products report a build string that differs from the upstream version. Treat `reported`
as "claimed by the service", which is valuable but not proof.

#### 4.5.3 Matched services

SSH, FTP, SMTP, POP3, IMAP, MySQL/MariaDB, VNC, Telnet, HTTP/HTTPS (including `Server`, `X-Powered-By` and page title), TLS (protocol and cipher; certificate with OpenSSL), Redis/Valkey, PostgreSQL,
SMB (SMB1 and SMB2/3 dialect), and over UDP: DNS (including `version.bind`), NTP, NetBIOS name service. A UDP reply on another port is reported as a port-number guess at confidence 40; a reply on 53/123/137 that fails protocol validation is a guess at confidence 25 and says so.

### 4.6 TLS inspection

When a probe identifies TLS and recon was built with OpenSSL, it completes a handshake (certificate **not** validated: you want to see what the server presents, including expired and self-signed certificates) and records:
protocol, cipher, subject, issuer, validity dates, DNS subject-alternative names, SHA-256 fingerprint, and booleans `self_signed` and `expired`. It then sends an HTTP request over the encrypted channel, so
a web server is reported as `https` with its real `Server` header. SNI is sent only for hostnames, never for IP literals. Disable with `--no-tls-inspect`.

> **Note.** Certificate inspection is the one feature whose OpenSSL code path could not be compiled in the author's development sandbox (no OpenSSL headers). It is built and exercised by CI when `libssl-dev` is present; if you see TLS identified but no `certificate` data in a build that has OpenSSL, please report it.

Without OpenSSL recon still recognises TLS and reports protocol and cipher from the ServerHello (`service` = `ssl/tls`, or `https` on 443-style ports with the application protocol marked as inferred), but has no certificate details.

### 4.7 OS inference

`-O` aggregates weak evidence into a guess with a **capped** confidence:

| Evidence | Effect |
|---|---|
| ICMP echo TTL (IPv4, unprivileged ping socket) | Family only (initial TTL 64 → Unix-like, 128 → Windows, 255 → network device). Capped at **40-50%**. |
| Two or more Windows-typical ports open (135, 139, 445, 3389, 5985) | Windows, 55%. |
| OS tags in service banners (Ubuntu, Debian, Windows, FreeBSD, ...) | 70-80%; reduced to 50% if banners and TTL disagree. |
| Target is a loopback address | The local kernel, 100%. |

Banner tags describe the **package**, not necessarily the host kernel (a Debian container on an Ubuntu host will say Debian). The evidence behind every guess is printed so you can judge it. IPv6 hop-limit probing is not implemented.
`-O` on its own (no ports) performs OS inference only.

### 4.8 Timing, rate and concurrency

| Setting | Default | What it bounds |
|---|---|---|
| `--rate` | 500 | New probes (socket opens, including retries) per second. `0` = unlimited. |
| `--max-inflight` | 128 | Sockets open at once in the scanner. Automatically clamped to the process file-descriptor limit; reduced further on `EMFILE`. |
| `--workers` | 16 | Threads performing service detection. At most `4 × workers` ports wait in the queue; when it is full the scanner pauses (back-pressure). |
| `--timeout` | 1500 ms | Wait for a connect/SYN answer before declaring a timeout. |
| `--retries` | 1 | Extra attempts after a timeout. A refusal is definitive and is never retried. |
| `--probe-timeout` | 1500 ms | Upper bound on how long detection waits for a reply to one probe. |
| `--banner-wait` | auto (≤ 400 ms) | How long the passive listen lasts. An explicit value is used exactly, not shortened by adaptive timing. |

**Adaptive timeouts.** Detection scales its waits by the connect round-trip time measured during the scan: roughly `6 × RTT + 300 ms`, never below a floor (300 ms for the passive wait, 500 ms for probes) and never above the configured cap.
On a fast network a silent port therefore costs about half a second per probe instead of the full 1.5 s; on a slow link the cap applies. `--no-adaptive` turns this off for strictly reproducible timing.

The scan stops with partial results on `SIGINT`/`SIGTERM` ([4.9](#49-interruption)).

### 4.9 Interruption

Press Ctrl-C at any time. Recon stops launching probes, closes every socket, writes the results gathered so far with `"status": "cancelled"`, and exits with code **130**. Nothing is left half-written.

---

## 5. Command reference

```
recon <target>... [options]
```

Options may appear before, between or after targets. Long options accept `--name value` or `--name=value`; `-p` also accepts `-p=<list>`.
Single-letter flags cannot be combined (`-pCT` is one token; `-q -O` not `-qO`).

### 5.1 Targets

| Option | Description |
|---|---|
| `<target>` | One or more IPv4/IPv6 addresses, hostnames, CIDR blocks or aliases (`localhost`, `me`). |
| `-t`, `--target <t>` | Add a target explicitly (repeatable). Useful when a target could be mistaken for an option. |
| `-iL`, `--input-list <file>` | Read targets from a file, one per line. `#` starts a comment; blank lines are ignored; `-` reads standard input. At most 1,048,576 lines. |
| `-4` / `-6` | Resolve hostnames to IPv4 only / IPv6 only. Mutually exclusive. |
| `--max-hosts <n>` | Maximum number of targets after CIDR expansion. Range 1-1048576, default 1024. Exceeding it is an error (exit 3). |

### 5.2 Ports

| Option | Description |
|---|---|
| `-p`, `--ports <list>` | TCP ports and ranges, e.g. `22,80,8000-8100`. Valid ports are 1-65535. May be repeated; lists are merged. |
| `-pCT` | The 68 common TCP ports ([Appendix A](#appendix-a-port-lists)). |
| `-pAT` | All 65535 TCP ports. |
| `-pCU` | The 13 common UDP ports. |
| `-pAU` | All 65535 UDP ports (slow and imprecise; see [4.3](#43-scan-types)). |

A run needs at least one scan action: a port selector, `-O`, `-A`, or a `--profile` that implies ports. Otherwise: `no scan action specified` (exit 2).

### 5.3 Scan type

| Option | Description |
|---|---|
| `-sT`, `--connect` | Full TCP connect scan. Default. No privileges. |
| `-sS`, `--syn` | Half-open SYN scan using raw sockets. IPv4 only; needs root or `cap_net_raw`. |

### 5.4 Detection

| Option | Default | Description |
|---|---|---|
| `-sV`, `--service-version` | on | Service and version detection. |
| `--no-sV` | | Skip detection. Open ports get only a port-number guess (confidence 25, `inferred`). Much faster. |
| `--intensity <0-9>` | 5 | Probe aggressiveness ([4.5.1](#451-intensity)). 0 = passive banner only. |
| `--no-tls-inspect` | | Do not complete TLS handshakes to read certificates. |
| `-O`, `-os`, `--os` | off | Heuristic OS inference ([4.7](#47-os-inference)). Alone, performs OS inference without scanning ports. |
| `-A`, `--all` | | Shorthand for `-pCT`, service detection and `-O`. |

### 5.5 Profiles

`--profile <name>` sets a bundle of defaults. **Explicit options always win**, whatever their position on the command line
(`--rate 50 --profile stealth` and `--profile stealth --rate 50` are identical).

| Profile | Ports | Settings |
|---|---|---|
| `quick` | common TCP | intensity 3, 1000 probes/s, 0 retries, 800 ms timeout |
| `standard` | common TCP | the defaults (same as `-pCT`) |
| `full` | all 65535 TCP | 2000 probes/s, 512 in flight |
| `stealth` | common TCP | intensity 2, 20 probes/s, 8 in flight, 2 retries, 3000 ms timeout, 2 workers |

### 5.6 Timing and safety

| Option | Default | Range | Description |
|---|---|---|---|
| `--rate <n>` | 500 | 0-10,000,000 | New probes per second. `0` = unlimited (use only on networks you control). |
| `--max-inflight <n>` | 128 | 1-100,000 | Concurrent scan sockets. Clamped to the file-descriptor limit. |
| `--workers <n>` | 16 | 1-512 | Service-detection threads. |
| `--timeout <ms>` | 1500 | 10-120,000 | Connect/SYN timeout. |
| `--probe-timeout <ms>` | 1500 | 50-120,000 | Cap on detection waits per probe. |
| `--banner-wait <ms>` | auto | 50-60,000 | How long to listen for a greeting before sending probes. Default: automatic (at most 400 ms, shortened on fast links). A value you set is used **exactly**. Raise it for slow-greeting servers. |
| `--no-adaptive` | | | Disable RTT-adaptive detection timeouts ([4.8](#48-timing-rate-and-concurrency)). |
| `--retries <n>` | 1 | 0-10 | Extra attempts after a timeout. |

### 5.7 Output and automation

| Option | Description |
|---|---|
| `--json` | JSON report ([Appendix B](#appendix-b-json-schema)). |
| `--csv` | CSV, one row per listed port. |
| `-o`, `--output <file>` | Write the report to a file instead of stdout; `-o -` means stdout. The file is created with mode **0600** (an existing file keeps its mode) and recon **refuses to write through a symbolic link** at the final path component. An unwritable path is exit 4. |
| `--show-open-filtered` | Also list UDP `open\|filtered` ports (omitted by default: they are numerous and ambiguous). |
| `-q`, `--quiet` | Suppress the authorization notice and the progress line on stderr. Errors are still printed. |
| `--fail-on-open` | Exit 1 if any open port is found. |
| `--baseline <file.json>` | Compare with a previous `--json` report; exit 5 if new ports opened ([8.4](#84-detect-changes-in-ci)). |
| `--color auto\|always\|never` | Table colours. `auto` = on when stdout is a terminal and `NO_COLOR` is unset. Never applied to JSON/CSV or to `-o` files. |
| `--progress` / `--no-progress` | Force or disable the live progress line. Default: shown only when stderr is a terminal and `-q` is absent. |
| `--dry-run` | Resolve targets and print what *would* happen (hosts, probe count, rate, time estimate). Sends nothing, exits 0. Still validates the command line and name resolution. |

### 5.8 Miscellaneous

| Option | Description |
|---|---|
| `-h`, `--help` | Print the built-in help. |
| `--version` | Print `recon <version>`. |

**Environment:** `NO_COLOR` (any value) disables automatic colour. No other environment variables, configuration files or state files are used.

---

## 6. Output reference

### 6.1 Streams

| Stream | Contents |
|---|---|
| **stdout** | The report (table, JSON or CSV), or `--help`/`--version`/`--dry-run` text. Never anything else, so it is always safe to pipe. |
| **stderr** | The authorization notice, the progress line, and error messages. |
| **`-o file`** | The report only (stdout is then empty). |

### 6.2 Table (default)

```
================================================================================================
TARGET: 127.0.0.1
================================================================================================
PORT       STATE          SERVICE         CONF  VERSION / DETAILS
------------------------------------------------------------------------------------------------
44211/tcp  open           ssh             98    dropbear 2022.83 (protocol 2.0)
35693/tcp  open           ftp             92    vsftpd 3.0.5
38137/tcp  open           unknown         0     [no banner]
```

| Column | Meaning |
|---|---|
| `PORT` | Port and protocol. |
| `STATE` | `open` (or `open\|filtered` with `--show-open-filtered`). |
| `SERVICE` | Detected service. A trailing `?` marks a **guess** (confidence < 50). |
| `CONF` | Confidence 0-100 ([4.5.2](#452-confidence-and-version-quality)); `-` if detection was not run. |
| `VERSION / DETAILS` | Product and version as reported, then extra details in parentheses. `[unverified]` follows a version that is not marked `reported`. `[no banner]` means nothing was received. |

After the ports: the OS guess and its evidence (with `-O`), a **DRIFT** section (with `--baseline`), and a summary line with duration, host and probe counts, state counts, retries, CPU time and peak memory.
With colour on: open = green, filtered-ish = yellow, weak guesses = yellow, new ports in drift = red. Colour never changes column alignment.

### 6.3 JSON

A single document, stable under `schema_version: 1`, always valid UTF-8 (invalid bytes from hostile banners are replaced, control characters escaped).
Full field list in [Appendix B](#appendix-b-json-schema). Abbreviated example:

```json
{
  "schema_version": 1,
  "tool": { "name": "recon", "version": "2.1.0" },
  "scan": { "started_utc": "2030-01-01T12:00:00Z", "status": "completed", "options": { "scan_type": "connect", "tcp_ports": 1 } },
  "hosts": [ { "address": "192.0.2.10", "hostname": "", "ports": [ { "port": 22, "protocol": "tcp", "state": "open",
      "service": { "name": "ssh", "product": "OpenSSH", "version": "9.6p1", "version_quality": "reported", "confidence": 98 } } ] } ],
  "summary": { "status": "completed", "open": 1, "closed": 0, "duration_ms": 12.5 }
}
```

### 6.4 CSV

Header and columns (RFC 4180, `CRLF` line endings, one row per listed port):

```
host,hostname,port,protocol,state,service,product,version,version_quality,confidence,method,os_hint,tls,banner
```

Fields beginning with `=`, `+`, `-`, `@`, tab or carriage return are prefixed with `'` so a spreadsheet will not execute a hostile banner as a formula.
CSV carries no OS or drift information (the exit code still reflects drift).

### 6.5 Progress line

On an interactive terminal, stderr shows a live line that is cleared when the phase ends:

```
[*] TCP 4096/65535 (6%)  open 3  812 probes/s  ETA 1m16s
```

Phases are labelled `TCP`, `SYN` or `UDP`; a final `finishing service detection...` shows while workers drain. It is off when stderr is not a terminal, with `-q`, or with `--no-progress`.

---

## 7. Exit codes and scripting

| Code | Meaning |
|---|---|
| `0` | Scan completed. |
| `1` | Open ports found, **only** with `--fail-on-open`. |
| `2` | Usage error: bad option, bad port list, unreadable baseline or target file, `-sS` with an IPv6 target. |
| `3` | Targets could not be resolved, or a CIDR exceeds `--max-hosts`. |
| `4` | Runtime or I/O error: unwritable output file, no raw-socket permission for `-sS`, `fatal:` errors, or every probe errored (e.g. no route). |
| `5` | `--baseline`: new open ports compared with the baseline. |
| `130` | Interrupted by `SIGINT`/`SIGTERM`. Partial results are still written. |

When several apply, the first of **130, 4, 5, 1** wins. A scan that finds nothing is exit `0`: *finding no open ports is a result, not an error*.

### Using the exit code

```bash
recon app.example.lan -pCT --json -q -o today.json --baseline baseline.json
case $? in
  0)   echo "no change" ;;
  5)   echo "NEW PORTS OPENED"; exit 1 ;;
  130) echo "interrupted" ;;
  *)   echo "scan failed" >&2; exit 1 ;;
esac
```

### GitHub Actions

```yaml
- name: Exposure check
  run: |
    recon ${{ vars.STAGING_HOST }} -pCT --json -q -o scan.json --baseline ci/baseline.json
- uses: actions/upload-artifact@v4
  if: always()
  with: { name: scan, path: scan.json }
```

### Reading the JSON

Any JSON tool works. With Python (always available):

```bash
recon localhost -p 22,80 --json -q | python3 -c 'import json,sys; [print(p["port"], p["service"]["name"]) for h in json.load(sys.stdin)["hosts"] for p in h["ports"]]'
```

With `jq`: `recon localhost -pCT --json -q | jq -r '.hosts[].ports[] | "\(.port)/\(.protocol) \(.service.name)"'`

Two helper scripts ship in `scripts/`: `cert_expiry.py` (warn about expiring TLS certificates) and `drift_cron.sh` (scheduled drift monitoring); see [8.3](#83-watch-tls-certificate-expiry) and [8.5](#85-scheduled-drift-monitoring).

---

## 8. Recipes

### 8.1 First look at a host

```bash
recon app.example.lan -pCT
recon app.example.lan -A
```

The first lists open common ports with services. The second adds OS inference and prints the evidence behind it.

### 8.2 Inventory a subnet or a list of hosts

```bash
recon 10.20.0.0/24 -pCT --rate 200 --json -o inventory.json
recon 10.20.0.0/24 -p 22,80,443,3389 --csv -o inventory.csv
recon -iL hosts.txt -pCT --json -o inventory.json
```

`hosts.txt` is one target per line with `#` comments. `-iL -` reads the list from standard input, so another tool can feed it. Keep the rate modest on shared networks;
`--max-hosts` guards against an accidental `/8`.

### 8.3 Watch TLS certificate expiry

```bash
recon -iL hosts.txt -p 443,8443 --json -q -o scan.json
python3 scripts/cert_expiry.py scan.json --days 30
```

`cert_expiry.py` exits 1 if any certificate is expired or expires within `--days`, 2 if the report contains no certificate data (no TLS ports, or recon was built without OpenSSL).
Put it in a nightly job to catch renewals that silently failed.

### 8.4 Detect changes in CI

Record a known-good state once, from a scan you have reviewed:

```bash
recon app.example.lan -pCT --json -q -o baseline.json
```

Then, on every run, compare:

```bash
recon app.example.lan -pCT --json -q -o today.json --baseline baseline.json
```

Exit code `5` means something **new is open**; the JSON `drift` section lists each new port with its detected service, and ports that disappeared under `no_longer_open`.
Drift is computed only over the hosts and ports the current scan actually covered, so a scan of a *subset* never claims the rest closed. For a human-readable view use the table output:

```bash
recon app.example.lan -pCT --baseline baseline.json
```

Use `--fail-on-open` when certain ports must **never** be reachable (a simple exposure policy):

```bash
recon app.example.lan -p 22,3306,6379,27017 --fail-on-open -q
```

A baseline must be a `--json` report from recon (schema version 1). A missing, corrupt or foreign file is a usage error (exit 2), never a silent pass.

### 8.5 Scheduled drift monitoring

`scripts/drift_cron.sh` wraps the baseline workflow for cron or systemd timers:

```bash
# crontab: hourly check; first run records the baseline
0 * * * *  RECON=/usr/local/bin/recon /opt/recon/scripts/drift_cron.sh /var/lib/recon-prod prod.example.lan -pCT
```

It keeps `baseline.json`, `latest.json` and a timestamped `history/`. On new ports it prints an alert on stderr and exits 5 **without** changing the baseline, so the alert repeats until a person acknowledges it:

```bash
ACCEPT=1 /opt/recon/scripts/drift_cron.sh /var/lib/recon-prod prod.example.lan -pCT
```

Files are created private (`umask 077`).

### 8.6 Quiet, low-impact scanning

```bash
recon app.example.lan --profile stealth
recon app.example.lan -pCT --intensity 0 --rate 20
```

`stealth` paces probes at 20 per second with 8 sockets in flight. `--intensity 0` never sends application data: recon only connects and listens. This is gentler on fragile systems and leaves fewer log lines, but
silent services (HTTP, TLS, Redis) will be reported only as port-number guesses.

### 8.7 A fast full-port sweep, then a closer look

```bash
sudo recon app.example.lan -sS -pAT --no-sV --rate 5000 --max-inflight 1024
recon app.example.lan -p 22,80,9000 --intensity 6
```

The first command finds open ports quickly (no service detection, SYN scan). The second runs full detection only on what you found. Raise `--rate` only on networks you control.
Without root, drop `-sS` to use the connect scan; add `--max-inflight 1024` for throughput.

### 8.8 UDP

```bash
recon app.example.lan -pCU
recon app.example.lan -pCU --show-open-filtered --retries 3
```

Expect many `open|filtered` results (hidden unless you ask) because UDP gives no positive "closed" signal without ICMP ([4.3](#43-scan-types)). More `--retries` improve reliability at the cost of time.

### 8.9 IPv6

```bash
recon fd00::10 -pCT
recon app.example.lan -6 -pCT
recon fd00::/124 -pCT
```

Connect scans fully support IPv6. `-sS` is IPv4-only and exits 2 with a clear message if given an IPv6 target. OS inference does not use IPv6.

### 8.10 Check specific services thoroughly

```bash
recon db.example.lan -p 3306,5432,6379,27017,9200 --intensity 6
```

Intensity 6 allows the Redis and PostgreSQL probes on any port, which is useful when services run on non-standard ports.

### 8.11 Reproducible timing for comparisons

```bash
recon app.example.lan -pCT --no-adaptive --rate 100 --retries 1
```

`--no-adaptive` removes RTT-dependent waits so two runs differ only by the network.
which records flags, environment and caveats with its results.

### 8.12 Preview the scope of a scan

```bash
recon 10.20.0.0/22 -pCT --dry-run
recon 10.20.0.0/22 -pAT --dry-run --rate 2000
```

`--dry-run` prints how many hosts and probes would be sent and a lower-bound time estimate, and sends nothing. Make it a habit before any large scan.

---

## 9. Tuning guide

| Goal | Settings | Trade-off |
|---|---|---|
| Be gentle | `--profile stealth` or `--rate 20 --max-inflight 8 --intensity 2` | Slow; less detail |
| Everyday audit | defaults (`-pCT`) | Balanced |
| Faster on a LAN | `--rate 2000 --max-inflight 512` or `--profile quick` | More load; may trip IDS |
| Fastest port discovery | `sudo ... -sS --no-sV --rate 5000 --max-inflight 1024` | No service info; needs privilege |
| Best identification | `--intensity 6` (or 7) | More probes per open port |
| Passive-only | `--intensity 0` | Sends no application data |
| Lossy or distant network | `--timeout 3000 --retries 3` | Slower; fewer false `filtered` |
| Many hosts | raise `--workers` (e.g. 64) to speed up detection | More concurrent connections |
| Reproducible timing | `--no-adaptive` | Slower on fast links |
| Machine-readable, quiet | `--json -q -o file` | |

**How the knobs interact**

* The overall pace of a connect/SYN scan is bounded by `min(--rate, --max-inflight / timeout-ish)`. With `--rate 500` and `--max-inflight 128`, a closed-heavy scan is rate-limited; against a filtered
  network each probe holds a socket for the full `--timeout`, so `--max-inflight` (not `--rate`) becomes the limit: 128 sockets / 1.5 s ≈ 85 probes/s per retry round.
* `--workers` bounds *detection* concurrency, not scanning. A host with hundreds of open ports is limited by `--workers` and per-probe waits.
* File descriptors: the scanner raises the soft limit to the hard limit and reserves 64 descriptors; very large `--max-inflight` values are clamped automatically. Raise `ulimit -n` for more.
* Detection time is dominated by *silent* open ports (each is tried with several probes). Lower `--intensity`, set `--probe-timeout 800`, or use `--no-sV` when you only need to know what is open.

**Rough time estimates.** `--dry-run` reports a lower bound (`probes / rate`). Real time adds timeouts for filtered ports (about `--timeout × (1 + --retries)` per port, overlapped up to `--max-inflight`) and service detection (a few hundred milliseconds
to a few seconds per open silent port, spread over `--workers`).

---

## 10. Interpreting results

**"What does `http?` (with a question mark) mean?"** Recon could not elicit any protocol response, so the name is taken from the port number (`confidence` 25, `version_quality: inferred`). It is a hint, not a finding. In JSON look at `method`: `port-guess`.

**"Why is the version empty?"** The service did not report one, or recon has no parser for its format. Many products hide versions on purpose. Recon never invents a version: an empty field is the honest answer.

**"Why does a port show as `unknown` with confidence 0?"** It accepted the connection but stayed silent, and recon's probes drew no recognizable reply at the chosen intensity. Try `--intensity 6` or `7`; if it is still unknown, the service speaks a protocol recon does not know.

**"What is `tcpwrapped`?"** The port accepted the connection and then closed it before any data was exchanged. Typical causes: TCP wrappers, a firewall or proxy that accepts and then filters, or a service that only talks to allow-listed clients. It means *something* answered the handshake, not that a particular service is there.

**"`filtered` vs `closed`?"** `closed` means the host answered "nothing here". `filtered` means no answer at all (dropped packets, down host, no route). A fully `filtered` scan of a host you expect to be up usually means a firewall, a wrong address or a routing problem.

**"`open|filtered` on UDP?"** No reply and no ICMP error. The port may be open and silent, filtered, or the ICMP error was rate-limited. It is *unknown*, not "probably open".

**"The version says `reported`. Is it verified?"** No. It was parsed from a validated, protocol-defined field, so it is what the service *claims*. Banners can be changed or can describe a package build rather than the upstream version.

**"The OS guess has confidence 40."** That is TTL-only evidence, deliberately capped. Add open ports with distro tags (SSH/HTTP banners) or run against a host where ICMP is permitted to get more. Read the printed evidence.

**"Why do I see a TLS service but no certificate?"** The build lacks OpenSSL (`recon: ... OpenSSL TLS inspection: OFF` at configure time), or `--no-tls-inspect` was used, or the handshake failed (for example a client-certificate-only service).

**"Two scans disagree."** Normal for filtered or rate-limited targets (loss, retries, ICMP limits) and for services with intermittent behaviour. Increase `--retries`, and compare with `--no-adaptive`.

---

## 11. Troubleshooting

### Messages

| Message (prefix `recon:`) | Exit | Meaning and fix |
|---|---|---|
| `no target specified` | 2 | Give a host, CIDR, `-t`, or `-iL`. |
| `no scan action specified (use -pCT, ...)` | 2 | Add a port selector, `-O`, `-A` or a profile. |
| `invalid port or range '80abc' (valid: 1-65535, lo<=hi)` | 2 | Fix the port list; trailing text, `0`, `65536`, reversed ranges are rejected. |
| `empty port token in '80,,443'` | 2 | Remove the stray comma. |
| `unknown option '--foo'` | 2 | Typo; see `recon --help`. |
| `option '-p' requires a value` | 2 | A value-taking option was last on the line. |
| `--rate must be 0 (unlimited) to 10000000 probes/s` (and similar range messages) | 2 | Value outside the documented range ([5](#5-command-reference)). |
| `unknown profile 'x' (quick, standard, full, stealth)` | 2 | Use a listed profile name. |
| `-4 and -6 are mutually exclusive` | 2 | Pick one. |
| `cannot open target file '...'` | 2 | Check the `-iL` path and permissions. |
| `cannot open baseline '...'` / `baseline is not valid JSON: ...` / `baseline is not a recon report` | 2 | The baseline must be an existing recon `--json` report (schema version 1). |
| `-sS supports IPv4 only; ::1 is IPv6 (use -sT)` | 2 | Use the connect scan for IPv6 targets. |
| `cannot resolve 'host': ...` | 3 | DNS failure; check the name, resolver, and `-4`/`-6`. |
| `'10.0.0.0/8' expands to too many hosts (limit 1024; raise with --max-hosts)` | 3 | Intentional guard. Narrow the range or raise `--max-hosts`. |
| `-sS: cannot open a raw socket (Operation not permitted); run as root or grant the capability: ...` | 4 | Run with `sudo`, or `sudo setcap cap_net_raw+ep "$(command -v recon)"`. |
| `cannot open '<file>' for writing` | 4 | Output path not writable. |
| `refusing to write through a symbolic link: '<file>'` | 4 | `-o` points at a symlink. Write to the real path, or use `-o -` and redirect. |
| `fatal: ...` | 4 | Unrecoverable runtime error; the text names the cause (for example `no route to <host>` for `-sS`). |

### Symptoms

| Symptom | Likely cause | What to do |
|---|---|---|
| Everything `filtered` | Firewall drops probes, host down, wrong address | Ping/route-check the host; raise `--timeout`/`--retries`; try from another vantage point. |
| Scan is very slow | Filtered network (each probe waits the full timeout), many silent open ports, low `--rate` | Check `--dry-run` estimate; lower `--timeout`; raise `--max-inflight`; use `--no-sV` or lower `--intensity`. |
| Known service shows `unknown` | Non-standard port needing a heavier probe, a silent protocol, or a server that **greets slowly** | `--intensity 6`/`7`; if `nc host port` shows a banner after a pause (SSH with reverse-DNS, FTP ident, SMTP greet-pause), use `--banner-wait 3000`. |
| No colour | Not a terminal, `NO_COLOR` set, or output goes to a file | `--color always` for a terminal pager (`less -R`). |
| No progress line | stderr is not a terminal, or `-q` | `--progress`. |
| Exit code 4, all probes errored | No route, IPv6 unavailable, or local network problem | Check connectivity; `-4` if IPv6 is broken. |
| OS guess is "Unknown", confidence 0 | No ICMP reply and no open ports or hints | Allow ICMP echo, set `net.ipv4.ping_group_range`, or scan more ports ([2.5](#25-privileges)). |
| Results differ between runs | Packet loss, ICMP/connection rate limits, services restarting | More `--retries`; lower `--rate`. |
| IDS/firewall alerts or blocking | Scan was noticed | Expected. Coordinate with the security team; use `--profile stealth`; allow-list the scanner. |
| `Too many open files` style issues | Descriptor limit | recon clamps itself; raise `ulimit -n` for more concurrency. |

If something looks wrong, run with `--json` and inspect `service.method`, `service.confidence`, `attempts` and the `summary` counters: they show how each result was obtained.

---

## 12. What recon sends on the network

Knowing the footprint helps defenders write allow-rules and IDS signatures, and helps you judge risk to fragile systems.

| Traffic | When | Details |
|---|---|---|
| TCP SYN (connect scan) | each `(host, port)` probe | An ordinary `connect()` from the kernel; closed again immediately. Source ports are chosen by the kernel. |
| TCP SYN (`-sS`) | each probe | Raw 24-byte TCP header: MSS option 1460, window 64240, random sequence number, source port randomly from **20000-29999**. No payload. The local kernel replies RST to a SYN-ACK. |
| UDP datagrams | `-pCU`/`-pAU` | Port 53: DNS query for `version.bind` CHAOS TXT (id `0x1234`, 30 bytes). Port 123: 48-byte NTP client request. Port 137: NetBIOS node-status request. Other ports: 4 zero bytes. |
| ICMP echo | `-O`, IPv4 | One echo request per host via an unprivileged ping socket. |
| Passive connection | each open TCP port | One extra connection per open port that only *listens* (≤ 400 ms). |
| HTTP probe | silent ports, intensity ≥ 1 | `GET / HTTP/1.1` with `Host:` set to the target name (or IP), `User-Agent: recon/<version>`, `Accept: */*`, `Connection: close`. **The user-agent identifies recon in server logs.** |
| TLS probe | silent ports, intensity ≥ 2 | A TLS ClientHello offering TLS 1.2/1.3 (SNI for hostnames only). With OpenSSL a full handshake follows, then `GET /` over TLS. No client certificate or credentials are ever sent. |
| Redis probe | port 6379, or intensity ≥ 6 | `INFO server\r\n` (read-only; a protected instance answers `NOAUTH`). |
| PostgreSQL probe | port 5432, or intensity ≥ 6 | The 8-byte `SSLRequest` (`00 00 00 08 04 d2 16 2f`); the server answers `S` or `N`. No login attempt. |
| SMB probe | ports 139/445, or intensity ≥ 7 | An SMB2 `NEGOTIATE` offering dialects 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1. No authentication. |

Recon **never** sends credentials, exploit payloads or mutated/fuzzed data, and never attempts to log in. Every probe has a hard timeout; a single open port gets at most 8 seconds of attention. Expect roughly one passive connection plus up to a few probe connections
for each *open* port.

---

## 13. Handling results safely

* **Reports are sensitive.** They map your infrastructure: addresses, hostnames, services, versions, certificate subjects and banner text. Store and share them like any security finding.
* **File permissions.** `-o` creates new files with mode `0600` and refuses to follow a symlink at the destination, so a predictable name in a shared directory such as `/tmp` cannot be hijacked. An existing file keeps its current mode: tighten it yourself if needed. The shell redirect `> file` does not get these protections; prefer `-o`.
* **Remote data is hostile.** Banners, `Server` headers and page titles come from the target. Recon validates and sanitizes them (printable ASCII only in text fields, length-capped, valid UTF-8 JSON, spreadsheet-formula-safe CSV), but
  your downstream tools should still treat them as untrusted input: never interpolate banner text into a shell command or an HTML page without escaping.
* **Version strings are claims.** Do not use a `reported` version as the sole basis for a "patched" or "vulnerable" decision.
* **Terminal safety.** Recon strips control characters so a malicious banner cannot inject terminal escape sequences into your screen.
* **Keep a record** of scope, authorization and time window alongside the report.

---

## 14. Development guide

### 14.1 Layout

```
include/recon/   public headers          src/            implementation (net, scanner, synscan, detector,
tests/           C++ + Python tests                       matchers, report, json, baseline, options, ...)
fuzz/            fuzz targets + corpus   completions/    bash and zsh completion
scripts/         install, helpers        docs/           architecture and this manual
```

Read [ARCHITECTURE.md](ARCHITECTURE.md) first: it has the component diagram, per-stage component tables, the three scan flows (TCP, SYN, UDP), the threading model and invariants. The diagram is generated from `docs/architecture.json` by `scripts/gen_architecture.py`, and the test suite checks it against the source tree.

### 14.2 Build and test

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
ctest --test-dir build --output-on-failure             # unit + integration + end-to-end + manual examples
sudo ctest --test-dir build -R '^(syn|cli_e2e)$'       # privileged tests (otherwise they report SKIP)
```

Sanitizer builds:

```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DRECON_SANITIZER="address;undefined" && cmake --build build-asan -j && ctest --test-dir build-asan
cmake -S . -B build-tsan -DCMAKE_BUILD_TYPE=Debug -DRECON_SANITIZER=thread && cmake --build build-tsan -j && ctest --test-dir build-tsan
```

Fuzzing (libFuzzer needs Clang; GCC builds a standalone random/mutation driver):

```bash
CXX=clang++ cmake -S . -B build-fuzz -DRECON_BUILD_FUZZERS=ON -DRECON_BUILD_TESTS=OFF && cmake --build build-fuzz
./build-fuzz/fuzz_matchers fuzz/corpus/matchers -max_total_time=60
```

Formatting and static analysis: `cmake --build build --target format` (clang-format in place), `--target check-format`, `--target tidy`.

### 14.3 Adding a protocol matcher

1. **Write a pure function** in `src/matchers.cpp` with the signature `std::optional<Detection> match_xyz(std::string_view data, std::uint16_t port)`. Parse only through `detail::Reader` or checked `string_view` operations; return `std::nullopt` unless the response is unambiguous.
   Never use `strchr` for membership tests on untrusted bytes (a NUL byte matches). Pass free text through `sanitize_ascii`.
2. **Declare it** in `include/recon/detect.hpp`.
3. **Register it.** Speak-first protocols go in the `kPassive` array in `src/detector.cpp`. Protocols needing a request get a `ProbeDef` (name, rarity, usual ports, payload builder, matcher) in `probes()`.
4. **Test it** in `tests/test_matchers.cpp` with a *wire-accurate* sample (mind endianness), rejects for near-miss inputs, and every-truncation safety. Add the function to the fuzz target list in `fuzz/fuzz_matchers.cpp`.
5. **Document it** in [4.5.3](#453-matched-services) and, if it sends data, in [section 12](#12-what-recon-sends-on-the-network).

### 14.4 Conventions

RAII for every descriptor and thread; no raw `new`/`delete`; no exceptions across the reactor's hot path; bounds-checked parsing; no shared mutable state except through `ResultStore`; every new behaviour gets a test that you have seen fail
(revert the fix and confirm the test catches it).

---

## 15. Limitations

* **Linux only** (`epoll`, raw sockets).
* **SYN scan:** IPv4 only; no ICMP-unreachable parsing (blocked ports are `filtered` after the timeout); needs `CAP_NET_RAW`.
* **IPv6:** address parsing and CIDR expansion are unit-tested; end-to-end IPv6 networking was not exercised in the author's environment.
* **Service detection:** a compact signature set, not a fingerprint database; versions are what services report. Service detection opens a second connection after a connect scan.
* **TLS certificates:** require an OpenSSL build; that code path could not be compiled in the author's sandbox and is covered by CI.
* **SMB2:** the parser is unit-tested against a wire-accurate response but was not checked against a real Windows/Samba server.
* **OS inference:** evidence aggregation with capped confidence; no active fingerprinting; IPv4 ICMP only.
* **UDP:** closed-port detection depends on ICMP, which Linux rate-limits; large sweeps under-report `closed`.
* **No host discovery** and no scan resume.

---

## Appendix A: port lists

**`-pCT` — 68 common TCP ports**

```
20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162, 179, 389,
443, 445, 465, 514, 515, 587, 631, 993, 995, 1080, 1194, 1433, 1521, 1716, 1723, 1883, 2049, 2375,
2376, 3306, 3389, 3690, 4369, 5000, 5432, 5672, 5900, 5985, 5986, 6379, 6443, 6667, 7001, 8000,
8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 9418, 11211, 27017
```

**`-pCU` — 13 common UDP ports**

```
53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 554
```

## Appendix B: JSON schema

Top level, `schema_version: 1`. Field order is stable; new optional fields may be added without a version bump, so parse tolerantly.

| Path | Type | Description |
|---|---|---|
| `schema_version` | number | Always `1`. |
| `tool.name`, `tool.version` | string | `"recon"` and its version. |
| `scan.started_utc` | string | ISO-8601 UTC start time. |
| `scan.status` | string | `completed` or `cancelled`. |
| `scan.options.scan_type` | string | `connect` or `syn`. |
| `scan.options.tcp_ports`, `.udp_ports` | number | Count of ports scanned per protocol. |
| `scan.options.service_detection`, `.intensity`, `.timeout_ms`, `.retries`, `.rate_per_sec`, `.max_inflight`, `.workers` | mixed | Effective settings. |
| `hosts[]` | array | One entry per target, in target order. |
| `hosts[].address` | string | IP address. |
| `hosts[].hostname` | string | Name as given (empty for address literals). |
| `hosts[].ports[]` | array | Listed ports (open; UDP `open\|filtered` only with `--show-open-filtered`), sorted by protocol then port. |
| `…port`, `…protocol`, `…state` | number, string, string | `tcp`/`udp`; `open` or `open\|filtered`. |
| `…rtt_ms`, `…attempts` | number | Probe round-trip time; attempts used (1 + retries). |
| `…service.name` | string | `ssh`, `http`, `https`, `ssl/tls`, `tcpwrapped`, `unknown`, ... |
| `…service.product`, `.version` | string | As reported (may be empty). |
| `…service.version_quality` | string | `reported`, `inferred` or `none`. |
| `…service.confidence` | number | 0-100 ([4.5.2](#452-confidence-and-version-quality)). |
| `…service.method` | string | `banner`, `probe:http`, `probe:tls`, `probe:redis`, `probe:postgres`, `probe:smb`, `probe:tls+tls` (with certificate inspection), `probe:udp`, `port-guess` or `none`. |
| `…service.extra`, `.os_hint`, `.banner` | string | Details, OS tag from the banner, sanitized banner text (≤ 200 chars). |
| `…service.error` | string | Present only if detection failed (for example a connect error). |
| `…service.tls` | bool or object | `false`/`true`, or an object: `protocol`, `cipher`, `certificate`. |
| `…tls.certificate` | false or object | `subject`, `issuer`, `not_before`, `not_after`, `sha256`, `san[]`, `self_signed`, `expired`. |
| `hosts[].os` | object | With `-O`: `family`, `name`, `confidence`, `ttl`, `estimated_hops`, `evidence[]`. |
| `drift` | object | With `--baseline`: `baseline` (path), `new_open[]`, `no_longer_open[]` (each: `address`, `port`, `protocol`, `service`). |
| `summary.status` | string | `completed` or `cancelled`. |
| `summary.hosts`, `.probes`, `.socket_attempts`, `.retries` | number | Totals; `socket_attempts` includes retries. |
| `summary.open`, `.closed`, `.filtered`, `.open_filtered`, `.errors` | number | Counts by state across all probes. |
| `summary.duration_ms` | number | Wall-clock duration. |
| `summary.resources` | object | `cpu_user_ms`, `cpu_sys_ms`, `max_rss_kb` of the recon process. |

## Appendix C: glossary

| Term | Meaning |
|---|---|
| Banner | Text a service sends on connect (or in reply to a probe) that identifies it. |
| Baseline | A previous JSON report used as the "known good" state for drift detection. |
| Connect scan | Port scan that completes the TCP handshake with the normal `connect()` call. |
| CIDR | Address-block notation, e.g. `10.0.0.0/24`. |
| Drift | Difference between the current scan and a baseline. |
| Half-open (SYN) scan | Scan that sends SYN and judges the reply without completing the handshake. |
| Inflight | Probes sent and awaiting an answer. |
| Probe | A deliberate request sent to elicit a service's identifying response. |
| RTT | Round-trip time between sending and receiving. |
| SNI | Server Name Indication: the hostname sent in a TLS ClientHello. |
| `tcpwrapped` | Port that accepted a connection and closed it before any data. |

## Appendix D: legacy flags

Kept for compatibility with recon 1.x: `-ip <target>` (same as `-t`), `-os` (same as `-O`), `-pCT`/`-pAT`/`-pCU`/`-pAU` (unchanged). Behaviour that changed in 2.x: `-p` is now strict, exit codes are meaningful,
and the default output includes a confidence column.
