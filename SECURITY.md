# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private reporting:
**Security → Report a vulnerability** on this repository (a private security advisory). Include the recon version
(`recon --version`), how you built it, the command line, and, if possible, a minimal reproducer (a mock server script or a
captured byte sequence is ideal).

You can expect an acknowledgement within a few days. Fixes are developed privately and released with an advisory and a
`CHANGELOG.md` entry.

## Supported versions

Only the latest release receives security fixes.

## Threat model (what recon defends against)

Recon connects to hosts you point it at, so **everything a remote host sends is untrusted input**. The parts that handle it are
written and tested with that in mind:

| Risk | Mitigation |
|---|---|
| Memory-safety bugs in protocol parsers | Pure functions over `std::string_view`, all reads through a bounds-checked reader; fuzzed (libFuzzer + AddressSanitizer/UBSan in CI); built with bounds-checked standard containers (`_GLIBCXX_ASSERTIONS`), stack protector, PIE, full RELRO |
| Resource exhaustion by a hostile peer | Response size caps, per-probe and per-port time budgets, bounded worker queue, bounded in-flight sockets, descriptor-limit clamping |
| Terminal/log injection via banners | Text fields are reduced to printable ASCII and length-capped |
| Malformed or hostile JSON baselines | Strict parser with depth and node-count limits, UTF-8 validation, file-size cap; malformed entries are skipped, never trusted |
| Spreadsheet formula injection via CSV | Leading `= + - @` are neutralised |
| Spoofed replies to the SYN scanner | Replies must acknowledge the scanner's own random 32-bit sequence number |
| Report file tampering | `-o` creates files `0600` and refuses symbolic links |

## Out of scope / known limitations

* Recon is a scanning tool. Using it against systems you do not own or have permission to test is your responsibility.
* `-sS` needs `CAP_NET_RAW`. Prefer `setcap cap_net_raw+ep` on the binary over running as root, and **never install it setuid**.
  Recon does not currently drop capabilities after opening its raw sockets.
* Version strings are what services *claim*; they are not verified.
* TLS certificates are deliberately **not validated** (the point is to see what the server presents).
* Reports contain sensitive infrastructure data; protect them accordingly.
