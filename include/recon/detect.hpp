// Service detection: result types, protocol matchers, and the probe engine.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "recon/common.hpp"
#include "recon/net.hpp"

namespace recon {

// How much to trust the version string.
//   Reported: extracted from a protocol-defined field of a response that passed strict
//             format validation. It is what the service *claims*; banners can be altered.
//   Inferred: guessed (e.g. from the port number). Never contains a version number.
enum class VersionQuality { None, Inferred, Reported };
const char* to_string(VersionQuality q);

struct TlsInfo {
    std::string protocol;  // "TLSv1.3"
    std::string cipher;
    bool has_certificate = false;
    std::string subject, issuer, not_before, not_after, sha256;
    std::vector<std::string> san;
    bool self_signed = false;
    bool expired = false;
};

struct Detection {
    std::string service = "unknown";
    std::string product, version, extra, os_hint;
    std::string banner;  // sanitized printable ASCII, length-capped
    std::string method = "none";  // "banner", "probe:<name>", "port-guess", "none"
    // 0..100: confidence that `service` is correct. >=90 protocol-validated response,
    // 50-89 partial or ambiguous evidence, <50 guess from port number.
    int confidence = 0;
    VersionQuality version_quality = VersionQuality::None;
    bool tls = false;
    std::optional<TlsInfo> tls_info;
    std::string error;
};

// ---- Pure protocol matchers: no I/O, bounds-checked, safe on arbitrary bytes -------------
using Matcher = std::optional<Detection> (*)(std::string_view data, std::uint16_t port);

std::optional<Detection> match_ssh(std::string_view data, std::uint16_t port);
std::optional<Detection> match_ftp(std::string_view data, std::uint16_t port);
std::optional<Detection> match_smtp(std::string_view data, std::uint16_t port);
std::optional<Detection> match_pop3(std::string_view data, std::uint16_t port);
std::optional<Detection> match_imap(std::string_view data, std::uint16_t port);
std::optional<Detection> match_mysql(std::string_view data, std::uint16_t port);
std::optional<Detection> match_vnc(std::string_view data, std::uint16_t port);
std::optional<Detection> match_telnet(std::string_view data, std::uint16_t port);
std::optional<Detection> match_http(std::string_view data, std::uint16_t port);
std::optional<Detection> match_tls(std::string_view data, std::uint16_t port);
std::optional<Detection> match_redis(std::string_view data, std::uint16_t port);
std::optional<Detection> match_postgres(std::string_view data, std::uint16_t port);
std::optional<Detection> match_smb2(std::string_view data, std::uint16_t port);

// UDP response matchers (payload sent by udp_probe_payload()).
std::optional<Detection> match_udp_response(std::uint16_t port, std::string_view data);

// ---- helpers shared with tests / output --------------------------------------------------
std::string sanitize_ascii(std::string_view s, std::size_t max_len);
std::string build_client_hello(const std::string& sni);
const char* port_guess_service(std::uint16_t port, bool tcp);

// ---- Probe engine ------------------------------------------------------------------------
struct DetectConfig {
    Millis connect_timeout{1500};
    Millis banner_wait{400};   // passive wait for server-speaks-first protocols
    Millis probe_timeout{1500};
    Millis quiet{150};         // silence that ends a response (handles slow/partial writes)
    Millis total_budget{8000}; // hard cap per port
    int intensity = 5;         // 0 = passive only .. 9 = try every probe
    // Scale waits by the measured connect RTT (like Nmap's RTT estimation): on a fast link a
    // silent port should not cost the full worst-case timeout per probe. The configured
    // banner_wait/probe_timeout remain hard upper bounds. Disable for reproducible timing.
    bool adaptive_timeouts = true;
    // When set (via --banner-wait), banner_wait is used exactly as given and never shortened by the
    // adaptive logic: for servers that greet slowly (reverse-DNS lookups, ident checks, greet-pause).
    bool fixed_banner_wait = false;
    bool tls_inspect = true;   // requires build with OpenSSL; otherwise ClientHello parsing only
};

class ServiceDetector {
public:
    explicit ServiceDetector(DetectConfig cfg = {}) : cfg_(cfg) {}
    // Never throws; failures are reported through Detection::error. `host_label` is used for
    // the HTTP Host header and TLS SNI.
    // `rtt_ms` is the connect RTT measured by the scanner (<0 if unknown), used for adaptive waits.
    Detection detect(const net::Endpoint& ep, const std::string& host_label,
                     const CancelToken& cancel, double rtt_ms = -1.0) const;

private:
    DetectConfig cfg_;
};

#ifdef RECON_WITH_OPENSSL
struct TlsInspectResult {
    bool ok = false;
    TlsInfo info;
    std::string http_response;
    std::string error;
};
TlsInspectResult tls_inspect(const net::Endpoint& ep, const std::string& sni,
                             Clock::time_point deadline, bool send_http_get,
                             const std::string& http_host);
#endif

}  // namespace recon
