// Half-open ("SYN") scanner using raw sockets. IPv4 only; needs CAP_NET_RAW (root).
// Same interface and semantics as PortScanner so the orchestrator can swap one for the other.
#pragma once

#include "recon/scanner.hpp"

namespace recon {

class SynScanner {
public:
    SynScanner(ScanConfig cfg, RateLimiter& limiter, const CancelToken& cancel);

    // True if raw sockets can be opened (needs root or CAP_NET_RAW). On failure `why` explains.
    static bool available(std::string* why = nullptr);

    // Throws std::runtime_error if raw sockets are unavailable or a host is not IPv4.
    ScanStats run(const std::vector<net::IpAddress>& hosts, const std::vector<std::uint16_t>& ports,
                  const PortScanner::Callback& cb);

    void set_progress(PortScanner::ProgressFn fn, Millis interval = Millis(250)) {
        progress_ = std::move(fn);
        progress_interval_ = interval;
    }

private:
    ScanConfig cfg_;
    RateLimiter& limiter_;
    const CancelToken& cancel_;
    PortScanner::ProgressFn progress_;
    Millis progress_interval_{250};
};

// Exposed for tests: RFC 793 checksum over the IPv4 pseudo-header plus TCP segment.
std::uint16_t tcp_checksum(const std::uint8_t src[4], const std::uint8_t dst[4], const std::uint8_t* seg,
                           std::size_t len);

}  // namespace recon
