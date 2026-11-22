// Event-driven port scanner (epoll). One reactor thread multiplexes up to `max_inflight`
// non-blocking sockets. Handles timeouts, retries, rate limiting, fd exhaustion, cancellation.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "recon/common.hpp"
#include "recon/net.hpp"
#include "recon/ratelimit.hpp"

namespace recon {

enum class PortState { Open, Closed, Filtered, OpenFiltered, Error };
enum class Protocol { Tcp, Udp };

const char* to_string(PortState s);
const char* to_string(Protocol p);

// Maps a connect()/SO_ERROR value to a port state (0 => Open).
PortState classify_connect_error(int err);

struct ScanConfig {
    Protocol protocol = Protocol::Tcp;
    std::size_t max_inflight = 128;
    Millis timeout{1500};
    int retries = 1;  // extra attempts after a timeout (total attempts = retries + 1)
};

struct ProbeOutcome {
    std::size_t host_index = 0;
    std::uint16_t port = 0;
    Protocol protocol = Protocol::Tcp;
    PortState state = PortState::Error;
    int error_code = 0;
    int attempts = 1;
    double rtt_ms = 0.0;
    std::string udp_response;  // UDP only: first datagram received
};

struct ScanStats {
    std::uint64_t tasks = 0;
    std::uint64_t attempts = 0;  // sockets opened, including retries
    std::uint64_t retries = 0;
    std::uint64_t open = 0, closed = 0, filtered = 0, open_filtered = 0, errors = 0;
    std::size_t peak_inflight = 0;
    std::size_t effective_inflight = 0;  // after fd-limit clamping / adaptive back-off
    bool cancelled = false;
};

// Payload sent in UDP probes for a given destination port.
std::string udp_probe_payload(std::uint16_t port);

class PortScanner {
public:
    using Callback = std::function<void(const ProbeOutcome&)>;
    using ProgressFn = std::function<void(const ScanStats&)>;

    PortScanner(ScanConfig cfg, RateLimiter& limiter, const CancelToken& cancel);

    // Probes every (host, port) pair, spreading load across hosts (port-major order).
    // The callback runs on the calling thread. A slow callback applies back-pressure to
    // the scan by design. Throws std::runtime_error on unrecoverable epoll failure.
    ScanStats run(const std::vector<net::IpAddress>& hosts, const std::vector<std::uint16_t>& ports,
                  const Callback& cb);

    // Optional: called on the reactor thread at most once per `interval` with live counters.
    void set_progress(ProgressFn fn, Millis interval = Millis(250)) {
        progress_ = std::move(fn);
        progress_interval_ = interval;
    }

private:
    ProgressFn progress_;
    Millis progress_interval_{250};
    ScanConfig cfg_;
    RateLimiter& limiter_;
    const CancelToken& cancel_;
};

}  // namespace recon
