// Heuristic OS inference. This is evidence aggregation, not fingerprinting: confidence is
// deliberately capped for weak signals (TTL alone never exceeds 50%).
#pragma once

#include <vector>

#include "recon/net.hpp"
#include "recon/report.hpp"

namespace recon {

// Returns the ICMP echo reply TTL (IPv4, unprivileged ping socket) or -1.
int icmp_echo_ttl(const net::IpAddress& ip, Millis timeout);

OsGuess infer_os(const net::IpAddress& ip, const std::vector<PortRecord>& open_ports, int icmp_ttl);

}  // namespace recon
