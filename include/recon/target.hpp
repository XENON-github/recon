// Target and port-specification parsing (IPv4, IPv6, hostnames, CIDR).
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "recon/net.hpp"

namespace recon {

struct Target {
    net::IpAddress addr;
    std::string label;  // user-supplied hostname if the input was not an address literal
};

struct ResolveOptions {
    bool ipv4_only = false;
    bool ipv6_only = false;
    std::size_t max_hosts = 1024;  // hard cap on expanded targets
};

// Strict parser: "80", "22,80,8000-8100". Rejects trailing garbage, empty tokens, 0, >65535,
// reversed ranges. Output is sorted and de-duplicated.
bool parse_port_spec(std::string_view spec, std::vector<std::uint16_t>& out, std::string& error);

// Expands "a.b.c.d/n" or "v6::/n". Fails if the range exceeds max_hosts.
bool expand_cidr(std::string_view cidr, std::size_t max_hosts, std::vector<net::IpAddress>& out,
                 std::string& error);

// Resolves each spec (IP literal, CIDR, hostname, or alias localhost/me) into targets.
bool resolve_targets(const std::vector<std::string>& specs, const ResolveOptions& opt,
                     std::vector<Target>& out, std::string& error);

const std::vector<std::uint16_t>& common_tcp_ports();
const std::vector<std::uint16_t>& common_udp_ports();
std::vector<std::uint16_t> all_ports();

}  // namespace recon
