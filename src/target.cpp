#include "recon/target.hpp"

#include <netdb.h>

#include <algorithm>
#include <charconv>
#include <cstring>

namespace recon {
namespace {

bool parse_uint(std::string_view s, unsigned long& v) {
    if (s.empty()) return false;
    unsigned long tmp = 0;
    const auto r = std::from_chars(s.data(), s.data() + s.size(), tmp);
    if (r.ec != std::errc() || r.ptr != s.data() + s.size()) return false;  // no trailing junk
    v = tmp;
    return true;
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
    return s;
}

void add_one(net::IpAddress& ip) {  // big-endian increment
    for (std::size_t i = ip.byte_len(); i-- > 0;) {
        if (++ip.bytes[i] != 0) break;
    }
}

}  // namespace

bool parse_port_spec(std::string_view spec, std::vector<std::uint16_t>& out, std::string& error) {
    std::vector<std::uint16_t> ports;
    std::size_t pos = 0;
    while (pos <= spec.size()) {
        const std::size_t comma = spec.find(',', pos);
        const std::string_view tok =
            trim(spec.substr(pos, comma == std::string_view::npos ? comma : comma - pos));
        if (tok.empty()) {
            error = "empty port token in '" + std::string(spec) + "'";
            return false;
        }
        unsigned long lo = 0, hi = 0;
        const std::size_t dash = tok.find('-');
        bool ok = dash == std::string_view::npos
                      ? (parse_uint(tok, lo) && (hi = lo, true))
                      : (parse_uint(tok.substr(0, dash), lo) && parse_uint(tok.substr(dash + 1), hi));
        if (!ok || lo < 1 || hi > 65535 || lo > hi) {
            error = "invalid port or range '" + std::string(tok) + "' (valid: 1-65535, lo<=hi)";
            return false;
        }
        for (unsigned long p = lo; p <= hi; ++p) ports.push_back(static_cast<std::uint16_t>(p));
        if (comma == std::string_view::npos) break;
        pos = comma + 1;
    }
    out.insert(out.end(), ports.begin(), ports.end());
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return !out.empty();
}

bool expand_cidr(std::string_view cidr, std::size_t max_hosts, std::vector<net::IpAddress>& out,
                 std::string& error) {
    const std::size_t slash = cidr.rfind('/');
    if (slash == std::string_view::npos) {
        error = "not a CIDR: '" + std::string(cidr) + "'";
        return false;
    }
    auto base = net::IpAddress::parse(cidr.substr(0, slash));
    unsigned long prefix = 0;
    if (!base || !parse_uint(cidr.substr(slash + 1), prefix) ||
        prefix > (base->is_v4() ? 32UL : 128UL)) {
        error = "invalid CIDR '" + std::string(cidr) + "'";
        return false;
    }
    const unsigned total_bits = base->is_v4() ? 32 : 128;
    const unsigned host_bits = total_bits - static_cast<unsigned>(prefix);
    if (host_bits >= 63 || (1ULL << host_bits) > max_hosts) {
        error = "'" + std::string(cidr) + "' expands to too many hosts (limit " +
                std::to_string(max_hosts) + "; raise with --max-hosts)";
        return false;
    }
    // Zero the host bits to get the network base address.
    for (unsigned bit = static_cast<unsigned>(prefix); bit < total_bits; ++bit) {
        base->bytes[bit / 8] = static_cast<std::uint8_t>(base->bytes[bit / 8] & ~(0x80U >> (bit % 8)));
    }
    const std::uint64_t count = 1ULL << host_bits;
    net::IpAddress cur = *base;
    for (std::uint64_t i = 0; i < count; ++i) {
        out.push_back(cur);
        add_one(cur);
    }
    return true;
}

bool resolve_targets(const std::vector<std::string>& specs, const ResolveOptions& opt,
                     std::vector<Target>& out, std::string& error) {
    for (const std::string& spec : specs) {
        if (spec == "localhost" || spec == "me" || spec == "my device") {
            out.push_back({*net::IpAddress::parse(opt.ipv6_only ? "::1" : "127.0.0.1"), spec});
        } else if (spec.find('/') != std::string::npos) {
            std::vector<net::IpAddress> addrs;
            if (!expand_cidr(spec, opt.max_hosts, addrs, error)) return false;
            for (const auto& a : addrs) out.push_back({a, ""});
        } else if (auto ip = net::IpAddress::parse(spec)) {
            out.push_back({*ip, ""});
        } else {
            addrinfo hints{};
            hints.ai_family = opt.ipv4_only ? AF_INET : (opt.ipv6_only ? AF_INET6 : AF_UNSPEC);
            hints.ai_socktype = SOCK_STREAM;
            addrinfo* res = nullptr;
            const int rc = ::getaddrinfo(spec.c_str(), nullptr, &hints, &res);
            if (rc != 0 || res == nullptr) {
                error = "cannot resolve '" + spec + "': " + ::gai_strerror(rc);
                return false;
            }
            // Prefer IPv4 when the caller did not constrain the family, matching legacy behaviour.
            const addrinfo* pick = res;
            for (const addrinfo* p = res; p != nullptr; p = p->ai_next) {
                if (p->ai_family == AF_INET) {
                    pick = p;
                    break;
                }
            }
            net::IpAddress resolved;
            if (pick->ai_family == AF_INET) {
                resolved.family = AF_INET;
                std::memcpy(resolved.bytes.data(),
                            &reinterpret_cast<const sockaddr_in*>(pick->ai_addr)->sin_addr, 4);
            } else {
                resolved.family = AF_INET6;
                std::memcpy(resolved.bytes.data(),
                            &reinterpret_cast<const sockaddr_in6*>(pick->ai_addr)->sin6_addr, 16);
            }
            ::freeaddrinfo(res);
            out.push_back({resolved, spec});
        }
        if (out.size() > opt.max_hosts) {
            error = "target list exceeds --max-hosts (" + std::to_string(opt.max_hosts) + ")";
            return false;
        }
    }
    // De-duplicate while keeping first-seen order.
    std::vector<Target> uniq;
    for (auto& t : out) {
        const bool dup = std::any_of(uniq.begin(), uniq.end(),
                                     [&](const Target& u) { return u.addr == t.addr; });
        if (!dup) uniq.push_back(std::move(t));
    }
    out = std::move(uniq);
    return !out.empty();
}

const std::vector<std::uint16_t>& common_tcp_ports() {
    static const std::vector<std::uint16_t> k = {
        20,   21,   22,   23,   25,   53,    67,   68,   69,   80,   110,  111,  123,  135,
        137,  138,  139,  143,  161,  162,   179,  389,  443,  445,  465,  514,  515,  587,
        631,  993,  995,  1080, 1194, 1433,  1521, 1716, 1723, 1883, 2049, 2375, 2376, 3306,
        3389, 3690, 4369, 5000, 5432, 5672,  5900, 5985, 5986, 6379, 6443, 6667, 7001, 8000,
        8008, 8080, 8081, 8443, 8888, 9000,  9090, 9200, 9300, 9418, 11211, 27017};
    return k;
}

const std::vector<std::uint16_t>& common_udp_ports() {
    static const std::vector<std::uint16_t> k = {53,  67,  68,  69,  123, 137, 138,
                                                 161, 162, 500, 514, 520, 554};
    return k;
}

std::vector<std::uint16_t> all_ports() {
    std::vector<std::uint16_t> v(65535);
    for (std::size_t i = 0; i < v.size(); ++i) v[i] = static_cast<std::uint16_t>(i + 1);
    return v;
}

}  // namespace recon
