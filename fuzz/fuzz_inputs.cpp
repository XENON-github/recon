// libFuzzer target: user-supplied strings (port specs, CIDR, IP literals).
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "recon/net.hpp"
#include "recon/target.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace recon;
    const std::string_view in(reinterpret_cast<const char*>(data), size);
    std::vector<std::uint16_t> ports;
    std::string err;
    parse_port_spec(in, ports, err);
    for (std::uint16_t p : ports) {
        if (p == 0) __builtin_trap();  // 0 must never be accepted
    }
    std::vector<net::IpAddress> hosts;
    if (expand_cidr(in, 4096, hosts, err) && hosts.size() > 4096) __builtin_trap();
    (void)net::IpAddress::parse(in);
    return 0;
}
