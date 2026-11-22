#include "recon/osdetect.hpp"

#include <netinet/ip_icmp.h>
#include <poll.h>
#include <sys/utsname.h>

#include <algorithm>
#include <cstring>
#include <map>

namespace recon {

int icmp_echo_ttl(const net::IpAddress& ip, Millis timeout) {
    if (!ip.is_v4()) return -1;  // ICMPv6 hop-limit probing not implemented
    net::UniqueFd fd(::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP));
    if (!fd) return -1;  // needs net.ipv4.ping_group_range to include our gid; no raw fallback
    const int on = 1;
    ::setsockopt(fd.get(), IPPROTO_IP, IP_RECVTTL, &on, sizeof(on));

    const net::Endpoint dst(ip, 0);
    icmphdr hdr{};
    hdr.type = ICMP_ECHO;
    hdr.un.echo.sequence = htons(1);  // kernel assigns id and checksum on ping sockets
    if (::sendto(fd.get(), &hdr, sizeof(hdr), MSG_NOSIGNAL, dst.addr(), dst.len()) < 0) return -1;

    if (net::wait_fd(fd.get(), POLLIN, Clock::now() + timeout) <= 0) return -1;
    char buf[256];
    alignas(cmsghdr) char ctrl[256];
    iovec iov{buf, sizeof(buf)};
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl;
    msg.msg_controllen = sizeof(ctrl);
    if (::recvmsg(fd.get(), &msg, 0) < 0) return -1;
    for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_TTL) {
            int ttl = 0;
            std::memcpy(&ttl, CMSG_DATA(c), sizeof(ttl));  // memcpy: CMSG_DATA may be unaligned
            return ttl;
        }
    }
    return -1;
}

OsGuess infer_os(const net::IpAddress& ip, const std::vector<PortRecord>& open_ports, int icmp_ttl) {
    OsGuess g;
    g.ttl = icmp_ttl;

    if (icmp_ttl > 0) {
        const int initial = icmp_ttl <= 64 ? 64 : (icmp_ttl <= 128 ? 128 : 255);
        g.hops = initial - icmp_ttl;
        g.evidence.push_back("ICMP echo TTL " + std::to_string(icmp_ttl) + " suggests initial TTL " +
                             std::to_string(initial) + " (~" + std::to_string(g.hops) + " hops)");
        if (initial == 64) { g.family = "Unix-like"; g.name = "Linux/BSD/macOS/Android (TTL 64)"; }
        else if (initial == 128) { g.family = "Windows"; g.name = "Windows (TTL 128)"; }
        else { g.family = "Network device"; g.name = "Network device / Solaris (TTL 255)"; }
        g.confidence = 40;
    }

    int win_ports = 0;
    for (const PortRecord& p : open_ports) {
        if (p.protocol == Protocol::Tcp &&
            (p.port == 135 || p.port == 139 || p.port == 445 || p.port == 3389 || p.port == 5985))
            ++win_ports;
    }
    if (win_ports >= 2) {
        g.evidence.push_back(std::to_string(win_ports) + " Windows-typical ports open (SMB/RPC/RDP/WinRM)");
        if (g.family != "Windows") {
            g.family = "Windows";
            g.name = "Windows (port profile)";
            g.confidence = 55;
        } else {
            g.confidence = 55;
        }
    }

    // Service banners: strongest signal we have, but still self-reported package metadata.
    std::map<std::string, int> votes;
    for (const PortRecord& p : open_ports) {
        if (p.detection && !p.detection->os_hint.empty()) {
            ++votes[p.detection->os_hint];
            g.evidence.push_back("port " + std::to_string(p.port) + " banner reports '" +
                                 p.detection->os_hint + "'");
        }
    }
    if (!votes.empty()) {
        const auto best = std::max_element(votes.begin(), votes.end(),
                                           [](auto& a, auto& b) { return a.second < b.second; });
        const bool win = best->first == "Windows";
        const bool conflict = (win && g.family == "Unix-like") || (!win && g.family == "Windows");
        g.name = best->first;
        g.family = win ? "Windows" : (best->first.find("BSD") != std::string::npos ? "BSD" : "Linux");
        g.confidence = conflict ? 50 : (votes.size() > 1 ? 70 : 80);
        if (conflict) g.evidence.push_back("banner and TTL evidence disagree; confidence reduced");
        if (votes.size() > 1) g.evidence.push_back("multiple conflicting OS hints in banners");
        g.evidence.push_back("note: distro tags describe the software package, not necessarily the host kernel (containers)");
    }

    if (ip.is_loopback()) {
        utsname u{};
        if (::uname(&u) == 0) {
            g.family = u.sysname;
            g.name = std::string(u.sysname) + " " + u.release;
            g.confidence = 100;
            g.evidence.push_back("target is a loopback address: local kernel is " + g.name);
        }
    }
    if (g.confidence == 0) g.evidence.push_back("no ICMP reply, no TCP services, no banner hints");
    return g;
}

}  // namespace recon
