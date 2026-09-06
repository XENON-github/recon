#include "os-detect.h"
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <poll.h>

namespace {

std::string to_lower(const std::string& s) {
    std::string res = s;
    std::transform(res.begin(), res.end(), res.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return res;
}

// Send ICMP Echo Request to target and retrieve reply TTL
int ping_icmp_ttl(const std::string& ip, int timeout_ms = 1000) {
    // Try unprivileged ICMP socket first (standard on Linux)
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock < 0) {
        // Try raw socket fallback if root
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) return -1;
    }

    int on = 1;
    setsockopt(sock, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on));

    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip.c_str(), &dest.sin_addr) != 1) {
        close(sock);
        return -1;
    }

    struct icmphdr icmp{};
    icmp.type = ICMP_ECHO;
    icmp.code = 0;
    icmp.un.echo.id = htons(static_cast<uint16_t>(getpid() & 0xFFFF));
    icmp.un.echo.sequence = htons(1);

    if (sendto(sock, &icmp, sizeof(icmp), 0, reinterpret_cast<sockaddr*>(&dest), sizeof(dest)) < 0) {
        close(sock);
        return -1;
    }

    pollfd pfd{sock, POLLIN, 0};
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret > 0 && (pfd.revents & POLLIN)) {
        char buf[512];
        char cbuf[256];
        iovec iov{buf, sizeof(buf)};
        msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof(cbuf);

        ssize_t n = recvmsg(sock, &msg, 0);
        if (n > 0) {
            for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL) {
                    int ttl = *reinterpret_cast<int*>(CMSG_DATA(cmsg));
                    close(sock);
                    return ttl;
                }
            }
        }
    }

    close(sock);
    return -1;
}

} // anonymous namespace

OsInfo detect_os(const std::string& ip, const std::vector<ServiceInfo>& open_services) {
    OsInfo result;
    result.target_ip = ip;

    // 1. Gather TTL
    int best_ttl = -1;

    // Check if any open service already caught incoming TTL
    for (const auto& svc : open_services) {
        if (svc.received_ttl > 0) {
            best_ttl = svc.received_ttl;
            result.evidence.push_back("TCP packet TTL captured on port " + std::to_string(svc.port) + 
                                     ": " + std::to_string(best_ttl));
            break;
        }
    }

    // Try ICMP Ping
    int icmp_ttl = ping_icmp_ttl(ip, 800);
    if (icmp_ttl > 0) {
        if (best_ttl < 0) best_ttl = icmp_ttl;
        result.evidence.push_back("ICMP Echo Reply received with TTL: " + std::to_string(icmp_ttl));
    }

    result.ttl_received = best_ttl;

    // Estimate initial TTL and network hops
    int initial_ttl = 64;
    if (best_ttl > 0) {
        if (best_ttl <= 64) {
            initial_ttl = 64;
            result.estimated_hops = 64 - best_ttl;
            result.os_family = "Linux / Unix";
            result.detailed_name = "Linux 3.x - 6.x / Unix";
            result.confidence = 70;
        } else if (best_ttl <= 128) {
            initial_ttl = 128;
            result.estimated_hops = 128 - best_ttl;
            result.os_family = "Windows";
            result.detailed_name = "Microsoft Windows 10/11 or Windows Server";
            result.confidence = 70;
        } else {
            initial_ttl = 255;
            result.estimated_hops = 255 - best_ttl;
            result.os_family = "Network Device / Solaris";
            result.detailed_name = "Cisco IOS / Network Device / Solaris";
            result.confidence = 65;
        }
        result.evidence.push_back("Initial TTL estimated: " + std::to_string(initial_ttl) + 
                                 " (hops: " + std::to_string(result.estimated_hops) + ")");
    }

    // 2. Port Profile Analysis
    bool has_win_ports = false;
    bool has_unix_ports = false;
    for (const auto& svc : open_services) {
        if (!svc.is_open) continue;
        if (svc.port == 135 || svc.port == 139 || svc.port == 445 || svc.port == 3389 || svc.port == 5985) {
            has_win_ports = true;
        }
        if (svc.port == 22 || svc.port == 111 || svc.port == 2049) {
            has_unix_ports = true;
        }
    }

    if (has_win_ports) {
        result.evidence.push_back("Windows signature ports detected open (e.g. SMB/MSRPC/RDP)");
        if (result.os_family == "Windows") {
            result.confidence = std::max(result.confidence, 85);
        } else if (result.confidence < 75) {
            result.os_family = "Windows";
            result.detailed_name = "Microsoft Windows";
            result.confidence = 75;
        }
    }

    if (has_unix_ports && !has_win_ports) {
        result.evidence.push_back("Unix signature ports detected open (SSH/RPC/NFS)");
        if (result.os_family == "Linux / Unix") {
            result.confidence = std::max(result.confidence, 80);
        }
    }

    // 3. Banner & Service Version Deep Inspection (High confidence!)
    for (const auto& svc : open_services) {
        std::string all_text = to_lower(svc.service_name + " " + svc.version + " " + svc.extra_info + " " + svc.raw_banner);

        // Ubuntu
        if (all_text.find("ubuntu") != std::string::npos) {
            result.os_family = "Linux";
            result.detailed_name = "Linux (Ubuntu)";
            result.confidence = 98;
            result.evidence.push_back("Banner on port " + std::to_string(svc.port) + " explicitly identifies Ubuntu (" + svc.version + ")");
            break;
        }
        // Debian
        if (all_text.find("debian") != std::string::npos) {
            result.os_family = "Linux";
            result.detailed_name = "Linux (Debian)";
            result.confidence = 98;
            result.evidence.push_back("Banner on port " + std::to_string(svc.port) + " explicitly identifies Debian (" + svc.version + ")");
            break;
        }
        // Arch Linux
        if (all_text.find("arch") != std::string::npos) {
            result.os_family = "Linux";
            result.detailed_name = "Linux (Arch Linux)";
            result.confidence = 98;
            result.evidence.push_back("Banner on port " + std::to_string(svc.port) + " explicitly identifies Arch Linux (" + svc.version + ")");
            break;
        }
        // CentOS / RHEL / Fedora
        if (all_text.find("centos") != std::string::npos || all_text.find("el7") != std::string::npos || 
            all_text.find("el8") != std::string::npos || all_text.find("el9") != std::string::npos ||
            all_text.find("red hat") != std::string::npos || all_text.find("fedora") != std::string::npos) {
            result.os_family = "Linux";
            result.detailed_name = "Linux (CentOS / RHEL / Fedora)";
            result.confidence = 96;
            result.evidence.push_back("Banner on port " + std::to_string(svc.port) + " identifies Enterprise Linux (" + svc.version + ")");
            break;
        }
        // Alpine Linux
        if (all_text.find("alpine") != std::string::npos) {
            result.os_family = "Linux";
            result.detailed_name = "Linux (Alpine)";
            result.confidence = 98;
            result.evidence.push_back("Banner on port " + std::to_string(svc.port) + " identifies Alpine Linux");
            break;
        }
        // OpenWrt / Embedded
        if (all_text.find("openwrt") != std::string::npos || all_text.find("dropbear") != std::string::npos) {
            result.os_family = "Linux";
            result.detailed_name = "Embedded Linux (OpenWrt / Router)";
            result.confidence = 92;
            result.evidence.push_back("Banner on port " + std::to_string(svc.port) + " indicates OpenWrt/Dropbear embedded system");
            break;
        }
        // FreeBSD / OpenBSD / NetBSD
        if (all_text.find("freebsd") != std::string::npos) {
            result.os_family = "BSD";
            result.detailed_name = "FreeBSD";
            result.confidence = 98;
            result.evidence.push_back("Banner on port " + std::to_string(svc.port) + " identifies FreeBSD");
            break;
        }
        if (all_text.find("openbsd") != std::string::npos) {
            result.os_family = "BSD";
            result.detailed_name = "OpenBSD";
            result.confidence = 98;
            result.evidence.push_back("Banner on port " + std::to_string(svc.port) + " identifies OpenBSD");
            break;
        }
        // Windows IIS or OpenSSH for Windows
        if (all_text.find("microsoft-iis/10") != std::string::npos) {
            result.os_family = "Windows";
            result.detailed_name = "Microsoft Windows 10/11 or Windows Server 2016-2022 (IIS 10.0)";
            result.confidence = 98;
            result.evidence.push_back("IIS 10.0 web server detected on port " + std::to_string(svc.port));
            break;
        }
        if (all_text.find("microsoft-iis") != std::string::npos || all_text.find("microsoft-httpapi") != std::string::npos ||
            all_text.find("openssh_for_windows") != std::string::npos) {
            result.os_family = "Windows";
            result.detailed_name = "Microsoft Windows";
            result.confidence = 95;
            result.evidence.push_back("Microsoft Windows service banner detected on port " + std::to_string(svc.port));
            break;
        }
        // Generic Linux banner (e.g. from redis info os:Linux ...)
        if (all_text.find("os:linux") != std::string::npos || all_text.find("linux") != std::string::npos) {
            result.os_family = "Linux";
            if (svc.extra_info.find("OS:") != std::string::npos) {
                result.detailed_name = svc.extra_info.substr(4);
            } else {
                result.detailed_name = "Linux Kernel (Unix-like)";
            }
            result.confidence = 95;
            result.evidence.push_back("Service on port " + std::to_string(svc.port) + " reported OS details: " + svc.extra_info);
            break;
        }
    }

    // 4. Localhost check: If target is loopback, verify with local kernel uname
    if (ip == "127.0.0.1") {
        struct utsname u{};
        if (uname(&u) == 0) {
            result.os_family = u.sysname;
            result.detailed_name = std::string(u.sysname) + " " + u.release + " (" + u.nodename + ")";
            result.confidence = 100;
            result.evidence.push_back("Target is local system (" + std::string(u.sysname) + " " + u.release + " " + u.machine + ")");
        }
    }

    // If completely unable to contact target
    if (result.confidence == 0) {
        result.os_family = "Unknown";
        result.detailed_name = "Unable to determine OS (No response received)";
        result.evidence.push_back("No ICMP response, TCP connection, or service banners available");
    }

    return result;
}

void print_os_results(const OsInfo& info) {
    std::cout << "\n-----------------------------------------------------\n"
              << "  OPERATING SYSTEM DETECTION REPORT\n"
              << "-----------------------------------------------------\n"
              << "Target IP:      " << info.target_ip << "\n"
              << "OS Detected:    " << info.detailed_name << "\n"
              << "OS Family:      " << info.os_family << "\n"
              << "Confidence:     " << info.confidence << "%\n";

    if (info.ttl_received > 0) {
        std::cout << "Observed TTL:   " << info.ttl_received << " (Estimated Hops: " << info.estimated_hops << ")\n";
    }

    if (!info.evidence.empty()) {
        std::cout << "\nDetection Evidence:\n";
        for (const auto& ev : info.evidence) {
            std::cout << "  * " << ev << "\n";
        }
    }
    std::cout << "-----------------------------------------------------\n";
}
