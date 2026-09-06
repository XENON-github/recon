#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <netdb.h>
#include <arpa/inet.h>
#include "port/port.h"

namespace {

void print_help(const char* prog) {
    std::cout << "Recon - Network Port, Service & OS Scanner\n\n"
              << "Usage:\n"
              << "  " << prog << " <TARGET_IP> [FLAGS]\n"
              << "  " << prog << " [FLAGS] <TARGET_IP>\n\n"
              << "TARGET SPECIFICATION:\n"
              << "  <target>                Target IPv4 address, hostname, or alias\n"
              << "                          Aliases: localhost, me, 'my device'\n"
              << "  -t, --target <target>   Explicit target specification\n"
              << "  * NOTE: Only 1 target IP address is allowed at most.\n\n"
              << "PORT SCANNING FLAGS:\n"
              << "  -pCT                    Scan common TCP ports (~70 popular services)\n"
              << "  -pAT                    Scan all TCP ports (1-65535)\n"
              << "  -pCU                    Scan common UDP ports with service probes\n"
              << "  -pAU                    Scan all UDP ports (1-65535)\n"
              << "  -p <ports>              Scan custom ports (e.g. -p 80,443,8000-8080)\n\n"
              << "SERVICE & VERSION DETECTION:\n"
              << "  -sV, --service-version  Probe open ports for exact service & version (default: ON)\n"
              << "  --no-sV                 Disable service and version probing\n\n"
              << "OPERATING SYSTEM DETECTION:\n"
              << "  -os, -O, --os           Scan and detect Operating System of the target IP\n\n"
              << "COMPREHENSIVE SCAN:\n"
              << "  -A, --all               Run common TCP scan + Service/Version detection + OS scan\n\n"
              << "HELP:\n"
              << "  -h, --help              Display this help message\n\n"
              << "EXAMPLES:\n"
              << "  " << prog << " 192.168.1.1 -pCT\n"
              << "  " << prog << " 192.168.1.1 -pCT -os\n"
              << "  " << prog << " 127.0.0.1 -p 22,80,6379 -os\n"
              << "  " << prog << " localhost -A\n";
}

// Parse comma and hyphen separated port strings: "80,443,8000-8005"
bool parse_custom_ports(const std::string& arg, std::vector<int>& out_ports) {
    std::stringstream ss(arg);
    std::string token;
    while (std::getline(ss, token, ',')) {
        if (token.empty()) continue;
        size_t dash = token.find('-');
        if (dash != std::string::npos) {
            std::string start_str = token.substr(0, dash);
            std::string end_str = token.substr(dash + 1);
            try {
                int start = std::stoi(start_str);
                int end = std::stoi(end_str);
                if (start < 1 || start > 65535 || end < 1 || end > 65535 || start > end) {
                    return false;
                }
                for (int p = start; p <= end; ++p) {
                    out_ports.push_back(p);
                }
            } catch (...) {
                return false;
            }
        } else {
            try {
                int p = std::stoi(token);
                if (p < 1 || p > 65535) return false;
                out_ports.push_back(p);
            } catch (...) {
                return false;
            }
        }
    }
    return !out_ports.empty();
}

// Resolve IP address or hostname to standard IPv4 address string
bool resolve_target_to_ipv4(const std::string& input, std::string& out_ip) {
    // Check aliases
    if (input == "localhost" || input == "me" || input == "my device") {
        out_ip = "127.0.0.1";
        return true;
    }

    // Direct IPv4 check
    sockaddr_in sa{};
    if (inet_pton(AF_INET, input.c_str(), &sa.sin_addr) == 1) {
        out_ip = input;
        return true;
    }

    // Attempt hostname resolution
    addrinfo hints{};
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(input.c_str(), nullptr, &hints, &res) == 0 && res != nullptr) {
        char buf[INET_ADDRSTRLEN];
        auto* addr = reinterpret_cast<sockaddr_in*>(res->ai_addr);
        inet_ntop(AF_INET, &addr->sin_addr, buf, sizeof(buf));
        out_ip = buf;
        std::cout << "[*] Resolved hostname '" << input << "' to " << out_ip << "\n";
        freeaddrinfo(res);
        return true;
    }

    return false;
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Error: No target IP address or flags provided.\n"
                  << "Usage: " << argv[0] << " <TARGET_IP> [FLAGS]\n"
                  << "Run '" << argv[0] << " --help' for available options.\n";
        return 1;
    }

    bool port_common_tcp_flag = false;
    bool port_all_tcp_flag = false;
    bool port_common_udp_flag = false;
    bool port_all_udp_flag = false;
    bool os_scan_flag = false;
    bool detect_services = true;

    std::vector<int> custom_ports;
    std::vector<std::string> raw_targets;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_help(argv[0]);
            return 0;
        } else if (arg == "-pCT") {
            port_common_tcp_flag = true;
        } else if (arg == "-pAT") {
            port_all_tcp_flag = true;
        } else if (arg == "-pCU") {
            port_common_udp_flag = true;
        } else if (arg == "-pAU") {
            port_all_udp_flag = true;
        } else if (arg == "-os" || arg == "-O" || arg == "--os") {
            os_scan_flag = true;
        } else if (arg == "-sV" || arg == "--service-version") {
            detect_services = true;
        } else if (arg == "--no-sV") {
            detect_services = false;
        } else if (arg == "-A" || arg == "--all") {
            port_common_tcp_flag = true;
            os_scan_flag = true;
            detect_services = true;
        } else if (arg == "-t" || arg == "--target" || arg == "-ip") {
            if (i + 1 >= argc) {
                std::cerr << "Error: No target specified after " << arg << "\n";
                return 1;
            }
            raw_targets.push_back(argv[++i]);
        } else if (arg == "-p" || arg == "--ports") {
            if (i + 1 >= argc) {
                std::cerr << "Error: No port list provided after " << arg << "\n";
                return 1;
            }
            if (!parse_custom_ports(argv[++i], custom_ports)) {
                std::cerr << "Error: Invalid port specification '" << argv[i] << "'\n";
                return 1;
            }
        } else if (arg.rfind("-p=", 0) == 0) {
            if (!parse_custom_ports(arg.substr(3), custom_ports)) {
                std::cerr << "Error: Invalid port specification '" << arg.substr(3) << "'\n";
                return 1;
            }
        } else if (arg[0] == '-') {
            std::cerr << "Error: Unknown flag '" << arg << "'. Run '" << argv[0] << " --help' for help.\n";
            return 1;
        } else {
            // Positional target candidate
            raw_targets.push_back(arg);
        }
    }

    // Validate single IP requirement
    if (raw_targets.empty()) {
        std::cerr << "Error: No target IP address provided.\n"
                  << "Usage: " << argv[0] << " <TARGET_IP> [FLAGS]\n"
                  << "Run '" << argv[0] << " --help' for details.\n";
        return 1;
    }

    if (raw_targets.size() > 1) {
        std::cerr << "Error: Multiple target IP addresses provided ('" 
                  << raw_targets[0] << "' and '" << raw_targets[1] 
                  << "'). Only 1 IP address is allowed.\n";
        return 1;
    }

    std::string ip_address;
    if (!resolve_target_to_ipv4(raw_targets[0], ip_address)) {
        std::cerr << "Error: Invalid target IP address or unresolved hostname '" << raw_targets[0] << "'.\n";
        return 1;
    }

    // Check if at least one scan action was requested
    if (!port_common_tcp_flag && !port_all_tcp_flag && !port_common_udp_flag && 
        !port_all_udp_flag && custom_ports.empty() && !os_scan_flag) {
        std::cerr << "Error: No scan action specified.\n"
                  << "Please specify at least one scan flag (e.g. -pCT, -pAT, -pCU, -pAU, -p <ports>, -os, -A).\n"
                  << "Run '" << argv[0] << " --help' for details.\n";
        return 1;
    }

    // Vector to collect all open services across scans for OS detection correlation
    std::vector<ServiceInfo> discovered_services;

    if (port_common_tcp_flag) {
        auto res = port_common_tcp(ip_address.c_str(), detect_services);
        discovered_services.insert(discovered_services.end(), res.begin(), res.end());
    }

    if (!custom_ports.empty()) {
        auto res = port_custom_tcp(ip_address.c_str(), custom_ports, detect_services);
        discovered_services.insert(discovered_services.end(), res.begin(), res.end());
    }

    if (port_all_tcp_flag) {
        auto res = port_all_tcp(ip_address.c_str(), detect_services);
        discovered_services.insert(discovered_services.end(), res.begin(), res.end());
    }

    if (port_common_udp_flag) {
        auto res = port_common_udp(ip_address.c_str());
        discovered_services.insert(discovered_services.end(), res.begin(), res.end());
    }

    if (port_all_udp_flag) {
        auto res = port_all_udp(ip_address.c_str());
        discovered_services.insert(discovered_services.end(), res.begin(), res.end());
    }

    if (os_scan_flag) {
        run_os_scan(ip_address.c_str(), discovered_services);
    }

    return 0;
}
