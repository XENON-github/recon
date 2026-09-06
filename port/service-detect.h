#ifndef SERVICE_DETECT_H
#define SERVICE_DETECT_H

#include <string>
#include <vector>

struct ServiceInfo {
    int port = 0;
    std::string protocol = "tcp"; // "tcp" or "udp"
    bool is_open = false;
    std::string service_name = "unknown";
    std::string version = "";
    std::string extra_info = "";
    std::string raw_banner = "";
    int received_ttl = -1; // Incoming TTL captured from packets if available
};

// Probe an open TCP port to determine the actual running service and version
ServiceInfo probe_tcp_service(const std::string& ip, int port, int timeout_ms = 1500);

// Probe an open UDP port to determine the running service and version
ServiceInfo probe_udp_service(const std::string& ip, int port, int timeout_ms = 1500);

#endif // SERVICE_DETECT_H
