#ifndef OS_DETECT_H
#define OS_DETECT_H

#include <string>
#include <vector>
#include "service-detect.h"

struct OsInfo {
    std::string target_ip;
    std::string os_family = "Unknown";
    std::string detailed_name = "Unknown OS";
    int confidence = 0;              // 0 - 100%
    int ttl_received = -1;           // Captured incoming TTL (-1 if none)
    int estimated_hops = -1;         // Estimated network hop count
    std::vector<std::string> evidence;
};

// Perform comprehensive OS detection against the target IP
OsInfo detect_os(const std::string& ip, const std::vector<ServiceInfo>& open_services);

// Cleanly format and print OS detection report
void print_os_results(const OsInfo& info);

#endif // OS_DETECT_H
