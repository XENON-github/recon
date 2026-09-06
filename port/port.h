#ifndef PORT_H
#define PORT_H

#include <string>
#include <vector>
#include "service-detect.h"
#include "os-detect.h"

// Scans common TCP ports and detects actual services/versions on open ports
std::vector<ServiceInfo> port_common_tcp(const char* ipAddr, bool detect_services = true);

// Scans all TCP ports (1-65535) and detects actual services/versions on open ports
std::vector<ServiceInfo> port_all_tcp(const char* ipAddr, bool detect_services = true);

// Scans common UDP ports with protocol probes
std::vector<ServiceInfo> port_common_udp(const char* ipAddr);

// Scans all UDP ports (1-65535)
std::vector<ServiceInfo> port_all_udp(const char* ipAddr);

// Scans custom TCP ports and detects actual services/versions on open ports
std::vector<ServiceInfo> port_custom_tcp(const char* ipAddr, const std::vector<int>& ports, bool detect_services = true);

// Run OS detection against the target IP using TTL, port profiles, and discovered service banners
OsInfo run_os_scan(const char* ipAddr, const std::vector<ServiceInfo>& services = {});

// Cleanly print port scan results in a formatted table
void print_scan_table(const std::string& title, const char* ipAddr, const std::vector<ServiceInfo>& results);

#endif // PORT_H
