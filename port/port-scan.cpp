#include "port.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

namespace {

bool check_tcp_port_open(const std::string& ip, int port, int timeout_ms = 500) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &target.sin_addr) != 1) {
        close(sock);
        return false;
    }

    int rc = connect(sock, reinterpret_cast<sockaddr*>(&target), sizeof(target));
    if (rc == 0) {
        close(sock);
        return true;
    }

    if (rc < 0 && errno == EINPROGRESS) {
        pollfd pfd{sock, POLLOUT, 0};
        int p_res = poll(&pfd, 1, timeout_ms);
        if (p_res > 0) {
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len) == 0 && so_error == 0) {
                close(sock);
                return true;
            }
        }
    }

    close(sock);
    return false;
}

std::vector<ServiceInfo> scan_tcp_ports_concurrent(const std::string& ip, 
                                                   const std::vector<int>& ports, 
                                                   bool detect_services,
                                                   size_t num_threads = 50) {
    std::vector<ServiceInfo> open_ports;
    std::mutex mtx;
    std::atomic<size_t> next_idx(0);

    auto worker = [&]() {
        while (true) {
            size_t idx = next_idx.fetch_add(1);
            if (idx >= ports.size()) break;
            int port = ports[idx];

            if (detect_services) {
                ServiceInfo info = probe_tcp_service(ip, port, 1000);
                if (info.is_open) {
                    std::lock_guard<std::mutex> lock(mtx);
                    open_ports.push_back(info);
                }
            } else {
                if (check_tcp_port_open(ip, port, 500)) {
                    ServiceInfo info;
                    info.port = port;
                    info.protocol = "tcp";
                    info.is_open = true;
                    info.service_name = "unknown";
                    info.version = "";
                    std::lock_guard<std::mutex> lock(mtx);
                    open_ports.push_back(info);
                }
            }
        }
    };

    size_t threads_to_launch = std::min(num_threads, ports.size());
    if (threads_to_launch == 0) threads_to_launch = 1;

    std::vector<std::thread> workers;
    workers.reserve(threads_to_launch);
    for (size_t i = 0; i < threads_to_launch; ++i) {
        workers.emplace_back(worker);
    }
    for (auto& t : workers) {
        if (t.joinable()) t.join();
    }

    std::sort(open_ports.begin(), open_ports.end(), [](const ServiceInfo& a, const ServiceInfo& b) {
        return a.port < b.port;
    });

    return open_ports;
}

} // anonymous namespace

void print_scan_table(const std::string& title, const char* ipAddr, const std::vector<ServiceInfo>& results) {
    std::cout << "\n================================================================================" << std::endl;
    std::cout << "TARGET: " << ipAddr << std::endl;
    std::cout << title << std::endl;
    std::cout << "================================================================================" << std::endl;

    if (results.empty()) {
        std::cout << "No open ports found." << std::endl;
        std::cout << "================================================================================" << std::endl;
        return;
    }

    std::cout << std::left << std::setw(12) << "PORT"
              << std::left << std::setw(8)  << "STATE"
              << std::left << std::setw(15) << "SERVICE"
              << "VERSION / BANNER DETAILS" << std::endl;
    std::cout << "--------------------------------------------------------------------------------" << std::endl;

    for (const auto& svc : results) {
        std::string port_str = std::to_string(svc.port) + "/" + svc.protocol;
        std::string state_str = svc.is_open ? "OPEN" : "CLOSED";
        std::string ver_details = svc.version;
        if (!svc.extra_info.empty()) {
            if (!ver_details.empty()) ver_details += " (" + svc.extra_info + ")";
            else ver_details = svc.extra_info;
        }
        if (ver_details.empty() && !svc.raw_banner.empty()) {
            ver_details = svc.raw_banner;
        }
        if (ver_details.empty()) {
            ver_details = "[no banner returned]";
        }

        std::cout << std::left << std::setw(12) << port_str
                  << std::left << std::setw(8)  << state_str
                  << std::left << std::setw(15) << svc.service_name
                  << ver_details << std::endl;
    }

    std::cout << "================================================================================" << std::endl;
    std::cout << "Found " << results.size() << " open port(s)." << std::endl;
}

std::vector<ServiceInfo> port_common_tcp(const char* ipAddr, bool detect_services) {
    const std::vector<int> commonPorts = {
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139, 143,
        161, 162, 179, 389, 443, 445, 465, 514, 515, 587, 631, 993, 995, 1080, 1194,
        1433, 1521, 1716, 1723, 1883, 2049, 2375, 2376, 3306, 3389, 3690, 4369, 5000,
        5432, 5672, 5900, 5985, 5986, 6379, 6443, 6667, 7001, 8000, 8008, 8080, 8081,
        8443, 8888, 9000, 9090, 9200, 9300, 9418, 11211, 27017, 40011, 46503
    };

    std::vector<ServiceInfo> results = scan_tcp_ports_concurrent(ipAddr, commonPorts, detect_services, 40);
    print_scan_table("Scanning common TCP ports...", ipAddr, results);
    return results;
}

std::vector<ServiceInfo> port_all_tcp(const char* ipAddr, bool detect_services) {
    std::vector<int> allPorts;
    allPorts.reserve(65535);
    for (int p = 1; p <= 65535; ++p) {
        allPorts.push_back(p);
    }

    std::vector<ServiceInfo> results = scan_tcp_ports_concurrent(ipAddr, allPorts, detect_services, 120);
    print_scan_table("Scanning all TCP ports (1-65535)...", ipAddr, results);
    return results;
}

std::vector<ServiceInfo> port_custom_tcp(const char* ipAddr, const std::vector<int>& ports, bool detect_services) {
    std::vector<ServiceInfo> results = scan_tcp_ports_concurrent(ipAddr, ports, detect_services, 40);
    print_scan_table("Scanning custom TCP ports...", ipAddr, results);
    return results;
}

std::vector<ServiceInfo> port_common_udp(const char* ipAddr) {
    const std::vector<int> commonUdpPorts = {
        53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 554, 6000
    };

    std::vector<ServiceInfo> results;
    std::mutex mtx;
    std::atomic<size_t> next_idx(0);

    auto worker = [&]() {
        while (true) {
            size_t idx = next_idx.fetch_add(1);
            if (idx >= commonUdpPorts.size()) break;
            int port = commonUdpPorts[idx];

            ServiceInfo info = probe_udp_service(ipAddr, port, 1200);
            if (info.is_open) {
                std::lock_guard<std::mutex> lock(mtx);
                results.push_back(info);
            }
        }
    };

    std::vector<std::thread> workers;
    size_t num_threads = std::min(size_t(8), commonUdpPorts.size());
    for (size_t i = 0; i < num_threads; ++i) workers.emplace_back(worker);
    for (auto& t : workers) if (t.joinable()) t.join();

    std::sort(results.begin(), results.end(), [](const ServiceInfo& a, const ServiceInfo& b) {
        return a.port < b.port;
    });

    print_scan_table("Scanning common UDP ports...", ipAddr, results);
    return results;
}

std::vector<ServiceInfo> port_all_udp(const char* ipAddr) {
    std::vector<ServiceInfo> results;
    std::mutex mtx;
    std::atomic<size_t> next_port(1);

    auto worker = [&]() {
        while (true) {
            int port = next_port.fetch_add(1);
            if (port > 65535) break;

            ServiceInfo info = probe_udp_service(ipAddr, port, 400);
            if (info.is_open) {
                std::lock_guard<std::mutex> lock(mtx);
                results.push_back(info);
            }
        }
    };

    std::vector<std::thread> workers;
    size_t num_threads = 60;
    for (size_t i = 0; i < num_threads; ++i) workers.emplace_back(worker);
    for (auto& t : workers) if (t.joinable()) t.join();

    std::sort(results.begin(), results.end(), [](const ServiceInfo& a, const ServiceInfo& b) {
        return a.port < b.port;
    });

    print_scan_table("Scanning all UDP ports (1-65535)...", ipAddr, results);
    return results;
}

OsInfo run_os_scan(const char* ipAddr, const std::vector<ServiceInfo>& services) {
    OsInfo info = detect_os(ipAddr, services);
    print_os_results(info);
    return info;
}
