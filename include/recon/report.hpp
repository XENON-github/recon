// Scan result model and output writers (table, JSON, CSV).
#pragma once

#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "recon/detect.hpp"
#include "recon/scanner.hpp"

namespace recon {

struct OsGuess {
    std::string family = "Unknown";
    std::string name = "Unknown";
    int confidence = 0;  // 0..100; TTL-only evidence is capped at 50
    int ttl = -1;
    int hops = -1;
    std::vector<std::string> evidence;
};

struct PortRecord {
    std::uint16_t port = 0;
    Protocol protocol = Protocol::Tcp;
    PortState state = PortState::Open;
    double rtt_ms = 0.0;
    int attempts = 1;
    std::optional<Detection> detection;
};

struct HostRecord {
    std::string address;
    std::string hostname;
    std::vector<PortRecord> ports;
    std::optional<OsGuess> os;
};

struct ReportOptions {
    std::size_t tcp_ports = 0, udp_ports = 0;
    bool service_detection = true;
    bool syn_scan = false;
    int intensity = 5;
    int timeout_ms = 1500, retries = 1;
    double rate_per_sec = 0.0;
    std::size_t max_inflight = 0, workers = 0;
};

struct ScanSummary {
    std::size_t hosts = 0;
    std::uint64_t probes = 0, attempts = 0, retries = 0;
    std::uint64_t open = 0, closed = 0, filtered = 0, open_filtered = 0, errors = 0;
    double duration_ms = 0.0, cpu_user_ms = 0.0, cpu_sys_ms = 0.0;
    long max_rss_kb = 0;
    std::string status = "completed";  // or "cancelled"
};

struct DriftEntry {
    std::string address;
    std::string protocol;
    std::uint16_t port = 0;
    std::string service;  // from the report that listed it (baseline or current)
};

// Difference between this scan and a previous (baseline) report, restricted to what this scan
// actually covered, so scanning a subset of ports never produces false "closed" alarms.
struct Drift {
    std::string baseline_path;
    std::vector<DriftEntry> new_open;        // open now, not open in the baseline
    std::vector<DriftEntry> no_longer_open;  // open in the baseline, scanned now, not open
};

struct ScanReport {
    std::string started_utc;
    ReportOptions options;
    std::vector<HostRecord> hosts;
    ScanSummary summary;
    std::optional<Drift> drift;
};

struct TableStyle {
    bool color = false;
};
void write_table(std::ostream& os, const ScanReport& r, const TableStyle& style = {});
void write_json(std::ostream& os, const ScanReport& r);
void write_csv(std::ostream& os, const ScanReport& r);

// Exposed for tests. Output is always valid UTF-8; invalid input bytes become U+FFFD.
std::string json_escape(std::string_view s);
std::string csv_field(std::string_view s);

}  // namespace recon
