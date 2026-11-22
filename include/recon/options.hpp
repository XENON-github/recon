// Command-line options and parsing.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "recon/target.hpp"

namespace recon {

namespace exit_code {
inline constexpr int kOk = 0;           // scan completed
inline constexpr int kOpenFound = 1;    // only with --fail-on-open
inline constexpr int kUsage = 2;        // bad command line
inline constexpr int kResolve = 3;      // target could not be resolved / expanded
inline constexpr int kRuntime = 4;      // I/O failure, or every probe errored
inline constexpr int kDrift = 5;        // --baseline: new open ports since the baseline
inline constexpr int kInterrupted = 130;
}  // namespace exit_code

enum class OutputFormat { Table, Json, Csv };
enum class AutoMode { Auto, On, Off };  // for --color and --progress

struct Options {
    std::vector<std::string> targets;
    bool tcp_common = false, tcp_all = false, udp_common = false, udp_all = false;
    std::vector<std::uint16_t> custom_ports;
    bool syn_scan = false;  // -sS: raw half-open scan (needs CAP_NET_RAW); default is connect()
    bool detect_services = true;
    bool os_detect = false;
    int intensity = 5;
    bool tls_inspect = true;
    ResolveOptions resolve;
    std::size_t max_inflight = 128;
    double rate = 500.0;  // new probes per second; 0 = unlimited
    int timeout_ms = 1500;
    int probe_timeout_ms = 1500;  // cap for service-detection waits
    int banner_wait_ms = 0;  // 0 = automatic (<= 400 ms, RTT-adaptive); >0 = exact passive wait
    bool adaptive_timeouts = true;
    int retries = 1;
    std::size_t workers = 16;
    OutputFormat format = OutputFormat::Table;
    std::string output_path;
    bool quiet = false;
    bool keep_open_filtered = false;
    bool fail_on_open = false;
    bool dry_run = false;  // --dry-run: print what would be scanned, send nothing
    std::string baseline_path;  // --baseline <report.json>
    AutoMode color = AutoMode::Auto;
    AutoMode progress = AutoMode::Auto;
    bool show_progress = false;  // resolved by main() from `progress` and isatty()

    [[nodiscard]] std::vector<std::uint16_t> tcp_ports() const;
    [[nodiscard]] std::vector<std::uint16_t> udp_ports() const;
    [[nodiscard]] bool has_scan_action() const {
        return tcp_common || tcp_all || udp_common || udp_all || !custom_ports.empty() || os_detect;
    }
};

enum class ParseStatus { Ok, Help, Version, Error };

// args excludes argv[0]. On Error, `error` holds a one-line message.
ParseStatus parse_args(const std::vector<std::string>& args, Options& opt, std::string& error);

// Reads one target per line ('#' starts a comment, blank lines ignored). Path "-" reads stdin.
bool read_target_file(const std::string& path, std::vector<std::string>& out, std::string& error);

std::string help_text(const std::string& prog);

}  // namespace recon
