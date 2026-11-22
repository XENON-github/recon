#include <unistd.h>

#include <csignal>
#include <cstdlib>
#include <sstream>
#include <iostream>

#include "recon/baseline.hpp"
#include "recon/fileio.hpp"
#include "recon/options.hpp"
#include "recon/scan.hpp"
#include "recon/synscan.hpp"

namespace {

recon::CancelToken g_cancel;

extern "C" void on_signal(int) { g_cancel.request(); }  // lock-free atomic store: signal-safe

void install_signal_handlers() {
    struct sigaction sa {};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  // no SA_RESTART: let epoll_wait return EINTR so we notice promptly
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    std::signal(SIGPIPE, SIG_IGN);  // defence in depth; sends already use MSG_NOSIGNAL
}

}  // namespace

int main(int argc, char** argv) {
    using namespace recon;
    const std::string prog = argc > 0 ? argv[0] : "recon";
    Options opt;
    std::string err;
    switch (parse_args(std::vector<std::string>(argv + 1, argv + argc), opt, err)) {
        case ParseStatus::Help: std::cout << help_text(prog); return exit_code::kOk;
        case ParseStatus::Version: std::cout << "recon " << kVersion << "\n"; return exit_code::kOk;
        case ParseStatus::Error:
            std::cerr << "recon: " << err << "\nTry '" << prog << " --help'.\n";
            return exit_code::kUsage;
        case ParseStatus::Ok: break;
    }

    std::vector<Target> targets;
    if (!resolve_targets(opt.targets, opt.resolve, targets, err)) {
        std::cerr << "recon: " << err << "\n";
        return exit_code::kResolve;
    }

    if (opt.dry_run) {
        const std::size_t tcp = opt.tcp_ports().size(), udp = opt.udp_ports().size();
        const std::uint64_t probes = static_cast<std::uint64_t>(targets.size()) * (tcp + udp);
        std::cout << "Dry run: nothing was sent.\n  targets:   " << targets.size() << " host(s)";
        for (std::size_t i = 0; i < targets.size() && i < 5; ++i) std::cout << (i ? ", " : ": ") << targets[i].addr.to_string();
        if (targets.size() > 5) std::cout << ", ...";
        std::cout << "\n  scan:      " << (opt.syn_scan ? "SYN" : "connect") << " (TCP " << tcp << " ports, UDP " << udp
                  << " ports) -> " << probes << " probes\n  detection: "
                  << (opt.detect_services ? "on (intensity " + std::to_string(opt.intensity) + ")" : std::string("off"))
                  << ", OS inference " << (opt.os_detect ? "on" : "off") << "\n  pacing:    "
                  << (opt.rate > 0 ? std::to_string(static_cast<long>(opt.rate)) + " probes/s" : std::string("unlimited rate")) << ", "
                  << opt.max_inflight << " in flight, timeout " << opt.timeout_ms << " ms, " << opt.retries << " retries\n";
        if (opt.rate > 0 && probes > 0) {
            std::cout << "  estimate:  >= " << static_cast<double>(probes) / opt.rate
                      << " s of probing (lower bound; excludes timeouts, retries and service detection)\n";
        }
        return exit_code::kOk;
    }

    if (!opt.quiet) {
        std::cerr << "[!] Only scan systems you own or have explicit written authorization to test.\n"
                  << "[*] " << targets.size() << " host(s), " << opt.tcp_ports().size() << " TCP + "
                  << opt.udp_ports().size() << " UDP port(s), rate "
                  << (opt.rate > 0 ? std::to_string(static_cast<long>(opt.rate)) + "/s" : "unlimited")
                  << ", max " << opt.max_inflight << " sockets in flight\n";
    }

    if (opt.syn_scan) {
        std::string why;
        if (!SynScanner::available(&why)) {
            std::cerr << "recon: -sS: " << why << "\n";
            return exit_code::kRuntime;
        }
        for (const Target& t : targets) {
            if (!t.addr.is_v4()) {
                std::cerr << "recon: -sS supports IPv4 only; " << t.addr.to_string() << " is IPv6 (use -sT)\n";
                return exit_code::kUsage;
            }
        }
    }
    Baseline baseline;
    if (!opt.baseline_path.empty() && !load_baseline(opt.baseline_path, baseline, err)) {
        std::cerr << "recon: " << err << "\n";
        return exit_code::kUsage;
    }
    opt.show_progress = !opt.quiet && (opt.progress == AutoMode::On ||
                                       (opt.progress == AutoMode::Auto && isatty(STDERR_FILENO) != 0));

    install_signal_handlers();
    ScanReport report;
    try {
        report = run_scan(opt, targets, g_cancel);
    } catch (const std::exception& e) {
        std::cerr << "recon: fatal: " << e.what() << "\n";
        return exit_code::kRuntime;
    }

    if (!opt.baseline_path.empty()) report.drift = compute_drift(report, baseline, opt.tcp_ports(), opt.udp_ports());

    const bool to_stdout = opt.output_path.empty() || opt.output_path == "-";
    std::ostringstream rendered;
    switch (opt.format) {
        case OutputFormat::Json: write_json(rendered, report); break;
        case OutputFormat::Csv: write_csv(rendered, report); break;
        case OutputFormat::Table: {
            TableStyle style;
            style.color = to_stdout && (opt.color == AutoMode::On ||
                                        (opt.color == AutoMode::Auto && isatty(STDOUT_FILENO) != 0 &&
                                         std::getenv("NO_COLOR") == nullptr));
            write_table(rendered, report, style);
            break;
        }
    }
    if (to_stdout) {
        std::cout << rendered.str();
        std::cout.flush();
        if (!std::cout) {
            std::cerr << "recon: failed writing output\n";
            return exit_code::kRuntime;
        }
    } else if (!write_file_private(opt.output_path, rendered.str(), err)) {
        std::cerr << "recon: " << err << "\n";
        return exit_code::kRuntime;
    }

    const auto& s = report.summary;
    if (s.status == "cancelled") return exit_code::kInterrupted;
    if (s.errors > 0 && s.open + s.closed + s.filtered + s.open_filtered == 0) return exit_code::kRuntime;
    if (report.drift && !report.drift->new_open.empty()) return exit_code::kDrift;
    if (opt.fail_on_open && s.open > 0) return exit_code::kOpenFound;
    return exit_code::kOk;
}
