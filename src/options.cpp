#include "recon/options.hpp"

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <fstream>
#include <iostream>

namespace recon {

std::vector<std::uint16_t> Options::tcp_ports() const {
    std::vector<std::uint16_t> v = custom_ports;
    if (tcp_all) {
        v = all_ports();
    } else if (tcp_common) {
        v.insert(v.end(), common_tcp_ports().begin(), common_tcp_ports().end());
    }
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
    return v;
}

std::vector<std::uint16_t> Options::udp_ports() const {
    if (udp_all) return all_ports();
    return udp_common ? common_udp_ports() : std::vector<std::uint16_t>{};
}

namespace {

bool to_int(const std::string& s, long lo, long hi, long& out) {
    long v = 0;
    const auto r = std::from_chars(s.data(), s.data() + s.size(), v);
    if (s.empty() || r.ec != std::errc() || r.ptr != s.data() + s.size() || v < lo || v > hi) return false;
    out = v;
    return true;
}

bool to_double(const std::string& s, double lo, double hi, double& out) {
    char* end = nullptr;
    const double v = std::strtod(s.c_str(), &end);
    if (s.empty() || end != s.c_str() + s.size() || !(v >= lo && v <= hi)) return false;
    out = v;
    return true;
}

bool apply_profile(const std::string& name, Options& o, std::string& err) {
    if (name == "quick") {
        o.tcp_common = true; o.intensity = 3; o.rate = 1000; o.retries = 0; o.timeout_ms = 800;
    } else if (name == "standard") {
        o.tcp_common = true;
    } else if (name == "full") {
        o.tcp_all = true; o.rate = 2000; o.max_inflight = 512;
    } else if (name == "stealth") {
        o.tcp_common = true; o.intensity = 2; o.rate = 20; o.max_inflight = 8; o.retries = 2;
        o.timeout_ms = 3000; o.workers = 2;
    } else {
        err = "unknown profile '" + name + "' (quick, standard, full, stealth)";
        return false;
    }
    return true;
}

bool parse_auto(const std::string& v, AutoMode& m) {
    if (v == "auto") m = AutoMode::Auto;
    else if (v == "always" || v == "on") m = AutoMode::On;
    else if (v == "never" || v == "off") m = AutoMode::Off;
    else return false;
    return true;
}

}  // namespace

bool read_target_file(const std::string& path, std::vector<std::string>& out, std::string& error) {
    std::ifstream file;
    std::istream* in = &std::cin;
    if (path != "-") {
        file.open(path);
        if (!file) { error = "cannot open target file '" + path + "'"; return false; }
        in = &file;
    }
    constexpr std::size_t kMaxLine = 4096;  // a hostname is at most 253 bytes; refuse absurd lines
    std::string line;
    std::size_t lines = 0;
    bool more = true;
    while (more) {
        line.clear();
        char c = 0;
        more = false;
        while (in->get(c)) {  // bounded read: never buffers more than kMaxLine bytes of one line
            more = true;
            if (c == '\n') break;
            if (line.size() >= kMaxLine) {
                error = "target file line " + std::to_string(lines + 1) + " is longer than " + std::to_string(kMaxLine) + " bytes";
                return false;
            }
            line.push_back(c);
        }
        if (!more) break;
        if (++lines > 1048576) { error = "target file has more than 1048576 lines"; return false; }
        const auto hash = line.find('#');
        if (hash != std::string::npos) line.erase(hash);
        const auto b2 = line.find_first_not_of(" \t\r");
        if (b2 == std::string::npos) continue;
        const auto e2 = line.find_last_not_of(" \t\r");
        out.push_back(line.substr(b2, e2 - b2 + 1));
    }
    return true;
}

ParseStatus parse_args(const std::vector<std::string>& args, Options& opt, std::string& err) {
    // Profiles only set defaults, so apply them first; explicit flags below then override them.
    for (std::size_t i = 0; i < args.size(); ++i) {
        std::string name;
        if (args[i] == "--profile" && i + 1 < args.size()) name = args[i + 1];
        else if (args[i].rfind("--profile=", 0) == 0) name = args[i].substr(10);
        else continue;
        if (!apply_profile(name, opt, err)) return ParseStatus::Error;
    }
    for (std::size_t i = 0; i < args.size(); ++i) {
        std::string a = args[i];
        std::string inline_val;
        bool has_inline = false;
        if (a.rfind("--", 0) == 0) {
            const auto eq = a.find('=');
            if (eq != std::string::npos) {
                inline_val = a.substr(eq + 1);
                a = a.substr(0, eq);
                has_inline = true;
            }
        } else if (a.rfind("-p=", 0) == 0) {
            inline_val = a.substr(3);
            a = "-p";
            has_inline = true;
        }
        auto value = [&](std::string& out) {
            if (has_inline) { out = inline_val; return true; }
            if (i + 1 >= args.size()) { err = "option '" + a + "' requires a value"; return false; }
            out = args[++i];
            return true;
        };
        std::string v;
        long n = 0;

        if (a == "-h" || a == "--help") return ParseStatus::Help;
        if (a == "--version") return ParseStatus::Version;
        else if (a == "-pCT") opt.tcp_common = true;
        else if (a == "-pAT") opt.tcp_all = true;
        else if (a == "-pCU") opt.udp_common = true;
        else if (a == "-pAU") opt.udp_all = true;
        else if (a == "-os" || a == "-O" || a == "--os") opt.os_detect = true;
        else if (a == "-sS" || a == "--syn") opt.syn_scan = true;
        else if (a == "-sT" || a == "--connect") opt.syn_scan = false;
        else if (a == "-sV" || a == "--service-version") opt.detect_services = true;
        else if (a == "--no-sV") opt.detect_services = false;
        else if (a == "--no-tls-inspect") opt.tls_inspect = false;
        else if (a == "--no-adaptive") opt.adaptive_timeouts = false;
        else if (a == "-A" || a == "--all") { opt.tcp_common = true; opt.os_detect = true; opt.detect_services = true; }
        else if (a == "--profile") { if (!value(v)) return ParseStatus::Error; }  // handled in the pre-pass
        else if (a == "--progress") opt.progress = AutoMode::On;
        else if (a == "--no-progress") opt.progress = AutoMode::Off;
        else if (a == "--color") {
            if (!value(v)) return ParseStatus::Error;
            if (!parse_auto(v, opt.color)) { err = "--color must be auto, always or never"; return ParseStatus::Error; }
        } else if (a == "--baseline") {
            if (!value(opt.baseline_path)) return ParseStatus::Error;
        } else if (a == "-iL" || a == "--input-list") {
            if (!value(v)) return ParseStatus::Error;
            if (!read_target_file(v, opt.targets, err)) return ParseStatus::Error;
        }
        else if (a == "-4") opt.resolve.ipv4_only = true;
        else if (a == "-6") opt.resolve.ipv6_only = true;
        else if (a == "--json") opt.format = OutputFormat::Json;
        else if (a == "--csv") opt.format = OutputFormat::Csv;
        else if (a == "-q" || a == "--quiet") opt.quiet = true;
        else if (a == "--fail-on-open") opt.fail_on_open = true;
        else if (a == "--dry-run") opt.dry_run = true;
        else if (a == "--show-open-filtered") opt.keep_open_filtered = true;
        else if (a == "-t" || a == "--target" || a == "-ip") {
            if (!value(v)) return ParseStatus::Error;
            opt.targets.push_back(v);
        } else if (a == "-p" || a == "--ports") {
            if (!value(v)) return ParseStatus::Error;
            if (!parse_port_spec(v, opt.custom_ports, err)) return ParseStatus::Error;
        } else if (a == "-o" || a == "--output") {
            if (!value(opt.output_path)) return ParseStatus::Error;
        } else if (a == "--timeout") {
            if (!value(v)) return ParseStatus::Error;
            if (!to_int(v, 10, 120000, n)) { err = "--timeout must be 10-120000 (ms)"; return ParseStatus::Error; }
            opt.timeout_ms = static_cast<int>(n);
        } else if (a == "--probe-timeout") {
            if (!value(v)) return ParseStatus::Error;
            if (!to_int(v, 50, 120000, n)) { err = "--probe-timeout must be 50-120000 (ms)"; return ParseStatus::Error; }
            opt.probe_timeout_ms = static_cast<int>(n);
        } else if (a == "--banner-wait") {
            if (!value(v)) return ParseStatus::Error;
            if (!to_int(v, 50, 60000, n)) { err = "--banner-wait must be 50-60000 (ms)"; return ParseStatus::Error; }
            opt.banner_wait_ms = static_cast<int>(n);
        } else if (a == "--retries") {
            if (!value(v)) return ParseStatus::Error;
            if (!to_int(v, 0, 10, n)) { err = "--retries must be 0-10"; return ParseStatus::Error; }
            opt.retries = static_cast<int>(n);
        } else if (a == "--max-inflight") {
            if (!value(v)) return ParseStatus::Error;
            if (!to_int(v, 1, 100000, n)) { err = "--max-inflight must be 1-100000"; return ParseStatus::Error; }
            opt.max_inflight = static_cast<std::size_t>(n);
        } else if (a == "--workers") {
            if (!value(v)) return ParseStatus::Error;
            if (!to_int(v, 1, 512, n)) { err = "--workers must be 1-512"; return ParseStatus::Error; }
            opt.workers = static_cast<std::size_t>(n);
        } else if (a == "--intensity") {
            if (!value(v)) return ParseStatus::Error;
            if (!to_int(v, 0, 9, n)) { err = "--intensity must be 0-9"; return ParseStatus::Error; }
            opt.intensity = static_cast<int>(n);
        } else if (a == "--max-hosts") {
            if (!value(v)) return ParseStatus::Error;
            if (!to_int(v, 1, 1 << 20, n)) { err = "--max-hosts must be 1-1048576"; return ParseStatus::Error; }
            opt.resolve.max_hosts = static_cast<std::size_t>(n);
        } else if (a == "--rate") {
            if (!value(v)) return ParseStatus::Error;
            if (!to_double(v, 0.0, 1e7, opt.rate)) { err = "--rate must be 0 (unlimited) to 10000000 probes/s"; return ParseStatus::Error; }
        } else if (!a.empty() && a[0] == '-') {
            err = "unknown option '" + a + "'";
            return ParseStatus::Error;
        } else {
            opt.targets.push_back(a);
        }
    }
    if (opt.resolve.ipv4_only && opt.resolve.ipv6_only) { err = "-4 and -6 are mutually exclusive"; return ParseStatus::Error; }
    if (opt.targets.empty()) { err = "no target specified"; return ParseStatus::Error; }
    if (!opt.has_scan_action()) { err = "no scan action specified (use -pCT, -pAT, -pCU, -pAU, -p <ports>, -O or -A)"; return ParseStatus::Error; }
    return ParseStatus::Ok;
}

std::string help_text(const std::string& prog) {
    return "Recon " + std::string(kVersion) + " - TCP/UDP port, service and OS scanner\n\n"
"Usage: " + prog + " <target>... [options]\n\n"
"Only scan systems you own or are explicitly authorized in writing to test.\n\n"
"TARGETS\n"
"  IPv4/IPv6 address, hostname, CIDR (10.0.0.0/24, fd00::/120), or alias (localhost, me)\n"
"  -t, --target <t>        explicit target (repeatable)\n"
"  -iL, --input-list <f>   read targets from file, one per line ('-' = stdin, '#' comments)\n"
"  -4 / -6                 restrict hostname resolution to IPv4 / IPv6\n"
"  --max-hosts <n>         cap on expanded targets (default 1024)\n\n"
"PORTS\n"
"  -pCT / -pAT             common TCP ports / all 65535 TCP ports\n"
"  -pCU / -pAU             common UDP ports / all 65535 UDP ports\n"
"  -p <list>               e.g. 22,80,8000-8100  (also -p=22,80)\n\n"
"SCAN TYPE\n"
"  -sT, --connect          full TCP connect() scan (default; no privileges needed)\n"
"  -sS, --syn              half-open SYN scan via raw sockets (IPv4; needs root or cap_net_raw)\n\n"
"DETECTION\n"
"  -sV (default) / --no-sV service & version detection on/off\n"
"  --intensity <0-9>       probe aggressiveness (default 5; 0 = passive banner only)\n"
"  --no-tls-inspect        skip TLS certificate inspection\n"
"  -O, -os, --os           heuristic OS inference\n"
"  -A, --all               -pCT + -sV + -O\n\n"
"PROFILES  (--profile <name>; explicit flags still override)\n"
"  quick     common TCP ports, light probing, fast timeouts\n"
"  standard  common TCP ports, default probing (same as -pCT)\n"
"  full      all 65535 TCP ports, 2000 probes/s, 512 sockets\n"
"  stealth   common ports, 20 probes/s, 8 sockets, 2 workers, patient timeouts\n\n"
"TIMING & SAFETY (defaults are deliberately conservative)\n"
"  --rate <n>              new probes per second (default 500; 0 = unlimited)\n"
"  --max-inflight <n>      concurrent sockets (default 128)\n"
"  --workers <n>           service-detection threads (default 16)\n"
"  --timeout <ms>          connect timeout (default 1500)\n"
"  --probe-timeout <ms>    cap on service-detection waits (default 1500)\n"
"  --banner-wait <ms>      how long to listen for a greeting before probing (default: auto, <= 400);\n"
"                          raise it for servers that greet slowly (reverse-DNS, ident, greet-pause)\n"
"  --no-adaptive           disable RTT-adaptive detection timeouts (reproducible timing)\n"
"  --retries <n>           extra attempts after a timeout (default 1)\n\n"
"OUTPUT\n"
"  --json | --csv          machine-readable output (default: table)\n"
"  -o, --output <file>     write results to a private file (mode 0600; symlinks refused; '-' = stdout)\n"
"  --show-open-filtered    also list UDP open|filtered ports\n"
"  -q, --quiet             suppress notices on stderr\n"
"  --fail-on-open          exit 1 if any open port is found (CI gating)\n"
"  --dry-run               show targets, probe count and time estimate; send nothing\n"
"  --baseline <f.json>     compare with a previous --json report; exit 5 if new ports opened\n"
"  --color auto|always|never    table colours (honours NO_COLOR)\n"
"  --progress / --no-progress   live progress line on stderr (default: only on a terminal)\n\n"
"EXIT CODES\n"
"  0 completed   1 open ports found (--fail-on-open)   2 usage error\n"
"  3 target resolution failed   4 runtime/I-O error   5 drift vs --baseline\n"
"  130 interrupted (partial results are still written)\n"
"  (precedence when several apply: 130, 4, 5, 1)\n";
}

}  // namespace recon
