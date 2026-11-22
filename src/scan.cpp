#include "recon/scan.hpp"

#include <sys/resource.h>

#include <cstdio>
#include <ctime>
#include <map>
#include <memory>
#include <mutex>
#include <tuple>

#include "recon/osdetect.hpp"
#include "recon/synscan.hpp"
#include "recon/pool.hpp"

namespace recon {
namespace {

std::string utc_now_iso() {
    const std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

double tv_ms(const timeval& tv) { return static_cast<double>(tv.tv_sec) * 1000.0 + static_cast<double>(tv.tv_usec) / 1000.0; }

Detection guess_only(std::uint16_t port, bool tcp) {
    Detection d;
    const char* g = port_guess_service(port, tcp);
    if (std::string(g) != "unknown") {
        d.service = g;
        d.confidence = 25;
        d.method = "port-guess";
        d.version_quality = VersionQuality::Inferred;
        d.extra = "guessed from port number; no probing performed";
    }
    return d;
}

// Thread-safe sink shared by the reactor thread and detection workers.
class ResultStore {
public:
    using Key = std::tuple<std::size_t, int, std::uint16_t>;  // host, protocol, port
    void put(const PortRecord& r, std::size_t host) {
        std::lock_guard<std::mutex> lk(m_);
        records_[{host, static_cast<int>(r.protocol), r.port}] = r;
    }
    void set_detection(std::size_t host, Protocol p, std::uint16_t port, Detection d) {
        std::lock_guard<std::mutex> lk(m_);
        auto it = records_.find({host, static_cast<int>(p), port});
        if (it != records_.end()) it->second.detection = std::move(d);
    }
    std::map<Key, PortRecord> take() {
        std::lock_guard<std::mutex> lk(m_);
        return std::move(records_);
    }

private:
    std::mutex m_;
    std::map<Key, PortRecord> records_;
};

// Single-line live progress on stderr (only when enabled; stdout stays clean for pipelines).
void print_progress(const char* label, const ScanStats& st, Clock::time_point t0) {
    const std::uint64_t done = st.open + st.closed + st.filtered + st.open_filtered + st.errors;
    const double secs = std::chrono::duration<double>(Clock::now() - t0).count();
    const double rate = secs > 0.0 ? static_cast<double>(done) / secs : 0.0;
    char eta[32] = "";
    if (rate > 1.0 && st.tasks > done) {
        const auto rem = static_cast<long>(static_cast<double>(st.tasks - done) / rate);
        std::snprintf(eta, sizeof(eta), "  ETA %ldm%02lds", rem / 60, rem % 60);
    }
    std::fprintf(stderr, "\r\x1b[K[*] %s %llu/%llu (%d%%)  open %llu  %.0f probes/s%s", label,
                 static_cast<unsigned long long>(done), static_cast<unsigned long long>(st.tasks),
                 st.tasks ? static_cast<int>(100 * done / st.tasks) : 100,
                 static_cast<unsigned long long>(st.open), rate, eta);
    std::fflush(stderr);
}

void add_stats(ScanSummary& s, const ScanStats& st) {
    s.probes += st.tasks;
    s.attempts += st.attempts;
    s.retries += st.retries;
    s.open += st.open;
    s.closed += st.closed;
    s.filtered += st.filtered;
    s.open_filtered += st.open_filtered;
    s.errors += st.errors;
}

}  // namespace

ScanReport run_scan(const Options& opt, const std::vector<Target>& targets, const CancelToken& cancel) {
    const auto t0 = Clock::now();
    ScanReport rep;
    rep.started_utc = utc_now_iso();
    const auto tcp_ports = opt.tcp_ports();
    const auto udp_ports = opt.udp_ports();
    rep.options = {tcp_ports.size(), udp_ports.size(), opt.detect_services, opt.syn_scan, opt.intensity,
                   opt.timeout_ms, opt.retries, opt.rate, opt.max_inflight, opt.workers};

    std::vector<net::IpAddress> addrs;
    for (const Target& t : targets) addrs.push_back(t.addr);

    RateLimiter limiter(opt.rate);
    ResultStore store;  // declared before the pool: outlives every job that references it

    if (!tcp_ports.empty()) {
        ScanConfig sc;
        sc.protocol = Protocol::Tcp;
        sc.max_inflight = opt.max_inflight;
        sc.timeout = Millis(opt.timeout_ms);
        sc.retries = opt.retries;
        DetectConfig dc;
        dc.connect_timeout = Millis(opt.timeout_ms);
        dc.probe_timeout = Millis(opt.probe_timeout_ms);
        dc.adaptive_timeouts = opt.adaptive_timeouts;
        if (opt.banner_wait_ms > 0) {
            dc.banner_wait = Millis(opt.banner_wait_ms);
            dc.fixed_banner_wait = true;
        }
        dc.intensity = opt.intensity;
        dc.tls_inspect = opt.tls_inspect;
        const ServiceDetector detector(dc);
        const auto tcp_t0 = Clock::now();
        auto progress = [&](const ScanStats& st) { print_progress(opt.syn_scan ? "SYN" : "TCP", st, tcp_t0); };

        std::unique_ptr<ThreadPool> pool;
        if (opt.detect_services) pool = std::make_unique<ThreadPool>(opt.workers, opt.workers * 4);

        const PortScanner::Callback on_tcp = [&](const ProbeOutcome& o) {
            if (o.state != PortState::Open) return;
            PortRecord rec;
            rec.port = o.port;
            rec.protocol = Protocol::Tcp;
            rec.state = o.state;
            rec.rtt_ms = o.rtt_ms;
            rec.attempts = o.attempts;
            if (!pool) rec.detection = guess_only(o.port, true);
            store.put(rec, o.host_index);
            if (pool) {
                const std::size_t host = o.host_index;
                const std::uint16_t port = o.port;
                const double rtt = o.rtt_ms;
                pool->submit([&, host, port, rtt] {
                    if (cancel.requested()) return;
                    Detection d = detector.detect(net::Endpoint(addrs[host], port), targets[host].label, cancel, rtt);
                    store.set_detection(host, Protocol::Tcp, port, std::move(d));
                });
            }
        };
        ScanStats st;
        if (opt.syn_scan) {
            SynScanner scanner(sc, limiter, cancel);
            if (opt.show_progress) scanner.set_progress(progress);
            st = scanner.run(addrs, tcp_ports, on_tcp);
        } else {
            PortScanner scanner(sc, limiter, cancel);
            if (opt.show_progress) scanner.set_progress(progress);
            st = scanner.run(addrs, tcp_ports, on_tcp);
        }
        if (opt.show_progress) std::fprintf(stderr, "\r\x1b[K");
        if (pool) {
            if (opt.show_progress) std::fprintf(stderr, "[*] finishing service detection...\r");
            pool->wait_idle();
            if (opt.show_progress) std::fprintf(stderr, "\r\x1b[K");
        }
        add_stats(rep.summary, st);
        if (st.cancelled) rep.summary.status = "cancelled";
    }

    if (!udp_ports.empty() && !cancel.requested()) {
        ScanConfig sc;
        sc.protocol = Protocol::Udp;
        sc.max_inflight = opt.max_inflight;
        sc.timeout = Millis(opt.timeout_ms);
        sc.retries = opt.retries;
        PortScanner scanner(sc, limiter, cancel);
        const auto udp_t0 = Clock::now();
        if (opt.show_progress) scanner.set_progress([&](const ScanStats& st) { print_progress("UDP", st, udp_t0); });
        const ScanStats st = scanner.run(addrs, udp_ports, [&](const ProbeOutcome& o) {
            if (o.state != PortState::Open && !(o.state == PortState::OpenFiltered && opt.keep_open_filtered)) return;
            PortRecord rec;
            rec.port = o.port;
            rec.protocol = Protocol::Udp;
            rec.state = o.state;
            rec.rtt_ms = o.rtt_ms;
            rec.attempts = o.attempts;
            if (o.state == PortState::Open) {
                rec.detection = match_udp_response(o.port, o.udp_response);
                if (!rec.detection) {
                    Detection d = guess_only(o.port, false);
                    d.extra = "UDP reply did not match the expected protocol";
                    rec.detection = d;
                } else {
                    rec.detection->method = rec.detection->method == "none" ? "probe:udp" : rec.detection->method;
                }
            }
            store.put(rec, o.host_index);
        });
        if (opt.show_progress) std::fprintf(stderr, "\r\x1b[K");
        add_stats(rep.summary, st);
        if (st.cancelled) rep.summary.status = "cancelled";
    }

    // Assemble per-host records in a deterministic order.
    rep.hosts.resize(targets.size());
    for (std::size_t i = 0; i < targets.size(); ++i) {
        rep.hosts[i].address = targets[i].addr.to_string();
        rep.hosts[i].hostname = targets[i].label;
    }
    for (auto& kv : store.take()) rep.hosts[std::get<0>(kv.first)].ports.push_back(std::move(kv.second));

    if (opt.os_detect && !cancel.requested()) {
        for (std::size_t i = 0; i < targets.size(); ++i) {
            if (cancel.requested()) break;
            if (rep.hosts[i].ports.empty() && targets.size() > 1) continue;  // skip dead-looking hosts
            const int ttl = icmp_echo_ttl(targets[i].addr, Millis(800));
            rep.hosts[i].os = infer_os(targets[i].addr, rep.hosts[i].ports, ttl);
        }
    }

    if (cancel.requested()) rep.summary.status = "cancelled";
    rep.summary.hosts = targets.size();
    rep.summary.duration_ms = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
    rusage ru{};
    if (getrusage(RUSAGE_SELF, &ru) == 0) {
        rep.summary.cpu_user_ms = tv_ms(ru.ru_utime);
        rep.summary.cpu_sys_ms = tv_ms(ru.ru_stime);
        rep.summary.max_rss_kb = ru.ru_maxrss;  // kilobytes on Linux
    }
    return rep;
}

}  // namespace recon
