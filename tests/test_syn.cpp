// SYN scanner tests. They need CAP_NET_RAW (root); without it they report SKIP and pass, so the
// suite stays green for unprivileged developers. CI runs them under sudo.
#include <atomic>
#include <map>
#include <memory>
#include <thread>

#include "mock_server.hpp"
#include "recon/synscan.hpp"
#include "testing.hpp"

using namespace recon;

namespace {
const net::IpAddress kLo = *net::IpAddress::parse("127.0.0.1");

bool privileged() {
    std::string why;
    if (SynScanner::available(&why)) return true;
    std::printf("  SKIP (no raw socket: %s)\n", why.c_str());
    return false;
}

std::map<std::uint16_t, ProbeOutcome> syn_scan(const std::vector<std::uint16_t>& ports, ScanConfig cfg, double rate = 0,
                                               ScanStats* out = nullptr, const CancelToken* cancel = nullptr) {
    static CancelToken never;
    RateLimiter rl(rate);
    SynScanner sc(cfg, rl, cancel ? *cancel : never);
    std::map<std::uint16_t, ProbeOutcome> r;
    const ScanStats st = sc.run({kLo}, ports, [&](const ProbeOutcome& o) { r[o.port] = o; });
    if (out) *out = st;
    return r;
}
}  // namespace

TEST(tcp_checksum_matches_independent_python_vectors) {
    // Vectors computed by a separate Python implementation of RFC 793, not by this code.
    std::uint8_t seg[24] = {};
    seg[0] = 0x4e; seg[1] = 0x20; seg[3] = 80;
    seg[4] = 1; seg[5] = 2; seg[6] = 3; seg[7] = 4;
    seg[12] = 6 << 4; seg[13] = 0x02; seg[14] = 0xfa; seg[15] = 0xf0;
    seg[20] = 2; seg[21] = 4; seg[22] = 0x05; seg[23] = 0xb4;
    const std::uint8_t lo[4] = {127, 0, 0, 1};
    CHECK_EQ(tcp_checksum(lo, lo, seg, sizeof(seg)), std::uint16_t(0x4cbd));
    const std::uint8_t a[4] = {10, 0, 0, 1}, b[4] = {192, 168, 1, 200};
    std::uint8_t odd[11];
    for (std::uint8_t i = 0; i < 11; ++i) odd[i] = static_cast<std::uint8_t>(i + 1);
    CHECK_EQ(tcp_checksum(a, b, odd, sizeof(odd)), std::uint16_t(0x0f5f));  // odd-length segment is padded
    // Self-check: inserting the checksum makes the verification sum come out to zero.
    seg[16] = 0x4c; seg[17] = 0xbd;
    CHECK_EQ(tcp_checksum(lo, lo, seg, sizeof(seg)), std::uint16_t(0));
}

TEST(syn_matches_connect_scan_on_loopback) {
    if (!privileged()) return;
    std::vector<std::unique_ptr<mock::Server>> servers;
    std::vector<std::uint16_t> ports;
    for (int i = 0; i < 12; ++i) {
        servers.push_back(std::make_unique<mock::Server>(mock::silent()));
        ports.push_back(servers.back()->port());
    }
    for (int i = 0; i < 12; ++i) ports.push_back(mock::closed_port());
    ScanConfig cfg;
    cfg.timeout = Millis(500);
    cfg.retries = 1;
    ScanStats syn_stats;
    auto syn = syn_scan(ports, cfg, 0, &syn_stats);

    RateLimiter rl(0);
    CancelToken c;
    PortScanner conn_sc(cfg, rl, c);
    std::map<std::uint16_t, PortState> conn;
    conn_sc.run({kLo}, ports, [&](const ProbeOutcome& o) { conn[o.port] = o.state; });

    CHECK_EQ(syn.size(), ports.size());  // every probe reported exactly once
    for (std::uint16_t p : ports) CHECK((syn[p].state == conn[p]));
    CHECK_EQ(syn_stats.open, std::uint64_t(12));
    CHECK_EQ(syn_stats.closed, std::uint64_t(12));
    CHECK(syn_stats.peak_inflight >= 1);
}

TEST(syn_scan_is_half_open_and_never_completes_a_handshake) {
    if (!privileged()) return;
    // A server that records whether any connection was ever accept()ed.
    std::atomic<int> accepted{0};
    mock::Server s([&](int, const std::atomic<bool>&) { ++accepted; });
    ScanConfig cfg;
    auto r = syn_scan({s.port()}, cfg);
    CHECK((r[s.port()].state == PortState::Open));
    mock::sleep_ms(300);
    CHECK_EQ(accepted.load(), 0);  // the kernel RSTs the SYN-ACK; no connection reaches accept()
}

TEST(syn_timeout_is_filtered_and_retried) {
    if (!privileged()) return;
    // Full accept queue => the kernel silently drops further SYNs: a genuine timeout.
    net::UniqueFd l(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ::bind(l.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a));
    ::listen(l.get(), 0);
    socklen_t len = sizeof(a);
    ::getsockname(l.get(), reinterpret_cast<sockaddr*>(&a), &len);
    std::vector<net::UniqueFd> fillers;
    for (int i = 0; i < 4; ++i) {
        net::UniqueFd f(::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
        ::connect(f.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a));
        fillers.push_back(std::move(f));
    }
    mock::sleep_ms(50);
    ScanConfig cfg;
    cfg.timeout = Millis(150);
    cfg.retries = 2;
    ScanStats st;
    const std::uint16_t port = ntohs(a.sin_port);
    auto r = syn_scan({port}, cfg, 0, &st);
    CHECK((r[port].state == PortState::Filtered));
    CHECK_EQ(r[port].attempts, 3);
    CHECK_EQ(st.retries, std::uint64_t(2));
}

TEST(syn_inflight_bound_rate_limit_and_cancel) {
    if (!privileged()) return;
    std::vector<std::uint16_t> ports;
    for (int i = 0; i < 300; ++i) ports.push_back(static_cast<std::uint16_t>(30100 + i));
    ScanConfig cfg;
    cfg.max_inflight = 8;
    cfg.timeout = Millis(300);
    ScanStats st;
    auto r = syn_scan(ports, cfg, 0, &st);
    CHECK(st.peak_inflight <= 8);
    CHECK_EQ(r.size(), std::size_t(300));
    CHECK_EQ(st.closed, std::uint64_t(300));

    const auto t0 = Clock::now();
    ScanConfig fast;
    syn_scan(std::vector<std::uint16_t>(ports.begin(), ports.begin() + 60), fast, 100.0);  // burst 5 => >= 0.55 s
    CHECK(std::chrono::duration<double>(Clock::now() - t0).count() >= 0.45);

    CancelToken cancel;
    ScanStats cst;
    std::thread killer([&] { mock::sleep_ms(120); cancel.request(); });
    const auto t1 = Clock::now();
    syn_scan(ports, fast, 20.0, &cst, &cancel);
    killer.join();
    CHECK(cst.cancelled);
    CHECK(std::chrono::duration_cast<Millis>(Clock::now() - t1).count() < 1500);
}

TEST(syn_rejects_ipv6_and_leaks_no_fds) {
    const std::size_t before = mock::open_fd_count();
    if (privileged()) {
        RateLimiter rl(0);
        CancelToken c;
        SynScanner sc(ScanConfig{}, rl, c);
        bool threw = false;
        try { sc.run({*net::IpAddress::parse("::1")}, {80}, [](const ProbeOutcome&) {}); }
        catch (const std::runtime_error& e) { threw = std::string(e.what()).find("IPv4") != std::string::npos; }
        CHECK(threw);
        ScanConfig cfg;
        cfg.timeout = Millis(200);
        for (int i = 0; i < 3; ++i) syn_scan({mock::closed_port(), mock::closed_port()}, cfg);
    }
    CHECK_EQ(mock::open_fd_count(), before);
}

// Off-path spoofing resistance: replies must acknowledge OUR random sequence number. A forger that
// guesses the 4-tuple (here it can brute-force every source port) but not the sequence number must
// not be able to turn a filtered port into an "open" one.
TEST(syn_ignores_forged_replies_with_wrong_ack) {
    if (!privileged()) return;
    net::UniqueFd l(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ::bind(l.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a));
    ::listen(l.get(), 0);
    socklen_t len = sizeof(a);
    ::getsockname(l.get(), reinterpret_cast<sockaddr*>(&a), &len);
    std::vector<net::UniqueFd> fillers;  // fill the accept queue so real SYNs are dropped (=> filtered)
    for (int i = 0; i < 4; ++i) {
        net::UniqueFd f(::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
        ::connect(f.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a));
        fillers.push_back(std::move(f));
    }
    const std::uint16_t target = ntohs(a.sin_port);

    std::atomic<bool> stop{false};
    std::atomic<long> forged{0};
    std::thread forger([&] {
        net::UniqueFd raw(::socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_TCP));
        const net::Endpoint dst(kLo, 0);
        while (!stop) {
            for (unsigned sport = 20000; sport < 30000 && !stop; ++sport) {
                std::uint8_t seg[20] = {};
                seg[0] = static_cast<std::uint8_t>(target >> 8); seg[1] = static_cast<std::uint8_t>(target);
                seg[2] = static_cast<std::uint8_t>(sport >> 8);  seg[3] = static_cast<std::uint8_t>(sport);
                seg[8] = 0xDE; seg[9] = 0xAD; seg[10] = 0xBE; seg[11] = 0xEF;  // wrong acknowledgment number
                seg[12] = 5 << 4; seg[13] = 0x12;                              // SYN|ACK
                const std::uint8_t lo[4] = {127, 0, 0, 1};
                const std::uint16_t cs = tcp_checksum(lo, lo, seg, sizeof(seg));
                seg[16] = static_cast<std::uint8_t>(cs >> 8); seg[17] = static_cast<std::uint8_t>(cs);
                if (::sendto(raw.get(), seg, sizeof(seg), 0, dst.addr(), dst.len()) > 0) ++forged;
            }
        }
    });
    ScanConfig cfg;
    cfg.timeout = Millis(700);
    cfg.retries = 0;
    auto r = syn_scan({target}, cfg);
    stop = true;
    forger.join();
    CHECK(forged.load() > 5000);                    // the forger really did blanket the source-port pool
    CHECK((r[target].state == PortState::Filtered));  // ...and none of it was believed
}
