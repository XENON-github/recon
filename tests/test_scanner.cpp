#include <poll.h>
#include <sys/socket.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <thread>

#include "mock_server.hpp"
#include "recon/scanner.hpp"
#include "testing.hpp"

using namespace recon;

namespace {
const net::IpAddress kLo = *net::IpAddress::parse("127.0.0.1");

std::map<std::uint16_t, ProbeOutcome> scan(const std::vector<std::uint16_t>& ports, ScanConfig cfg,
                                           double rate, ScanStats* stats_out = nullptr,
                                           const CancelToken* cancel = nullptr) {
    static CancelToken never;
    RateLimiter rl(rate);
    PortScanner sc(cfg, rl, cancel ? *cancel : never);
    std::map<std::uint16_t, ProbeOutcome> out;
    const ScanStats st = sc.run({kLo}, ports, [&](const ProbeOutcome& o) { out[o.port] = o; });
    if (stats_out) *stats_out = st;
    return out;
}
}  // namespace

TEST(classify_errors) {
    CHECK(classify_connect_error(0) == PortState::Open);
    CHECK(classify_connect_error(ECONNREFUSED) == PortState::Closed);
    CHECK(classify_connect_error(ECONNRESET) == PortState::Open);  // handshake completed, then RST
    CHECK(classify_connect_error(ETIMEDOUT) == PortState::Filtered);
    CHECK(classify_connect_error(EHOSTUNREACH) == PortState::Filtered);
    CHECK(classify_connect_error(EINVAL) == PortState::Error);
}

TEST(finds_open_and_closed) {
    mock::Server open1(mock::silent());
    mock::Server open2(mock::silent());
    const std::uint16_t closed = mock::closed_port();
    ScanConfig cfg;
    ScanStats st;
    auto r = scan({open1.port(), open2.port(), closed}, cfg, 0, &st);
    CHECK(r[open1.port()].state == PortState::Open);
    CHECK(r[open2.port()].state == PortState::Open);
    CHECK(r[closed].state == PortState::Closed);
    CHECK_EQ(st.open, std::uint64_t(2));
    CHECK_EQ(st.closed, std::uint64_t(1));
    CHECK_EQ(st.tasks, std::uint64_t(3));
}

TEST(inflight_is_bounded_and_nothing_is_missed) {
    std::vector<std::unique_ptr<mock::Server>> servers;
    std::vector<std::uint16_t> ports;
    for (int i = 0; i < 60; ++i) {
        servers.push_back(std::make_unique<mock::Server>(mock::silent()));
        ports.push_back(servers.back()->port());
    }
    for (int i = 0; i < 40; ++i) ports.push_back(mock::closed_port());
    ScanConfig cfg;
    cfg.max_inflight = 8;
    ScanStats st;
    auto r = scan(ports, cfg, 0, &st);
    CHECK(st.peak_inflight <= 8);
    std::size_t open = 0;
    for (auto& s : servers) open += r[s->port()].state == PortState::Open;
    CHECK_EQ(open, std::size_t(60));
}

TEST(reset_after_accept_counts_as_open_and_does_not_kill_us) {
    mock::Server rst(mock::reset_on_accept());
    ScanConfig cfg;
    auto r = scan({rst.port()}, cfg, 0);
    CHECK(r[rst.port()].state == PortState::Open);
}

// Fill a listener's accept queue so further SYNs are silently dropped => genuine timeouts.
struct BlackHole {
    net::UniqueFd listener;
    std::vector<net::UniqueFd> fillers;
    std::uint16_t port = 0;
    BlackHole() {
        listener.reset(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ::bind(listener.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a));
        ::listen(listener.get(), 0);
        socklen_t l = sizeof(a);
        ::getsockname(listener.get(), reinterpret_cast<sockaddr*>(&a), &l);
        port = ntohs(a.sin_port);
        for (int i = 0; i < 4; ++i) {
            net::UniqueFd f(::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
            ::connect(f.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a));
            fillers.push_back(std::move(f));
        }
        mock::sleep_ms(50);
    }
};

TEST(timeout_is_filtered_and_retried) {
    BlackHole bh;
    ScanConfig cfg;
    cfg.timeout = Millis(150);
    cfg.retries = 2;
    ScanStats st;
    const auto t0 = Clock::now();
    auto r = scan({bh.port}, cfg, 0, &st);
    const auto ms = std::chrono::duration_cast<Millis>(Clock::now() - t0).count();
    CHECK(r[bh.port].state == PortState::Filtered);
    CHECK_EQ(r[bh.port].attempts, 3);  // 1 + 2 retries
    CHECK_EQ(st.retries, std::uint64_t(2));
    CHECK(ms >= 3 * 150 - 30);
    CHECK(ms < 3 * 150 + 600);
}

TEST(no_retries_means_single_attempt) {
    BlackHole bh;
    ScanConfig cfg;
    cfg.timeout = Millis(100);
    cfg.retries = 0;
    auto r = scan({bh.port}, cfg, 0);
    CHECK_EQ(r[bh.port].attempts, 1);
    CHECK(r[bh.port].state == PortState::Filtered);
}

TEST(rate_limit_is_respected) {
    std::vector<std::uint16_t> ports;
    for (int i = 0; i < 60; ++i) ports.push_back(static_cast<std::uint16_t>(30000 + i));  // mostly closed
    ScanConfig cfg;
    const auto t0 = Clock::now();
    scan(ports, cfg, 100.0);  // burst 5, so >= (60-5)/100 = 0.55 s
    const double secs = std::chrono::duration<double>(Clock::now() - t0).count();
    CHECK(secs >= 0.45);
}

TEST(cancellation_stops_promptly_and_leaks_no_fds) {
    BlackHole bh;
    std::vector<std::uint16_t> ports(2000, bh.port);
    ports.clear();
    for (int i = 0; i < 2000; ++i) ports.push_back(static_cast<std::uint16_t>(20000 + i));
    const std::size_t fds_before = mock::open_fd_count();
    CancelToken cancel;
    ScanConfig cfg;
    cfg.max_inflight = 16;
    ScanStats st;
    std::thread killer([&] { mock::sleep_ms(150); cancel.request(); });
    const auto t0 = Clock::now();
    scan(ports, cfg, 20.0, &st, &cancel);  // 2000 probes at 20/s would take 100 s
    const auto ms = std::chrono::duration_cast<Millis>(Clock::now() - t0).count();
    killer.join();
    CHECK(st.cancelled);
    CHECK(ms < 1500);
    CHECK_EQ(mock::open_fd_count(), fds_before);
}

TEST(no_fd_leak_over_many_probes) {
    const std::size_t before = mock::open_fd_count();
    std::vector<std::uint16_t> ports;
    for (int i = 0; i < 3000; ++i) ports.push_back(static_cast<std::uint16_t>(10000 + i));
    ScanConfig cfg;
    cfg.max_inflight = 64;
    ScanStats st;
    scan(ports, cfg, 0, &st);
    CHECK_EQ(st.tasks, std::uint64_t(3000));
    CHECK_EQ(st.open + st.closed + st.filtered + st.errors, std::uint64_t(3000));  // every task accounted for
    CHECK_EQ(mock::open_fd_count(), before);
}

TEST(callback_exception_does_not_leak) {
    mock::Server s(mock::banner("x"));  // short-lived server-side socket (same process as the test)
    const std::size_t before = mock::open_fd_count();
    RateLimiter rl(0);
    CancelToken c;
    PortScanner sc(ScanConfig{}, rl, c);
    bool threw = false;
    try {
        sc.run({kLo}, {s.port(), mock::closed_port()}, [](const ProbeOutcome&) { throw std::runtime_error("x"); });
    } catch (const std::runtime_error&) { threw = true; }
    CHECK(threw);
    mock::sleep_ms(600);  // let the mock's accepted socket close before counting fds
    CHECK_EQ(mock::open_fd_count(), before);
}

TEST(multi_host_port_major_coverage) {
    mock::Server s(mock::silent());
    RateLimiter rl(0);
    CancelToken c;
    PortScanner sc(ScanConfig{}, rl, c);
    std::map<std::pair<std::size_t, std::uint16_t>, PortState> got;
    const auto h2 = *net::IpAddress::parse("127.0.0.2");  // loopback /8 but the mock only listens on .1
    sc.run({kLo, h2}, {s.port(), mock::closed_port()}, [&](const ProbeOutcome& o) { got[{o.host_index, o.port}] = o.state; });
    CHECK_EQ(got.size(), std::size_t(4));  // 2 hosts x 2 ports, each reported exactly once
    CHECK((got[{0, s.port()}] == PortState::Open));
    CHECK((got[{1, s.port()}] == PortState::Closed));  // host index maps back to the right address
}

TEST(udp_closed_port_detected_via_icmp) {
    ScanConfig cfg;
    cfg.protocol = Protocol::Udp;
    cfg.timeout = Millis(500);
    cfg.retries = 0;
    const std::uint16_t port = mock::closed_port();  // nothing bound for TCP; UDP likewise unbound
    auto r = scan({port}, cfg, 0);
    CHECK(r[port].state == PortState::Closed);
}

TEST(udp_open_port_and_open_filtered) {
    // UDP echo-ish responder on an ephemeral port, plus a silent UDP socket.
    auto make = [](net::UniqueFd& fd) {
        fd.reset(::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ::bind(fd.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a));
        socklen_t l = sizeof(a);
        ::getsockname(fd.get(), reinterpret_cast<sockaddr*>(&a), &l);
        return ntohs(a.sin_port);
    };
    net::UniqueFd responder, silent;
    const std::uint16_t rp = make(responder), sp = make(silent);
    std::atomic<bool> stop{false};
    std::thread t([&] {
        while (!stop) {
            pollfd p{responder.get(), POLLIN, 0};
            if (::poll(&p, 1, 20) > 0) {
                char b[64];
                sockaddr_in from{};
                socklen_t fl = sizeof(from);
                const ssize_t n = ::recvfrom(responder.get(), b, sizeof(b), 0, reinterpret_cast<sockaddr*>(&from), &fl);
                if (n > 0) ::sendto(responder.get(), "pong", 4, 0, reinterpret_cast<sockaddr*>(&from), fl);
            }
        }
    });
    ScanConfig cfg;
    cfg.protocol = Protocol::Udp;
    cfg.timeout = Millis(250);
    cfg.retries = 0;
    auto r = scan({rp, sp}, cfg, 0);
    stop = true;
    t.join();
    CHECK(r[rp].state == PortState::Open);
    CHECK_EQ(r[rp].udp_response, std::string("pong"));
    CHECK(r[sp].state == PortState::OpenFiltered);  // bound but silent: cannot distinguish from firewall drop
}

TEST(progress_callback_is_monotonic_and_bounded) {
    std::vector<std::uint16_t> ports;
    for (int i = 0; i < 400; ++i) ports.push_back(static_cast<std::uint16_t>(30000 + i));
    RateLimiter rl(800.0);  // ~0.5 s of work so several progress ticks fire
    CancelToken c;
    ScanConfig cfg;
    PortScanner sc(cfg, rl, c);
    std::vector<std::uint64_t> seen;
    sc.set_progress([&](const ScanStats& st) { seen.push_back(st.open + st.closed + st.filtered + st.errors); }, Millis(50));
    const ScanStats final_st = sc.run({kLo}, ports, [](const ProbeOutcome&) {});
    CHECK(seen.size() >= 3);
    for (std::size_t i = 1; i < seen.size(); ++i) CHECK(seen[i] >= seen[i - 1]);
    CHECK(seen.back() <= final_st.tasks);
    CHECK_EQ(final_st.open + final_st.closed + final_st.filtered + final_st.errors, std::uint64_t(400));
}

TEST(no_phantom_open_ports_from_tcp_self_connect) {
    // Regression: sweeping the whole ephemeral range on loopback at high concurrency used to report a
    // few "open" ports that nothing listened on (source port == destination port => self-connect).
    mock::Server real(mock::silent());
    std::vector<std::uint16_t> ports;
    for (int p = 32768; p <= 60999; ++p) ports.push_back(static_cast<std::uint16_t>(p));
    ScanConfig cfg;
    cfg.max_inflight = 1024;
    cfg.timeout = Millis(500);
    // The quirk is probabilistic (a few hits per sweep), so sweep several times: with the bug present the
    // chance of three clean sweeps in a row is negligible.
    std::size_t phantom = 0;
    for (int sweep = 0; sweep < 3; ++sweep) {
        auto r = scan(ports, cfg, 0);
        for (auto& [port, o] : r) phantom += o.state == PortState::Open && port != real.port();
        CHECK((r[real.port()].state == PortState::Open));
    }
    CHECK_EQ(phantom, std::size_t(0));
}
