#include <chrono>

#include "mock_server.hpp"
#include "recon/detect.hpp"
#include "testing.hpp"

using namespace recon;

namespace {
Detection detect(std::uint16_t port, DetectConfig cfg = {}) {
    static CancelToken never;
    cfg.total_budget = Millis(4000);
    return ServiceDetector(cfg).detect(net::Endpoint(*net::IpAddress::parse("127.0.0.1"), port), "", never);
}
}  // namespace

TEST(detect_ssh_banner) {
    mock::Server s(mock::banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"));
    auto d = detect(s.port());
    CHECK_EQ(d.service, std::string("ssh"));
    CHECK_EQ(d.version, std::string("8.9p1"));
    CHECK(d.version_quality == VersionQuality::Reported);
    CHECK_EQ(d.method, std::string("banner"));
}

TEST(detect_reassembles_slow_partial_writes) {
    // 3 bytes every 40 ms: well under the 150 ms quiet period, so it must be one banner.
    mock::Server s(mock::slow_drip("SSH-2.0-OpenSSH_9.6p1 Debian-5\r\n", 3, 40));
    auto d = detect(s.port());
    CHECK_EQ(d.service, std::string("ssh"));
    CHECK_EQ(d.product, std::string("OpenSSH"));
    CHECK_EQ(d.version, std::string("9.6p1"));
    CHECK_EQ(d.os_hint, std::string("Debian Linux"));
}

TEST(detect_http_after_silent_connect) {
    mock::Server s(mock::respond_after_request("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n"));
    auto d = detect(s.port());
    CHECK_EQ(d.service, std::string("http"));
    CHECK_EQ(d.product, std::string("nginx"));
    CHECK_EQ(d.version, std::string("1.24.0"));
    CHECK_EQ(d.method, std::string("probe:http"));
}

TEST(detect_redis_requires_info_probe) {
    mock::Server s(mock::respond_after_request("$60\r\n# Server\r\nredis_version:6.2.14\r\nredis_mode:standalone\r\n"));
    DetectConfig cfg;
    cfg.intensity = 6;
    auto d = detect(s.port(), cfg);
    CHECK_EQ(d.service, std::string("redis"));
    CHECK_EQ(d.version, std::string("6.2.14"));
}

TEST(silent_port_is_a_labelled_guess_not_a_fact) {
    mock::Server s(mock::silent());
    DetectConfig cfg;
    cfg.banner_wait = Millis(100);
    cfg.probe_timeout = Millis(150);
    auto d = detect(s.port(), cfg);
    CHECK(d.confidence < 50);
    CHECK(d.version.empty());
    CHECK(d.version_quality != VersionQuality::Reported);
}

TEST(rst_after_accept_does_not_crash_or_hang) {
    mock::Server s(mock::reset_on_accept());
    const auto t0 = Clock::now();
    auto d = detect(s.port());  // original implementation died with SIGPIPE here
    CHECK(std::chrono::duration_cast<Millis>(Clock::now() - t0).count() < 3000);
    CHECK_EQ(d.service, std::string("tcpwrapped"));  // accepted then reset: no further probing
    CHECK(d.version.empty());
}

TEST(accept_then_close_is_tcpwrapped_and_fast) {
    mock::Server s([](int, const std::atomic<bool>&) { /* close immediately, politely (FIN) */ });
    const auto t0 = Clock::now();
    auto d = detect(s.port());
    CHECK_EQ(d.service, std::string("tcpwrapped"));
    CHECK(d.confidence >= 50 && d.confidence < 90);
    CHECK(std::chrono::duration_cast<Millis>(Clock::now() - t0).count() < 500);  // no probe cascade
}

TEST(adaptive_timeouts_shorten_silent_port_cost) {
    mock::Server s(mock::silent());
    DetectConfig fixed;
    fixed.adaptive_timeouts = false;
    fixed.banner_wait = Millis(400);
    fixed.probe_timeout = Millis(1500);
    DetectConfig adaptive = fixed;
    adaptive.adaptive_timeouts = true;
    static CancelToken never;
    const net::Endpoint ep(*net::IpAddress::parse("127.0.0.1"), s.port());
    auto timed = [&](const DetectConfig& c, double rtt) {
        const auto t0 = Clock::now();
        ServiceDetector(c).detect(ep, "", never, rtt);
        return std::chrono::duration_cast<Millis>(Clock::now() - t0).count();
    };
    const auto slow = timed(fixed, 0.05);      // adaptive off: full 1500 ms per probe
    const auto fast = timed(adaptive, 0.05);   // loopback RTT: ~500 ms floor
    CHECK(fast < slow);
    CHECK(fast < 2500);
    CHECK(slow > 2500);
    // A far-away host (RTT 400 ms) must get the full cap, not the floor.
    const auto wan = timed(adaptive, 400.0);
    CHECK(wan > fast);
}

TEST(unrecognised_greeting_reports_banner_with_low_confidence) {
    mock::Server s(mock::banner("WELCOME TO THE FOOBAR SERVER v9\r\n"));
    auto d = detect(s.port());
    CHECK_EQ(d.service, std::string("unknown"));
    CHECK(d.confidence <= 10);
    CHECK(d.banner.find("FOOBAR") != std::string::npos);
}

TEST(flood_server_is_bounded) {
    mock::Server s(mock::flood());
    const auto t0 = Clock::now();
    auto d = detect(s.port());
    CHECK(std::chrono::duration_cast<Millis>(Clock::now() - t0).count() < 4500);
    CHECK(d.banner.size() <= 200);
}

TEST(connect_failure_is_reported_not_thrown) {
    auto d = detect(mock::closed_port());
    CHECK(!d.error.empty());
}

TEST(passive_only_intensity_zero_sends_nothing) {
    // A server that only answers if it receives data: with intensity 0 we must not send.
    mock::Server s(mock::respond_after_request("HTTP/1.1 200 OK\r\nServer: x/1\r\n\r\n"));
    DetectConfig cfg;
    cfg.intensity = 0;
    cfg.banner_wait = Millis(150);
    auto d = detect(s.port(), cfg);
    CHECK_EQ(d.service == "http", false);
}

TEST(no_fd_leak_across_detections) {
    mock::Server s(mock::banner("SSH-2.0-test_1.0\r\n"));
    const std::size_t before = mock::open_fd_count();
    for (int i = 0; i < 30; ++i) detect(s.port());
    mock::sleep_ms(700);  // let the mock's own server-side sockets finish (they are in this process)
    CHECK_EQ(mock::open_fd_count(), before);
}

TEST(slow_greeting_needs_banner_wait_and_explicit_value_is_exact) {
    mock::Server s(mock::delayed_banner("SSH-2.0-OpenSSH_9.6p1\r\n", 700));  // e.g. sshd doing a reverse-DNS lookup
    static CancelToken never;
    const net::Endpoint ep(*net::IpAddress::parse("127.0.0.1"), s.port());
    DetectConfig dflt;
    dflt.total_budget = Millis(6000);
    auto missed = ServiceDetector(dflt).detect(ep, "", never, 0.05);       // default: ~300 ms listen => too early
    CHECK(missed.service != "ssh");
    DetectConfig waits = dflt;
    waits.banner_wait = Millis(1500);
    waits.fixed_banner_wait = true;                                         // --banner-wait 1500: used exactly,
    auto found = ServiceDetector(waits).detect(ep, "", never, 0.05);        // even though RTT says "fast link"
    CHECK_EQ(found.service, std::string("ssh"));
    CHECK_EQ(found.version, std::string("9.6p1"));
}
