#include "mock_server.hpp"
#include "recon/net.hpp"
#include "testing.hpp"

using namespace recon;

namespace {
net::Endpoint lo(std::uint16_t port) { return net::Endpoint(*net::IpAddress::parse("127.0.0.1"), port); }
}  // namespace

// Regression for the original tool dying with exit 141: sending on a connection the peer has
// already reset raises SIGPIPE unless MSG_NOSIGNAL is used. test_main leaves SIGPIPE at SIG_DFL,
// so a regression here kills the test process instead of passing silently.
TEST(send_after_peer_reset_returns_error_not_sigpipe) {
    mock::Server s(mock::reset_on_accept());
    // The server's RST can win the race against connect()'s SO_ERROR check (then connect itself
    // reports ECONNRESET), so retry until we hold an established-then-reset connection.
    std::optional<net::Connection> conn;
    for (int i = 0; i < 50 && !conn; ++i) conn = net::Connection::connect(lo(s.port()), Clock::now() + Millis(1000));
    CHECK(conn.has_value());
    if (!conn) return;
    mock::sleep_ms(150);  // RST has definitely arrived
    // Linux reports the pending ECONNRESET on the first call; only a *later* send gets EPIPE
    // (and SIGPIPE). The original scanner read first, then sent: reproduce that order.
    char buf[16];
    std::size_t n = 0;
    (void)conn->recv_some(buf, sizeof(buf), n, Clock::now() + Millis(500));
    const auto st = conn->send_all("GET / HTTP/1.1\r\n\r\n", Clock::now() + Millis(500));
    CHECK(st == net::IoStatus::Closed || st == net::IoStatus::Error);
}

TEST(read_response_reassembles_chunks_and_stops_on_quiet) {
    mock::Server s(mock::slow_drip("0123456789ABCDEF", 4, 30));
    auto conn = net::Connection::connect(lo(s.port()), Clock::now() + Millis(1000));
    CHECK(conn.has_value());
    std::string out;
    CHECK(conn->read_response(out, 4096, Clock::now() + Millis(2000), Millis(150)) == net::IoStatus::Ok);
    CHECK_EQ(out, std::string("0123456789ABCDEF"));
}

TEST(read_response_respects_max_bytes) {
    mock::Server s(mock::flood());
    auto conn = net::Connection::connect(lo(s.port()), Clock::now() + Millis(1000));
    CHECK(conn.has_value());
    std::string out;
    conn->read_response(out, 1000, Clock::now() + Millis(2000), Millis(150));
    CHECK(out.size() <= 1000);
    CHECK(out.size() > 0);
}

TEST(read_response_times_out_on_silent_peer) {
    mock::Server s(mock::silent());
    auto conn = net::Connection::connect(lo(s.port()), Clock::now() + Millis(1000));
    CHECK(conn.has_value());
    std::string out;
    const auto t0 = Clock::now();
    CHECK(conn->read_response(out, 100, Clock::now() + Millis(200), Millis(50)) == net::IoStatus::Timeout);
    const auto ms = std::chrono::duration_cast<Millis>(Clock::now() - t0).count();
    CHECK(ms >= 190 && ms < 600);
    CHECK(out.empty());
}

TEST(connect_to_closed_port_reports_refused) {
    int err = 0;
    auto conn = net::Connection::connect(lo(mock::closed_port()), Clock::now() + Millis(1000), &err);
    CHECK(!conn.has_value());
    CHECK_EQ(err, ECONNREFUSED);
}

TEST(unique_fd_closes_once_and_moves) {
    const std::size_t before = mock::open_fd_count();
    {
        net::UniqueFd a(::socket(AF_INET, SOCK_STREAM, 0));
        CHECK(a);
        net::UniqueFd b(std::move(a));
        CHECK(!a);
        CHECK(b);
        CHECK_EQ(mock::open_fd_count(), before + 1);
        net::UniqueFd c;
        c = std::move(b);
        CHECK_EQ(mock::open_fd_count(), before + 1);
    }
    CHECK_EQ(mock::open_fd_count(), before);
}

TEST(self_connect_is_detected) {
    // Bind the client to port P, then connect to 127.0.0.1:P with nothing listening: Linux completes a
    // TCP simultaneous open with itself. That must be recognised and never reported as a listener.
    const std::uint16_t p = mock::closed_port();
    net::UniqueFd s(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    int one = 1;
    ::setsockopt(s.get(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(p);
    CHECK(::bind(s.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);
    CHECK(::connect(s.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);  // the quirk itself
    CHECK(net::is_self_connected(s.get()));
    // A normal connection to a real listener is not a self-connect.
    mock::Server srv(mock::silent());
    auto c = net::Connection::connect(lo(srv.port()), Clock::now() + Millis(1000));
    CHECK(c.has_value());
    CHECK(!net::is_self_connected(c->fd()));
}
