#include "recon/net.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>

namespace recon::net {

void UniqueFd::reset(int fd) noexcept {
    if (fd_ >= 0) {
        // Do not retry close() on EINTR: the descriptor state is unspecified on Linux
        // and retrying could close an fd that another thread has just reused.
        ::close(fd_);
    }
    fd_ = fd;
}

std::optional<IpAddress> IpAddress::parse(std::string_view text) {
    if (text.empty() || text.size() > 45) return std::nullopt;
    const std::string s(text);  // inet_pton needs NUL termination
    IpAddress ip;
    if (inet_pton(AF_INET, s.c_str(), ip.bytes.data()) == 1) {
        ip.family = AF_INET;
        return ip;
    }
    if (inet_pton(AF_INET6, s.c_str(), ip.bytes.data()) == 1) {
        ip.family = AF_INET6;
        return ip;
    }
    return std::nullopt;
}

std::string IpAddress::to_string() const {
    char buf[INET6_ADDRSTRLEN] = {};
    if (inet_ntop(family, bytes.data(), buf, sizeof(buf)) == nullptr) return "?";
    return buf;
}

bool IpAddress::is_loopback() const noexcept {
    if (is_v4()) return bytes[0] == 127;
    static constexpr std::array<std::uint8_t, 16> kLo = {0, 0, 0, 0, 0, 0, 0, 0,
                                                         0, 0, 0, 0, 0, 0, 0, 1};
    return family == AF_INET6 && bytes == kLo;
}

Endpoint::Endpoint(const IpAddress& ip, std::uint16_t port) noexcept : port_(port), ip_(ip) {
    if (ip.is_v4()) {
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        std::memcpy(&sa.sin_addr, ip.bytes.data(), 4);
        std::memcpy(&ss_, &sa, sizeof(sa));
        len_ = sizeof(sa);
    } else {
        sockaddr_in6 sa{};
        sa.sin6_family = AF_INET6;
        sa.sin6_port = htons(port);
        std::memcpy(&sa.sin6_addr, ip.bytes.data(), 16);
        std::memcpy(&ss_, &sa, sizeof(sa));
        len_ = sizeof(sa);
    }
}

std::string Endpoint::to_string() const {
    const std::string a = ip_.to_string();
    return ip_.is_v4() ? a + ":" + std::to_string(port_) : "[" + a + "]:" + std::to_string(port_);
}

bool is_self_connected(int fd) {
    sockaddr_storage a{}, b{};
    socklen_t la = sizeof(a), lb = sizeof(b);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&a), &la) != 0 ||
        ::getpeername(fd, reinterpret_cast<sockaddr*>(&b), &lb) != 0) {
        return false;
    }
    return la == lb && std::memcmp(&a, &b, la) == 0;  // sockaddr_storage is zero-initialised
}

UniqueFd make_socket(int family, int type) {
    return UniqueFd(::socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
}

namespace {

int ms_until(Clock::time_point deadline) {
    const auto now = Clock::now();
    if (deadline <= now) return 0;
    const auto d = std::chrono::duration_cast<Millis>(deadline - now).count();
    // Round up so we never spin on a sub-millisecond remainder.
    return static_cast<int>(std::min<long long>(d + 1, 1 << 30));
}

}  // namespace

int wait_fd(int fd, short events, Clock::time_point deadline) {
    for (;;) {
        pollfd pfd{fd, events, 0};
        const int rc = ::poll(&pfd, 1, ms_until(deadline));
        if (rc > 0) return pfd.revents;
        if (rc == 0) return 0;
        if (errno != EINTR) return -1;
        if (Clock::now() >= deadline) return 0;
    }
}

std::optional<Connection> Connection::connect(const Endpoint& ep, Clock::time_point deadline,
                                              int* err) {
    auto set_err = [&](int e) {
        if (err != nullptr) *err = e;
    };
    UniqueFd fd = make_socket(ep.family(), SOCK_STREAM);
    if (!fd) {
        set_err(errno);
        return std::nullopt;
    }
    if (::connect(fd.get(), ep.addr(), ep.len()) != 0) {
        if (errno != EINPROGRESS && errno != EINTR) {
            set_err(errno);
            return std::nullopt;
        }
        const int ready = wait_fd(fd.get(), POLLOUT, deadline);
        if (ready <= 0) {
            set_err(ready == 0 ? ETIMEDOUT : errno);
            return std::nullopt;
        }
        int so_error = 0;
        socklen_t sl = sizeof(so_error);
        if (::getsockopt(fd.get(), SOL_SOCKET, SO_ERROR, &so_error, &sl) != 0) so_error = errno;
        if (so_error != 0) {
            set_err(so_error);
            return std::nullopt;
        }
    }
    if (is_self_connected(fd.get())) {
        set_err(ECONNREFUSED);  // nothing is listening; the kernel connected us to ourselves
        return std::nullopt;
    }
    return Connection(std::move(fd));
}

IoStatus Connection::send_all(std::string_view data, Clock::time_point deadline) {
    std::size_t sent = 0;
    while (sent < data.size()) {
        // MSG_NOSIGNAL: a peer reset must surface as EPIPE, never as a process-killing SIGPIPE.
        const ssize_t n =
            ::send(fd_.get(), data.data() + sent, data.size() - sent, MSG_NOSIGNAL);
        if (n > 0) {
            sent += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            const int r = wait_fd(fd_.get(), POLLOUT, deadline);
            if (r == 0) return IoStatus::Timeout;
            if (r < 0) return IoStatus::Error;
            continue;
        }
        return (errno == EPIPE || errno == ECONNRESET) ? IoStatus::Closed : IoStatus::Error;
    }
    return IoStatus::Ok;
}

IoStatus Connection::recv_some(char* buf, std::size_t cap, std::size_t& n,
                               Clock::time_point deadline) {
    n = 0;
    for (;;) {
        const ssize_t r = ::recv(fd_.get(), buf, cap, 0);
        if (r > 0) {
            n = static_cast<std::size_t>(r);
            return IoStatus::Ok;
        }
        if (r == 0) return IoStatus::Closed;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            const int w = wait_fd(fd_.get(), POLLIN, deadline);
            if (w == 0) return IoStatus::Timeout;
            if (w < 0) return IoStatus::Error;
            continue;
        }
        return errno == ECONNRESET ? IoStatus::Closed : IoStatus::Error;
    }
}

IoStatus Connection::read_response(std::string& out, std::size_t max_bytes,
                                   Clock::time_point deadline, Millis quiet) {
    char buf[2048];
    IoStatus last = IoStatus::Timeout;
    while (out.size() < max_bytes && Clock::now() < deadline) {
        const auto wait_until =
            out.empty() ? deadline : std::min(deadline, Clock::now() + quiet);
        std::size_t n = 0;
        const std::size_t want = std::min(sizeof(buf), max_bytes - out.size());
        last = recv_some(buf, want, n, wait_until);
        if (last != IoStatus::Ok) break;
        out.append(buf, n);
    }
    if (!out.empty()) return IoStatus::Ok;
    return last == IoStatus::Ok ? IoStatus::Timeout : last;
}

}  // namespace recon::net
