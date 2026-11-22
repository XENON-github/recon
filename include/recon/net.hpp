// Low-level networking primitives: RAII file descriptors, address types, and a
// deadline-aware blocking connection used by the service-detection probes.
#pragma once

#include <netinet/in.h>
#include <sys/socket.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "recon/common.hpp"

namespace recon::net {

// Owns a file descriptor; closes it exactly once. Move-only.
class UniqueFd {
public:
    UniqueFd() noexcept = default;
    explicit UniqueFd(int fd) noexcept : fd_(fd) {}
    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    UniqueFd(UniqueFd&& o) noexcept : fd_(o.release()) {}
    UniqueFd& operator=(UniqueFd&& o) noexcept {
        if (this != &o) reset(o.release());
        return *this;
    }
    ~UniqueFd() { reset(); }

    [[nodiscard]] int get() const noexcept { return fd_; }
    [[nodiscard]] explicit operator bool() const noexcept { return fd_ >= 0; }
    int release() noexcept {
        int f = fd_;
        fd_ = -1;
        return f;
    }
    void reset(int fd = -1) noexcept;

private:
    int fd_ = -1;
};

// IPv4 or IPv6 address in network byte order. For IPv4 only bytes[0..3] are used.
struct IpAddress {
    int family = AF_UNSPEC;
    std::array<std::uint8_t, 16> bytes{};

    static std::optional<IpAddress> parse(std::string_view text);  // no scope ids, no brackets
    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] bool is_v4() const noexcept { return family == AF_INET; }
    [[nodiscard]] bool is_loopback() const noexcept;
    [[nodiscard]] std::size_t byte_len() const noexcept { return is_v4() ? 4 : 16; }
    friend bool operator==(const IpAddress& a, const IpAddress& b) noexcept {
        return a.family == b.family && a.bytes == b.bytes;
    }
};

// A concrete socket address (address + port) ready to pass to connect()/sendto().
class Endpoint {
public:
    Endpoint(const IpAddress& ip, std::uint16_t port) noexcept;
    [[nodiscard]] const sockaddr* addr() const noexcept {
        return reinterpret_cast<const sockaddr*>(&ss_);
    }
    [[nodiscard]] socklen_t len() const noexcept { return len_; }
    [[nodiscard]] int family() const noexcept { return ss_.ss_family; }
    [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
    [[nodiscard]] IpAddress ip() const noexcept { return ip_; }
    [[nodiscard]] std::string to_string() const;  // "1.2.3.4:80" or "[::1]:80"

private:
    sockaddr_storage ss_{};
    socklen_t len_ = 0;
    std::uint16_t port_ = 0;
    IpAddress ip_{};
};

// True if the connected socket's local and peer addresses are identical. Linux can "connect" a
// socket to itself (TCP simultaneous open) when the kernel picks a source port equal to the
// destination port on loopback; such a connection is NOT evidence of a listener.
bool is_self_connected(int fd);

// Creates a non-blocking, close-on-exec socket. Returns an invalid fd on failure (errno set).
UniqueFd make_socket(int family, int type);

enum class IoStatus { Ok, Timeout, Closed, Error };

// Waits for `events` on fd until `deadline`. Returns revents (>0), 0 on timeout, -1 on error.
// Retries transparently on EINTR.
int wait_fd(int fd, short events, Clock::time_point deadline);

// Blocking-with-deadline TCP connection. All operations honour an absolute
// deadline, handle partial reads/writes, EINTR and EAGAIN, and never raise SIGPIPE.
class Connection {
public:
    // On failure returns nullopt and stores errno in *err (if given).
    static std::optional<Connection> connect(const Endpoint& ep, Clock::time_point deadline,
                                             int* err = nullptr);

    Connection(Connection&&) noexcept = default;
    Connection& operator=(Connection&&) noexcept = default;

    [[nodiscard]] int fd() const noexcept { return fd_.get(); }

    IoStatus send_all(std::string_view data, Clock::time_point deadline);

    // Reads at least one byte if available. `n` is set to the byte count on Ok.
    IoStatus recv_some(char* buf, std::size_t cap, std::size_t& n, Clock::time_point deadline);

    // Accumulates a response into `out`. Waits until `deadline` for the first byte,
    // then stops after `quiet` of silence, at EOF, or once `max_bytes` have been read.
    // Returns Ok if any bytes were collected (even if the peer then reset), otherwise
    // Timeout / Closed / Error.
    IoStatus read_response(std::string& out, std::size_t max_bytes, Clock::time_point deadline,
                           Millis quiet);

private:
    explicit Connection(UniqueFd fd) noexcept : fd_(std::move(fd)) {}
    UniqueFd fd_;
};

}  // namespace recon::net
