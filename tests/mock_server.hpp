// In-process mock TCP services on 127.0.0.1 (ephemeral ports) for hermetic integration tests.
#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "recon/net.hpp"

namespace mock {

using Handler = std::function<void(int client_fd, const std::atomic<bool>& stop)>;

inline void sleep_ms(int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

inline void write_all(int fd, const std::string& s) {
    std::size_t off = 0;
    while (off < s.size()) {
        const ssize_t n = ::send(fd, s.data() + off, s.size() - off, MSG_NOSIGNAL);
        if (n <= 0) return;
        off += static_cast<std::size_t>(n);
    }
}

// Reads whatever the client sends for up to `ms` milliseconds.
inline std::string read_for(int fd, int ms) {
    std::string out;
    pollfd p{fd, POLLIN, 0};
    while (::poll(&p, 1, ms) > 0) {
        char b[1024];
        const ssize_t n = ::recv(fd, b, sizeof(b), 0);
        if (n <= 0) break;
        out.append(b, static_cast<std::size_t>(n));
        if (out.find("\r\n\r\n") != std::string::npos || out.find("\r\n") != std::string::npos) break;
        ms = 50;
    }
    return out;
}

class Server {
public:
    explicit Server(Handler h) : handler_(std::move(h)) {
        fd_.reset(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
        int one = 1;
        ::setsockopt(fd_.get(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ::bind(fd_.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a));
        ::listen(fd_.get(), 64);
        socklen_t l = sizeof(a);
        ::getsockname(fd_.get(), reinterpret_cast<sockaddr*>(&a), &l);
        port_ = ntohs(a.sin_port);
        acceptor_ = std::thread([this] { loop(); });
    }
    ~Server() {
        stop_ = true;
        if (acceptor_.joinable()) acceptor_.join();
        for (auto& t : handlers_) t.join();
    }
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;
    [[nodiscard]] std::uint16_t port() const { return port_; }

private:
    void loop() {
        while (!stop_) {
            pollfd p{fd_.get(), POLLIN, 0};
            if (::poll(&p, 1, 20) <= 0) continue;
            const int c = ::accept(fd_.get(), nullptr, nullptr);
            if (c < 0) continue;
            handlers_.emplace_back([this, c] {
                handler_(c, stop_);
                ::close(c);
            });
        }
    }
    Handler handler_;
    recon::net::UniqueFd fd_;
    std::uint16_t port_ = 0;
    std::atomic<bool> stop_{false};
    std::thread acceptor_;
    std::vector<std::thread> handlers_;  // only touched by the acceptor thread, then joined in dtor
};

// ---- canned behaviours ----
inline Handler banner(std::string text) {
    return [text](int fd, const std::atomic<bool>&) { write_all(fd, text); sleep_ms(300); };
}
inline Handler delayed_banner(std::string text, int delay_ms) {
    return [=](int fd, const std::atomic<bool>& stop) {
        for (int waited = 0; waited < delay_ms && !stop; waited += 10) sleep_ms(10);
        write_all(fd, text);
        sleep_ms(300);
    };
}
inline Handler slow_drip(std::string text, std::size_t chunk, int delay_ms) {
    return [=](int fd, const std::atomic<bool>& stop) {
        for (std::size_t i = 0; i < text.size() && !stop; i += chunk) {
            write_all(fd, text.substr(i, chunk));
            sleep_ms(delay_ms);
        }
    };
}
inline Handler silent() {
    return [](int, const std::atomic<bool>& stop) { while (!stop) sleep_ms(10); };
}
inline Handler reset_on_accept() {
    return [](int fd, const std::atomic<bool>&) {
        linger l{1, 0};
        ::setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l));  // close() sends RST
    };
}
inline Handler respond_after_request(std::string response) {
    return [response](int fd, const std::atomic<bool>&) {
        read_for(fd, 500);
        write_all(fd, response);
    };
}
inline Handler flood() {  // endless data: probe must stay bounded
    return [](int fd, const std::atomic<bool>& stop) {
        const std::string chunk(4096, 'A');
        while (!stop) {
            pollfd p{fd, POLLOUT, 0};
            if (::poll(&p, 1, 50) > 0) {
                if (::send(fd, chunk.data(), chunk.size(), MSG_NOSIGNAL) <= 0) break;
            }
        }
    };
}

inline std::size_t open_fd_count() {
    std::size_t n = 0;
    for (int i = 0; i < 4096; ++i) {
        if (::fcntl(i, F_GETFD) != -1) ++n;
    }
    return n;
}

// Returns a port that was just free (nothing listening) -> connects get ECONNREFUSED.
inline std::uint16_t closed_port() {
    recon::net::UniqueFd s(::socket(AF_INET, SOCK_STREAM, 0));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ::bind(s.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a));
    socklen_t l = sizeof(a);
    ::getsockname(s.get(), reinterpret_cast<sockaddr*>(&a), &l);
    return ntohs(a.sin_port);
}

}  // namespace mock
