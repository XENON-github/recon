#include "recon/scanner.hpp"

#include <sys/epoll.h>
#include <sys/resource.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <deque>
#include <set>
#include <stdexcept>
#include <unordered_map>

namespace recon {

const char* to_string(PortState s) {
    switch (s) {
        case PortState::Open: return "open";
        case PortState::Closed: return "closed";
        case PortState::Filtered: return "filtered";
        case PortState::OpenFiltered: return "open|filtered";
        case PortState::Error: return "error";
    }
    return "error";
}

const char* to_string(Protocol p) { return p == Protocol::Tcp ? "tcp" : "udp"; }

PortState classify_connect_error(int err) {
    switch (err) {
        case 0: return PortState::Open;
        case ECONNREFUSED: return PortState::Closed;
        // ECONNRESET while completing connect() means the handshake succeeded and the peer then
        // reset: something is accepting connections, so the port is open. A truly closed port
        // answers the SYN with RST, which Linux reports as ECONNREFUSED.
        case ECONNRESET: return PortState::Open;
        case ETIMEDOUT:
        case EHOSTUNREACH:
        case ENETUNREACH:
        case EHOSTDOWN:
        case ENETDOWN:
        case EACCES:
        case EPERM: return PortState::Filtered;
        default: return PortState::Error;
    }
}

std::string udp_probe_payload(std::uint16_t port) {
    switch (port) {
        case 53:  // DNS: CHAOS TXT version.bind
            return std::string("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                               "\x07version\x04" "bind\x00\x00\x10\x00\x03", 30);
        case 123: {  // NTP client request (mode 3, version 3)
            std::string p(48, '\0');
            p[0] = 0x1b;
            return p;
        }
        case 137:  // NetBIOS node status request
            return std::string("\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20"
                               "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                               "\x00\x00\x21\x00\x01", 50);
        default: return std::string(4, '\0');
    }
}

namespace {

struct Slot {
    net::UniqueFd fd;
    std::size_t task = 0;
    int attempt = 1;
    Clock::time_point start;
    Clock::time_point deadline;
};

struct Retry {
    std::size_t task;
    int attempt;
};

int ceil_ms(Clock::duration d) {
    if (d <= Clock::duration::zero()) return 0;
    const auto ms = std::chrono::duration_cast<Millis>(d).count();
    return static_cast<int>(std::min<long long>(ms + 1, 1000000));
}

// Clamp requested concurrency so we never exhaust the process fd table.
std::size_t clamp_to_fd_limit(std::size_t want) {
    rlimit rl{};
    if (::getrlimit(RLIMIT_NOFILE, &rl) != 0) return std::min<std::size_t>(want, 256);
    if (rl.rlim_cur < rl.rlim_max) {
        rl.rlim_cur = rl.rlim_max;
        ::setrlimit(RLIMIT_NOFILE, &rl);
        ::getrlimit(RLIMIT_NOFILE, &rl);
    }
    constexpr rlim_t kReserve = 64;  // stdio, epoll fd, detection workers, output files
    const rlim_t usable = rl.rlim_cur > kReserve + 1 ? rl.rlim_cur - kReserve : 1;
    return static_cast<std::size_t>(std::min<rlim_t>(want, usable));
}

}  // namespace

PortScanner::PortScanner(ScanConfig cfg, RateLimiter& limiter, const CancelToken& cancel)
    : cfg_(cfg), limiter_(limiter), cancel_(cancel) {
    if (cfg_.max_inflight == 0) cfg_.max_inflight = 1;
    if (cfg_.retries < 0) cfg_.retries = 0;
}

ScanStats PortScanner::run(const std::vector<net::IpAddress>& hosts,
                           const std::vector<std::uint16_t>& ports, const Callback& cb) {
    ScanStats st;
    const std::size_t H = hosts.size();
    const std::size_t total = H * ports.size();
    st.tasks = total;
    if (total == 0) return st;

    net::UniqueFd ep(::epoll_create1(EPOLL_CLOEXEC));
    if (!ep) throw std::runtime_error(std::string("epoll_create1: ") + std::strerror(errno));

    std::size_t cap = clamp_to_fd_limit(cfg_.max_inflight);
    st.effective_inflight = cap;

    std::unordered_map<std::uint64_t, Slot> slots;
    std::set<std::pair<Clock::time_point, std::uint64_t>> deadlines;
    std::deque<Retry> retry_q;
    std::uint64_t next_id = 1;
    std::size_t next_task = 0;
    auto next_progress = Clock::now();
    const bool udp = cfg_.protocol == Protocol::Udp;

    auto emit = [&](std::size_t task, int attempt, PortState state, int err, double rtt,
                    std::string resp) {
        ProbeOutcome o;
        o.host_index = task % H;
        o.port = ports[task / H];
        o.protocol = cfg_.protocol;
        o.state = state;
        o.error_code = err;
        o.attempts = attempt;
        o.rtt_ms = rtt;
        o.udp_response = std::move(resp);
        switch (state) {
            case PortState::Open: ++st.open; break;
            case PortState::Closed: ++st.closed; break;
            case PortState::Filtered: ++st.filtered; break;
            case PortState::OpenFiltered: ++st.open_filtered; break;
            case PortState::Error: ++st.errors; break;
        }
        cb(o);
    };

    // Called when a probe ends without a definitive answer: retry or finalize.
    auto finish_timeout = [&](std::size_t task, int attempt, PortState final_state, int err) {
        if (attempt <= cfg_.retries) {
            ++st.retries;
            retry_q.push_back({task, attempt + 1});
        } else {
            emit(task, attempt, final_state, err, 0.0, {});
        }
    };

    auto ms_since = [](Clock::time_point t) {
        return std::chrono::duration<double, std::milli>(Clock::now() - t).count();
    };

    // Returns false when the launch was blocked by resource exhaustion (task re-queued).
    auto launch = [&](std::size_t task, int attempt) -> bool {
        const net::Endpoint dst(hosts[task % H], ports[task / H]);
        net::UniqueFd fd = net::make_socket(dst.family(), udp ? SOCK_DGRAM : SOCK_STREAM);
        if (!fd) {
            const int e = errno;
            if ((e == EMFILE || e == ENFILE || e == ENOBUFS || e == ENOMEM) && !slots.empty()) {
                cap = std::max<std::size_t>(1, slots.size());  // adaptive back-off
                st.effective_inflight = cap;
                retry_q.push_front({task, attempt});
                return false;
            }
            emit(task, attempt, PortState::Error, e, 0.0, {});
            return true;
        }
        ++st.attempts;
        const auto start = Clock::now();
        int rc = ::connect(fd.get(), dst.addr(), dst.len());
        const int cerr = errno;
        if (udp) {
            if (rc != 0) {
                emit(task, attempt, classify_connect_error(cerr), cerr, 0.0, {});
                return true;
            }
            const std::string payload = udp_probe_payload(dst.port());
            if (::send(fd.get(), payload.data(), payload.size(), MSG_NOSIGNAL) < 0) {
                const int e = errno;
                emit(task, attempt, e == ECONNREFUSED ? PortState::Closed : PortState::Error, e,
                     0.0, {});
                return true;
            }
        } else if (rc == 0) {
            const bool self = net::is_self_connected(fd.get());
            emit(task, attempt, self ? PortState::Closed : PortState::Open, self ? ECONNREFUSED : 0,
                 ms_since(start), {});
            return true;
        } else if (cerr != EINPROGRESS) {
            const PortState s = classify_connect_error(cerr);
            if (s == PortState::Filtered && attempt <= cfg_.retries) {
                finish_timeout(task, attempt, s, cerr);
            } else {
                emit(task, attempt, s, cerr, ms_since(start), {});
            }
            return true;
        }
        const std::uint64_t id = next_id++;
        epoll_event ev{};
        ev.events = (udp ? EPOLLIN : EPOLLOUT) | EPOLLERR;
        ev.data.u64 = id;  // ids are never reused, so stale events can't hit a recycled fd
        if (::epoll_ctl(ep.get(), EPOLL_CTL_ADD, fd.get(), &ev) != 0) {
            emit(task, attempt, PortState::Error, errno, 0.0, {});
            return true;
        }
        Slot s;
        s.fd = std::move(fd);
        s.task = task;
        s.attempt = attempt;
        s.start = start;
        s.deadline = start + cfg_.timeout;
        deadlines.emplace(s.deadline, id);
        slots.emplace(id, std::move(s));
        st.peak_inflight = std::max(st.peak_inflight, slots.size());
        return true;
    };

    auto handle_ready = [&](std::uint64_t id, std::uint32_t revents) {
        auto it = slots.find(id);
        if (it == slots.end()) return;
        Slot s = std::move(it->second);
        slots.erase(it);
        deadlines.erase({s.deadline, id});
        ::epoll_ctl(ep.get(), EPOLL_CTL_DEL, s.fd.get(), nullptr);

        int so_error = 0;
        socklen_t sl = sizeof(so_error);
        if (::getsockopt(s.fd.get(), SOL_SOCKET, SO_ERROR, &so_error, &sl) != 0) so_error = errno;

        if (udp) {
            if (so_error == 0 && (revents & EPOLLIN)) {
                char buf[1024];
                const ssize_t n = ::recv(s.fd.get(), buf, sizeof(buf), MSG_DONTWAIT);
                if (n >= 0) {
                    emit(s.task, s.attempt, PortState::Open, 0, ms_since(s.start),
                         std::string(buf, static_cast<std::size_t>(n)));
                    return;
                }
                so_error = errno;
            }
            emit(s.task, s.attempt, classify_connect_error(so_error), so_error, ms_since(s.start), {});
            return;
        }
        PortState state = classify_connect_error(so_error);
        if (state == PortState::Open && so_error == 0 && net::is_self_connected(s.fd.get())) {
            state = PortState::Closed;  // TCP self-connect on loopback: not a real listener
            so_error = ECONNREFUSED;
        }
        if (state == PortState::Filtered && s.attempt <= cfg_.retries) {
            finish_timeout(s.task, s.attempt, state, so_error);
        } else {
            emit(s.task, s.attempt, state, so_error, ms_since(s.start), {});
        }
    };

    while (true) {
        if (cancel_.requested()) {
            st.cancelled = true;
            break;
        }
        bool rate_blocked = false;
        bool resource_blocked = false;
        while (slots.size() < cap && (!retry_q.empty() || next_task < total)) {
            if (!limiter_.try_acquire()) {
                rate_blocked = true;
                break;
            }
            std::size_t task;
            int attempt;
            if (!retry_q.empty()) {
                task = retry_q.front().task;
                attempt = retry_q.front().attempt;
                retry_q.pop_front();
            } else {
                task = next_task++;
                attempt = 1;
            }
            if (!launch(task, attempt)) {
                resource_blocked = true;
                break;
            }
        }
        if (slots.empty() && retry_q.empty() && next_task >= total) break;

        int wait_ms = 100;  // upper bound keeps cancellation responsive
        if (!deadlines.empty()) {
            wait_ms = std::min(wait_ms, ceil_ms(deadlines.begin()->first - Clock::now()));
        }
        if (rate_blocked) wait_ms = std::min(wait_ms, std::max(1, ceil_ms(limiter_.time_to_next())));
        if (resource_blocked && slots.empty()) wait_ms = 1;

        epoll_event events[256];
        const int n = ::epoll_wait(ep.get(), events, 256, wait_ms);
        if (n < 0 && errno != EINTR) {
            throw std::runtime_error(std::string("epoll_wait: ") + std::strerror(errno));
        }
        for (int i = 0; i < n; ++i) handle_ready(events[i].data.u64, events[i].events);

        const auto now = Clock::now();
        if (progress_ && now >= next_progress) {
            progress_(st);
            next_progress = now + progress_interval_;
        }
        while (!deadlines.empty() && deadlines.begin()->first <= now) {
            const std::uint64_t id = deadlines.begin()->second;
            deadlines.erase(deadlines.begin());
            auto it = slots.find(id);
            if (it == slots.end()) continue;
            Slot s = std::move(it->second);
            slots.erase(it);
            ::epoll_ctl(ep.get(), EPOLL_CTL_DEL, s.fd.get(), nullptr);
            if (udp) {
                if (s.attempt <= cfg_.retries) {
                    ++st.retries;
                    retry_q.push_back({s.task, s.attempt + 1});
                } else {
                    emit(s.task, s.attempt, PortState::OpenFiltered, 0, 0.0, {});
                }
            } else {
                finish_timeout(s.task, s.attempt, PortState::Filtered, ETIMEDOUT);
            }
        }
    }
    return st;  // remaining slots close via UniqueFd destructors (also on cancel / exception)
}

}  // namespace recon
