#include "recon/synscan.hpp"

#include <netinet/in.h>
#include <poll.h>
#include <sys/resource.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <deque>
#include <optional>
#include <random>
#include <set>
#include <stdexcept>
#include <unordered_map>

namespace recon {
namespace {

constexpr std::uint16_t kPortLo = 20000;  // source-port pool: below the Linux ephemeral range (32768+)
constexpr std::uint16_t kPortHi = 30000;
constexpr std::uint8_t kFin = 0x01, kSyn = 0x02, kRst = 0x04, kAck = 0x10;

std::uint16_t be16(const std::uint8_t* p) { return static_cast<std::uint16_t>((p[0] << 8) | p[1]); }
std::uint32_t be32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | p[3];
}
void put16(std::uint8_t* p, std::uint16_t v) { p[0] = static_cast<std::uint8_t>(v >> 8); p[1] = static_cast<std::uint8_t>(v); }
void put32(std::uint8_t* p, std::uint32_t v) { put16(p, static_cast<std::uint16_t>(v >> 16)); put16(p + 2, static_cast<std::uint16_t>(v)); }

// Picks the local source address the kernel would use to reach `dst` (no packet is sent).
std::optional<std::array<std::uint8_t, 4>> local_address_for(const net::IpAddress& dst) {
    net::UniqueFd s(::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    if (!s) return std::nullopt;
    const net::Endpoint ep(dst, 9);
    if (::connect(s.get(), ep.addr(), ep.len()) != 0) return std::nullopt;
    sockaddr_in me{};
    socklen_t l = sizeof(me);
    if (::getsockname(s.get(), reinterpret_cast<sockaddr*>(&me), &l) != 0) return std::nullopt;
    std::array<std::uint8_t, 4> out{};
    std::memcpy(out.data(), &me.sin_addr, 4);
    return out;
}

struct Slot {
    std::size_t task = 0;
    int attempt = 1;
    std::uint32_t seq = 0;
    Clock::time_point start;
    Clock::time_point deadline;
};

}  // namespace

std::uint16_t tcp_checksum(const std::uint8_t src[4], const std::uint8_t dst[4], const std::uint8_t* seg, std::size_t len) {
    std::uint32_t sum = 0;
    auto add16 = [&](std::uint16_t v) { sum += v; };
    add16(be16(src)); add16(be16(src + 2)); add16(be16(dst)); add16(be16(dst + 2));
    add16(6);  // protocol
    add16(static_cast<std::uint16_t>(len));
    for (std::size_t i = 0; i + 1 < len; i += 2) add16(be16(seg + i));
    if (len % 2 != 0) add16(static_cast<std::uint16_t>(seg[len - 1] << 8));
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<std::uint16_t>(~sum);
}

SynScanner::SynScanner(ScanConfig cfg, RateLimiter& limiter, const CancelToken& cancel)
    : cfg_(cfg), limiter_(limiter), cancel_(cancel) {
    if (cfg_.max_inflight == 0) cfg_.max_inflight = 1;
    if (cfg_.retries < 0) cfg_.retries = 0;
}

bool SynScanner::available(std::string* why) {
    net::UniqueFd s(::socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_TCP));
    if (s) return true;
    if (why != nullptr) {
        *why = std::string("cannot open a raw socket (") + std::strerror(errno) +
               "); run as root or grant the capability: sudo setcap cap_net_raw+ep $(command -v recon)";
    }
    return false;
}

ScanStats SynScanner::run(const std::vector<net::IpAddress>& hosts, const std::vector<std::uint16_t>& ports,
                          const PortScanner::Callback& cb) {
    ScanStats st;
    const std::size_t H = hosts.size();
    const std::size_t total = H * ports.size();
    st.tasks = total;
    if (total == 0) return st;

    std::vector<std::array<std::uint8_t, 4>> src_addr(H);
    for (std::size_t i = 0; i < H; ++i) {
        if (!hosts[i].is_v4()) throw std::runtime_error("SYN scan supports IPv4 targets only (got " + hosts[i].to_string() + ")");
        auto a = local_address_for(hosts[i]);
        if (!a) throw std::runtime_error("no route to " + hosts[i].to_string());
        src_addr[i] = *a;
    }

    net::UniqueFd tx(::socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_TCP));
    net::UniqueFd rx(::socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP));
    if (!tx || !rx) {
        std::string why;
        available(&why);
        throw std::runtime_error(why);
    }
    const int rcvbuf = 4 * 1024 * 1024;  // bursts of replies must not be dropped by the kernel
    ::setsockopt(rx.get(), SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    std::mt19937 rng{std::random_device{}()};
    std::deque<std::uint16_t> free_ports;
    {
        std::vector<std::uint16_t> all;
        for (std::uint32_t p = kPortLo; p < kPortHi; ++p) all.push_back(static_cast<std::uint16_t>(p));
        std::shuffle(all.begin(), all.end(), rng);
        free_ports.assign(all.begin(), all.end());
    }
    const std::size_t cap = std::min<std::size_t>(cfg_.max_inflight, free_ports.size());
    st.effective_inflight = cap;

    struct Retry { std::size_t task; int attempt; };
    std::unordered_map<std::uint16_t, Slot> slots;  // keyed by OUR source port
    std::set<std::pair<Clock::time_point, std::uint16_t>> deadlines;
    std::deque<Retry> retry_q;
    std::size_t next_task = 0;
    auto next_progress = Clock::now();

    auto ms_since = [](Clock::time_point t) { return std::chrono::duration<double, std::milli>(Clock::now() - t).count(); };
    auto emit = [&](std::size_t task, int attempt, PortState state, int err, double rtt) {
        ProbeOutcome o;
        o.host_index = task % H;
        o.port = ports[task / H];
        o.protocol = Protocol::Tcp;
        o.state = state;
        o.error_code = err;
        o.attempts = attempt;
        o.rtt_ms = rtt;
        switch (state) {
            case PortState::Open: ++st.open; break;
            case PortState::Closed: ++st.closed; break;
            case PortState::Filtered: ++st.filtered; break;
            case PortState::OpenFiltered: ++st.open_filtered; break;
            case PortState::Error: ++st.errors; break;
        }
        cb(o);
    };
    auto release = [&](std::uint16_t port) {
        auto it = slots.find(port);
        if (it == slots.end()) return;
        deadlines.erase({it->second.deadline, port});
        slots.erase(it);
        free_ports.push_back(port);  // back of the queue: delays reuse so stale replies can't alias
    };

    // Returns false if the send buffer was full (task re-queued; caller should yield).
    auto launch = [&](std::size_t task, int attempt) -> bool {
        const std::size_t h = task % H;
        const std::uint16_t dport = ports[task / H];
        const std::uint16_t sport = free_ports.front();
        std::uint8_t seg[24] = {};
        const std::uint32_t seq = static_cast<std::uint32_t>(rng());
        put16(seg, sport);
        put16(seg + 2, dport);
        put32(seg + 4, seq);
        seg[12] = 6 << 4;  // data offset: 6 words (20-byte header + 4-byte MSS option)
        seg[13] = kSyn;
        put16(seg + 14, 64240);  // window
        seg[20] = 2; seg[21] = 4; put16(seg + 22, 1460);  // MSS option
        put16(seg + 16, tcp_checksum(src_addr[h].data(), hosts[h].bytes.data(), seg, sizeof(seg)));
        const net::Endpoint dst(hosts[h], dport);
        if (::sendto(tx.get(), seg, sizeof(seg), MSG_NOSIGNAL, dst.addr(), dst.len()) < 0) {
            const int e = errno;
            if (e == ENOBUFS || e == EAGAIN || e == EINTR) {
                retry_q.push_front({task, attempt});
                return false;
            }
            if (e == EPERM) throw std::runtime_error("raw send refused (firewall or missing capability)");
            emit(task, attempt, e == ENETUNREACH || e == EHOSTUNREACH ? PortState::Filtered : PortState::Error, e, 0.0);
            return true;
        }
        free_ports.pop_front();
        ++st.attempts;
        Slot s;
        s.task = task; s.attempt = attempt; s.seq = seq; s.start = Clock::now(); s.deadline = s.start + cfg_.timeout;
        deadlines.emplace(s.deadline, sport);
        slots.emplace(sport, s);
        st.peak_inflight = std::max(st.peak_inflight, slots.size());
        return true;
    };

    auto handle_packet = [&](const std::uint8_t* p, std::size_t n) {
        if (n < 20 || (p[0] >> 4) != 4 || p[9] != IPPROTO_TCP) return;
        const std::size_t ihl = static_cast<std::size_t>(p[0] & 0x0F) * 4;
        if (ihl < 20 || n < ihl + 20) return;
        const std::uint8_t* tcp = p + ihl;
        const std::uint16_t sport = be16(tcp), dport = be16(tcp + 2);  // sport = target's port, dport = ours
        const std::uint8_t flags = tcp[13];
        if ((flags & kAck) == 0) return;                      // our own looped-back SYN, or noise
        if ((flags & (kSyn | kRst)) == 0 || (flags & kFin)) return;
        auto it = slots.find(dport);
        if (it == slots.end()) return;
        const Slot& s = it->second;
        const std::size_t h = s.task % H;
        if (sport != ports[s.task / H] || std::memcmp(p + 12, hosts[h].bytes.data(), 4) != 0) return;
        if (be32(tcp + 8) != s.seq + 1) return;                // must acknowledge OUR sequence number
        const PortState state = (flags & kSyn) ? PortState::Open : PortState::Closed;
        const std::size_t task = s.task;
        const int attempt = s.attempt;
        const double rtt = ms_since(s.start);
        release(dport);
        emit(task, attempt, state, 0, rtt);
        // For SYN-ACK the kernel (which has no socket for this tuple) answers with RST, closing the half-open.
    };

    std::uint8_t buf[2048];
    while (true) {
        if (cancel_.requested()) { st.cancelled = true; break; }
        bool rate_blocked = false, send_blocked = false;
        while (slots.size() < cap && !free_ports.empty() && (!retry_q.empty() || next_task < total)) {
            if (!limiter_.try_acquire()) { rate_blocked = true; break; }
            std::size_t task; int attempt;
            if (!retry_q.empty()) { task = retry_q.front().task; attempt = retry_q.front().attempt; retry_q.pop_front(); }
            else { task = next_task++; attempt = 1; }
            if (!launch(task, attempt)) { send_blocked = true; break; }
        }
        if (slots.empty() && retry_q.empty() && next_task >= total) break;

        auto wait_ms = std::chrono::milliseconds(100);
        const auto now0 = Clock::now();
        if (!deadlines.empty()) {
            const auto d = deadlines.begin()->first - now0;
            wait_ms = std::min(wait_ms, std::max(std::chrono::milliseconds(0), std::chrono::duration_cast<std::chrono::milliseconds>(d) + std::chrono::milliseconds(1)));
        }
        if (rate_blocked) {
            const auto r = std::chrono::duration_cast<std::chrono::milliseconds>(limiter_.time_to_next()) + std::chrono::milliseconds(1);
            wait_ms = std::min(wait_ms, std::max(std::chrono::milliseconds(1), r));
        }
        if (send_blocked) wait_ms = std::chrono::milliseconds(1);

        pollfd pfd{rx.get(), POLLIN, 0};
        const int pr = ::poll(&pfd, 1, static_cast<int>(wait_ms.count()));
        if (pr < 0 && errno != EINTR) throw std::runtime_error(std::string("poll: ") + std::strerror(errno));
        if (pr > 0) {
            for (int i = 0; i < 4096; ++i) {  // drain, but yield periodically to launch/expire
                const ssize_t n = ::recv(rx.get(), buf, sizeof(buf), MSG_DONTWAIT);
                if (n < 0) break;
                handle_packet(buf, static_cast<std::size_t>(n));
            }
        }

        const auto now = Clock::now();
        if (progress_ && now >= next_progress) {
            progress_(st);
            next_progress = now + progress_interval_;
        }
        while (!deadlines.empty() && deadlines.begin()->first <= now) {
            const std::uint16_t port = deadlines.begin()->second;
            const Slot s = slots.at(port);
            release(port);
            if (s.attempt <= cfg_.retries) {
                ++st.retries;
                retry_q.push_back({s.task, s.attempt + 1});
            } else {
                emit(s.task, s.attempt, PortState::Filtered, ETIMEDOUT, 0.0);
            }
        }
    }
    return st;
}

}  // namespace recon
