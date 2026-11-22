#include <algorithm>
#include <cerrno>
#include <cstring>
#include <random>

#include "bytes.hpp"
#include "recon/detect.hpp"

namespace recon {
using namespace detail;

namespace {

void put16(std::string& s, unsigned v) {
    s.push_back(static_cast<char>((v >> 8) & 0xFF));
    s.push_back(static_cast<char>(v & 0xFF));
}
void put24(std::string& s, unsigned v) {
    s.push_back(static_cast<char>((v >> 16) & 0xFF));
    put16(s, v & 0xFFFF);
}

}  // namespace

// Builds a TLS ClientHello offering TLS 1.2 and 1.3. Random fields come from the system RNG
// (they need not be secret; this never completes a handshake).
std::string build_client_hello(const std::string& sni) {
    std::random_device rd;
    auto rnd = [&](std::string& s, std::size_t n) {
        for (std::size_t i = 0; i < n; ++i) s.push_back(static_cast<char>(rd() & 0xFF));
    };

    std::string exts;
    if (!sni.empty() && !net::IpAddress::parse(sni)) {  // SNI must be a hostname, never an IP
        std::string name;
        name.push_back('\0');
        put16(name, static_cast<unsigned>(sni.size()));
        name += sni;
        put16(exts, 0x0000);
        put16(exts, static_cast<unsigned>(name.size() + 2));
        put16(exts, static_cast<unsigned>(name.size()));
        exts += name;
    }
    // supported_groups: x25519, secp256r1, secp384r1
    put16(exts, 0x000a); put16(exts, 8); put16(exts, 6);
    put16(exts, 0x001d); put16(exts, 0x0017); put16(exts, 0x0018);
    // ec_point_formats: uncompressed
    put16(exts, 0x000b); put16(exts, 2); exts.push_back(1); exts.push_back(0);
    // signature_algorithms
    const unsigned sigs[] = {0x0804, 0x0805, 0x0806, 0x0403, 0x0503, 0x0603, 0x0401, 0x0501, 0x0601};
    put16(exts, 0x000d); put16(exts, static_cast<unsigned>(2 + 2 * std::size(sigs)));
    put16(exts, static_cast<unsigned>(2 * std::size(sigs)));
    for (unsigned sg : sigs) put16(exts, sg);
    // supported_versions: 1.3, 1.2
    put16(exts, 0x002b); put16(exts, 5); exts.push_back(4); put16(exts, 0x0304); put16(exts, 0x0303);
    // key_share: x25519
    put16(exts, 0x0033); put16(exts, 38); put16(exts, 36); put16(exts, 0x001d); put16(exts, 32);
    rnd(exts, 32);

    const unsigned suites[] = {0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0x009c, 0x002f};
    std::string hello;
    put16(hello, 0x0303);
    rnd(hello, 32);
    hello.push_back('\0');  // empty session id
    put16(hello, static_cast<unsigned>(2 * std::size(suites)));
    for (unsigned c : suites) put16(hello, c);
    hello.push_back(1);
    hello.push_back(0);  // null compression
    put16(hello, static_cast<unsigned>(exts.size()));
    hello += exts;

    std::string hs;
    hs.push_back(0x01);
    put24(hs, static_cast<unsigned>(hello.size()));
    hs += hello;

    std::string rec;
    rec.push_back(0x16);
    put16(rec, 0x0301);
    put16(rec, static_cast<unsigned>(hs.size()));
    rec += hs;
    return rec;
}

namespace {

struct ProbeDef {
    const char* name;
    int rarity;                        // probe runs if rarity <= intensity ...
    std::vector<std::uint16_t> ports;  // ... or the port is listed here (and intensity >= 1)
    std::string (*build)(const std::string& host);
    Matcher match;
};

std::string http_get(const std::string& host) {
    return "GET / HTTP/1.1\r\nHost: " + host +
           "\r\nUser-Agent: recon/" + std::string(kVersion) +
           "\r\nAccept: */*\r\nConnection: close\r\n\r\n";
}
std::string tls_hello(const std::string& host) { return build_client_hello(host); }
std::string redis_info(const std::string&) { return "INFO server\r\n"; }
std::string pg_sslreq(const std::string&) { return std::string("\x00\x00\x00\x08\x04\xd2\x16\x2f", 8); }
std::string smb2_negotiate(const std::string&) {
    std::string h;
    auto le16 = [&](unsigned v) { h.push_back(static_cast<char>(v & 0xFF)); h.push_back(static_cast<char>((v >> 8) & 0xFF)); };
    auto le32 = [&](unsigned v) { le16(v & 0xFFFF); le16(v >> 16); };
    h += std::string("\xFE" "SMB", 4);
    le16(64); le16(0); le32(0); le16(0); le16(1); le32(0); le32(0);
    h.append(8, '\0');   // MessageId
    le32(0); le32(0);    // Reserved/ProcessId, TreeId
    h.append(8, '\0');   // SessionId
    h.append(16, '\0');  // Signature
    le16(36); le16(5); le16(1); le16(0); le32(0);
    h.append(16, '\0');  // ClientGuid
    h.append(8, '\0');   // ClientStartTime
    for (unsigned d : {0x0202U, 0x0210U, 0x0300U, 0x0302U, 0x0311U}) le16(d);
    std::string out(1, '\0');
    put24(out, static_cast<unsigned>(h.size()));
    return out + h;
}

const std::vector<ProbeDef>& probes() {
    static const std::vector<ProbeDef> k = {
        {"http", 1, {80, 8000, 8008, 8080, 8081, 8888, 9000, 9090, 3000, 5000}, http_get, match_http},
        {"tls", 2, {443, 8443, 4443, 9443, 993, 995, 465, 636}, tls_hello, match_tls},
        {"redis", 6, {6379}, redis_info, match_redis},
        {"postgres", 6, {5432}, pg_sslreq, match_postgres},
        {"smb", 7, {445, 139}, smb2_negotiate, match_smb2},
    };
    return k;
}

constexpr Matcher kPassive[] = {match_ssh,  match_ftp,   match_smtp,   match_pop3,
                                match_imap, match_mysql, match_vnc,    match_telnet};

}  // namespace

Detection ServiceDetector::detect(const net::Endpoint& ep, const std::string& host_label,
                                  const CancelToken& cancel, double rtt_ms) const {
    Detection result;
    const std::uint16_t port = ep.port();
    const auto budget_end = Clock::now() + cfg_.total_budget;
    const std::string host = host_label.empty() ? ep.ip().to_string() : host_label;
    std::string unmatched_banner;

    // Adaptive waits: ~6 RTTs + 300 ms of slack, never below a floor, never above the configured cap.
    auto adapt = [&](Millis cap, Millis floor) {
        if (!cfg_.adaptive_timeouts || rtt_ms < 0.0) return cap;
        const auto est = Millis(static_cast<long long>(rtt_ms * 6.0) + 300);
        return std::min(cap, std::max(floor, est));
    };
    const Millis banner_wait = cfg_.fixed_banner_wait ? cfg_.banner_wait : adapt(cfg_.banner_wait, Millis(300));
    const Millis probe_timeout = adapt(cfg_.probe_timeout, Millis(500));

    auto finalize_guess = [&]() {
        Detection d;
        d.error = result.error;
        const char* guess = port_guess_service(port, true);
        if (std::strcmp(guess, "unknown") != 0) {
            d.service = guess;
            d.confidence = 25;
            d.method = "port-guess";
            d.version_quality = VersionQuality::Inferred;
            d.extra = "guessed from port number; no protocol response";
        } else if (!unmatched_banner.empty()) {
            d.confidence = 10;
        }
        d.banner = unmatched_banner;
        return d;
    };

    // ---- 1. Passive: many protocols speak first. ----
    {
        int err = 0;
        auto conn = net::Connection::connect(
            ep, std::min(budget_end, Clock::now() + cfg_.connect_timeout), &err);
        if (!conn && err == ECONNRESET) {
            // The handshake completed and the peer reset before we could even check: same situation
            // as accept-then-close, just observed at connect() instead of at the first read.
            Detection d;
            d.service = "tcpwrapped";
            d.confidence = 60;
            d.method = "banner";
            d.extra = "connection reset by peer immediately after the handshake";
            return d;
        }
        if (!conn) {
            result.error = std::string("connect failed: ") + std::strerror(err);
            return finalize_guess();
        }
        std::string data;
        const net::IoStatus st = conn->read_response(data, 4096, Clock::now() + banner_wait, cfg_.quiet);
        if (data.empty() && st == net::IoStatus::Closed) {
            // Accepted, then closed (or reset) before sending anything and before we sent anything:
            // the classic TCP-wrapper / filtering-proxy signature. More probes would be wasted.
            Detection d;
            d.service = "tcpwrapped";
            d.confidence = 60;
            d.method = "banner";
            d.extra = "connection closed by peer before any data was exchanged";
            return d;
        }
        if (!data.empty()) {
            for (Matcher m : kPassive) {
                if (auto d = m(data, port)) {
                    d->method = "banner";
                    return *d;
                }
            }
            unmatched_banner = sanitize_ascii(data, 200);
            if (cfg_.intensity < 7) return finalize_guess();  // spoke first, unrecognised
        }
    }
    if (cfg_.intensity <= 0) return finalize_guess();

    // ---- 2. Active probes: port-hinted first, then by rarity. ----
    std::vector<const ProbeDef*> plan;
    for (const ProbeDef& p : probes()) {
        const bool hinted = std::find(p.ports.begin(), p.ports.end(), port) != p.ports.end();
        if (hinted || p.rarity <= cfg_.intensity) plan.push_back(&p);
    }
    std::stable_sort(plan.begin(), plan.end(), [&](const ProbeDef* a, const ProbeDef* b) {
        const bool ha = std::find(a->ports.begin(), a->ports.end(), port) != a->ports.end();
        const bool hb = std::find(b->ports.begin(), b->ports.end(), port) != b->ports.end();
        if (ha != hb) return ha;
        return a->rarity < b->rarity;
    });

    for (const ProbeDef* p : plan) {
        if (cancel.requested() || Clock::now() >= budget_end) break;
        auto conn = net::Connection::connect(
            ep, std::min(budget_end, Clock::now() + cfg_.connect_timeout), nullptr);
        if (!conn) continue;
        const auto deadline = std::min(budget_end, Clock::now() + probe_timeout);
        if (conn->send_all(p->build(host), deadline) != net::IoStatus::Ok) continue;
        std::string resp;
        conn->read_response(resp, 8192, deadline, cfg_.quiet);
        if (resp.empty()) continue;
        if (auto d = p->match(resp, port)) {
            d->method = std::string("probe:") + p->name;
#ifdef RECON_WITH_OPENSSL
            if (d->tls && cfg_.tls_inspect) {
                TlsInspectResult t = tls_inspect(ep, host, std::min(budget_end, Clock::now() + cfg_.probe_timeout), true, host);  // handshakes get the full cap
                if (t.ok) {
                    if (auto h = match_http(t.http_response, port)) {
                        h->tls = true;
                        h->service = "https";
                        h->method = d->method + "+tls";
                        h->confidence = 97;
                        h->tls_info = t.info;
                        return *h;
                    }
                    d->tls_info = t.info;
                    d->confidence = std::max(d->confidence, 95);
                }
            }
#endif
            return *d;
        }
        if (unmatched_banner.empty()) unmatched_banner = sanitize_ascii(resp, 200);
    }
    return finalize_guess();
}

}  // namespace recon
