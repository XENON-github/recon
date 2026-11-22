#include "recon/report.hpp"

#include <cstdio>
#include <iomanip>
#include <ostream>

namespace recon {

// ------------------------------------------------------------------ JSON
std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    auto put_u = [&](unsigned cp) {
        char b[8];
        std::snprintf(b, sizeof(b), "\\u%04x", cp);
        out += b;
    };
    for (std::size_t i = 0; i < s.size();) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20 || c == 0x7F) put_u(c);
                    else out.push_back(static_cast<char>(c));
            }
            ++i;
            continue;
        }
        // Validate a multi-byte UTF-8 sequence (reject overlong forms, surrogates, > U+10FFFF).
        std::size_t len = 0;
        unsigned cp = 0, min = 0;
        if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; min = 0x80; }
        else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; min = 0x800; }
        else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; min = 0x10000; }
        bool ok = len != 0 && i + len <= s.size();
        for (std::size_t k = 1; ok && k < len; ++k) {
            const auto cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) ok = false;
            cp = (cp << 6) | (cc & 0x3F);
        }
        if (ok && (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))) ok = false;
        if (ok) {
            out.append(s.substr(i, len));
            i += len;
        } else {
            out += "\\ufffd";
            ++i;
        }
    }
    return out;
}

namespace {

class JsonWriter {
public:
    explicit JsonWriter(std::ostream& os) : os_(os) {}
    void begin_object() { open('{'); }
    void end_object() { close('}'); }
    void begin_array() { open('['); }
    void end_array() { close(']'); }
    void key(std::string_view k) {
        sep();
        os_ << '"' << json_escape(k) << "\": ";
        after_key_ = true;
    }
    void str(std::string_view v) { sep(); os_ << '"' << json_escape(v) << '"'; }
    void boolean(bool v) { sep(); os_ << (v ? "true" : "false"); }
    void num(std::uint64_t v) { sep(); os_ << v; }
    void num(long v) { sep(); os_ << v; }
    void num(int v) { sep(); os_ << v; }
    void num(double v) {
        sep();
        char b[32];
        std::snprintf(b, sizeof(b), "%.3f", v);
        os_ << b;
    }
    void kv(std::string_view k, std::string_view v) { key(k); str(v); }
    void kv(std::string_view k, const std::string& v) { key(k); str(v); }
    void kv(std::string_view k, const char* v) { key(k); str(v); }
    template <class T>
    void kv(std::string_view k, T v) { key(k); num(v); }

private:
    void sep() {
        if (after_key_) { after_key_ = false; return; }
        if (!first_.empty()) {
            if (!first_.back()) os_ << ',';
            first_.back() = false;
            os_ << '\n' << std::string(first_.size() * 2, ' ');
        }
    }
    void open(char c) { sep(); os_ << c; first_.push_back(true); }
    void close(char c) {
        const bool empty = first_.back();
        first_.pop_back();
        if (!empty) os_ << '\n' << std::string(first_.size() * 2, ' ');
        os_ << c;
        if (first_.empty()) os_ << '\n';
    }
    std::ostream& os_;
    std::vector<bool> first_;
    bool after_key_ = false;
};

void write_detection(JsonWriter& w, const Detection& d) {
    w.key("service");
    w.begin_object();
    w.kv("name", d.service);
    w.kv("product", d.product);
    w.kv("version", d.version);
    w.kv("version_quality", to_string(d.version_quality));
    w.kv("confidence", d.confidence);
    w.kv("method", d.method);
    w.kv("extra", d.extra);
    w.kv("os_hint", d.os_hint);
    w.kv("banner", d.banner);
    if (!d.error.empty()) w.kv("error", d.error);
    w.key("tls");
    if (!d.tls_info) {
        w.boolean(d.tls);
    } else {
        const TlsInfo& t = *d.tls_info;
        w.begin_object();
        w.kv("protocol", t.protocol);
        w.kv("cipher", t.cipher);
        w.key("certificate");
        if (!t.has_certificate) {
            w.boolean(false);
        } else {
            w.begin_object();
            w.kv("subject", t.subject);
            w.kv("issuer", t.issuer);
            w.kv("not_before", t.not_before);
            w.kv("not_after", t.not_after);
            w.kv("sha256", t.sha256);
            w.key("san");
            w.begin_array();
            for (const auto& s : t.san) w.str(s);
            w.end_array();
            w.key("self_signed"); w.boolean(t.self_signed);
            w.key("expired"); w.boolean(t.expired);
            w.end_object();
        }
        w.end_object();
    }
    w.end_object();
}

}  // namespace

void write_json(std::ostream& os, const ScanReport& r) {
    JsonWriter w(os);
    w.begin_object();
    w.kv("schema_version", 1);
    w.key("tool");
    w.begin_object();
    w.kv("name", "recon");
    w.kv("version", kVersion);
    w.end_object();
    w.key("scan");
    w.begin_object();
    w.kv("started_utc", r.started_utc);
    w.kv("status", r.summary.status);
    w.key("options");
    w.begin_object();
    w.kv("scan_type", r.options.syn_scan ? "syn" : "connect");
    w.kv("tcp_ports", static_cast<std::uint64_t>(r.options.tcp_ports));
    w.kv("udp_ports", static_cast<std::uint64_t>(r.options.udp_ports));
    w.key("service_detection"); w.boolean(r.options.service_detection);
    w.kv("intensity", r.options.intensity);
    w.kv("timeout_ms", r.options.timeout_ms);
    w.kv("retries", r.options.retries);
    w.kv("rate_per_sec", r.options.rate_per_sec);
    w.kv("max_inflight", static_cast<std::uint64_t>(r.options.max_inflight));
    w.kv("workers", static_cast<std::uint64_t>(r.options.workers));
    w.end_object();
    w.end_object();

    w.key("hosts");
    w.begin_array();
    for (const HostRecord& h : r.hosts) {
        w.begin_object();
        w.kv("address", h.address);
        w.kv("hostname", h.hostname);
        w.key("ports");
        w.begin_array();
        for (const PortRecord& p : h.ports) {
            w.begin_object();
            w.kv("port", static_cast<int>(p.port));
            w.kv("protocol", to_string(p.protocol));
            w.kv("state", to_string(p.state));
            w.kv("rtt_ms", p.rtt_ms);
            w.kv("attempts", p.attempts);
            if (p.detection) write_detection(w, *p.detection);
            w.end_object();
        }
        w.end_array();
        if (h.os) {
            w.key("os");
            w.begin_object();
            w.kv("family", h.os->family);
            w.kv("name", h.os->name);
            w.kv("confidence", h.os->confidence);
            w.kv("ttl", h.os->ttl);
            w.kv("estimated_hops", h.os->hops);
            w.key("evidence");
            w.begin_array();
            for (const auto& e : h.os->evidence) w.str(e);
            w.end_array();
            w.end_object();
        }
        w.end_object();
    }
    w.end_array();

    if (r.drift) {
        auto entries = [&](const char* name, const std::vector<DriftEntry>& v) {
            w.key(name);
            w.begin_array();
            for (const DriftEntry& e : v) {
                w.begin_object();
                w.kv("address", e.address);
                w.kv("port", static_cast<int>(e.port));
                w.kv("protocol", e.protocol);
                w.kv("service", e.service);
                w.end_object();
            }
            w.end_array();
        };
        w.key("drift");
        w.begin_object();
        w.kv("baseline", r.drift->baseline_path);
        entries("new_open", r.drift->new_open);
        entries("no_longer_open", r.drift->no_longer_open);
        w.end_object();
    }

    const ScanSummary& s = r.summary;
    w.key("summary");
    w.begin_object();
    w.kv("status", s.status);
    w.kv("hosts", static_cast<std::uint64_t>(s.hosts));
    w.kv("probes", s.probes);
    w.kv("socket_attempts", s.attempts);
    w.kv("retries", s.retries);
    w.kv("open", s.open);
    w.kv("closed", s.closed);
    w.kv("filtered", s.filtered);
    w.kv("open_filtered", s.open_filtered);
    w.kv("errors", s.errors);
    w.kv("duration_ms", s.duration_ms);
    w.key("resources");
    w.begin_object();
    w.kv("cpu_user_ms", s.cpu_user_ms);
    w.kv("cpu_sys_ms", s.cpu_sys_ms);
    w.kv("max_rss_kb", s.max_rss_kb);
    w.end_object();
    w.end_object();
    w.end_object();
}

// ------------------------------------------------------------------ CSV
std::string csv_field(std::string_view s) {
    std::string v(s);
    // Neutralise spreadsheet formula injection: banners are attacker-controlled input.
    if (!v.empty() && (v[0] == '=' || v[0] == '+' || v[0] == '-' || v[0] == '@' || v[0] == '\t' || v[0] == '\r'))
        v.insert(v.begin(), '\'');
    if (v.find_first_of(",\"\r\n") == std::string::npos) return v;
    std::string out = "\"";
    for (char c : v) {
        if (c == '"') out += '"';
        out += c;
    }
    return out + "\"";
}

void write_csv(std::ostream& os, const ScanReport& r) {
    os << "host,hostname,port,protocol,state,service,product,version,version_quality,"
          "confidence,method,os_hint,tls,banner\r\n";
    for (const HostRecord& h : r.hosts) {
        for (const PortRecord& p : h.ports) {
            const Detection d = p.detection.value_or(Detection{});
            os << csv_field(h.address) << ',' << csv_field(h.hostname) << ',' << p.port << ','
               << to_string(p.protocol) << ',' << to_string(p.state) << ',' << csv_field(d.service)
               << ',' << csv_field(d.product) << ',' << csv_field(d.version) << ','
               << to_string(d.version_quality) << ',' << d.confidence << ',' << csv_field(d.method)
               << ',' << csv_field(d.os_hint) << ',' << (d.tls ? "true" : "false") << ','
               << csv_field(d.banner) << "\r\n";
        }
    }
}

// ------------------------------------------------------------------ Table
namespace {

// ANSI helpers. Padding is applied to the plain text first so escape codes never skew columns.
std::string paint(const TableStyle& st, const char* code, const std::string& text) {
    return st.color ? std::string("\x1b[") + code + "m" + text + "\x1b[0m" : text;
}
std::string pad(const std::string& s, std::size_t w) { return s.size() >= w ? s : s + std::string(w - s.size(), ' '); }

}  // namespace

void write_table(std::ostream& os, const ScanReport& r, const TableStyle& style) {
    const std::string rule(96, '=');
    for (const HostRecord& h : r.hosts) {
        os << '\n' << rule << '\n' << "TARGET: " << h.address;
        if (!h.hostname.empty()) os << " (" << h.hostname << ')';
        os << '\n' << rule << '\n';
        if (h.ports.empty()) {
            os << "No open ports found.\n";
        } else {
            os << paint(style, "1", pad("PORT", 11) + pad("STATE", 15) + pad("SERVICE", 16) + pad("CONF", 6) +
                                        "VERSION / DETAILS")
               << '\n' << std::string(96, '-') << '\n';
            for (const PortRecord& p : h.ports) {
                const Detection d = p.detection.value_or(Detection{});
                std::string svc = d.service;
                if (p.protocol == Protocol::Tcp && p.detection && d.confidence < 50 && svc != "unknown") svc += '?';
                std::string detail;
                if (!d.product.empty()) detail = d.product;
                if (!d.version.empty()) detail += (detail.empty() ? "" : " ") + d.version;
                if (d.version_quality == VersionQuality::None && !d.version.empty()) detail += " [unverified]";
                if (!d.extra.empty()) {
                    const bool wrapped = d.extra.front() == '(' && d.extra.back() == ')';
                    detail += detail.empty() ? d.extra : (wrapped ? " " + d.extra : " (" + d.extra + ")");
                }
                if (detail.empty()) detail = d.banner.empty() ? "[no banner]" : d.banner;
                const bool weak = p.detection && d.confidence < 50;
                const char* state_color = p.state == PortState::Open ? "32" : "33";
                os << pad(std::to_string(p.port) + "/" + to_string(p.protocol), 11)
                   << paint(style, state_color, pad(to_string(p.state), 15))
                   << paint(style, weak ? "33" : "36", pad(svc, 16))
                   << pad(p.detection ? std::to_string(d.confidence) : "-", 6) << detail << '\n';
            }
        }
        if (h.os) {
            os << "\nOS guess: " << h.os->name << "  (confidence " << h.os->confidence << "%)\n";
            for (const auto& e : h.os->evidence) os << "  - " << e << '\n';
        }
    }
    if (r.drift) {
        os << '\n' << paint(style, "1", "DRIFT vs baseline " + r.drift->baseline_path) << '\n';
        if (r.drift->new_open.empty() && r.drift->no_longer_open.empty()) os << "  no changes\n";
        for (const DriftEntry& e : r.drift->new_open)
            os << paint(style, "31", "  + NEW OPEN   ") << e.address << ' ' << e.port << '/' << e.protocol
               << (e.service.empty() ? "" : " (" + e.service + ")") << '\n';
        for (const DriftEntry& e : r.drift->no_longer_open)
            os << paint(style, "32", "  - NO LONGER  ") << e.address << ' ' << e.port << '/' << e.protocol
               << (e.service.empty() ? "" : " (" + e.service + ")") << '\n';
    }
    const ScanSummary& s = r.summary;
    os << '\n' << rule << '\n'
       << "Scan " << s.status << " in " << std::fixed << std::setprecision(2) << s.duration_ms / 1000.0
       << "s | hosts " << s.hosts << " | probes " << s.probes << " | open " << s.open << " | closed "
       << s.closed << " | filtered " << s.filtered;
    if (s.open_filtered) os << " | open|filtered " << s.open_filtered;
    if (s.errors) os << " | errors " << s.errors;
    os << " | retries " << s.retries << '\n'
       << "CPU " << (s.cpu_user_ms + s.cpu_sys_ms) / 1000.0 << "s, peak RSS " << s.max_rss_kb / 1024.0 << " MiB\n"
       << "Version column shows what the service reports; confidence < 50 marks port-number guesses (?).\n";
}

}  // namespace recon
