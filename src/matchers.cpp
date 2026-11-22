// Protocol matchers. Every function here is pure (no I/O) and treats its input as hostile:
// all offsets go through detail::Reader or string_view bounds checks.
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <map>

#include "bytes.hpp"
#include "recon/detect.hpp"

namespace recon {
using namespace detail;

const char* to_string(VersionQuality q) {
    switch (q) {
        case VersionQuality::None: return "none";
        case VersionQuality::Inferred: return "inferred";
        case VersionQuality::Reported: return "reported";
    }
    return "none";
}

std::string sanitize_ascii(std::string_view s, std::size_t max_len) {
    std::string out;
    out.reserve(std::min(s.size(), max_len));
    for (char ch : s) {
        if (out.size() >= max_len) break;
        const auto c = static_cast<unsigned char>(ch);
        if (c == '\r' || c == '\n' || c == '\t') {
            if (!out.empty() && out.back() != ' ') out.push_back(' ');
        } else if (c >= 0x20 && c < 0x7F) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('.');
        }
    }
    return std::string(trim(out));
}

namespace {

bool is_alnum(char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0; }
bool is_alpha(char c) { return std::isalpha(static_cast<unsigned char>(c)) != 0; }

// Matches `word` only when it is not embedded in a longer run of letters. Digits may touch it
// because package versions look like "0ubuntu0.22.04" and "3ubuntu13.5", while letters may not
// ("search" must never match "arch").
bool contains_word(std::string_view low, std::string_view word) {
    for (std::size_t p = low.find(word); p != std::string_view::npos; p = low.find(word, p + 1)) {
        const bool left = p == 0 || !is_alpha(low[p - 1]);
        const std::size_t e = p + word.size();
        const bool right = e >= low.size() || !is_alpha(low[e]);
        if (left && right) return true;
    }
    return false;
}

// Distribution/OS tag found in free-text banners. Conservative: whole-word matches only.
std::string os_hint_from_text(std::string_view text) {
    const std::string low = to_lower(text);
    static const struct { const char* word; const char* os; } kTable[] = {
        {"ubuntu", "Ubuntu Linux"},   {"debian", "Debian Linux"}, {"raspbian", "Raspbian Linux"},
        {"centos", "CentOS Linux"},   {"fedora", "Fedora Linux"}, {"rhel", "Red Hat Linux"},
        {"alpine", "Alpine Linux"},   {"freebsd", "FreeBSD"},     {"openbsd", "OpenBSD"},
        {"netbsd", "NetBSD"},         {"win64", "Windows"},       {"win32", "Windows"},
        {"windows", "Windows"},       {"microsoft-iis", "Windows"},
    };
    for (const auto& e : kTable) {
        if (contains_word(low, e.word)) return e.os;
    }
    if (low.find("red hat") != std::string::npos) return "Red Hat Linux";
    return "";
}

// NOTE: never use strchr() for membership tests on untrusted bytes: strchr(set, '\0') returns a
// pointer to the terminator, so a NUL byte would count as "in the set". (Found by fuzzing.)
bool is_version_punct(char c) { return c == '.' || c == '+' || c == '~' || c == '_' || c == '-'; }

// Version token: starts with a digit; stops at the first char outside [A-Za-z0-9.+~_-].
std::string version_token(std::string_view s) {
    std::size_t i = 0;
    while (i < s.size() && (is_alnum(s[i]) || is_version_punct(s[i]))) ++i;
    std::string_view t = s.substr(0, i);
    while (!t.empty() && is_version_punct(t.back())) t.remove_suffix(1);
    if (t.empty() || !is_digit(t.front())) return "";
    return std::string(t);
}

struct ProductSig {
    const char* keyword;  // lowercase
    const char* product;
};

bool apply_product(std::string_view text, const ProductSig* sigs, std::size_t n, Detection& d) {
    const std::string low = to_lower(text);
    for (std::size_t i = 0; i < n; ++i) {
        const std::size_t pos = low.find(sigs[i].keyword);
        if (pos == std::string::npos) continue;
        d.product = sigs[i].product;
        std::size_t after = pos + std::strlen(sigs[i].keyword);
        while (after < text.size() && (text[after] == ' ' || text[after] == '/' || text[after] == '_')) ++after;
        const std::string v = version_token(text.substr(std::min(after, text.size())));
        if (!v.empty()) {
            d.version = v;
            d.version_quality = VersionQuality::Reported;
        }
        return true;
    }
    return false;
}

Detection make(const char* service, int conf, std::string_view banner_src) {
    Detection d;
    d.service = service;
    d.confidence = conf;
    d.banner = sanitize_ascii(banner_src, 200);
    return d;
}

bool is_reply_code_220(std::string_view data) {
    return data.size() >= 4 && data.substr(0, 3) == "220" && (data[3] == ' ' || data[3] == '-');
}

bool contains_any(std::string_view low, std::initializer_list<const char*> words) {
    for (const char* w : words) {
        if (low.find(w) != std::string_view::npos) return true;
    }
    return false;
}

}  // namespace

// ---------------------------------------------------------------- SSH
std::optional<Detection> match_ssh(std::string_view data, std::uint16_t) {
    if (data.substr(0, 4) != "SSH-") return std::nullopt;
    const std::string_view line = first_line(data);
    if (line.size() > 255) return std::nullopt;  // RFC 4253 section 4.2
    const std::string_view rest = line.substr(4);
    const std::size_t dash = rest.find('-');
    if (dash == std::string_view::npos) return std::nullopt;
    const std::string_view proto = rest.substr(0, dash);
    // protoversion: digits '.' digits (2.0, 1.99, 1.5)
    const std::size_t dot = proto.find('.');
    if (dot == std::string_view::npos || dot == 0 || dot + 1 >= proto.size()) return std::nullopt;
    for (std::size_t i = 0; i < proto.size(); ++i) {
        if (i != dot && !is_digit(proto[i])) return std::nullopt;
    }
    const std::string_view tail = rest.substr(dash + 1);
    const std::size_t sp = tail.find(' ');
    const std::string_view software = tail.substr(0, sp);
    const std::string comment_clean =
        sp == std::string_view::npos ? std::string() : sanitize_ascii(tail.substr(sp + 1), 120);
    const std::string_view comment = comment_clean;
    if (software.empty()) return std::nullopt;
    for (char c : software) {
        if (static_cast<unsigned char>(c) < 0x21 || static_cast<unsigned char>(c) > 0x7E)
            return std::nullopt;
    }

    Detection d = make("ssh", 98, line);
    const std::size_t us = software.find('_');
    if (us != std::string_view::npos) {
        d.product = std::string(software.substr(0, us));
        d.version = std::string(software.substr(us + 1));
    } else {
        const std::size_t ld = software.rfind('-');
        if (ld != std::string_view::npos && ld + 1 < software.size() && is_digit(software[ld + 1])) {
            d.product = std::string(software.substr(0, ld));
            d.version = std::string(software.substr(ld + 1));
        } else {
            d.product = std::string(software);
        }
    }
    if (!d.version.empty() && is_digit(d.version.front())) {
        d.version_quality = VersionQuality::Reported;
    } else if (!d.version.empty()) {  // e.g. "OpenSSH_for_Windows_8.1": keep as product text
        d.product += "_" + d.version;
        d.version.clear();
    }
    d.extra = "protocol " + std::string(proto) + (comment.empty() ? "" : "; " + std::string(comment));
    d.os_hint = os_hint_from_text(std::string(software) + " " + std::string(comment));
    return d;
}

// ---------------------------------------------------------------- FTP / SMTP / POP3 / IMAP
std::optional<Detection> match_ftp(std::string_view data, std::uint16_t port) {
    if (!is_reply_code_220(data)) return std::nullopt;
    const std::string_view line = first_line(data);
    static const ProductSig kSigs[] = {{"vsftpd", "vsftpd"},
                                       {"proftpd", "ProFTPD"},
                                       {"pure-ftpd", "Pure-FTPd"},
                                       {"filezilla server", "FileZilla Server"},
                                       {"microsoft ftp service", "Microsoft FTP Service"},
                                       {"bftpd", "bftpd"}};
    Detection d = make("ftp", 92, line);
    if (!apply_product(line, kSigs, sizeof(kSigs) / sizeof(kSigs[0]), d)) {
        if (to_lower(line).find("ftp") != std::string::npos) {
            d.confidence = 85;
        } else if (port == 21) {
            d.confidence = 55;
            d.version_quality = VersionQuality::None;
        } else {
            return std::nullopt;
        }
    }
    d.os_hint = os_hint_from_text(line);
    return d;
}

std::optional<Detection> match_smtp(std::string_view data, std::uint16_t port) {
    if (!is_reply_code_220(data)) return std::nullopt;
    const std::string_view line = first_line(data);
    static const ProductSig kSigs[] = {{"postfix", "Postfix"},
                                       {"exim", "Exim"},
                                       {"sendmail", "Sendmail"},
                                       {"opensmtpd", "OpenSMTPD"},
                                       {"microsoft esmtp mail service", "Microsoft ESMTP"},
                                       {"haraka", "Haraka"}};
    const std::string low = to_lower(line);
    Detection d = make("smtp", 92, line);
    const bool named = contains_any(low, {"smtp"});
    const bool product = apply_product(line, kSigs, sizeof(kSigs) / sizeof(kSigs[0]), d);
    if (!named && !product) {
        if (port == 25 || port == 465 || port == 587 || port == 2525) {
            d.confidence = 55;
        } else {
            return std::nullopt;
        }
    }
    d.os_hint = os_hint_from_text(line);
    return d;
}

std::optional<Detection> match_pop3(std::string_view data, std::uint16_t port) {
    if (data.substr(0, 3) != "+OK" || (data.size() > 3 && data[3] != ' ' && data[3] != '\r' && data[3] != '\n'))
        return std::nullopt;
    static const ProductSig kSigs[] = {{"dovecot", "Dovecot"}, {"courier", "Courier"}, {"cyrus", "Cyrus"}};
    Detection d = make("pop3", (port == 110 || port == 995) ? 90 : 70, first_line(data));
    apply_product(first_line(data), kSigs, 3, d);
    d.os_hint = os_hint_from_text(first_line(data));
    return d;
}

std::optional<Detection> match_imap(std::string_view data, std::uint16_t port) {
    if (data.substr(0, 4) != "* OK" || (data.size() > 4 && data[4] != ' ' && data[4] != '\r' && data[4] != '\n'))
        return std::nullopt;
    static const ProductSig kSigs[] = {{"dovecot", "Dovecot"}, {"cyrus", "Cyrus"}, {"courier", "Courier"}};
    Detection d = make("imap", (port == 143 || port == 993) ? 90 : 70, first_line(data));
    apply_product(first_line(data), kSigs, 3, d);
    d.os_hint = os_hint_from_text(first_line(data));
    return d;
}

// ---------------------------------------------------------------- MySQL / MariaDB
std::optional<Detection> match_mysql(std::string_view data, std::uint16_t) {
    Reader r(data);
    std::uint8_t l0 = 0, l1 = 0, l2 = 0, seq = 0, proto = 0;
    // MySQL packet length is a 3-byte LITTLE-endian integer (Reader::u24 is big-endian).
    if (!r.u8(l0) || !r.u8(l1) || !r.u8(l2) || !r.u8(seq) || !r.u8(proto)) return std::nullopt;
    const std::uint32_t len = l0 | (static_cast<std::uint32_t>(l1) << 8) | (static_cast<std::uint32_t>(l2) << 16);
    if (seq != 0 || len < 2 || len > 1024) return std::nullopt;
    if (proto == 0xFF) {  // error packet before handshake, e.g. "Host is not allowed to connect"
        std::uint16_t code = 0;  // little-endian error code; value unused
        if (!r.u16(code)) return std::nullopt;
        return make("mysql", 60, "MySQL error packet");
    }
    if (proto != 10) return std::nullopt;
    const std::size_t avail = std::min<std::size_t>(len - 1, r.remaining());
    std::string_view rest;
    if (!r.take(avail, rest)) return std::nullopt;
    const std::size_t nul = rest.find('\0');
    if (nul == std::string_view::npos || nul == 0 || nul > 64) return std::nullopt;
    const std::string_view ver = rest.substr(0, nul);
    for (char c : ver) {
        if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) > 0x7E) return std::nullopt;
    }
    if (!is_digit(ver.front())) return std::nullopt;
    Detection d = make("mysql", 95, ver);
    const std::string low = to_lower(ver);
    std::string_view v = ver;
    if (low.find("mariadb") != std::string::npos) {
        d.product = "MariaDB";
        if (v.substr(0, 6) == "5.5.5-") v.remove_prefix(6);  // replication-compat prefix
    } else {
        d.product = "MySQL";
    }
    d.version = version_token(v);
    if (!d.version.empty()) d.version_quality = VersionQuality::Reported;
    d.os_hint = os_hint_from_text(ver);
    return d;
}

// ---------------------------------------------------------------- VNC / Telnet
std::optional<Detection> match_vnc(std::string_view data, std::uint16_t) {
    // "RFB xxx.yyy\n" exactly 12 bytes
    if (data.size() < 12 || data.substr(0, 4) != "RFB " || data[11] != '\n' || data[7] != '.')
        return std::nullopt;
    for (std::size_t i : {4U, 5U, 6U, 8U, 9U, 10U}) {
        if (!is_digit(data[i])) return std::nullopt;
    }
    Detection d = make("vnc", 97, data.substr(0, 11));
    d.extra = "RFB protocol " + std::string(data.substr(4, 7));
    return d;
}

std::optional<Detection> match_telnet(std::string_view data, std::uint16_t) {
    // Require well-formed IAC <WILL|WONT|DO|DONT> <option> triples at the start.
    std::size_t i = 0, triples = 0;
    while (i + 2 < data.size() + 0 && static_cast<unsigned char>(data[i]) == 0xFF && triples < 8) {
        const auto cmd = static_cast<unsigned char>(data[i + 1]);
        if (cmd < 0xFB || cmd > 0xFE) break;
        i += 3;
        ++triples;
    }
    if (triples == 0) return std::nullopt;
    Detection d = make("telnet", 85, "");
    d.banner = "telnet option negotiation";
    return d;
}

// ---------------------------------------------------------------- HTTP
std::optional<Detection> match_http(std::string_view data, std::uint16_t) {
    const std::string_view status = first_line(data);
    if (status.size() < 12 || status.substr(0, 5) != "HTTP/") return std::nullopt;
    const std::string_view ver = status.substr(5, status.find(' ') == std::string_view::npos ? 0 : status.find(' ') - 5);
    if (ver != "1.0" && ver != "1.1" && ver != "2" && ver != "2.0") return std::nullopt;
    const std::size_t sp = status.find(' ');
    if (sp == std::string_view::npos || status.size() < sp + 4) return std::nullopt;
    for (std::size_t i = 1; i <= 3; ++i) {
        if (!is_digit(status[sp + i])) return std::nullopt;
    }

    std::string server, powered;
    std::size_t pos = data.find('\n');
    std::size_t body_at = std::string_view::npos;
    while (pos != std::string_view::npos && pos + 1 <= data.size()) {
        const std::size_t start = pos + 1;
        std::size_t end = data.find('\n', start);
        std::string_view line = data.substr(start, end == std::string_view::npos ? std::string_view::npos : end - start);
        line = trim(line);
        if (line.empty()) {
            body_at = end == std::string_view::npos ? data.size() : end + 1;
            break;
        }
        const std::size_t colon = line.find(':');
        if (colon != std::string_view::npos) {
            const std::string name = to_lower(line.substr(0, colon));
            const std::string_view value = trim(line.substr(colon + 1));
            if (name == "server" && server.empty()) server = sanitize_ascii(value, 200);
            if (name == "x-powered-by" && powered.empty()) powered = sanitize_ascii(value, 100);
        }
        pos = end;
    }
    const std::string_view body = body_at == std::string_view::npos ? "" : data.substr(body_at);

    Detection d = make("http", 95, status);
    if (!server.empty()) {
        const std::size_t sp2 = server.find(' ');
        const std::string token = server.substr(0, sp2);
        const std::size_t slash = token.find('/');
        d.product = token.substr(0, slash);
        if (slash != std::string::npos) {
            d.version = version_token(std::string_view(token).substr(slash + 1));
            if (!d.version.empty()) d.version_quality = VersionQuality::Reported;
        }
        if (sp2 != std::string::npos) d.extra = server.substr(sp2 + 1);
        d.os_hint = os_hint_from_text(server);
    }
    if (!powered.empty()) d.extra += (d.extra.empty() ? "" : "; ") + std::string("X-Powered-By: ") + powered;

    const std::string low_body = to_lower(body.substr(0, 4096));
    const std::size_t t0 = low_body.find("<title>");
    if (t0 != std::string::npos) {
        const std::size_t t1 = low_body.find("</title>", t0 + 7);
        if (t1 != std::string::npos && t1 - (t0 + 7) <= 200) {
            const std::string title = sanitize_ascii(body.substr(t0 + 7, t1 - (t0 + 7)), 60);
            if (!title.empty()) d.extra += (d.extra.empty() ? "" : "; ") + std::string("title: ") + title;
        }
    }
    if (low_body.find("client sent an http request to an https server") != std::string::npos ||
        low_body.find("plain http request was sent to https port") != std::string::npos) {
        d.service = "https";
        d.tls = true;
        d.confidence = 85;
        d.extra += (d.extra.empty() ? "" : "; ") + std::string("plain HTTP rejected, TLS expected");
    }
    return d;
}

// ---------------------------------------------------------------- TLS
namespace {

const char* tls_version_name(std::uint16_t v) {
    switch (v) {
        case 0x0300: return "SSLv3";
        case 0x0301: return "TLSv1.0";
        case 0x0302: return "TLSv1.1";
        case 0x0303: return "TLSv1.2";
        case 0x0304: return "TLSv1.3";
        default: return "TLS";
    }
}

std::string cipher_name(std::uint16_t c) {
    switch (c) {
        case 0x1301: return "TLS_AES_128_GCM_SHA256";
        case 0x1302: return "TLS_AES_256_GCM_SHA384";
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
        case 0xc02b: return "ECDHE-ECDSA-AES128-GCM-SHA256";
        case 0xc02c: return "ECDHE-ECDSA-AES256-GCM-SHA384";
        case 0xc02f: return "ECDHE-RSA-AES128-GCM-SHA256";
        case 0xc030: return "ECDHE-RSA-AES256-GCM-SHA384";
        case 0xcca8: return "ECDHE-RSA-CHACHA20-POLY1305";
        case 0xcca9: return "ECDHE-ECDSA-CHACHA20-POLY1305";
        default: {
            char b[8];
            std::snprintf(b, sizeof(b), "0x%04x", c);
            return b;
        }
    }
}

}  // namespace

std::optional<Detection> match_tls(std::string_view data, std::uint16_t port) {
    Reader r(data);
    std::uint8_t type = 0;
    std::uint16_t rec_ver = 0, rec_len = 0;
    if (!r.u8(type) || !r.u16(rec_ver) || !r.u16(rec_len)) return std::nullopt;
    if ((rec_ver >> 8) != 0x03 || (rec_ver & 0xFF) > 0x04) return std::nullopt;
    const bool https_port = port == 443 || port == 8443 || port == 4443 || port == 9443;

    auto finish = [&](const std::string& proto, const std::string& cipher, int conf) {
        Detection d = make(https_port ? "https" : "ssl/tls", https_port ? std::min(conf, 85) : conf, "");
        d.banner = "TLS " + proto + (cipher.empty() ? "" : " " + cipher);
        d.tls = true;
        TlsInfo t;
        t.protocol = proto;
        t.cipher = cipher;
        d.tls_info = t;
        if (https_port) d.extra = "application protocol inferred from port";
        return d;
    };

    if (type == 0x15) {  // alert record: 2-byte payload
        if (rec_len != 2) return std::nullopt;
        return finish(tls_version_name(rec_ver), "", 80);
    }
    if (type != 0x16) return std::nullopt;

    std::uint8_t hs_type = 0;
    std::uint32_t hs_len = 0;
    if (!r.u8(hs_type) || hs_type != 0x02) return std::nullopt;  // must be ServerHello
    if (!r.u24(hs_len)) return finish(tls_version_name(rec_ver), "", 80);

    std::uint16_t legacy = 0, cipher = 0, selected = 0;
    std::uint8_t sid_len = 0, comp = 0;
    if (!r.u16(legacy) || !r.skip(32) || !r.u8(sid_len) || !r.skip(sid_len) || !r.u16(cipher) ||
        !r.u8(comp)) {
        return finish(tls_version_name(rec_ver), "", 80);  // truncated but clearly TLS
    }
    std::uint16_t ext_total = 0;
    if (r.u16(ext_total)) {
        std::string_view exts;
        if (!r.take(std::min<std::size_t>(ext_total, r.remaining()), exts)) exts = {};
        Reader er(exts);
        std::uint16_t et = 0, el = 0;
        while (er.u16(et) && er.u16(el)) {
            std::string_view ed;
            if (!er.take(el, ed)) break;
            if (et == 0x002b && ed.size() == 2) {
                Reader vr(ed);
                vr.u16(selected);
            }
        }
    }
    return finish(tls_version_name(selected != 0 ? selected : legacy), cipher_name(cipher), 95);
}

// ---------------------------------------------------------------- Redis
std::optional<Detection> match_redis(std::string_view data, std::uint16_t port) {
    const bool info_reply = data.size() > 3 && data[0] == '$' && data.find("# Server") != std::string_view::npos &&
                            data.find("\r\n") != std::string_view::npos && is_digit(data[1]);
    const bool noauth = data.substr(0, 8) == "-NOAUTH ";
    const bool denied = data.substr(0, 7) == "-DENIED" && to_lower(data).find("redis") != std::string::npos;
    const bool generic_err = data.substr(0, 5) == "-ERR " && port == 6379;
    if (!info_reply && !noauth && !denied && !generic_err) return std::nullopt;

    Detection d = make("redis", generic_err ? 55 : 92, first_line(data));
    d.product = "Redis";
    if (info_reply) {
        std::string redis_ver, valkey_ver;
        std::size_t pos = 0;
        while (pos < data.size()) {
            const std::size_t e = data.find('\n', pos);
            const std::string_view line = trim(data.substr(pos, e == std::string_view::npos ? std::string_view::npos : e - pos));
            if (line.substr(0, 14) == "redis_version:") {
                redis_ver = version_token(line.substr(14));
            } else if (line.substr(0, 15) == "valkey_version:") {
                valkey_ver = version_token(line.substr(15));
            } else if (line.substr(0, 3) == "os:") {
                d.extra = "os: " + sanitize_ascii(line.substr(3), 80);
                d.os_hint = os_hint_from_text(line.substr(3));
                if (d.os_hint.empty() && to_lower(line).find("linux") != std::string::npos) d.os_hint = "Linux";
            }
            if (e == std::string_view::npos) break;
            pos = e + 1;
        }
        if (!valkey_ver.empty()) {  // Valkey keeps redis_version at 7.2.4 for compatibility
            d.product = "Valkey";
            d.version = valkey_ver;
        } else {
            d.version = redis_ver;
        }
        if (!d.version.empty()) d.version_quality = VersionQuality::Reported;
        d.banner = "Redis INFO server";
    } else if (noauth) {
        d.extra = "authentication required; version hidden";
    }
    return d;
}

// ---------------------------------------------------------------- PostgreSQL
std::optional<Detection> match_postgres(std::string_view data, std::uint16_t port) {
    if (data.size() == 1 && (data[0] == 'S' || data[0] == 'N')) {
        Detection d = make("postgresql", port == 5432 ? 90 : 75, "");
        d.banner = std::string("SSLRequest reply: ") + data[0];
        d.extra = data[0] == 'S' ? "TLS supported" : "TLS not offered";
        return d;
    }
    if (data.size() > 5 && data[0] == 'E') {  // ErrorResponse with sane length
        Reader r(data.substr(1));
        std::uint32_t len = 0;  // big-endian length, includes itself
        if (r.u32(len) && len == data.size() - 1 && data.find("SFATAL") != std::string_view::npos) {
            return make("postgresql", 80, "PostgreSQL ErrorResponse");
        }
    }
    return std::nullopt;
}

// ---------------------------------------------------------------- SMB
std::optional<Detection> match_smb2(std::string_view data, std::uint16_t) {
    Reader r(data);
    std::uint8_t zero = 0;
    std::uint32_t len = 0;
    if (!r.u8(zero) || zero != 0 || !r.u24(len)) return std::nullopt;
    std::string_view magic;
    if (!r.take(4, magic)) return std::nullopt;
    if (magic == std::string_view("\xFF" "SMB", 4)) {
        Detection d = make("smb", 90, "SMB1 response");
        d.extra = "dialect SMB1";
        return d;
    }
    if (magic != std::string_view("\xFE" "SMB", 4)) return std::nullopt;
    // SMB2 fields are little-endian; Reader is big-endian, so compare byte-swapped constants.
    auto swap16 = [](std::uint16_t v) { return static_cast<std::uint16_t>((v >> 8) | (v << 8)); };
    std::uint16_t hdr_size = 0;
    if (!r.u16(hdr_size) || swap16(hdr_size) != 64 || !r.skip(64 - 6)) return std::nullopt;
    std::uint16_t body_size = 0, sec = 0, dialect_le = 0;
    if (!r.u16(body_size) || swap16(body_size) != 65 || !r.u16(sec) || !r.u16(dialect_le))
        return std::nullopt;
    const std::uint16_t dialect = swap16(dialect_le);
    const char* name = "unknown";
    switch (dialect) {
        case 0x0202: name = "2.0.2"; break;
        case 0x0210: name = "2.1"; break;
        case 0x0300: name = "3.0"; break;
        case 0x0302: name = "3.0.2"; break;
        case 0x0311: name = "3.1.1"; break;
        case 0x02FF: name = "2.x (wildcard)"; break;
        default: break;
    }
    Detection d = make("smb", 95, "SMB2 NEGOTIATE response");
    d.extra = std::string("dialect SMB ") + name;
    return d;
}

// ---------------------------------------------------------------- UDP
namespace {

bool skip_dns_name(Reader& r) {
    for (int guard = 0; guard < 128; ++guard) {
        std::uint8_t l = 0;
        if (!r.u8(l)) return false;
        if (l == 0) return true;
        if ((l & 0xC0) == 0xC0) return r.skip(1);
        if (l > 63 || !r.skip(l)) return false;
    }
    return false;
}

}  // namespace

std::optional<Detection> match_udp_response(std::uint16_t port, std::string_view data) {
    if (port == 53) {
        Reader r(data);
        std::uint16_t id = 0, flags = 0, qd = 0, an = 0;
        if (!r.u16(id) || id != 0x1234 || !r.u16(flags) || (flags & 0x8000) == 0) return std::nullopt;
        if (!r.u16(qd) || !r.u16(an) || !r.skip(4)) return std::nullopt;
        Detection d = make("dns", 95, "DNS response");
        d.extra = "rcode " + std::to_string(flags & 0xF);
        for (std::uint16_t i = 0; i < qd && i < 4; ++i) {
            if (!skip_dns_name(r) || !r.skip(4)) return d;
        }
        std::uint16_t type = 0, cls = 0, rdlen = 0;
        if (an > 0 && skip_dns_name(r) && r.u16(type) && r.u16(cls) && r.skip(4) && r.u16(rdlen) &&
            type == 16 && rdlen >= 2) {
            std::uint8_t tl = 0;
            std::string_view txt;
            if (r.u8(tl) && tl <= rdlen - 1 && r.take(tl, txt) && !txt.empty()) {
                d.version = sanitize_ascii(txt, 80);
                d.version_quality = VersionQuality::Reported;
                d.extra = "version.bind";
            }
        }
        return d;
    }
    if (port == 123) {
        if (data.size() < 48) return std::nullopt;
        const auto b0 = static_cast<std::uint8_t>(data[0]);
        const unsigned mode = b0 & 7U, ver = (b0 >> 3) & 7U;
        if (mode != 4 || ver < 1 || ver > 4) return std::nullopt;
        Detection d = make("ntp", 95, "NTP server reply");
        d.extra = "NTPv" + std::to_string(ver) + ", stratum " + std::to_string(static_cast<std::uint8_t>(data[1]));
        return d;
    }
    if (port == 137) {
        if (data.size() < 12 || static_cast<std::uint8_t>(data[0]) != 0x80 ||
            (static_cast<std::uint8_t>(data[2]) & 0x80) == 0)
            return std::nullopt;
        return make("netbios-ns", 90, "NetBIOS name service reply");
    }
    Detection d = make(port_guess_service(port, false), 40, "UDP reply");
    d.method = "port-guess";
    return d;
}

const char* port_guess_service(std::uint16_t port, bool tcp) {
    static const std::map<std::uint16_t, const char*> kTcp = {
        {21, "ftp"},     {22, "ssh"},      {23, "telnet"},   {25, "smtp"},       {53, "domain"},
        {80, "http"},    {110, "pop3"},    {111, "rpcbind"}, {135, "msrpc"},     {139, "netbios-ssn"},
        {143, "imap"},   {389, "ldap"},    {443, "https"},   {445, "microsoft-ds"}, {465, "smtps"},
        {587, "submission"}, {993, "imaps"}, {995, "pop3s"}, {1433, "ms-sql-s"}, {1521, "oracle"},
        {2049, "nfs"},   {3306, "mysql"},  {3389, "ms-wbt-server"}, {5432, "postgresql"},
        {5900, "vnc"},   {6379, "redis"},  {8080, "http-proxy"}, {8443, "https-alt"},
        {9200, "elasticsearch"}, {11211, "memcache"}, {27017, "mongodb"}};
    static const std::map<std::uint16_t, const char*> kUdp = {
        {53, "domain"}, {67, "dhcps"}, {68, "dhcpc"}, {69, "tftp"}, {123, "ntp"},
        {137, "netbios-ns"}, {138, "netbios-dgm"}, {161, "snmp"}, {162, "snmptrap"},
        {500, "isakmp"}, {514, "syslog"}, {520, "route"}, {554, "rtsp"}};
    const auto& m = tcp ? kTcp : kUdp;
    const auto it = m.find(port);
    return it == m.end() ? "unknown" : it->second;
}

}  // namespace recon
