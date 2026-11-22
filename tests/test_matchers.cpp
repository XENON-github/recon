#include <random>

#include "recon/detect.hpp"
#include "recon/report.hpp"
#include "testing.hpp"

using namespace recon;
using std::string;

// Binary-safe literal: length is deduced from the array, so it can never over-read.
template <std::size_t N>
static string S(const char (&s)[N]) { return string(s, N - 1); }

TEST(ssh_openssh_with_comment) {
    auto d = match_ssh("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n", 22);
    CHECK(d.has_value());
    CHECK_EQ(d->service, string("ssh"));
    CHECK_EQ(d->product, string("OpenSSH"));
    CHECK_EQ(d->version, string("9.6p1"));
    CHECK(d->version_quality == VersionQuality::Reported);
    CHECK_EQ(d->os_hint, string("Ubuntu Linux"));
    CHECK(d->confidence >= 90);
}

TEST(ssh_variants_and_rejects) {
    auto db = match_ssh("SSH-2.0-dropbear_2022.83\r\n", 22);
    CHECK(db && db->product == "dropbear" && db->version == "2022.83");
    auto lib = match_ssh("SSH-2.0-libssh-0.9.6\r\n", 22);
    CHECK(lib && lib->product == "libssh" && lib->version == "0.9.6");
    auto win = match_ssh("SSH-2.0-OpenSSH_for_Windows_8.1\r\n", 22);
    CHECK(win && win->os_hint == "Windows" && win->version.empty());
    CHECK(!match_ssh("SSH-banana\r\n", 22));
    CHECK(!match_ssh("SSH-x.y-Foo\r\n", 22));
    CHECK(!match_ssh("XSSH-2.0-Foo\r\n", 22));
    CHECK(!match_ssh("SSH-2.0-\r\n", 22));
    CHECK(!match_ssh(string("SSH-2.0-") + string(300, 'A'), 22));   // > 255 bytes
    CHECK(!match_ssh(S("SSH-2.0-Foo\x01\x02"), 22));            // control chars in software
}

TEST(ftp_and_smtp_are_not_confused) {
    auto f = match_ftp("220 (vsFTPd 3.0.5)\r\n", 21);
    CHECK(f && f->product == "vsftpd" && f->version == "3.0.5");
    auto p = match_ftp("220 ProFTPD 1.3.8 Server (Debian) [10.0.0.1]\r\n", 21);
    CHECK(p && p->product == "ProFTPD" && p->version == "1.3.8" && p->os_hint == "Debian Linux");
    CHECK(!match_ftp("220 mail.example.com ESMTP Postfix\r\n", 25));    // SMTP greeting on a non-FTP port
    auto s = match_smtp("220 mail.example.com ESMTP Postfix (Ubuntu)\r\n", 25);
    CHECK(s && s->service == "smtp" && s->product == "Postfix" && s->version.empty());
    auto e = match_smtp("220 host ESMTP Exim 4.96 Tue, 01 Jan 2030\r\n", 587);
    CHECK(e && e->product == "Exim" && e->version == "4.96");
    CHECK(!match_smtp("220 welcome to my mailbox thing\r\n", 9999));      // "mail" alone must not match
    CHECK(!match_smtp("221 bye\r\n", 25));
    auto multi = match_smtp("220-mx.example.org ESMTP Sendmail 8.15.2/8.15.2; Mon\r\n220 more\r\n", 25);
    CHECK(multi && multi->product == "Sendmail" && multi->version == "8.15.2");
}

TEST(pop3_imap) {
    auto p = match_pop3("+OK Dovecot ready.\r\n", 110);
    CHECK(p && p->service == "pop3" && p->product == "Dovecot" && p->confidence == 90);
    CHECK(!match_pop3("+OKAY\r\n", 110));
    auto i = match_imap("* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n", 143);
    CHECK(i && i->service == "imap" && i->product == "Dovecot");
    CHECK(!match_imap("* OKAY\r\n", 143));
}

static string mysql_packet(const string& version) {
    string payload;
    payload.push_back(10);
    payload += version;
    payload.push_back('\0');
    payload += string(31, 'x');  // rest of handshake (thread id, salt, caps...)
    string pkt;
    const std::size_t n = payload.size();
    pkt.push_back(static_cast<char>(n & 0xFF));
    pkt.push_back(static_cast<char>((n >> 8) & 0xFF));
    pkt.push_back(static_cast<char>((n >> 16) & 0xFF));
    pkt.push_back(0);  // sequence id
    return pkt + payload;
}

TEST(mysql_mariadb) {
    auto m = match_mysql(mysql_packet("8.0.36-0ubuntu0.22.04.1"), 3306);
    CHECK(m && m->product == "MySQL" && m->version == "8.0.36-0ubuntu0.22.04.1" && m->os_hint == "Ubuntu Linux");
    auto maria = match_mysql(mysql_packet("5.5.5-10.11.6-MariaDB-1:10.11.6+maria~ubu2204"), 3306);
    CHECK(maria && maria->product == "MariaDB" && maria->version.rfind("10.11.6", 0) == 0);
    CHECK(!match_mysql(S("\x05\x00\x00\x00\x0a" "abc"), 3306));         // no NUL terminator in packet
    CHECK(!match_mysql(S("\x20\x00\x00\x01\x0a" "5.7\0"), 3306));       // sequence id must be 0
    CHECK(!match_mysql(S("\x20\x00\x00\x00\x0b" "5.7\0"), 3306));       // unknown protocol byte
    CHECK(!match_mysql(S("\x20\x00\x00\x00\x0a" "x.7\0"), 3306));       // version must start with digit
    CHECK(!match_mysql("", 3306));
}

TEST(vnc_telnet) {
    auto v = match_vnc("RFB 003.008\n", 5900);
    CHECK(v && v->service == "vnc");
    CHECK(!match_vnc("RFB 003.00X\n", 5900));
    CHECK(!match_vnc("RFB 003.008", 5900));
    CHECK(match_telnet(S("\xff\xfd\x18\xff\xfd\x20"), 23).has_value());
    CHECK(!match_telnet(S("\xff\xf0\x01"), 23));          // not WILL/WONT/DO/DONT
    CHECK(!match_telnet("hello", 23));
}

TEST(http_nginx_iis_and_title) {
    auto n = match_http("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n<html><head><TITLE>Welcome</TITLE></head>", 80);
    CHECK(n && n->service == "http" && n->product == "nginx" && n->version == "1.18.0");
    CHECK(n->extra.find("(Ubuntu)") != string::npos && n->extra.find("title: Welcome") != string::npos);
    CHECK_EQ(n->os_hint, string("Ubuntu Linux"));
    auto i = match_http("HTTP/1.1 404 Not Found\r\nserver: Microsoft-IIS/10.0\r\nX-Powered-By: ASP.NET\r\n\r\n", 80);
    CHECK(i && i->product == "Microsoft-IIS" && i->version == "10.0" && i->os_hint == "Windows");
    CHECK(i->extra.find("ASP.NET") != string::npos);
    auto bare = match_http("HTTP/1.0 200 OK\r\n\r\nhi", 8080);
    CHECK(bare && bare->product.empty() && bare->version_quality == VersionQuality::None);
}

TEST(http_tls_on_plain_port) {
    auto d = match_http("HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n\r\n<html><center><h1>400 Bad Request</h1></center>The plain HTTP request was sent to HTTPS port</html>", 443);
    CHECK(d && d->service == "https" && d->tls);
}

TEST(http_rejects_lookalikes) {
    CHECK(!match_http("HTTP/9.9 200 OK\r\n\r\n", 80));
    CHECK(!match_http("HTTP/1.1 2x0 OK\r\n\r\n", 80));
    CHECK(!match_http("HTTP/1.1\r\n\r\n", 80));
    CHECK(!match_http("GET / HTTP/1.1\r\n", 80));
    CHECK(!match_http("", 80));
}

TEST(http_header_injection_in_banner_is_sanitized) {
    auto d = match_http("HTTP/1.1 200 OK\r\nServer: evil\x1b[31m\x07/1.0\r\n\r\n", 80);
    CHECK(d.has_value());
    for (char c : d->product + d->extra + d->banner) CHECK(static_cast<unsigned char>(c) >= 0x20 || c == 0);
}

static string tls_server_hello(unsigned legacy, unsigned selected_ext, unsigned cipher) {
    string body;
    body.push_back(static_cast<char>(legacy >> 8)); body.push_back(static_cast<char>(legacy));
    body += string(32, 'r');
    body.push_back(0);  // session id len
    body.push_back(static_cast<char>(cipher >> 8)); body.push_back(static_cast<char>(cipher));
    body.push_back(0);  // compression
    string ext;
    if (selected_ext) {
        ext += S("\x00\x2b\x00\x02");
        ext.push_back(static_cast<char>(selected_ext >> 8)); ext.push_back(static_cast<char>(selected_ext));
    }
    body.push_back(static_cast<char>(ext.size() >> 8)); body.push_back(static_cast<char>(ext.size()));
    body += ext;
    string hs;
    hs.push_back(2);
    hs.push_back(0); hs.push_back(static_cast<char>(body.size() >> 8)); hs.push_back(static_cast<char>(body.size()));
    hs += body;
    string rec;
    rec.push_back(0x16); rec += S("\x03\x03");
    rec.push_back(static_cast<char>(hs.size() >> 8)); rec.push_back(static_cast<char>(hs.size()));
    return rec + hs;
}

TEST(tls_server_hello_versions) {
    auto t13 = match_tls(tls_server_hello(0x0303, 0x0304, 0x1301), 8443);
    CHECK(t13 && t13->tls_info && t13->tls_info->protocol == "TLSv1.3" && t13->tls_info->cipher == "TLS_AES_128_GCM_SHA256");
    CHECK(t13->confidence >= 80);
    auto t12 = match_tls(tls_server_hello(0x0303, 0, 0xc02f), 9999);
    CHECK(t12 && t12->service == "ssl/tls" && t12->tls_info->protocol == "TLSv1.2" && t12->confidence >= 90);
    auto h = match_tls(tls_server_hello(0x0303, 0x0304, 0x1302), 443);
    CHECK(h && h->service == "https" && h->extra.find("inferred") != string::npos);
}

TEST(tls_alert_and_rejects) {
    CHECK(match_tls(S("\x15\x03\x03\x00\x02\x02\x46"), 443).has_value());       // fatal protocol_version alert
    CHECK(!match_tls(S("\x15\x03\x03\x00\x09\x02\x46"), 443));                  // bad alert length
    CHECK(!match_tls(S("\x16\x03\x03\x00\x05\x01\x00\x00\x01\x00"), 443));     // ClientHello, not ServerHello
    CHECK(!match_tls(S("\x16\x09\x03\x00\x05\x02"), 443));                      // bogus version
    CHECK(!match_tls("HTTP/1.1 200 OK", 443));
}

TEST(tls_every_truncation_is_safe) {
    const string full = tls_server_hello(0x0303, 0x0304, 0x1301);
    for (std::size_t n = 0; n <= full.size(); ++n) (void)match_tls(std::string_view(full).substr(0, n), 443);
}

TEST(client_hello_is_wellformed) {
    const string ch = build_client_hello("example.org");
    CHECK(ch.size() > 100 && ch.size() < 1000);
    CHECK_EQ(static_cast<unsigned char>(ch[0]), 0x16u);
    CHECK_EQ(static_cast<unsigned char>(ch[5]), 0x01u);  // ClientHello
    const std::size_t rec_len = (static_cast<unsigned char>(ch[3]) << 8) | static_cast<unsigned char>(ch[4]);
    CHECK_EQ(rec_len, ch.size() - 5);
    const std::size_t hs_len = (static_cast<unsigned char>(ch[6]) << 16) | (static_cast<unsigned char>(ch[7]) << 8) | static_cast<unsigned char>(ch[8]);
    CHECK_EQ(hs_len, ch.size() - 9);
    CHECK(ch.find("example.org") != string::npos);
    CHECK(build_client_hello("10.0.0.1").find("10.0.0.1") == string::npos);  // no IP literal in SNI
}

TEST(redis) {
    auto info = match_redis("$80\r\n# Server\r\nredis_version:7.0.11\r\nos:Linux 5.15.0 x86_64\r\n", 6379);
    CHECK(info && info->product == "Redis" && info->version == "7.0.11" && info->os_hint == "Linux");
    CHECK(info->version_quality == VersionQuality::Reported);
    auto vk = match_redis("$80\r\n# Server\r\nredis_version:7.2.4\r\nvalkey_version:8.0.1\r\n", 6379);
    CHECK(vk && vk->product == "Valkey" && vk->version == "8.0.1");
    auto na = match_redis("-NOAUTH Authentication required.\r\n", 6379);
    CHECK(na && na->service == "redis" && na->version.empty() && na->version_quality == VersionQuality::None);
    CHECK(!match_redis("-ERR whatever\r\n", 9999));  // generic error only trusted on 6379
    CHECK(!match_redis("+PONG\r\n", 9999));
    CHECK(!match_redis("$5\r\nhello\r\n", 6379));
}

TEST(postgres_smb) {
    CHECK(match_postgres("S", 5432).has_value());
    CHECK(match_postgres("N", 15432).has_value());
    CHECK(!match_postgres("X", 5432));
    CHECK(!match_postgres("SS", 5432));
    // Wire-accurate SMB2 NEGOTIATE response skeleton: NetBIOS hdr + 64B header + body (little-endian).
    string h = S("\xfe" "SMB");
    h += S("\x40\x00") + string(58, '\0');                     // StructureSize=64, rest of header
    h += S("\x41\x00\x01\x00\x11\x03");                        // body size 65, security mode, dialect 0x0311
    string pkt = string(1, '\0');
    pkt.push_back(0); pkt.push_back(0); pkt.push_back(static_cast<char>(h.size()));
    auto s = match_smb2(pkt + h, 445);
    CHECK(s && s->service == "smb" && s->extra.find("3.1.1") != string::npos);
    CHECK(!match_smb2(pkt + h.substr(0, 40), 445));
    CHECK(!match_smb2("\x01\x00\x00\x10", 445));
}

TEST(udp_responses) {
    // DNS: id 0x1234, QR, 1 question (version.bind CH TXT), 1 answer TXT "9.18.12-Ubuntu"
    string q = S("\x07version\x04" "bind\x00\x00\x10\x00\x03");
    string resp = S("\x12\x34\x85\x00\x00\x01\x00\x01\x00\x00\x00\x00") + q;
    resp += S("\xc0\x0c\x00\x10\x00\x03\x00\x00\x00\x00");
    const string txt = "9.18.12-Ubuntu";
    resp.push_back('\0'); resp.push_back(static_cast<char>(txt.size() + 1)); resp.push_back(static_cast<char>(txt.size()));
    resp += txt;
    auto dns = match_udp_response(53, resp);
    CHECK(dns && dns->service == "dns" && dns->version == "9.18.12-Ubuntu" && dns->version_quality == VersionQuality::Reported);
    CHECK(!match_udp_response(53, S("\x12\x34\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00")));  // QR bit clear
    CHECK(!match_udp_response(53, S("\xAA\xAA\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00")));  // wrong txn id
    string ntp(48, '\0');
    ntp[0] = 0x24;  // LI 0, v4, mode 4
    ntp[1] = 2;
    auto n = match_udp_response(123, ntp);
    CHECK(n && n->service == "ntp" && n->extra.find("NTPv4") != string::npos);
    ntp[0] = 0x23;  // mode 3 (a client packet reflected) must not match
    CHECK(!match_udp_response(123, ntp));
    CHECK(!match_udp_response(123, "short"));
    auto other = match_udp_response(161, "anything");
    CHECK(other && other->confidence < 50 && other->service == "snmp");
}

TEST(dns_truncated_is_safe) {
    string resp = S("\x12\x34\x85\x00\x00\x01\x00\x01\x00\x00\x00\x00") + S("\x07version\x04" "bind\x00\x00\x10\x00\x03\xc0\x0c\x00\x10");
    for (std::size_t n = 0; n <= resp.size(); ++n) (void)match_udp_response(53, std::string_view(resp).substr(0, n));
}

TEST(fuzz_all_matchers_never_crash) {
    // Deterministic random + mutated-seed fuzzing. Value comes from running under ASan/UBSan.
    std::mt19937 rng(0xC0FFEE);
    const Matcher all[] = {match_ssh, match_ftp, match_smtp, match_pop3, match_imap, match_mysql, match_vnc,
                           match_telnet, match_http, match_tls, match_redis, match_postgres, match_smb2};
    const string seeds[] = {"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n", "220 ESMTP Postfix\r\n", "HTTP/1.1 200 OK\r\nServer: a/1\r\n\r\n<title>x</title>",
                            mysql_packet("8.0.1"), tls_server_hello(0x0303, 0x0304, 0x1301), "$10\r\n# Server\r\nredis_version:1\r\n",
                            "+OK Dovecot\r\n", "RFB 003.008\n", S("\xff\xfd\x18")};
    for (int iter = 0; iter < 30000; ++iter) {
        string data;
        if (iter % 2 == 0) {
            data.resize(rng() % 300);
            for (auto& c : data) c = static_cast<char>(rng());
        } else {
            data = seeds[rng() % (sizeof(seeds) / sizeof(seeds[0]))];
            for (int m = 0; m < 1 + static_cast<int>(rng() % 4); ++m) {
                if (!data.empty()) data[rng() % data.size()] = static_cast<char>(rng());
            }
            if (rng() % 3 == 0 && !data.empty()) data.resize(rng() % data.size());
        }
        for (Matcher m : all) {
            for (std::uint16_t port : {std::uint16_t(22), std::uint16_t(443), std::uint16_t(6379)}) (void)m(data, port);
        }
        for (std::uint16_t port : {std::uint16_t(53), std::uint16_t(123), std::uint16_t(137), std::uint16_t(9)}) (void)match_udp_response(port, data);
    }
    CHECK(true);
}

TEST(sanitize_strips_control_and_caps_length) {
    CHECK_EQ(sanitize_ascii("a\r\nb\tc", 50), string("a b c"));
    CHECK_EQ(sanitize_ascii(S("x\x1b[31my\x00z"), 50), string("x.[31my.z"));
    CHECK_EQ(sanitize_ascii(string(500, 'A'), 10).size(), std::size_t(10));
}

TEST(port_guess_table) {
    CHECK_EQ(string(port_guess_service(22, true)), string("ssh"));
    CHECK_EQ(string(port_guess_service(53, false)), string("domain"));
    CHECK_EQ(string(port_guess_service(40011, true)), string("unknown"));
}

TEST(os_hint_requires_word_boundary) {
    // "windows"/"ubuntu" glued to preceding letters must not produce an OS hint
    // (right boundary is fine here, so only the LEFT-boundary rule can reject these).
    auto a = match_http("HTTP/1.1 200 OK\r\nServer: mywindows/1.0\r\n\r\n", 80);
    CHECK(a && a->os_hint.empty());
    auto b = match_http("HTTP/1.1 200 OK\r\nServer: Xubuntu/2.0\r\n\r\n", 80);
    CHECK(b && b->os_hint.empty());
    auto c = match_ssh("SSH-2.0-OpenSSH_9.6 research-search-march\r\n", 22);
    CHECK(c && c->os_hint.empty());
    // ...but distro package suffixes where digits touch the tag still work.
    auto d = match_ssh("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n", 22);
    CHECK(d && d->os_hint == "Ubuntu Linux");
    auto e = match_mysql(mysql_packet("8.0.36-0ubuntu0.22.04.1"), 3306);
    CHECK(e && e->os_hint == "Ubuntu Linux");
}

TEST(version_tokens_never_contain_nul_or_control_bytes) {
    // Regression (found by fuzzing): strchr(set, '\0') is non-null, so NUL passed as a version char.
    const string info = string("$20\r\n# Server\r\nredis_version:7.0") + string(1, '\0') + "9\r\n";
    auto r = match_redis(info, 6379);
    CHECK(r.has_value());
    CHECK_EQ(r->version, string("7.0"));  // token stops at the NUL
    const string http = string("HTTP/1.1 200 OK\r\nServer: nginx/1.2") + string(1, '\0') + "3\r\n\r\n";
    auto h = match_http(http, 80);
    CHECK(h.has_value());
    for (char c : h->product + h->version + h->extra + h->banner) CHECK(static_cast<unsigned char>(c) >= 0x20);
}
