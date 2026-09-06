#include "service-detect.h"
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>

namespace {

std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::string to_lower(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return result;
}

std::string clean_printable(const char* data, size_t len, size_t max_out = 80) {
    std::string out;
    for (size_t i = 0; i < len && out.size() < max_out; ++i) {
        unsigned char c = static_cast<unsigned char>(data[i]);
        if (c == '\r' || c == '\n') {
            if (!out.empty() && out.back() != ' ') out.push_back(' ');
        } else if (std::isprint(c)) {
            out.push_back(static_cast<char>(c));
        } else if (c == '\t') {
            out.push_back(' ');
        }
    }
    return trim(out);
}

int connect_tcp_with_timeout(const std::string& ip, int port, int timeout_ms, int& out_ttl) {
    out_ttl = -1;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    int on = 1;
    setsockopt(sock, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on));

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &target.sin_addr) != 1) {
        close(sock);
        return -1;
    }

    int rc = connect(sock, reinterpret_cast<sockaddr*>(&target), sizeof(target));
    if (rc < 0 && errno != EINPROGRESS) {
        close(sock);
        return -1;
    }

    if (rc != 0) {
        pollfd pfd{sock, POLLOUT, 0};
        int poll_rc = poll(&pfd, 1, timeout_ms);
        if (poll_rc <= 0) {
            close(sock);
            return -1;
        }

        int so_error = 0;
        socklen_t len = sizeof(so_error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0 || so_error != 0) {
            close(sock);
            return -1;
        }
    }

    fcntl(sock, F_SETFL, flags);
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    return sock;
}

ssize_t recv_tcp_data(int sock, char* buf, size_t buf_len, int timeout_ms, int& out_ttl) {
    pollfd pfd{sock, POLLIN, 0};
    int p_res = poll(&pfd, 1, timeout_ms);
    if (p_res <= 0 || !(pfd.revents & POLLIN)) {
        return 0;
    }

    char cbuf[256];
    iovec iov;
    iov.iov_base = buf;
    iov.iov_len = buf_len - 1;

    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    ssize_t n = recvmsg(sock, &msg, 0);
    if (n > 0) {
        buf[n] = '\0';
        for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL) {
                out_ttl = *reinterpret_cast<int*>(CMSG_DATA(cmsg));
            }
        }
    }
    return n;
}

bool send_tcp_data(int sock, const void* data, size_t len) {
    size_t total_sent = 0;
    const char* ptr = reinterpret_cast<const char*>(data);
    while (total_sent < len) {
        ssize_t s = send(sock, ptr + total_sent, len - total_sent, 0);
        if (s <= 0) return false;
        total_sent += s;
    }
    return true;
}

bool parse_ssh_banner(const char* buf, size_t len, ServiceInfo& info) {
    std::string text(buf, len);
    size_t ssh_pos = text.find("SSH-");
    if (ssh_pos != std::string::npos) {
        info.service_name = "ssh";
        size_t end_line = text.find_first_of("\r\n", ssh_pos);
        std::string full_id = (end_line != std::string::npos) 
            ? text.substr(ssh_pos, end_line - ssh_pos) 
            : text.substr(ssh_pos);
        
        info.raw_banner = full_id;
        size_t first_dash = full_id.find('-');
        size_t second_dash = (first_dash != std::string::npos) ? full_id.find('-', first_dash + 1) : std::string::npos;
        if (second_dash != std::string::npos) {
            std::string proto = full_id.substr(first_dash + 1, second_dash - first_dash - 1);
            std::string software = full_id.substr(second_dash + 1);
            info.version = software;
            info.extra_info = "protocol " + proto;
        } else {
            info.version = full_id;
        }
        return true;
    }
    return false;
}

bool parse_ftp_banner(const char* buf, size_t len, ServiceInfo& info) {
    std::string text(buf, len);
    if (text.rfind("220", 0) == 0) {
        std::string lower = to_lower(text);
        if (lower.find("ftp") != std::string::npos || lower.find("filezilla") != std::string::npos ||
            lower.find("vsftpd") != std::string::npos || lower.find("proftpd") != std::string::npos ||
            lower.find("pure-ftpd") != std::string::npos) {
            info.service_name = "ftp";
            info.raw_banner = clean_printable(buf, len);
            size_t end = text.find_first_of("\r\n");
            std::string line = (end != std::string::npos) ? text.substr(0, end) : text;
            if (line.size() > 4) {
                info.version = trim(line.substr(4));
            } else {
                info.version = "FTP Server";
            }
            return true;
        }
    }
    return false;
}

bool parse_smtp_banner(const char* buf, size_t len, ServiceInfo& info) {
    std::string text(buf, len);
    if (text.rfind("220", 0) == 0) {
        std::string lower = to_lower(text);
        if (lower.find("smtp") != std::string::npos || lower.find("esmtp") != std::string::npos ||
            lower.find("postfix") != std::string::npos || lower.find("exim") != std::string::npos ||
            lower.find("sendmail") != std::string::npos || lower.find("mail") != std::string::npos) {
            info.service_name = "smtp";
            info.raw_banner = clean_printable(buf, len);
            size_t end = text.find_first_of("\r\n");
            std::string line = (end != std::string::npos) ? text.substr(0, end) : text;
            if (line.size() > 4) {
                info.version = trim(line.substr(4));
            } else {
                info.version = "SMTP Mail Server";
            }
            return true;
        }
    }
    return false;
}

bool parse_pop3_banner(const char* buf, size_t len, ServiceInfo& info) {
    std::string text(buf, len);
    if (text.rfind("+OK", 0) == 0) {
        info.service_name = "pop3";
        info.raw_banner = clean_printable(buf, len);
        size_t end = text.find_first_of("\r\n");
        std::string line = (end != std::string::npos) ? text.substr(3, end - 3) : text.substr(3);
        info.version = trim(line);
        return true;
    }
    return false;
}

bool parse_imap_banner(const char* buf, size_t len, ServiceInfo& info) {
    std::string text(buf, len);
    if (text.rfind("* OK", 0) == 0) {
        info.service_name = "imap";
        info.raw_banner = clean_printable(buf, len);
        size_t end = text.find_first_of("\r\n");
        std::string line = (end != std::string::npos) ? text.substr(4, end - 4) : text.substr(4);
        info.version = trim(line);
        return true;
    }
    return false;
}

bool parse_mysql_banner(const char* buf, size_t len, ServiceInfo& info) {
    if (len >= 6 && static_cast<unsigned char>(buf[4]) == 0x0A) {
        const char* ver_start = buf + 5;
        size_t max_ver_len = len - 5;
        size_t ver_len = 0;
        while (ver_len < max_ver_len && ver_start[ver_len] != '\0') {
            ver_len++;
        }
        if (ver_len > 0 && ver_len < max_ver_len) {
            std::string ver(ver_start, ver_len);
            info.service_name = "mysql";
            info.version = "MySQL / MariaDB " + ver;
            info.raw_banner = ver;
            return true;
        }
    }
    return false;
}

bool parse_vnc_banner(const char* buf, size_t len, ServiceInfo& info) {
    std::string text(buf, len);
    if (text.rfind("RFB ", 0) == 0) {
        info.service_name = "vnc";
        size_t end = text.find_first_of("\r\n");
        info.version = (end != std::string::npos) ? text.substr(0, end) : text;
        info.raw_banner = info.version;
        return true;
    }
    return false;
}

bool parse_telnet_banner(const char* buf, size_t len, ServiceInfo& info) {
    if (len >= 3 && static_cast<unsigned char>(buf[0]) == 0xFF &&
        (static_cast<unsigned char>(buf[1]) == 0xFD || 
         static_cast<unsigned char>(buf[1]) == 0xFB || 
         static_cast<unsigned char>(buf[1]) == 0xFE || 
         static_cast<unsigned char>(buf[1]) == 0xFC)) {
        info.service_name = "telnet";
        info.version = "Telnet daemon (negotiating IAC)";
        info.raw_banner = clean_printable(buf, len);
        return true;
    }
    return false;
}

bool parse_redis_banner(const char* buf, size_t len, ServiceInfo& info) {
    std::string text(buf, len);
    if (text.find("+PONG") != std::string::npos || text.find("redis_version:") != std::string::npos ||
        text.find("valkey_version:") != std::string::npos || text.find("-NOAUTH") != std::string::npos) {
        info.service_name = "redis";
        info.raw_banner = clean_printable(buf, std::min(len, size_t(120)));

        std::string server_name = "Redis";
        std::string redis_ver = "";
        std::string valkey_ver = "";
        std::string os_info = "";

        std::istringstream stream(text);
        std::string line;
        while (std::getline(stream, line)) {
            line = trim(line);
            if (line.rfind("server_name:", 0) == 0) {
                server_name = trim(line.substr(12));
            } else if (line.rfind("redis_version:", 0) == 0) {
                redis_ver = trim(line.substr(14));
            } else if (line.rfind("valkey_version:", 0) == 0) {
                valkey_ver = trim(line.substr(15));
            } else if (line.rfind("os:", 0) == 0) {
                os_info = trim(line.substr(3));
            }
        }

        if (!valkey_ver.empty()) {
            info.version = "Valkey " + valkey_ver + (redis_ver.empty() ? "" : " (Redis " + redis_ver + ")");
        } else if (!redis_ver.empty()) {
            info.version = server_name + " " + redis_ver;
        } else if (text.find("-NOAUTH") != std::string::npos) {
            info.version = "Redis (password protected)";
        } else {
            info.version = "Redis key-value store";
        }

        if (!os_info.empty()) {
            info.extra_info = "OS: " + os_info;
        }
        return true;
    }
    return false;
}

bool parse_http_response(const char* buf, size_t len, ServiceInfo& info) {
    std::string text(buf, len);
    if (text.rfind("HTTP/", 0) == 0) {
        if (text.find("Client sent an HTTP request to an HTTPS server") != std::string::npos ||
            text.find("plain HTTP request was sent to HTTPS port") != std::string::npos) {
            info.service_name = "https";
            info.version = "SSL/TLS HTTP Service";
            info.raw_banner = clean_printable(buf, std::min(len, size_t(80)));
            return true;
        }

        info.service_name = "http";
        info.raw_banner = clean_printable(buf, std::min(len, size_t(80)));

        std::string server_header = "";
        std::string powered_by = "";
        std::string title = "";

        std::istringstream stream(text);
        std::string line;
        bool in_headers = true;
        while (std::getline(stream, line)) {
            line = trim(line);
            if (line.empty()) {
                in_headers = false;
                continue;
            }
            if (in_headers) {
                if (line.rfind("Server:", 0) == 0 || line.rfind("server:", 0) == 0) {
                    server_header = trim(line.substr(7));
                } else if (line.rfind("X-Powered-By:", 0) == 0 || line.rfind("x-powered-by:", 0) == 0) {
                    powered_by = trim(line.substr(13));
                }
            }
        }

        size_t t_start = text.find("<title>");
        if (t_start == std::string::npos) t_start = text.find("<TITLE>");
        if (t_start != std::string::npos) {
            size_t t_end = text.find("</title>", t_start);
            if (t_end == std::string::npos) t_end = text.find("</TITLE>", t_start);
            if (t_end != std::string::npos) {
                title = trim(clean_printable(text.c_str() + t_start + 7, t_end - (t_start + 7), 50));
            }
        }

        if (!server_header.empty()) {
            info.version = server_header;
            if (!powered_by.empty()) {
                info.extra_info = "Powered by " + powered_by;
            } else if (!title.empty()) {
                info.extra_info = "Title: " + title;
            }
        } else if (!title.empty()) {
            info.version = "HTTP Server (Title: " + title + ")";
        } else {
            size_t first_line_end = text.find_first_of("\r\n");
            info.version = (first_line_end != std::string::npos) ? text.substr(0, first_line_end) : "HTTP Service";
        }
        return true;
    }
    return false;
}

bool parse_tls_response(const char* buf, size_t len, ServiceInfo& info, int port) {
    if (len >= 5 && static_cast<unsigned char>(buf[0]) == 0x16 &&
        static_cast<unsigned char>(buf[1]) == 0x03) {
        unsigned char major = static_cast<unsigned char>(buf[1]);
        unsigned char minor = static_cast<unsigned char>(buf[2]);
        std::string tls_ver = "TLS";
        if (major == 3 && minor == 1) tls_ver = "TLS 1.0";
        else if (major == 3 && minor == 2) tls_ver = "TLS 1.1";
        else if (major == 3 && minor == 3) tls_ver = "TLS 1.2";
        else if (major == 3 && minor == 4) tls_ver = "TLS 1.3";

        if (port == 443 || port == 8443 || port == 46503) {
            info.service_name = "https";
        } else {
            info.service_name = "ssl/tls";
        }
        info.version = "Encrypted (" + tls_ver + ")";
        info.raw_banner = "TLS Handshake ServerHello (" + tls_ver + ")";
        return true;
    }
    return false;
}

bool probe_tls_active(const std::string& ip, int port, int timeout_ms, ServiceInfo& info, int& out_ttl) {
    int sock = connect_tcp_with_timeout(ip, port, timeout_ms, out_ttl);
    if (sock < 0) return false;

    const unsigned char tls_hello[] = {
        0x16, 0x03, 0x01, 0x00, 0x5a,
        0x01, 0x00, 0x00, 0x56,
        0x03, 0x03,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x00,
        0x00, 0x1c,
        0xc0, 0x2f, 0xc0, 0x30, 0xc0, 0x2b, 0xc0, 0x2c,
        0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14,
        0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35,
        0x00, 0x0a, 0x00, 0xff,
        0x01, 0x00,
        0x00, 0x11,
        0x00, 0x0d, 0x00, 0x0c, 0x00, 0x0a, 0x04, 0x03,
        0x08, 0x04, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x00
    };

    send_tcp_data(sock, tls_hello, sizeof(tls_hello));

    char buf[2048];
    int ttl_recv = -1;
    ssize_t n = recv_tcp_data(sock, buf, sizeof(buf), timeout_ms, ttl_recv);
    if (ttl_recv > 0) out_ttl = ttl_recv;
    close(sock);

    if (n > 0) {
        return parse_tls_response(buf, n, info, port);
    }
    return false;
}

bool probe_redis_active(const std::string& ip, int port, int timeout_ms, ServiceInfo& info, int& out_ttl) {
    int sock = connect_tcp_with_timeout(ip, port, timeout_ms, out_ttl);
    if (sock < 0) return false;

    std::string cmd = "PING\r\nINFO server\r\nQUIT\r\n";
    send_tcp_data(sock, cmd.c_str(), cmd.size());

    char buf[4096];
    int ttl_recv = -1;
    ssize_t n = recv_tcp_data(sock, buf, sizeof(buf), timeout_ms, ttl_recv);
    if (ttl_recv > 0) out_ttl = ttl_recv;
    close(sock);

    if (n > 0) {
        return parse_redis_banner(buf, n, info);
    }
    return false;
}

bool probe_postgres_active(const std::string& ip, int port, int timeout_ms, ServiceInfo& info, int& out_ttl) {
    int sock = connect_tcp_with_timeout(ip, port, timeout_ms, out_ttl);
    if (sock < 0) return false;

    const unsigned char ssl_req[] = {0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f};
    send_tcp_data(sock, ssl_req, sizeof(ssl_req));

    char buf[1024];
    int ttl_recv = -1;
    ssize_t n = recv_tcp_data(sock, buf, sizeof(buf), timeout_ms, ttl_recv);
    if (ttl_recv > 0) out_ttl = ttl_recv;

    if (n > 0 && (buf[0] == 'S' || buf[0] == 'N')) {
        info.service_name = "postgresql";
        info.version = "PostgreSQL Database";
        info.raw_banner = std::string("SSLRequest response: ") + buf[0];
        close(sock);
        return true;
    }
    close(sock);
    return false;
}

bool probe_smb_active(const std::string& ip, int port, int timeout_ms, ServiceInfo& info, int& out_ttl) {
    int sock = connect_tcp_with_timeout(ip, port, timeout_ms, out_ttl);
    if (sock < 0) return false;

    const unsigned char smb2_req[] = {
        0x00, 0x00, 0x00, 0x44,
        0xfe, 'S', 'M', 'B',
        0x40, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x24, 0x00,
        0x02, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x70, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x02, 0x02,
        0x10, 0x02
    };

    send_tcp_data(sock, smb2_req, sizeof(smb2_req));

    char buf[1024];
    int ttl_recv = -1;
    ssize_t n = recv_tcp_data(sock, buf, sizeof(buf), timeout_ms, ttl_recv);
    if (ttl_recv > 0) out_ttl = ttl_recv;
    close(sock);

    if (n >= 8 && buf[4] == '\xfe' && buf[5] == 'S' && buf[6] == 'M' && buf[7] == 'B') {
        info.service_name = "smb";
        info.version = "Microsoft SMB Service";
        info.raw_banner = "SMB2 Header";
        return true;
    }
    return false;
}

} // anonymous namespace

// Single connection probe: connects, listens for unsolicited banner, or sends HTTP GET directly
ServiceInfo probe_tcp_service(const std::string& ip, int port, int timeout_ms) {
    ServiceInfo info;
    info.port = port;
    info.protocol = "tcp";
    info.is_open = false;

    int ttl = -1;
    int sock = connect_tcp_with_timeout(ip, port, timeout_ms, ttl);
    if (sock < 0) {
        return info; // Port is closed
    }

    info.is_open = true;
    info.received_ttl = ttl;

    // Step 1: Listen for passive unsolicited banner (e.g. SSH, FTP, SMTP, MySQL, etc.)
    char buf[4096];
    int ttl_recv = -1;
    ssize_t n = recv_tcp_data(sock, buf, sizeof(buf), 400, ttl_recv);
    if (ttl_recv > 0) info.received_ttl = ttl_recv;

    if (n > 0) {
        if (parse_ssh_banner(buf, n, info)) { close(sock); return info; }
        if (parse_ftp_banner(buf, n, info)) { close(sock); return info; }
        if (parse_smtp_banner(buf, n, info)) { close(sock); return info; }
        if (parse_pop3_banner(buf, n, info)) { close(sock); return info; }
        if (parse_imap_banner(buf, n, info)) { close(sock); return info; }
        if (parse_mysql_banner(buf, n, info)) { close(sock); return info; }
        if (parse_vnc_banner(buf, n, info)) { close(sock); return info; }
        if (parse_telnet_banner(buf, n, info)) { close(sock); return info; }
        if (parse_redis_banner(buf, n, info)) { close(sock); return info; }
        if (parse_http_response(buf, n, info)) { close(sock); return info; }

        std::string cleaned = clean_printable(buf, n);
        if (!cleaned.empty()) {
            info.service_name = "unknown";
            info.version = cleaned;
            info.raw_banner = cleaned;
            close(sock);
            return info;
        }
    }

    // Step 2: No passive banner received -> Send HTTP GET probe on the same open socket!
    std::string req = "GET / HTTP/1.1\r\nHost: " + ip + "\r\nUser-Agent: Mozilla/5.0 (recon)\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    send_tcp_data(sock, req.c_str(), req.size());

    n = recv_tcp_data(sock, buf, sizeof(buf), 700, ttl_recv);
    if (ttl_recv > 0) info.received_ttl = ttl_recv;
    close(sock);

    if (n > 0) {
        if (parse_http_response(buf, n, info)) {
            return info;
        }
        std::string cleaned = clean_printable(buf, n);
        if (!cleaned.empty()) {
            info.service_name = "unknown";
            info.version = cleaned;
            info.raw_banner = cleaned;
            return info;
        }
    }

    // Step 3: Targeted Active Probes
    // Probe TLS/SSL
    if (port == 443 || port == 8443 || port == 46503 || info.service_name == "https") {
        if (probe_tls_active(ip, port, timeout_ms, info, ttl)) {
            if (ttl > 0) info.received_ttl = ttl;
            return info;
        }
    }

    // Probe Redis
    if (probe_redis_active(ip, port, timeout_ms, info, ttl)) {
        if (ttl > 0) info.received_ttl = ttl;
        return info;
    }

    // Probe PostgreSQL
    if (probe_postgres_active(ip, port, timeout_ms, info, ttl)) {
        if (ttl > 0) info.received_ttl = ttl;
        return info;
    }

    // Probe SMB (if port 445 or 139)
    if (port == 445 || port == 139) {
        if (probe_smb_active(ip, port, timeout_ms, info, ttl)) {
            if (ttl > 0) info.received_ttl = ttl;
            return info;
        }
    }

    // If port 443 / 8443 didn't respond to previous, try TLS anyway
    if (probe_tls_active(ip, port, timeout_ms, info, ttl)) {
        if (ttl > 0) info.received_ttl = ttl;
        return info;
    }

    // Silent port: do NOT guess common services!
    info.service_name = "unknown";
    info.version = "[no banner returned]";
    return info;
}

// UDP probing
ServiceInfo probe_udp_service(const std::string& ip, int port, int timeout_ms) {
    ServiceInfo info;
    info.port = port;
    info.protocol = "udp";
    info.is_open = false;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return info;

    int on = 1;
    setsockopt(sock, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on));

    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &dest.sin_addr) != 1) {
        close(sock);
        return info;
    }

    std::vector<uint8_t> probe;
    if (port == 53) {
        probe = {
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x09, 'l', 'o', 'c', 'a',
            'l', 'h', 'o', 's', 't', 0x00, 0x00, 0x01, 0x00, 0x01
        };
    } else if (port == 123) {
        probe.resize(48, 0);
        probe[0] = 0x1b;
    } else if (port == 137) {
        probe = {
            0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x20,
            'C', 'K', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
            'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
            0x00, 0x00, 0x21, 0x00, 0x01
        };
    } else {
        probe = {0x00, 0x00, 0x00, 0x00};
    }

    sendto(sock, probe.data(), probe.size(), 0, reinterpret_cast<sockaddr*>(&dest), sizeof(dest));

    pollfd pfd{sock, POLLIN, 0};
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret > 0 && (pfd.revents & POLLIN)) {
        char buf[2048];
        char cbuf[256];
        iovec iov{buf, sizeof(buf) - 1};
        msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof(cbuf);

        ssize_t n = recvmsg(sock, &msg, 0);
        if (n > 0) {
            buf[n] = '\0';
            info.is_open = true;
            for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL) {
                    info.received_ttl = *reinterpret_cast<int*>(CMSG_DATA(cmsg));
                }
            }

            if (port == 53) {
                info.service_name = "dns";
                info.version = "Domain Name System (response received)";
            } else if (port == 123) {
                info.service_name = "ntp";
                info.version = "Network Time Protocol (v3/v4)";
            } else if (port == 137) {
                info.service_name = "netbios-ns";
                info.version = "NetBIOS Name Service";
            } else {
                info.service_name = "unknown-udp";
                info.version = clean_printable(buf, n);
            }
        }
    }
    close(sock);
    return info;
}
