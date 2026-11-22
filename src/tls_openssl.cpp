// Optional TLS certificate inspection. Compiled only when CMake finds OpenSSL
// (-DRECON_WITH_OPENSSL). Certificates are NOT validated: this is reconnaissance, so we want to
// see whatever the server presents, including expired and self-signed certificates.
#ifdef RECON_WITH_OPENSSL

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <memory>
#include <poll.h>

#include "recon/detect.hpp"

namespace recon {
namespace {

template <class T, void (*Free)(T*)>
struct Deleter {
    void operator()(T* p) const { if (p) Free(p); }
};
using CtxPtr = std::unique_ptr<SSL_CTX, Deleter<SSL_CTX, SSL_CTX_free>>;
using SslPtr = std::unique_ptr<SSL, Deleter<SSL, SSL_free>>;
using X509Ptr = std::unique_ptr<X509, Deleter<X509, X509_free>>;
using BioPtr = std::unique_ptr<BIO, Deleter<BIO, BIO_vfree>>;

std::string name_to_string(const X509_NAME* n) {
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio || n == nullptr) return "";
    X509_NAME_print_ex(bio.get(), n, 0, XN_FLAG_RFC2253);
    char* p = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &p);
    return sanitize_ascii(std::string_view(p, len > 0 ? static_cast<std::size_t>(len) : 0), 300);
}

std::string time_to_string(const ASN1_TIME* t) {
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio || t == nullptr) return "";
    ASN1_TIME_print(bio.get(), t);
    char* p = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &p);
    return sanitize_ascii(std::string_view(p, len > 0 ? static_cast<std::size_t>(len) : 0), 64);
}

// Drives a non-blocking SSL call to completion, waiting on the fd as required.
template <class F>
bool drive(SSL* ssl, int fd, Clock::time_point deadline, F call) {
    for (;;) {
        const int rc = call();
        if (rc > 0) return true;
        const int e = SSL_get_error(ssl, rc);
        if (e == SSL_ERROR_WANT_READ) {
            if (net::wait_fd(fd, POLLIN, deadline) <= 0) return false;
        } else if (e == SSL_ERROR_WANT_WRITE) {
            if (net::wait_fd(fd, POLLOUT, deadline) <= 0) return false;
        } else {
            return false;
        }
    }
}

}  // namespace

TlsInspectResult tls_inspect(const net::Endpoint& ep, const std::string& sni,
                             Clock::time_point deadline, bool send_http_get,
                             const std::string& http_host) {
    TlsInspectResult res;
    int err = 0;
    auto conn = net::Connection::connect(ep, deadline, &err);
    if (!conn) {
        res.error = "connect failed";
        return res;
    }
    CtxPtr ctx(SSL_CTX_new(TLS_client_method()));
    if (!ctx) {
        res.error = "SSL_CTX_new failed";
        return res;
    }
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_security_level(ctx.get(), 0);  // inspect legacy servers too
    SSL_CTX_set_min_proto_version(ctx.get(), TLS1_VERSION);

    SslPtr ssl(SSL_new(ctx.get()));
    if (!ssl) {
        res.error = "SSL_new failed";
        return res;
    }
    SSL_set_fd(ssl.get(), conn->fd());
    if (!sni.empty() && !net::IpAddress::parse(sni)) SSL_set_tlsext_host_name(ssl.get(), sni.c_str());

    if (!drive(ssl.get(), conn->fd(), deadline, [&] { return SSL_connect(ssl.get()); })) {
        res.error = "TLS handshake failed";
        ERR_clear_error();
        return res;
    }
    res.info.protocol = SSL_get_version(ssl.get());
    if (const char* c = SSL_get_cipher_name(ssl.get())) res.info.cipher = c;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    X509Ptr cert(SSL_get1_peer_certificate(ssl.get()));
#else
    X509Ptr cert(SSL_get_peer_certificate(ssl.get()));
#endif
    if (cert) {
        TlsInfo& t = res.info;
        t.has_certificate = true;
        t.subject = name_to_string(X509_get_subject_name(cert.get()));
        t.issuer = name_to_string(X509_get_issuer_name(cert.get()));
        t.not_before = time_to_string(X509_get0_notBefore(cert.get()));
        t.not_after = time_to_string(X509_get0_notAfter(cert.get()));
        t.expired = X509_cmp_current_time(X509_get0_notAfter(cert.get())) < 0;
        t.self_signed = X509_check_issued(cert.get(), cert.get()) == X509_V_OK;
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int mdlen = 0;
        if (X509_digest(cert.get(), EVP_sha256(), md, &mdlen) == 1) {
            static const char* hex = "0123456789abcdef";
            for (unsigned i = 0; i < mdlen; ++i) {
                t.sha256.push_back(hex[md[i] >> 4]);
                t.sha256.push_back(hex[md[i] & 0xF]);
            }
        }
        std::unique_ptr<GENERAL_NAMES, Deleter<GENERAL_NAMES, GENERAL_NAMES_free>> sans(
            static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(cert.get(), NID_subject_alt_name, nullptr, nullptr)));
        if (sans) {
            for (int i = 0; i < sk_GENERAL_NAME_num(sans.get()) && t.san.size() < 32; ++i) {
                const GENERAL_NAME* g = sk_GENERAL_NAME_value(sans.get(), i);
                if (g->type != GEN_DNS) continue;
                const unsigned char* d = ASN1_STRING_get0_data(g->d.dNSName);
                const int len = ASN1_STRING_length(g->d.dNSName);
                if (d != nullptr && len > 0) {
                    t.san.push_back(sanitize_ascii(std::string_view(reinterpret_cast<const char*>(d), static_cast<std::size_t>(len)), 255));
                }
            }
        }
    }

    if (send_http_get) {
        const std::string req = "GET / HTTP/1.1\r\nHost: " + http_host + "\r\nUser-Agent: recon/" +
                                std::string(kVersion) + "\r\nConnection: close\r\n\r\n";
        if (drive(ssl.get(), conn->fd(), deadline, [&] {
                return SSL_write(ssl.get(), req.data(), static_cast<int>(req.size()));
            })) {
            char buf[4096];
            while (res.http_response.size() < 8192) {
                int n = 0;
                const bool ok = drive(ssl.get(), conn->fd(), std::min(deadline, Clock::now() + Millis(300)),
                                      [&] { return n = SSL_read(ssl.get(), buf, sizeof(buf)); });
                if (!ok) break;
                res.http_response.append(buf, static_cast<std::size_t>(n));
            }
        }
    }
    res.ok = true;
    return res;
}

}  // namespace recon
#endif  // RECON_WITH_OPENSSL
