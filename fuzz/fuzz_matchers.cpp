// libFuzzer target: every protocol matcher on arbitrary bytes. Must never crash, hang or trip a sanitizer.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <string_view>

#include "recon/detect.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace recon;
    const std::string_view in(reinterpret_cast<const char*>(data), size);
    static constexpr Matcher kAll[] = {match_ssh,  match_ftp,    match_smtp,  match_pop3,  match_imap,
                                       match_mysql, match_vnc,    match_telnet, match_http, match_tls,
                                       match_redis, match_postgres, match_smb2};
    int index = 0;
    for (Matcher m : kAll) {
        for (std::uint16_t port : {std::uint16_t{22}, std::uint16_t{443}, std::uint16_t{6379}}) {
            if (auto d = m(in, port)) {
                // Matchers promise sanitized, bounded text; assert it so the fuzzer can find violations.
                const std::pair<const char*, const std::string*> fields[] = {
                    {"product", &d->product}, {"version", &d->version}, {"extra", &d->extra},
                    {"banner", &d->banner},   {"os_hint", &d->os_hint}};
                for (const auto& [name, text] : fields) {
                    for (char c : *text) {
                        if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) > 0x7E) {
                            std::fprintf(stderr, "INVARIANT: matcher #%d port %u field %s has byte 0x%02x\n", index,
                                         static_cast<unsigned>(port), name, static_cast<unsigned>(static_cast<unsigned char>(c)));
                            __builtin_trap();
                        }
                    }
                }
                if (d->banner.size() > 200 || d->confidence < 0 || d->confidence > 100) {
                    std::fprintf(stderr, "INVARIANT: matcher #%d banner len %zu confidence %d\n", index, d->banner.size(), d->confidence);
                    __builtin_trap();
                }
            }
        }
        ++index;
    }
    for (std::uint16_t port : {std::uint16_t{53}, std::uint16_t{123}, std::uint16_t{137}, std::uint16_t{9}}) {
        (void)match_udp_response(port, in);
    }
    return 0;
}
