// Internal helpers: bounds-checked byte reader and small text utilities.
#pragma once

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>
#include <string_view>

namespace recon::detail {

// Sequential big-endian reader that can never read past the end of its buffer.
class Reader {
public:
    explicit Reader(std::string_view d) : d_(d) {}
    [[nodiscard]] std::size_t remaining() const { return d_.size() - pos_; }
    bool u8(std::uint8_t& v) {
        if (remaining() < 1) return false;
        v = static_cast<std::uint8_t>(d_[pos_++]);
        return true;
    }
    bool u16(std::uint16_t& v) {
        if (remaining() < 2) return false;
        v = static_cast<std::uint16_t>((static_cast<std::uint8_t>(d_[pos_]) << 8) |
                                       static_cast<std::uint8_t>(d_[pos_ + 1]));
        pos_ += 2;
        return true;
    }
    bool u24(std::uint32_t& v) {
        if (remaining() < 3) return false;
        v = (static_cast<std::uint32_t>(static_cast<std::uint8_t>(d_[pos_])) << 16) |
            (static_cast<std::uint32_t>(static_cast<std::uint8_t>(d_[pos_ + 1])) << 8) |
            static_cast<std::uint8_t>(d_[pos_ + 2]);
        pos_ += 3;
        return true;
    }
    bool u32(std::uint32_t& v) {
        if (remaining() < 4) return false;
        v = 0;
        for (int i = 0; i < 4; ++i) v = (v << 8) | static_cast<std::uint8_t>(d_[pos_ + static_cast<std::size_t>(i)]);
        pos_ += 4;
        return true;
    }
    bool skip(std::size_t n) {
        if (remaining() < n) return false;
        pos_ += n;
        return true;
    }
    bool take(std::size_t n, std::string_view& out) {
        if (remaining() < n) return false;
        out = d_.substr(pos_, n);
        pos_ += n;
        return true;
    }

private:
    std::string_view d_;
    std::size_t pos_ = 0;
};

inline char lower(char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); }

inline std::string to_lower(std::string_view s) {
    std::string r(s);
    std::transform(r.begin(), r.end(), r.begin(), lower);
    return r;
}

inline bool istarts_with(std::string_view s, std::string_view p) {
    return s.size() >= p.size() &&
           std::equal(p.begin(), p.end(), s.begin(), [](char a, char b) { return lower(a) == lower(b); });
}

inline std::string_view trim(std::string_view s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
    return s;
}

inline std::string_view first_line(std::string_view s) {
    const auto e = s.find_first_of("\r\n");
    return e == std::string_view::npos ? s : s.substr(0, e);
}

inline bool is_digit(char c) { return c >= '0' && c <= '9'; }

}  // namespace recon::detail
