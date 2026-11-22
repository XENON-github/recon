#include "recon/json.hpp"

#include <cstdlib>

namespace recon::json {

const std::string Value::empty_;
const std::vector<Value> Value::no_vals_;

const Value* Value::find(std::string_view key) const noexcept {
    if (type_ != Type::Object) return nullptr;
    for (std::size_t i = 0; i < keys_.size(); ++i) {
        if (keys_[i] == key) return &vals_[i];
    }
    return nullptr;
}

namespace {

class Parser {
public:
    Parser(std::string_view s, std::size_t max_depth, std::size_t max_nodes)
        : s_(s), max_depth_(max_depth), max_nodes_(max_nodes) {}

    ParseResult run() {
        ParseResult r;
        skip_ws();
        Value v;
        if (!value(v, 0)) return fail(r);
        skip_ws();
        if (i_ != s_.size()) {
            err_ = "trailing characters after document";
            return fail(r);
        }
        r.value = std::move(v);
        return r;
    }

private:
    ParseResult fail(ParseResult& r) {
        r.error = err_.empty() ? "invalid JSON" : err_;
        r.offset = i_;
        return r;
    }
    bool error(const char* m) {
        err_ = m;
        return false;
    }
    void skip_ws() {
        while (i_ < s_.size() && (s_[i_] == ' ' || s_[i_] == '\t' || s_[i_] == '\n' || s_[i_] == '\r')) ++i_;
    }
    bool literal(std::string_view lit) {
        if (s_.substr(i_, lit.size()) != lit) return error("invalid literal");
        i_ += lit.size();
        return true;
    }

    bool value(Value& out, std::size_t depth) {
        if (++nodes_ > max_nodes_) return error("document has too many values");
        if (i_ >= s_.size()) return error("unexpected end of input");
        const char c = s_[i_];
        if (c == '{') return object(out, depth);
        if (c == '[') return array(out, depth);
        if (c == '"') {
            std::string str;
            if (!string(str)) return false;
            out = Value::make_string(std::move(str));
            return true;
        }
        if (c == 't') { out = Value::make_bool(true); return literal("true"); }
        if (c == 'f') { out = Value::make_bool(false); return literal("false"); }
        if (c == 'n') { out = Value(); return literal("null"); }
        if (c == '-' || (c >= '0' && c <= '9')) return number(out);
        return error("unexpected character");
    }

    bool object(Value& out, std::size_t depth) {
        if (depth + 1 > max_depth_) return error("nesting too deep");
        ++i_;  // '{'
        out = Value::make_object();
        skip_ws();
        if (i_ < s_.size() && s_[i_] == '}') { ++i_; return true; }
        for (;;) {
            skip_ws();
            if (i_ >= s_.size() || s_[i_] != '"') return error("expected object key");
            std::string key;
            if (!string(key)) return false;
            skip_ws();
            if (i_ >= s_.size() || s_[i_] != ':') return error("expected ':'");
            ++i_;
            skip_ws();
            Value v;
            if (!value(v, depth + 1)) return false;
            out.set(std::move(key), std::move(v));
            skip_ws();
            if (i_ >= s_.size()) return error("unterminated object");
            if (s_[i_] == ',') { ++i_; continue; }
            if (s_[i_] == '}') { ++i_; return true; }
            return error("expected ',' or '}'");
        }
    }

    bool array(Value& out, std::size_t depth) {
        if (depth + 1 > max_depth_) return error("nesting too deep");
        ++i_;  // '['
        out = Value::make_array();
        skip_ws();
        if (i_ < s_.size() && s_[i_] == ']') { ++i_; return true; }
        for (;;) {
            skip_ws();
            Value v;
            if (!value(v, depth + 1)) return false;
            out.push(std::move(v));
            skip_ws();
            if (i_ >= s_.size()) return error("unterminated array");
            if (s_[i_] == ',') { ++i_; continue; }
            if (s_[i_] == ']') { ++i_; return true; }
            return error("expected ',' or ']'");
        }
    }

    bool number(Value& out) {
        const std::size_t start = i_;
        if (s_[i_] == '-') ++i_;
        if (i_ >= s_.size()) return error("bad number");
        if (s_[i_] == '0') {
            ++i_;
        } else if (s_[i_] >= '1' && s_[i_] <= '9') {
            while (i_ < s_.size() && is_digit(s_[i_])) ++i_;
        } else {
            return error("bad number");
        }
        if (i_ < s_.size() && s_[i_] == '.') {
            ++i_;
            if (i_ >= s_.size() || !is_digit(s_[i_])) return error("bad fraction");
            while (i_ < s_.size() && is_digit(s_[i_])) ++i_;
        }
        if (i_ < s_.size() && (s_[i_] == 'e' || s_[i_] == 'E')) {
            ++i_;
            if (i_ < s_.size() && (s_[i_] == '+' || s_[i_] == '-')) ++i_;
            if (i_ >= s_.size() || !is_digit(s_[i_])) return error("bad exponent");
            while (i_ < s_.size() && is_digit(s_[i_])) ++i_;
        }
        const std::string tok(s_.substr(start, i_ - start));  // grammar already validated
        out = Value::make_number(std::strtod(tok.c_str(), nullptr));
        return true;
    }

    static bool is_digit(char c) { return c >= '0' && c <= '9'; }

    bool hex4(unsigned& cp) {
        if (s_.size() - i_ < 4) return error("short \\u escape");
        cp = 0;
        for (int k = 0; k < 4; ++k) {
            const char c = s_[i_++];
            cp <<= 4;
            if (c >= '0' && c <= '9') cp |= static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f') cp |= static_cast<unsigned>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') cp |= static_cast<unsigned>(c - 'A' + 10);
            else return error("bad hex digit in \\u escape");
        }
        return true;
    }

    static void put_utf8(std::string& out, unsigned cp) {
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }

    bool string(std::string& out) {
        ++i_;  // opening quote
        while (i_ < s_.size()) {
            const auto c = static_cast<unsigned char>(s_[i_]);
            if (c == '"') { ++i_; return true; }
            if (c < 0x20) return error("control character in string");
            if (c == '\\') {
                if (++i_ >= s_.size()) break;
                const char e = s_[i_++];
                switch (e) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        unsigned cp = 0;
                        if (!hex4(cp)) return false;
                        if (cp >= 0xDC00 && cp <= 0xDFFF) return error("lone low surrogate");
                        if (cp >= 0xD800 && cp <= 0xDBFF) {  // needs a following low surrogate
                            unsigned lo = 0;
                            if (s_.substr(i_, 2) != "\\u") return error("lone high surrogate");
                            i_ += 2;
                            if (!hex4(lo)) return false;
                            if (lo < 0xDC00 || lo > 0xDFFF) return error("invalid surrogate pair");
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        }
                        put_utf8(out, cp);
                        break;
                    }
                    default: return error("invalid escape");
                }
                continue;
            }
            if (c < 0x80) {
                out.push_back(static_cast<char>(c));
                ++i_;
                continue;
            }
            // Validate one multi-byte UTF-8 sequence (no overlong forms, surrogates, > U+10FFFF).
            std::size_t len = 0;
            unsigned cp = 0, min = 0;
            if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1FU; min = 0x80; }
            else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0FU; min = 0x800; }
            else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07U; min = 0x10000; }
            if (len == 0 || i_ + len > s_.size()) return error("invalid UTF-8");
            for (std::size_t k = 1; k < len; ++k) {
                const auto cc = static_cast<unsigned char>(s_[i_ + k]);
                if ((cc & 0xC0) != 0x80) return error("invalid UTF-8");
                cp = (cp << 6) | (cc & 0x3FU);
            }
            if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return error("invalid UTF-8");
            out.append(s_.substr(i_, len));
            i_ += len;
        }
        return error("unterminated string");
    }

    std::string_view s_;
    std::size_t i_ = 0;
    std::size_t max_depth_;
    std::size_t max_nodes_;
    std::size_t nodes_ = 0;
    std::string err_;
};

}  // namespace

ParseResult parse(std::string_view text, std::size_t max_depth, std::size_t max_nodes) {
    return Parser(text, max_depth, max_nodes).run();
}

}  // namespace recon::json
