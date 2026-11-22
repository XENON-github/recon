// Minimal dependency-free test framework (keeps the build hermetic: no network fetch needed).
#pragma once

#include <cstdio>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace testing {

struct Case {
    const char* name;
    std::function<void()> fn;
};
inline std::vector<Case>& registry() {
    static std::vector<Case> r;
    return r;
}
inline int& failures() {
    static int f = 0;
    return f;
}
struct Registrar {
    Registrar(const char* n, std::function<void()> f) { registry().push_back({n, std::move(f)}); }
};

template <class T>
std::string show(const T& v) {
    std::ostringstream o;
    o << v;
    return o.str();
}

template <class T>
std::string show(const std::vector<T>& v) {
    std::string s = "{";
    for (std::size_t i = 0; i < v.size(); ++i) s += (i ? ", " : "") + show(v[i]);
    return s + "}";
}

}  // namespace testing

#define TEST(name)                                                    \
    static void test_##name();                                        \
    static ::testing::Registrar reg_##name(#name, test_##name);       \
    static void test_##name()

#define CHECK(cond)                                                                       \
    do {                                                                                  \
        if (!(cond)) {                                                                    \
            std::fprintf(stderr, "  FAIL %s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond); \
            ++::testing::failures();                                                      \
        }                                                                                 \
    } while (0)

#define CHECK_EQ(a, b)                                                                          \
    do {                                                                                        \
        const auto& va_ = (a);                                                                  \
        const auto& vb_ = (b);                                                                  \
        if (!(va_ == vb_)) {                                                                    \
            std::fprintf(stderr, "  FAIL %s:%d: %s == %s\n    lhs: %s\n    rhs: %s\n", __FILE__, \
                         __LINE__, #a, #b, ::testing::show(va_).c_str(),                        \
                         ::testing::show(vb_).c_str());                                         \
            ++::testing::failures();                                                            \
        }                                                                                       \
    } while (0)
