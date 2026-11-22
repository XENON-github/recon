#include <csignal>
#include <cstring>

#include "testing.hpp"

int main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_DFL);  // deliberately NOT ignored: library code must not raise it
    const char* filter = argc > 1 ? argv[1] : nullptr;
    int run = 0;
    for (auto& c : testing::registry()) {
        if (filter != nullptr && std::strstr(c.name, filter) == nullptr) continue;
        const int before = testing::failures();
        c.fn();
        std::printf("[%s] %s\n", testing::failures() == before ? " OK " : "FAIL", c.name);
        ++run;
    }
    std::printf("%d test(s) run, %d failure(s)\n", run, testing::failures());
    return testing::failures() == 0 ? 0 : 1;
}
