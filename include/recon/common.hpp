// Shared primitives: clock aliases, version, cooperative cancellation.
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>

namespace recon {

using Clock = std::chrono::steady_clock;
using Millis = std::chrono::milliseconds;

inline constexpr const char* kVersion = "2.1.0";

// Cooperative cancellation flag. Safe to set from a signal handler (the
// underlying atomic is lock-free) and to poll from any thread.
class CancelToken {
public:
    void request() noexcept { flag_.store(true, std::memory_order_relaxed); }
    [[nodiscard]] bool requested() const noexcept { return flag_.load(std::memory_order_relaxed); }

private:
    std::atomic<bool> flag_{false};
};
static_assert(std::atomic<bool>::is_always_lock_free,
              "CancelToken must be async-signal-safe");

}  // namespace recon
