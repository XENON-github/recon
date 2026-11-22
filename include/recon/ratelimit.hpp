// Thread-safe token bucket used to cap new connection/probe rate.
#pragma once

#include <algorithm>
#include <mutex>
#include <thread>

#include "recon/common.hpp"

namespace recon {

class RateLimiter {
public:
    // per_second <= 0 means unlimited.
    explicit RateLimiter(double per_second)
        : rate_(per_second), burst_(std::max(1.0, per_second / 20.0)), tokens_(burst_),
          last_(Clock::now()) {}

    [[nodiscard]] bool unlimited() const noexcept { return rate_ <= 0.0; }

    bool try_acquire() {
        if (unlimited()) return true;
        std::lock_guard<std::mutex> lk(m_);
        refill();
        if (tokens_ >= 1.0) {
            tokens_ -= 1.0;
            return true;
        }
        return false;
    }

    // Time until one token will be available (zero if available now).
    Clock::duration time_to_next() {
        if (unlimited()) return Clock::duration::zero();
        std::lock_guard<std::mutex> lk(m_);
        refill();
        if (tokens_ >= 1.0) return Clock::duration::zero();
        const double secs = (1.0 - tokens_) / rate_;
        return std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(secs));
    }

    // Blocking acquire for worker threads. Returns false if cancelled.
    bool acquire(const CancelToken& cancel) {
        while (!cancel.requested()) {
            if (try_acquire()) return true;
            const auto wait = std::min<Clock::duration>(time_to_next(), Millis(50));
            std::this_thread::sleep_for(std::max<Clock::duration>(wait, std::chrono::microseconds(200)));
        }
        return false;
    }

private:
    void refill() {
        const auto now = Clock::now();
        const double dt = std::chrono::duration<double>(now - last_).count();
        last_ = now;
        tokens_ = std::min(burst_, tokens_ + dt * rate_);
    }

    double rate_;
    double burst_;
    double tokens_;
    Clock::time_point last_;
    std::mutex m_;
};

}  // namespace recon
