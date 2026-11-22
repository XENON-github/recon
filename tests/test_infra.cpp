#include <atomic>
#include <chrono>

#include "recon/pool.hpp"
#include "recon/ratelimit.hpp"
#include "testing.hpp"

using namespace recon;

TEST(pool_runs_everything_exactly_once) {
    std::atomic<int> sum{0};
    {
        ThreadPool pool(8, 16);
        for (int i = 1; i <= 2000; ++i) CHECK(pool.submit([&sum, i] { sum += i; }));
        pool.wait_idle();
        CHECK_EQ(sum.load(), 2000 * 2001 / 2);
    }
}

TEST(pool_is_bounded_and_applies_backpressure) {
    std::atomic<int> running{0}, peak{0};
    ThreadPool pool(3, 2);
    for (int i = 0; i < 30; ++i) {
        pool.submit([&] {
            const int now = ++running;
            int p = peak.load();
            while (now > p && !peak.compare_exchange_weak(p, now)) {}
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            --running;
        });
    }
    pool.wait_idle();
    CHECK(peak.load() <= 3);
    CHECK(peak.load() >= 1);
}

TEST(pool_survives_throwing_jobs) {
    std::atomic<int> ok{0};
    ThreadPool pool(2, 4);
    for (int i = 0; i < 20; ++i) {
        pool.submit([&, i] { if (i % 2) throw std::runtime_error("boom"); ++ok; });
    }
    pool.wait_idle();
    CHECK_EQ(ok.load(), 10);
    CHECK_EQ(pool.failed_jobs(), std::size_t(10));
}

TEST(pool_shutdown_drains_and_rejects_new_work) {
    std::atomic<int> n{0};
    ThreadPool pool(2, 64);
    for (int i = 0; i < 50; ++i) pool.submit([&] { ++n; });
    pool.shutdown();
    CHECK_EQ(n.load(), 50);
    CHECK(!pool.submit([] {}));
    pool.shutdown();  // idempotent
}

TEST(ratelimiter_enforces_rate) {
    RateLimiter rl(200.0);  // burst = 10
    CancelToken c;
    const auto t0 = Clock::now();
    for (int i = 0; i < 50; ++i) CHECK(rl.acquire(c));
    const double secs = std::chrono::duration<double>(Clock::now() - t0).count();
    CHECK(secs >= 0.15);  // (50 - 10 burst) / 200 = 0.2 s
    CHECK(secs < 1.0);
}

TEST(ratelimiter_unlimited_and_cancel) {
    RateLimiter unl(0.0);
    for (int i = 0; i < 100000; ++i) CHECK(unl.try_acquire());
    RateLimiter slow(1.0);
    CancelToken c;
    CHECK(slow.acquire(c));  // burst token
    c.request();
    CHECK(!slow.acquire(c));  // would otherwise wait a full second
}
