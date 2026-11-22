// Bounded worker pool. Uses std::jthread where the standard library provides it and falls back
// to a small join-on-destroy wrapper for C++17 builds, so threads are always joined (RAII).
#pragma once

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>
#if __has_include(<version>)
#include <version>
#endif

namespace recon {

#if defined(__cpp_lib_jthread) && __cpp_lib_jthread >= 201911L
using JoiningThread = std::jthread;
inline constexpr bool kHasJthread = true;
#else
class JoiningThread {
public:
    JoiningThread() = default;
    template <class F>
    explicit JoiningThread(F&& f) : t_(std::forward<F>(f)) {}
    JoiningThread(JoiningThread&&) noexcept = default;
    JoiningThread& operator=(JoiningThread&& o) noexcept {
        if (this != &o) {
            join();
            t_ = std::move(o.t_);
        }
        return *this;
    }
    ~JoiningThread() { join(); }
    void join() {
        if (t_.joinable()) t_.join();
    }

private:
    std::thread t_;
};
inline constexpr bool kHasJthread = false;
#endif

// Fixed-size pool with a bounded queue: submit() blocks when the queue is full, giving the
// producer natural back-pressure instead of unbounded memory growth.
class ThreadPool {
public:
    ThreadPool(std::size_t workers, std::size_t queue_capacity)
        : capacity_(queue_capacity == 0 ? 1 : queue_capacity) {
        workers_.reserve(workers == 0 ? 1 : workers);
        for (std::size_t i = 0; i < (workers == 0 ? 1 : workers); ++i) {
            workers_.emplace_back([this] { run(); });
        }
    }
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ~ThreadPool() { shutdown(); }

    // Returns false if the pool is shutting down (job not queued).
    bool submit(std::function<void()> job) {
        std::unique_lock<std::mutex> lk(m_);
        not_full_.wait(lk, [&] { return queue_.size() < capacity_ || stop_; });
        if (stop_) return false;
        queue_.push_back(std::move(job));
        not_empty_.notify_one();
        return true;
    }

    // Blocks until the queue is empty and no job is running.
    void wait_idle() {
        std::unique_lock<std::mutex> lk(m_);
        idle_.wait(lk, [&] { return queue_.empty() && active_ == 0; });
    }

    // Finishes queued jobs, then joins all workers. Idempotent.
    void shutdown() {
        {
            std::lock_guard<std::mutex> lk(m_);
            stop_ = true;
        }
        not_empty_.notify_all();
        not_full_.notify_all();
        workers_.clear();  // joins via ~JoiningThread / ~jthread
    }

    // Number of jobs that exited via an exception (swallowed so one bad job cannot terminate()).
    [[nodiscard]] std::size_t failed_jobs() const {
        std::lock_guard<std::mutex> lk(m_);
        return failed_;
    }

private:
    void run() {
        for (;;) {
            std::function<void()> job;
            {
                std::unique_lock<std::mutex> lk(m_);
                not_empty_.wait(lk, [&] { return !queue_.empty() || stop_; });
                if (queue_.empty()) return;  // stop_ && drained
                job = std::move(queue_.front());
                queue_.pop_front();
                ++active_;
                not_full_.notify_one();
            }
            bool threw = false;
            try {
                job();
            } catch (...) {
                threw = true;
            }
            {
                std::lock_guard<std::mutex> lk(m_);
                --active_;
                if (threw) ++failed_;
                if (queue_.empty() && active_ == 0) idle_.notify_all();
            }
        }
    }

    const std::size_t capacity_;
    mutable std::mutex m_;
    std::condition_variable not_empty_, not_full_, idle_;
    std::deque<std::function<void()>> queue_;
    std::size_t active_ = 0;
    std::size_t failed_ = 0;
    bool stop_ = false;
    std::vector<JoiningThread> workers_;  // declared last: destroyed (joined) first
};

}  // namespace recon
