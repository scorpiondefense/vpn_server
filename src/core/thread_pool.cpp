#include "vpn/core/thread_pool.hpp"

namespace vpn::core {

ThreadPool::ThreadPool(size_t num_threads) {
    if (num_threads == 0) {
        num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) {
            num_threads = 4;  // Fallback
        }
    }

    workers_.reserve(num_threads);
    for (size_t i = 0; i < num_threads; ++i) {
        workers_.emplace_back(&ThreadPool::worker_loop, this);
    }
}

ThreadPool::~ThreadPool() {
    stop();
}

void ThreadPool::worker_loop() {
    while (true) {
        std::function<void()> task;

        {
            std::unique_lock lock(mutex_);
            condition_.wait(lock, [this] {
                return stop_.load(std::memory_order_relaxed) || !tasks_.empty();
            });

            if (stop_.load(std::memory_order_relaxed) && tasks_.empty()) {
                return;
            }

            if (!tasks_.empty()) {
                task = std::move(tasks_.front());
                tasks_.pop();
                active_tasks_.fetch_add(1, std::memory_order_relaxed);
            }
        }

        if (task) {
            task();
            active_tasks_.fetch_sub(1, std::memory_order_relaxed);
            completion_condition_.notify_all();
        }
    }
}

void ThreadPool::submit_detached(std::function<void()> task) {
    {
        std::lock_guard lock(mutex_);
        if (stop_) {
            return;  // Silently drop if stopped
        }
        tasks_.emplace(std::move(task));
    }
    condition_.notify_one();
}

size_t ThreadPool::pending_tasks() const {
    std::lock_guard lock(mutex_);
    return tasks_.size() + active_tasks_.load(std::memory_order_relaxed);
}

void ThreadPool::wait_all() {
    std::unique_lock lock(mutex_);
    completion_condition_.wait(lock, [this] {
        return tasks_.empty() && active_tasks_.load(std::memory_order_relaxed) == 0;
    });
}

void ThreadPool::stop() {
    {
        std::lock_guard lock(mutex_);
        if (stop_.load(std::memory_order_relaxed)) {
            return;  // Already stopped
        }
        stop_.store(true, std::memory_order_relaxed);
    }

    condition_.notify_all();

    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

} // namespace vpn::core
