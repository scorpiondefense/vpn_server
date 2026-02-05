#pragma once

#include <string>
#include <string_view>
#include <source_location>
#include <format>
#include <iostream>
#include <mutex>
#include <chrono>

namespace vpn::util {

enum class LogLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Fatal
};

class Logger {
public:
    static Logger& instance();

    void set_level(LogLevel level) { level_ = level; }
    LogLevel level() const { return level_; }

    void set_show_source(bool show) { show_source_ = show; }

    template<typename... Args>
    void log(LogLevel level, std::format_string<Args...> fmt, Args&&... args) {
        if (level < level_) return;

        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        std::tm tm_buf;
        localtime_r(&time, &tm_buf);

        std::lock_guard lock(mutex_);
        std::cerr << std::format("[{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}.{:03d}] ",
            tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
            tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
            static_cast<int>(ms.count()));
        std::cerr << level_string(level) << " ";
        std::cerr << std::format(fmt, std::forward<Args>(args)...);
        std::cerr << std::endl;
    }

    template<typename... Args>
    void trace(std::format_string<Args...> fmt, Args&&... args) {
        log(LogLevel::Trace, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void debug(std::format_string<Args...> fmt, Args&&... args) {
        log(LogLevel::Debug, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void info(std::format_string<Args...> fmt, Args&&... args) {
        log(LogLevel::Info, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void warning(std::format_string<Args...> fmt, Args&&... args) {
        log(LogLevel::Warning, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void error(std::format_string<Args...> fmt, Args&&... args) {
        log(LogLevel::Error, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void fatal(std::format_string<Args...> fmt, Args&&... args) {
        log(LogLevel::Fatal, fmt, std::forward<Args>(args)...);
    }

private:
    Logger() = default;

    static std::string_view level_string(LogLevel level) {
        switch (level) {
            case LogLevel::Trace: return "[TRACE]";
            case LogLevel::Debug: return "[DEBUG]";
            case LogLevel::Info: return "[INFO] ";
            case LogLevel::Warning: return "[WARN] ";
            case LogLevel::Error: return "[ERROR]";
            case LogLevel::Fatal: return "[FATAL]";
        }
        return "[?????]";
    }

    LogLevel level_ = LogLevel::Info;
    bool show_source_ = false;
    std::mutex mutex_;
};

// Global logging macros
#define LOG_TRACE(...) vpn::util::Logger::instance().trace(__VA_ARGS__)
#define LOG_DEBUG(...) vpn::util::Logger::instance().debug(__VA_ARGS__)
#define LOG_INFO(...) vpn::util::Logger::instance().info(__VA_ARGS__)
#define LOG_WARNING(...) vpn::util::Logger::instance().warning(__VA_ARGS__)
#define LOG_ERROR(...) vpn::util::Logger::instance().error(__VA_ARGS__)
#define LOG_FATAL(...) vpn::util::Logger::instance().fatal(__VA_ARGS__)

} // namespace vpn::util
