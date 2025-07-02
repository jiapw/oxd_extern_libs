#pragma once

// tweak spdlog
#define SPDLOG_LEVEL_NAMES { "TRACE", "DEBUG", "INFOR", "WARNG", "ERROR", "CRITL", "_OFF_" }

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <spdlog/sinks/udp_sink.h>

#ifdef __ANDROID__
#include <spdlog/sinks/android_sink.h>
#endif // __ANDROID__

#include <cstdint>
#include <array>

#if __has_include(<filesystem>)
    #include <filesystem>
    namespace simple_fs = std::filesystem;
#elif __has_include(<experimental/filesystem>)
    #include <experimental/filesystem>
    namespace simple_fs = std::experimental::filesystem;
#else
    #error "Neither <filesystem> nor <experimental/filesystem> is available."
#endif

#include "fmt.hpp"
#include "time.hpp"

/*
constexpr uint64_t generate_crc64_entry(uint64_t index) {
    uint64_t crc = index;
    for (int j = 0; j < 8; ++j) {
        if (crc & 1) {
            crc = (crc >> 1) ^ 0xC96C5795D7870F42; // CRC64 polynomial
        }
        else {
            crc >>= 1;
        }
    }
    return crc;
}

constexpr std::array<uint64_t, 256> generate_crc64_table() {
    std::array<uint64_t, 256> table{};
    for (uint64_t i = 0; i < 256; ++i) {
        table[i] = generate_crc64_entry(i);
    }
    return table;
}

constexpr auto crc64_table = generate_crc64_table();

constexpr uint64_t crc64(const char* data, size_t length) {
    uint64_t crc = 0xFFFFFFFFFFFFFFFF;
    for (size_t i = 0; i < length; ++i) {
        uint8_t index = (crc ^ data[i]) & 0xFF;
        crc = (crc >> 8) ^ crc64_table[index];
    }
    return crc ^ 0xFFFFFFFFFFFFFFFF;
}

template<size_t N>
constexpr uint64_t crc64_compile_time(const char(&str)[N]) {
    return crc64(str, N - 1); // N-1 to exclude null terminator
}
*/

constexpr uint64_t char_as_byte(const char* data, size_t length) 
{
    uint64_t r = 0;
    for (int i = 0; i<length; i++)
    {
        r <<= 8;
        r += (uint8_t)data[i];
    }
    return r;
}

template<size_t N>
constexpr uint64_t short_string_to_uint64_in_compile_time(const char(&str)[N]) 
{
    static_assert((0<N)&&(N<=9), "short_string_to_uint64_in_compile_time(const char(&str)[N]) : length of the parameter str only be from 1 to 8");
    return char_as_byte(str, N - 1); // N-1 to exclude null terminator
}

#ifdef SIMPLE_LOG_NULL
namespace simple
{

using namespace spdlog;

template<uint64_t id>
struct Logger
{
    static inline void FileSink(const std::string& file_path = "")
    {}

    static constexpr level::level_enum Level(level::level_enum lvl)
    {
        return level::level_enum::off;
    }

    static constexpr level::level_enum Level()
    {
        return level::level_enum::off;
    }

    template<typename... Args>
    static inline void Log(level::level_enum lvl, format_string_t<Args...> fmt, Args &&... args)
    {}

    template<typename... Args>
    static inline void Trace(format_string_t<Args...> fmt, Args &&... args)
    {}

    template<typename... Args>
    static inline void Debug(format_string_t<Args...> fmt, Args &&... args)
    {}

    template<typename... Args>
    static inline void Info(format_string_t<Args...> fmt, Args &&... args)
    {}

    template<typename... Args>
    static inline void Warn(format_string_t<Args...> fmt, Args &&... args)
    {}

    template<typename... Args>
    static inline void Error(format_string_t<Args...> fmt, Args &&... args)
    {}

    template<typename... Args>
    static inline void Critical(format_string_t<Args...> fmt, Args &&... args)
    {}
};

} // namespace simple

#else

namespace spdlog {

namespace details {

    namespace severity {
        enum severity_enum : int {
            emergency = 0,
            alert = 1,
            critical = 2,
            error = 3,
            warning = 4,
            notice = 5,
            informational = 6,
            debug = 7,
        };
    }

} // namespace details

class syslog_formatter : public formatter {
public:
    syslog_formatter(int facility, std::string_view hostname, std::string_view appname)
        : facility_(facility)
        , hostname_(hostname)
        , appname_(appname)
        , pattern_formatter_("%Y-%m-%dT%H:%M:%S.%eZ", pattern_time_type::utc, "")
    {
        pattern_formatter_.need_localtime();
    }

    syslog_formatter(const syslog_formatter& other) = delete;
    syslog_formatter& operator=(const syslog_formatter& other) = delete;

    std::unique_ptr<formatter> clone() const override
    {
        auto cloned = std::make_unique<syslog_formatter>(facility_, hostname_, appname_);
        return cloned;
    }

    void format(const details::log_msg& msg, memory_buf_t& dest) override
    {
        details::severity::severity_enum severity;

        switch (msg.level) {
        case level::critical:
            severity = details::severity::critical;
            break;

        case level::err:
            severity = details::severity::error;
            break;

        case level::warn:
            severity = details::severity::warning;
            break;

        case level::info:
            severity = details::severity::informational;
            break;

        default:
            severity = details::severity::debug;
            break;
        }

        dest.push_back('<');
        details::fmt_helper::append_int((facility_ * 8) + severity, dest);
        dest.push_back('>');

        dest.push_back('1');

        dest.push_back(' ');
        pattern_formatter_.format(msg, dest);

        dest.push_back(' ');
        if (hostname_.empty()) {
            dest.push_back('-');
        }
        else {
            details::fmt_helper::append_string_view(hostname_, dest);
        }

        dest.push_back(' ');
        if (appname_.empty()) {
            dest.push_back('-');
        }
        else {
            details::fmt_helper::append_string_view(appname_, dest);
        }

        dest.push_back(' ');
        details::fmt_helper::append_int(details::os::pid(), dest);

        dest.push_back(' ');
        if (msg.logger_name.size() == 0) {
            dest.push_back('-');
        }
        else {
            details::fmt_helper::append_string_view(msg.logger_name, dest);
        }

        dest.push_back(' ');
        dest.push_back('-'); // nil structured data

        dest.push_back(' ');
        details::fmt_helper::append_string_view(msg.payload, dest);
    }

private:
    int facility_;
    std::string hostname_;
    std::string appname_;
    spdlog::pattern_formatter pattern_formatter_;
};

} // namespace spdlog

namespace simple
{

using namespace spdlog;

struct GlobalFileSink
{
    static std::shared_ptr<spdlog::sinks::basic_file_sink_mt> SingleInstance()
    {
        static std::shared_ptr<spdlog::sinks::basic_file_sink_mt> gfs;
        if (!gfs)
        {
            simple_fs::path temp_dir = simple_fs::temp_directory_path();
            uint64_t pid =
#ifdef _WIN32
                GetCurrentProcessId(); // Windows
#else
                getpid(); // Linux/Unix
#endif
            std::string temp_name = fmt::format("pid_{}_{}.log", pid, simple::ms::now());
            simple_fs::path full_path = temp_dir / temp_name;
            gfs = std::make_shared<spdlog::sinks::basic_file_sink_mt>(full_path.string());
        }
        return gfs;
    }

};

template<uint64_t id>
struct Logger
{
    typedef Logger<id> _LOG;

    static const std::string& GetLoggerName()
    {
        static std::string r;
        if (r.empty())
        {
            uint64_t t = id;
            for (int i = 0; i < 8; i++)
            {
                if (char c = t & 0xff)
                    r.insert(0, 1, c);
                t >>= 8;
            }

        }
        return r;
    }

    static std::shared_ptr<spdlog::logger> SingleInstance()
    {
        static struct SI
        {
            std::shared_ptr<spdlog::logger> logger;
            SI()
            {
                auto color_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

                // supported console types: windows & unix-base
                {
                    #ifdef _WIN32
                        color_sink->set_color(spdlog::level::trace, FOREGROUND_INTENSITY);
                    #else
                        color_sink->set_color(spdlog::level::trace, "\033[2m");
                    #endif // _WIN32
                }

                logger = std::make_shared<spdlog::logger>(GetLoggerName(), color_sink);

                // android requires a special sink
                {
                    #ifdef __ANDROID__
                        auto my_android_sink = std::make_shared<spdlog::sinks::android_sink_mt>();
                        logger->sinks().push_back(my_android_sink);
                    #endif // __ANDROID__
                }

                // default level
                {
                    #if defined(DEBUG) || defined(_DEBUG)
                        logger->set_level(spdlog::level::trace);
                    #else
                        logger->set_level(spdlog::level::off);
                    #endif // DEBUG
                }

            }
            ~SI()
            {
                logger = nullptr;
            }
        } _si;
        return _si.logger;
    }

    static level::level_enum Level(level::level_enum lvl)
    {
        SingleInstance()->set_level(lvl);
        return Level();
    }

    static level::level_enum Level()
    {
        return SingleInstance()->level();
    }

    // If file_path is empty, the auto-named file in the temporary path is used.
    static void FileSink(const std::string& file_path = "")
    {
        std::shared_ptr<spdlog::sinks::basic_file_sink_mt> sink;
        if (file_path.empty())
        {
            static bool global_added = false;
            if (global_added)
                return;
            global_added = true;

            sink = GlobalFileSink::SingleInstance();
        }
        else
            sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(file_path);

        auto obj = SingleInstance();
        obj->sinks().push_back(sink);
        Info(
            file_path.empty() ? "add auto-named file sink : {}" : "add specific file sink : {}",
            sink->filename()
        );
    }

    static void UdpSink(const std::string_view host, const uint16_t port)
    {
        spdlog::sinks::udp_sink_config cfg = { std::string(host), port };
        auto sink = std::make_shared<spdlog::sinks::udp_sink_mt>(cfg);

        spdlog::syslog_formatter syslog_formatter(1, "localhost", "example"); // 1 means "user" in syslog
        sink->set_formatter(syslog_formatter.clone());

        auto obj = SingleInstance();
        obj->sinks().push_back(sink);
        Info( "add UDP sink, sendto: {}:{}", host, port);
    }

    template<typename... Args>
    static void Log(level::level_enum lvl, format_string_t<Args...> fmt, Args &&... args)
    {
        if (auto si = SingleInstance())
            si->log(lvl, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void Trace(format_string_t<Args...> fmt, Args &&... args)
    {
        if (auto si = SingleInstance())
            si->log(level::trace, fmt, std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    static void Debug(format_string_t<Args...> fmt, Args &&... args)
    {
        if (auto si = SingleInstance())
            si->log(level::debug, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void Info(format_string_t<Args...> fmt, Args &&... args)
    {
        if (auto si = SingleInstance())
            si->log(level::info, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void Warn(format_string_t<Args...> fmt, Args &&... args)
    {
        if (auto si = SingleInstance())
            si->log(level::warn, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void Error(format_string_t<Args...> fmt, Args &&... args)
    {
        if (auto si = SingleInstance())
            si->log(level::err, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void Critical(format_string_t<Args...> fmt, Args &&... args)
    {
        if (auto si = SingleInstance())
            si->log(level::critical, fmt, std::forward<Args>(args)...);
    }

};

} // namespace simple

#endif // SIMPLE_LOG_NULL

#define LOG_DEFINE(logger) using logger = simple::Logger<short_string_to_uint64_in_compile_time(#logger)>

namespace simple
{

inline void test_logger()
{
    LOG_DEFINE(FOO);
    FOO::FileSink();
    FOO::FileSink();
    FOO::FileSink("foo.log");

    FOO::UdpSink("192.168.218.39", 514);

    FOO::Log(spdlog::level::info, "start with level({})", (int)FOO::Level());
    FOO::Log(spdlog::level::info, "set level({})", (int)FOO::Level(spdlog::level::trace));
    FOO::Trace("this is {}", "trace");
    FOO::Debug("this is {}", "debug");
    FOO::Info("this is {}", "info");
    FOO::Warn("this is {}", "warn");
    FOO::Error("this is {}", "error");
    FOO::Critical("this is {}", "critical");
    FOO::Log(spdlog::level::off, "this is {}", "off");

    LOG_DEFINE(FOO);
    FOO::Info("We can define LOG_DEFINE(FOO) multiple times!");

    LOG_DEFINE(FOOLISH);
    FOOLISH::FileSink();
    FOOLISH::FileSink("foolish.log");
    FOOLISH::Info("FOOLSIH info");

}

}
