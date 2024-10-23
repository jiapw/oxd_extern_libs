#pragma once

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <cstdint>
#include <array>
#include <filesystem>
#include "fmt.hpp"
#include "time.hpp"

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
    static_assert((0<N)&&(N<9), "short_string_to_uint64_in_compile_time(const char(&str)[N]) : length of the parameter str only be from 1 to 8");
    return char_as_byte(str, N - 1); // N-1 to exclude null terminator
}

namespace simple
{

using namespace spdlog;

std::shared_ptr<spdlog::sinks::basic_file_sink_mt> global_file_sink()
{
    static std::shared_ptr<spdlog::sinks::basic_file_sink_mt> gfs;
    if (!gfs)
    {
        std::filesystem::path temp_dir = std::filesystem::temp_directory_path();
        uint64_t pid =
#ifdef _WIN32
            GetCurrentProcessId(); // Windows
#else
            getpid(); // Linux/Unix
#endif
        std::string temp_name = fmt::format("pid_{}_{}.log", pid, simple::ms::now());
        std::filesystem::path full_path = temp_dir / temp_name;
        gfs = std::make_shared<spdlog::sinks::basic_file_sink_mt>(full_path.string());
    }
    return gfs;
}

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
        static auto _ = std::make_shared<spdlog::logger>(GetLoggerName(), std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
        return _;
    }

    static level::level_enum LEVEL(level::level_enum lvl)
    {
        SingleInstance()->set_level(lvl);
        return LEVEL();
    }

    static level::level_enum LEVEL()
    {
        return SingleInstance()->level();
    }

    // If file_path is empty, the auto-named file in the temporary path is used.
    static void FILESINK(const std::string& file_path = "")
    {
        std::shared_ptr<spdlog::sinks::basic_file_sink_mt> sink;
        if (file_path.empty())
        {
            static bool global_added = false;
            if (global_added)
                return;
            global_added = true;

            sink = global_file_sink();
        }
        else
            sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(file_path);

        auto obj = SingleInstance();
        obj->sinks().push_back(sink);
        INFO("write file : {}", sink->filename());
    }

    template<typename... Args>
    static void LOG(level::level_enum lvl, format_string_t<Args...> fmt, Args &&... args)
    {
        SingleInstance()->log(lvl, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void TRACE(format_string_t<Args...> fmt, Args &&... args)
    {
        SingleInstance()->log(level::trace, fmt, std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    static void DEBUG(format_string_t<Args...> fmt, Args &&... args)
    {
        SingleInstance()->log(level::debug, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void INFO(format_string_t<Args...> fmt, Args &&... args)
    {
        SingleInstance()->log(level::info, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void WARN(format_string_t<Args...> fmt, Args &&... args)
    {
        SingleInstance()->log(level::warn, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void ERR(format_string_t<Args...> fmt, Args &&... args)
    {
        SingleInstance()->log(level::err, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void CRITICAL(format_string_t<Args...> fmt, Args &&... args)
    {
        SingleInstance()->log(level::critical, fmt, std::forward<Args>(args)...);
    }

};

} // namespace simple

#define LOG_DEFINE(logger) using logger = simple::Logger<short_string_to_uint64_in_compile_time(#logger)>

namespace level = spdlog::level;

namespace simple
{

void test_logger()
{
    LOG_DEFINE(FOO);
    FOO::FILESINK();
    FOO::FILESINK();
    FOO::FILESINK("foo.log");

    FOO::LOG(level::info, "start with level({})", FOO::LEVEL());
    FOO::LOG(level::info, "set level({})", FOO::LEVEL(level::trace));
    FOO::TRACE("this is {}", "trace");
    FOO::DEBUG("this is {}", "debug");
    FOO::INFO("this is {}", "info");
    FOO::WARN("this is {}", "warn");
    FOO::ERR("this is {}", "error");
    FOO::CRITICAL("this is {}", "critical");

    LOG_DEFINE(FOO);
    FOO::INFO("We can define LOG_DEFINE(FOO) multiple times!");

    LOG_DEFINE(FOOLISH);
    FOOLISH::FILESINK();
    FOOLISH::FILESINK("foolish.log");
    FOOLISH::INFO("FOOLSIH info");

}

}
