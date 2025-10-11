#pragma once
#include <spdlog/fmt/fmt.h>

template <>
struct fmt::formatter<std::error_code> : fmt::formatter<std::string> {
    auto format(const std::error_code& ec, fmt::format_context& ctx) const {
        return fmt::formatter<std::string>::format(
            fmt::format("{}: {} ({})", ec.category().name(), ec.value(), ec.message()), ctx
        );
    }
};
