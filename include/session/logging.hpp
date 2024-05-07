#pragma once

#include <functional>
#include <string_view>

#include "log_level.h"

// forward declaration
namespace spdlog::level {
enum level_enum : int;
}

namespace session {

// This is working roughly like an enum class, but with some useful conversions and comparisons
// defined.  We allow implicit conversion to this from a spdlog level_enum, and explicit conversion
// *to* a level_enum, as well as comparison operators (so that, for example, LogLevel::warn >=
// LogLevel::info).
struct LogLevel {
    int level;

    LogLevel(spdlog::level::level_enum lvl);
    explicit constexpr LogLevel(int lvl) : level{lvl} {}

    explicit operator spdlog::level::level_enum() const;

    static const LogLevel trace;
    static const LogLevel debug;
    static const LogLevel info;
    static const LogLevel warn;
    static const LogLevel error;
    static const LogLevel critical;

    auto operator<=>(const LogLevel& other) const { return level <=> other.level; }
};

inline const LogLevel LogLevel::trace{LOG_LEVEL_TRACE};
inline const LogLevel LogLevel::debug{LOG_LEVEL_DEBUG};
inline const LogLevel LogLevel::info{LOG_LEVEL_INFO};
inline const LogLevel LogLevel::warn{LOG_LEVEL_WARN};
inline const LogLevel LogLevel::error{LOG_LEVEL_ERROR};
inline const LogLevel LogLevel::critical{LOG_LEVEL_CRITICAL};

/// API: add_logger
///
/// Adds a logger callback for oxen-logging log messages (such as from the network object).
///
/// Inputs:
/// - `callback` -- [in] callback to be called when a new message should be logged.  This
///   callback must be callable as one of:
///
///     callback(std::string_view msg)
///     callback(std::string_view msg, std::string_view log_cat, LogLevel level)
///
void add_logger(std::function<void(std::string_view msg)> cb);
void add_logger(
        std::function<void(std::string_view msg, std::string_view category, LogLevel level)> cb);

}  // namespace session
