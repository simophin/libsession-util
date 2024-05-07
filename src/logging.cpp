#include "session/logging.hpp"

#include <memory>
#include <oxen/log.hpp>
#include <oxen/log/formatted_callback_sink.hpp>
#include <type_traits>

#include "oxen/log/level.hpp"
#include "session/export.h"

namespace session {

LogLevel::LogLevel(spdlog::level::level_enum lvl) : level{static_cast<int>(lvl)} {}

void add_logger(std::function<void(std::string_view msg)> cb) {
    oxen::log::add_sink(std::make_shared<oxen::log::formatted_callback_sink>(std::move(cb)));
}
void add_logger(
        std::function<void(std::string_view msg, std::string_view category, LogLevel level)> cb) {
    oxen::log::add_sink(std::make_shared<oxen::log::formatted_callback_sink>(std::move(cb)));
}

}  // namespace session

LIBSESSION_EXPORT void network_add_logger_simple(void (*callback)(const char* msg, size_t msglen)) {
    assert(callback);
    session::add_logger([cb = callback](std::string_view msg) { cb(msg.data(), msg.size()); });
}

LIBSESSION_EXPORT void network_add_logger_full(void (*callback)(
        const char* msg, size_t msglen, const char* cat, size_t can_len, LOG_LEVEL level)) {
    assert(callback);
    session::add_logger(
            [cb = callback](
                    std::string_view msg, std::string_view category, session::LogLevel level) {
                cb(msg.data(),
                   msg.size(),
                   category.data(),
                   category.size(),
                   static_cast<LOG_LEVEL>(level.level));
            });
}
