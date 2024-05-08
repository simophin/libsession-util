#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#include "export.h"
#include "log_level.h"

/// API: session/session_add_logger_simple
///
/// Registers a callback that is invoked when a message is logged.  This callback is invoked with just the log message.
///
/// Inputs:
/// - `callback` -- [in] callback to be called when a new message should be logged.
LIBSESSION_EXPORT void session_add_logger_simple(void (*callback)(const char* msg, size_t msglen));

/// API: session/session_add_logger_full
///
/// Registers a callback that is invoked when a message is logged.  The callback is invoked with the log message, the
/// category name of the log message, and the level of the message.
///
/// Inputs:
/// - `callback` -- [in] callback to be called when a new message should be logged.
LIBSESSION_EXPORT void session_add_logger_full(void (*callback)(
        const char* msg, size_t msglen, const char* cat, size_t can_len, LOG_LEVEL level));

#ifdef __cplusplus
}
#endif
