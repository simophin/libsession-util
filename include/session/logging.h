#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <cstddef>

#include "export.h"
#include "log_level.h"

/// API: network/network_add_logger_simple
///
/// Adds a logger to the network object.  The callback is invoked with just the log message.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object
/// - `callback` -- [in] callback to be called when a new message should be logged.
LIBSESSION_EXPORT void network_add_logger_simple(void (*callback)(const char* msg, size_t msglen));

/// API: network/network_add_logger_full
///
/// Adds a logger to the network object.  The callback is invoked with the log message, the
/// category name of the log message, and the level of the message.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object
/// - `callback` -- [in] callback to be called when a new message should be logged.

LIBSESSION_EXPORT void network_add_logger_full(void (*callback)(
        const char* msg, size_t msglen, const char* cat, size_t can_len, LOG_LEVEL level));

#ifdef __cplusplus
}
#endif
