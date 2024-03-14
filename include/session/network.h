#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "export.h"

typedef struct remote_address {
    char pubkey[67];  // in hex; 66 hex chars + null terminator.
    char ip[16];      // 15 chars + null terminator.
    uint16_t port;
} remote_address;

LIBSESSION_EXPORT void network_send_request(
        const unsigned char* ed25519_secretkey_bytes,
        const remote_address remote,
        const char* endpoint,
        size_t endpoint_size,
        const unsigned char* body,
        size_t body_size,
        void (*callback)(
                bool success,
                int16_t status_code,
                const char* response,
                size_t response_size,
                void*),
        void* ctx);

#ifdef __cplusplus
}
#endif
