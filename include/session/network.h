#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "export.h"
#include "onionreq/builder.h"

typedef struct remote_address {
    char pubkey[65];  // in hex; 64 hex chars + null terminator.
    char ip[40];      // IPv4 is 15 chars, IPv6 is 39 chars, + null terminator.
    uint16_t port;
} remote_address;

LIBSESSION_EXPORT void network_add_logger(void (*callback)(const char*, size_t));

LIBSESSION_EXPORT void network_send_request(
        const unsigned char* ed25519_secretkey_bytes,
        const remote_address remote,
        const char* endpoint,
        size_t endpoint_size,
        const unsigned char* body,
        size_t body_size,
        void (*callback)(
                bool success,
                bool timeout,
                int16_t status_code,
                const char* response,
                size_t response_size,
                void*),
        void* ctx);

LIBSESSION_EXPORT void network_send_onion_request_to_snode_destination(
        const onion_request_path path,
        const unsigned char* ed25519_secretkey_bytes,
        const onion_request_service_node node,
        const unsigned char* body,
        size_t body_size,
        void (*callback)(
                bool success,
                bool timeout,
                int16_t status_code,
                const char* response,
                size_t response_size,
                void*),
        void* ctx);

LIBSESSION_EXPORT void network_send_onion_request_to_server_destination(
        const onion_request_path path,
        const unsigned char* ed25519_secretkey_bytes,
        const char* method,
        const char* host,
        const char* target,
        const char* protocol,
        const char* x25519_pubkey,
        uint16_t port,
        const char** headers_,
        const char** header_values,
        size_t headers_size,
        const unsigned char* body,
        size_t body_size,
        void (*callback)(
                bool success,
                bool timeout,
                int16_t status_code,
                const char* response,
                size_t response_size,
                void*),
        void* ctx);

#ifdef __cplusplus
}
#endif
