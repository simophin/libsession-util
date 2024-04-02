#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "export.h"
#include "network_service_node.h"
#include "onionreq/builder.h"

typedef enum SERVICE_NODE_CHANGE_TYPE {
    SERVICE_NODE_CHANGE_TYPE_NONE = 0,
    SERVICE_NODE_CHANGE_TYPE_INVALID_PATH = 1,
    SERVICE_NODE_CHANGE_TYPE_REPLACE_SWARM = 2,
    SERVICE_NODE_CHANGE_TYPE_UPDATE_PATH = 3,
    SERVICE_NODE_CHANGE_TYPE_UPDATE_NODE = 4,
} SERVICE_NODE_CHANGE_TYPE;

typedef struct network_service_node_changes {
    SERVICE_NODE_CHANGE_TYPE type;
    network_service_node* nodes;
    size_t nodes_count;
    uint8_t failure_count;
    bool invalid;
} network_service_node_changes;

LIBSESSION_EXPORT void network_add_logger(void (*callback)(const char*, size_t));

LIBSESSION_EXPORT void network_send_request(
        const unsigned char* ed25519_secretkey_bytes,
        const network_service_node destination,
        const char* endpoint,
        const unsigned char* body,
        size_t body_size,
        const network_service_node* swarm,
        const size_t swarm_count,
        void (*callback)(
                bool success,
                bool timeout,
                int16_t status_code,
                const char* response,
                size_t response_size,
                network_service_node_changes changes,
                void*),
        void* ctx);

LIBSESSION_EXPORT void network_send_onion_request_to_snode_destination(
        const onion_request_path path,
        const unsigned char* ed25519_secretkey_bytes,
        const onion_request_service_node_destination node,
        const unsigned char* body,
        size_t body_size,
        void (*callback)(
                bool success,
                bool timeout,
                int16_t status_code,
                const char* response,
                size_t response_size,
                network_service_node_changes changes,
                void*),
        void* ctx);

LIBSESSION_EXPORT void network_send_onion_request_to_server_destination(
        const onion_request_path path,
        const unsigned char* ed25519_secretkey_bytes,
        const char* method,
        const char* protocol,
        const char* host,
        const char* endpoint,
        uint16_t port,
        const char* x25519_pubkey,
        const char** query_param_keys,
        const char** query_param_values,
        size_t query_params_size,
        const char** headers,
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
                network_service_node_changes changes,
                void*),
        void* ctx);

#ifdef __cplusplus
}
#endif
