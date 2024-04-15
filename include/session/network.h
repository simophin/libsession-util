#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "export.h"
#include "network_service_node.h"
#include "onionreq/builder.h"

typedef struct network_object {
    // Internal opaque object pointer; calling code should leave this alone.
    void* internals;
} network_object;

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

typedef struct onion_request_path {
    const network_service_node* nodes;
    const size_t nodes_count;
    uint8_t failure_count;
} onion_request_path;

/// API: network/network_init
///
/// Constructs a new network object.
///
/// When done with the object the `network_object` must be destroyed by passing the pointer to
/// network_free().
///
/// Inputs:
/// - `network` -- [out] Pointer to the network object
/// - `ed25519_secretkey_bytes` -- [in] must be the 64-byte libsodium "secret key" value.  This
/// field cannot be null.
/// - `error` -- [out] the pointer to a buffer in which we will write an error string if an error
/// occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
/// buffer of at least 256 bytes.
///
/// Outputs:
/// - `bool` -- Returns true on success; returns false and write the exception message as a C-string
/// into `error` (if not NULL) on failure.
LIBSESSION_EXPORT bool network_init(
        network_object** network, const unsigned char* ed25519_secretkey_bytes, char* error)
        __attribute__((warn_unused_result));

/// API: network/network_free
///
/// Frees a network object.
///
/// Inputs:
/// - `network` -- [in] Pointer to network_object object
LIBSESSION_EXPORT void network_free(network_object* network);

/// API: network/network_add_logger
///
/// Adds a logger to the network object.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object
/// - `callback` -- [in] callback to be called when a new message should be logged.
LIBSESSION_EXPORT void network_add_logger(
        network_object* network, void (*callback)(const char*, size_t));

/// API: network/network_replace_key
///
/// Replaces the secret key used to make network connections. Note: This will result in existing
/// path connections being removed and new ones created with the updated key on the next use.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object
/// - `ed25519_seckey` -- [in] new ed25519 secret key to be used.
/// - `error` -- [out] the pointer to a buffer in which we will write an error string if an error
/// occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
/// buffer of at least 256 bytes.
///
/// Outputs:
/// - `bool` -- Returns true on success; returns false and write the exception message as a C-string
/// into `error` (if not NULL) on failure.
LIBSESSION_EXPORT bool network_replace_key(
        network_object* network, const unsigned char* ed25519_secretkey_bytes, char* error);

/// API: network/network_add_path
///
/// Adds a path to the list on the network object that is randomly selected from when making an
/// onion request.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object
/// - `path` -- [in] the path of service nodes to be added as an option to the network.
/// - `error` -- [out] the pointer to a buffer in which we will write an error string if an error
/// occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
/// buffer of at least 256 bytes.
///
/// Outputs:
/// - `bool` -- Returns true on success; returns false and write the exception message as a C-string
/// into `error` (if not NULL) on failure.
LIBSESSION_EXPORT bool network_add_path(
        network_object* network, const onion_request_path path, char* error);

/// API: network/network_remove_path
///
/// Removes a path from the list on the network object that is randomly selected from when making an
/// onion request.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object
/// - `path` -- [in] the path of service nodes to be removed from the network.
/// - `error` -- [out] the pointer to a buffer in which we will write an error string if an error
/// occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
/// buffer of at least 256 bytes.
///
/// Outputs:
/// - `bool` -- Returns true on success; returns false and write the exception message as a C-string
/// into `error` (if not NULL) on failure.
LIBSESSION_EXPORT bool network_remove_path(
        network_object* network, const network_service_node node, char* error);

/// API: network/network_remove_all_paths
///
/// Removes all paths from the list on the network object that are randomly selected from when
/// making an onion request.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object
LIBSESSION_EXPORT void network_remove_all_paths(network_object* network);

/// API: network/network_send_request
///
/// Sends a request directly to the provided service node.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object.
/// - `destination` -- [in] address information about the service node the request should be sent
/// to.
/// - `endpoint` -- [in] endpoint for the request.
/// - `body` -- [in] data to send to the specified endpoint.
/// - `body_size` -- [in] size of the `body`.
/// - `swarm` -- [in] current swarm information for the destination service node. Set to NULL if not
/// used.
/// - `swarm_count` -- [in] number of service nodes included in the `swarm`.
/// - `callback` -- [in] callback to be called with the result of the request.
/// - `ctx` -- [in, optional] Pointer to an optional context. Set to NULL if unused.
LIBSESSION_EXPORT void network_send_request(
        network_object* network,
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

/// API: network/network_send_onion_request_to_snode_destination
///
/// Sends a request via onion routing to the provided service node.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object.
/// - `node` -- [in] address information about the service node the request should be sent to.
/// - `body` -- [in] data to send to the specified node.
/// - `body_size` -- [in] size of the `body`.
/// - `callback` -- [in] callback to be called with the result of the request.
/// - `ctx` -- [in, optional] Pointer to an optional context. Set to NULL if unused.
LIBSESSION_EXPORT void network_send_onion_request_to_snode_destination(
        network_object* network,
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

/// API: network/network_send_onion_request_to_server_destination
///
/// Sends a request via onion routing to the provided server.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object.
/// - `method` -- [in] the HTTP method to use for performing the request on the server.
/// - `protocol` -- [in] the protocol to use for performing the request on the server.
/// - `host` -- [in] the server host.
/// - `endpoint` -- [in] the endpoint to call on the server.
/// - `port` -- [in] the port to send the request to on the server.
/// - `x25519_pubkey` -- [in] the x25519 pubkey of the server.
/// - `query_param_keys` -- [in] array of keys for any query params to send to the server, must be
/// the same size as `query_param_values`. Set to NULL if unused.
/// - `query_param_values` -- [in] array of values for any query params to send to the server, must
/// be the same size as `query_param_keys`. Set to NULL if unused.
/// - `query_params_size` -- [in] The number of query params provided.
/// - `headers` -- [in] array of keys for any headers to send to the server, must be the same size
/// as `header_values`. Set to NULL if unused.
/// - `header_values` -- [in] array of values for any headers to send to the server, must be the
/// same size as `headers`. Set to NULL if unused.
/// - `headers_size` -- [in] The number of headers provided.
/// - `body` -- [in] data to send to the specified endpoint.
/// - `body_size` -- [in] size of the `body`.
/// - `callback` -- [in] callback to be called with the result of the request.
/// - `ctx` -- [in, optional] Pointer to an optional context. Set to NULL if unused.
LIBSESSION_EXPORT void network_send_onion_request_to_server_destination(
        network_object* network,
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
