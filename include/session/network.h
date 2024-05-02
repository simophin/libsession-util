#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "export.h"
#include "log_level.h"
#include "onionreq/builder.h"

typedef enum CONNECTION_STATUS {
    CONNECTION_STATUS_UNKNOWN = 0,
    CONNECTION_STATUS_CONNECTING = 1,
    CONNECTION_STATUS_CONNECTED = 2,
    CONNECTION_STATUS_DISCONNECTED = 3,
} CONNECTION_STATUS;

typedef struct network_object {
    // Internal opaque object pointer; calling code should leave this alone.
    void* internals;
} network_object;

typedef struct network_service_node {
    uint8_t ip[4];
    uint16_t quic_port;
    char ed25519_pubkey_hex[65];  // The 64-byte ed25519 pubkey in hex + null terminator.
} network_service_node;

typedef struct network_server_destination {
    const char* method;
    const char* protocol;
    const char* host;
    const char* endpoint;
    uint16_t port;
    const char* x25519_pubkey;
    const char** headers;
    const char** header_values;
    size_t headers_size;
} network_server_destination;

typedef struct onion_request_path {
    const network_service_node* nodes;
    const size_t nodes_count;
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
/// - `cache_path` -- [in] Path where the snode cache files should be stored.  Should be
/// NULL-terminated.
/// - `use_testnet` -- [in] Flag indicating whether the network should connect to testnet or
/// mainnet.
/// - `pre_build_paths` -- [in] Flag indicating whether the network should pre-build it's paths.
/// - `error` -- [out] the pointer to a buffer in which we will write an error string if an error
/// occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
/// buffer of at least 256 bytes.
///
/// Outputs:
/// - `bool` -- Returns true on success; returns false and write the exception message as a C-string
/// into `error` (if not NULL) on failure.
LIBSESSION_EXPORT bool network_init(
        network_object** network,
        const char* cache_path,
        bool use_testnet,
        bool pre_build_paths,
        char* error) __attribute__((warn_unused_result));

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
        network_object* network,
        void (*callback)(
                LOG_LEVEL lvl, const char* name, size_t namelen, const char* msg, size_t msglen));

/// API: network/network_close_connections
///
/// Closes any currently active connections.
LIBSESSION_EXPORT void network_close_connections(network_object* network);

/// API: network/network_clear_cache
///
/// Clears the cached from memory and from disk (if a cache path was provided during
/// initialization).
LIBSESSION_EXPORT void network_clear_cache(network_object* network);

/// API: network/network_set_status_changed_callback
///
/// Registers a callback to be called whenever the network connection status changes.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object
/// - `callback` -- [in] callback to be called when the network connection status changes.
/// - `ctx` -- [in, optional] Pointer to an optional context. Set to NULL if unused.
LIBSESSION_EXPORT void network_set_status_changed_callback(
        network_object* network, void (*callback)(CONNECTION_STATUS status, void* ctx), void* ctx);

/// API: network/network_set_paths_changed_callback
///
/// Registers a callback to be called whenever the onion request paths are updated.
///
/// The pointer provided to the callback belongs to the caller and must be freed via `free()` when done with it.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object
/// - `callback` -- [in] callback to be called when the onion request paths are updated.
/// - `ctx` -- [in, optional] Pointer to an optional context. Set to NULL if unused.
LIBSESSION_EXPORT void network_set_paths_changed_callback(
        network_object* network,
        void (*callback)(onion_request_path* paths, size_t paths_len, void* ctx),
        void* ctx);

/// API: network/network_get_swarm
///
/// Retrieves the swarm for the given pubkey.  If there is already an entry in the cache for the
/// swarm then that will be returned, otherwise a network request will be made to retrieve the
/// swarm and save it to the cache.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object
/// - 'swarm_pubkey_hex' - [in] x25519 pubkey for the swarm in hex (64 characters).
/// - 'callback' - [in] callback to be called with the retrieved swarm (in the case of an error
/// the callback will be called with an empty list).
/// - `ctx` -- [in, optional] Pointer to an optional context. Set to NULL if unused.
LIBSESSION_EXPORT void network_get_swarm(
        network_object* network,
        const char* swarm_pubkey_hex,
        void (*callback)(network_service_node* nodes, size_t nodes_len, void*),
        void* ctx);

/// API: network/network_get_random_nodes
///
/// Retrieves a number of random nodes from the snode pool.  If the are no nodes in the pool a
/// new pool will be populated and the nodes will be retrieved from that.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object
/// - 'count' - [in] the number of nodes to retrieve.
/// - 'callback' - [in] callback to be called with the retrieved nodes (in the case of an error
/// the callback will be called with an empty list).
/// - `ctx` -- [in, optional] Pointer to an optional context. Set to NULL if unused.
LIBSESSION_EXPORT void network_get_random_nodes(
        network_object* network,
        uint16_t count,
        void (*callback)(network_service_node*, size_t, void*),
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
/// - `timeout_ms` -- [in] timeout in milliseconds to use for the request.
/// - `callback` -- [in] callback to be called with the result of the request.
/// - `ctx` -- [in, optional] Pointer to an optional context. Set to NULL if unused.
LIBSESSION_EXPORT void network_send_onion_request_to_snode_destination(
        network_object* network,
        const network_service_node node,
        const unsigned char* body,
        size_t body_size,
        const char* swarm_pubkey_hex,
        int64_t timeout_ms,
        void (*callback)(
                bool success,
                bool timeout,
                int16_t status_code,
                const char* response,
                size_t response_size,
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
/// - `timeout_ms` -- [in] timeout in milliseconds to use for the request.
/// - `callback` -- [in] callback to be called with the result of the request.
/// - `ctx` -- [in, optional] Pointer to an optional context.  Set to NULL if unused.
LIBSESSION_EXPORT void network_send_onion_request_to_server_destination(
        network_object* network,
        const network_server_destination server,
        const unsigned char* body,
        size_t body_size,
        int64_t timeout_ms,
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
