#pragma once

#include <oxen/quic.hpp>

#include "onionreq/builder.hpp"
#include "onionreq/key_types.hpp"
#include "platform.hpp"
#include "types.hpp"

namespace session::network {

namespace fs = std::filesystem;

using network_response_callback_t = std::function<void(
        bool success, bool timeout, int16_t status_code, std::optional<std::string> response)>;

enum class ConnectionStatus {
    unknown,
    connecting,
    connected,
    disconnected,
};

enum class PathType {
    standard,
    upload,
    download,
};

struct service_node : public oxen::quic::RemoteAddress {
  public:
    std::vector<int> storage_server_version;

    service_node() = delete;

    template <typename... Opt>
    service_node(
            std::string_view remote_pk, std::vector<int> storage_server_version, Opt&&... opts) :
            oxen::quic::RemoteAddress{remote_pk, std::forward<Opt>(opts)...},
            storage_server_version{storage_server_version} {}

    template <typename... Opt>
    service_node(ustring_view remote_pk, std::vector<int> storage_server_version, Opt&&... opts) :
            oxen::quic::RemoteAddress{remote_pk, std::forward<Opt>(opts)...},
            storage_server_version{storage_server_version} {}

    service_node(const service_node& obj) :
            oxen::quic::RemoteAddress{obj}, storage_server_version{obj.storage_server_version} {}
    service_node& operator=(const service_node& obj) {
        storage_server_version = obj.storage_server_version;
        oxen::quic::RemoteAddress::operator=(obj);
        _copy_internals(obj);
        return *this;
    }

    bool operator==(const service_node& other) const {
        return static_cast<const oxen::quic::RemoteAddress&>(*this) ==
                       static_cast<const oxen::quic::RemoteAddress&>(other) &&
               storage_server_version == other.storage_server_version;
    }
};

struct connection_info {
    service_node node;
    std::shared_ptr<oxen::quic::connection_interface> conn;
    std::shared_ptr<oxen::quic::BTRequestStream> stream;

    bool is_valid() const { return conn && stream && !stream->is_closing(); };
};

struct onion_path {
    connection_info conn_info;
    std::vector<service_node> nodes;
    uint8_t failure_count;

    bool operator==(const onion_path& other) const {
        // The `conn_info` and failure/timeout counts can be reset for a path in a number
        // of situations so just use the nodes to determine if the paths match
        return nodes == other.nodes;
    }
};

struct request_info {
    enum class RetryReason {
        decryption_failure,
        redirect,
    };

    std::string request_id;
    service_node target;
    session::onionreq::network_destination destination;
    std::string endpoint;
    std::optional<ustring> body;
    std::optional<ustring> original_body;
    std::optional<session::onionreq::x25519_pubkey> swarm_pubkey;
    PathType path_type;
    std::chrono::milliseconds timeout;
    bool node_destination;
    std::optional<RetryReason> retry_reason;
};

class Network {
  private:
    const bool use_testnet;
    const bool should_cache_to_disk;
    const bool single_path_mode;
    const fs::path cache_path;

    // Disk thread state
    std::mutex snode_cache_mutex;  // This guards all the below:
    std::condition_variable snode_cache_cv;
    bool shut_down_disk_thread = false;
    bool need_write = false;
    bool need_pool_write = false;
    bool need_failure_counts_write = false;
    bool need_swarm_write = false;
    bool need_clear_cache = false;

    // Values persisted to disk
    std::vector<service_node> snode_pool;
    std::unordered_map<std::string, uint8_t> snode_failure_counts;
    std::chrono::system_clock::time_point last_snode_pool_update{};
    std::unordered_map<std::string, std::vector<service_node>> swarm_cache;

    std::thread disk_write_thread;

    bool suspended = false;
    ConnectionStatus status;
    oxen::quic::Network net;
    std::vector<onion_path> standard_paths;
    std::vector<onion_path> upload_paths;
    std::vector<onion_path> download_paths;
    std::shared_ptr<oxen::quic::Loop> paths_and_pool_loop;

    std::shared_ptr<oxen::quic::Endpoint> endpoint;

  public:
    friend class TestNetwork;

    // Hook to be notified whenever the network connection status changes.
    std::function<void(ConnectionStatus status)> status_changed;

    // Hook to be notified whenever the onion request paths are updated.
    std::function<void(std::vector<std::vector<service_node>> paths)> paths_changed;

    // Constructs a new network with the given cache path and a flag indicating whether it should
    // use testnet or mainnet, all requests should be made via a single Network instance.
    Network(std::optional<fs::path> cache_path,
            bool use_testnet,
            bool single_path_mode,
            bool pre_build_paths);
    ~Network();

    /// API: network/suspend
    ///
    /// Suspends the network preventing any further requests from creating new connections and
    /// paths.  This function also calls the `close_connections` function.
    void suspend();

    /// API: network/resume
    ///
    /// Resumes the network allowing new requests to creating new connections and paths.
    void resume();

    /// API: network/close_connections
    ///
    /// Closes any currently active connections.
    void close_connections();

    /// API: network/clear_cache
    ///
    /// Clears the cached from memory and from disk (if a cache path was provided during
    /// initialization).
    void clear_cache();

    /// API: network/get_swarm
    ///
    /// Retrieves the swarm for the given pubkey.  If there is already an entry in the cache for the
    /// swarm then that will be returned, otherwise a network request will be made to retrieve the
    /// swarm and save it to the cache.
    ///
    /// Inputs:
    /// - 'swarm_pubkey' - [in] public key for the swarm.
    /// - 'callback' - [in] callback to be called with the retrieved swarm (in the case of an error
    /// the callback will be called with an empty list).
    void get_swarm(
            session::onionreq::x25519_pubkey swarm_pubkey,
            std::function<void(std::vector<service_node> swarm)> callback);

    /// API: network/set_swarm
    ///
    /// Update the nodes to be used for a swarm.  This function should never be called directly.
    ///
    /// Inputs:
    /// - 'swarm_pubkey' - [in] public key for the swarm.
    /// - `swarm` -- [in] nodes for the swarm.
    void set_swarm(session::onionreq::x25519_pubkey swarm_pubkey, std::vector<service_node> swarm);

    /// API: network/get_random_nodes
    ///
    /// Retrieves a number of random nodes from the snode pool.  If the are no nodes in the pool a
    /// new pool will be populated and the nodes will be retrieved from that.
    ///
    /// Inputs:
    /// - 'count' - [in] the number of nodes to retrieve.
    /// - 'callback' - [in] callback to be called with the retrieved nodes (in the case of an error
    /// the callback will be called with an empty list).
    void get_random_nodes(
            uint16_t count, std::function<void(std::vector<service_node> nodes)> callback);

    /// API: network/send_request
    ///
    /// Send a request via the network.
    ///
    /// Inputs:
    /// - `info` -- [in] wrapper around all of the information required to send a request.
    /// - `conn` -- [in] connection information used to send the request.
    /// - `handle_response` -- [in] callback to be called with the result of the request.
    void send_request(
            request_info info, connection_info conn, network_response_callback_t handle_response);

    /// API: network/send_onion_request
    ///
    /// Sends a request via onion routing to the provided service node or server destination.
    ///
    /// Inputs:
    /// - `destination` -- [in] service node or server destination information.
    /// - `body` -- [in] data to send to the specified destination.
    /// - `swarm_pubkey` -- [in, optional] pubkey for the swarm the request is associated with.
    /// Should be NULL if the request is not associated with a swarm.
    /// - `timeout` -- [in] timeout in milliseconds to use for the request.
    /// - `is_retry` -- [in] flag indicating whether this request is a retry. Generally only used
    /// for internal purposes for cases which should retry automatically (like receiving a `421`) in
    /// order to prevent subsequent retries.
    /// - `handle_response` -- [in] callback to be called with the result of the request.
    void send_onion_request(
            onionreq::network_destination destination,
            std::optional<ustring> body,
            std::optional<session::onionreq::x25519_pubkey> swarm_pubkey,
            std::chrono::milliseconds timeout,
            network_response_callback_t handle_response);

    /// API: network/upload_file_to_server
    ///
    /// Uploads a file to a given server destination.
    ///
    /// Inputs:
    /// - 'data' - [in] the data to be uploaded to a server.
    /// - `server` -- [in] the server destination to upload the file to.
    /// - `file_name` -- [in, optional] optional name to use for the file.
    /// - `timeout` -- [in] timeout in milliseconds to use for the request.
    /// - `handle_response` -- [in] callback to be called with the result of the request.
    void upload_file_to_server(
            ustring data,
            onionreq::ServerDestination server,
            std::optional<std::string> file_name,
            std::chrono::milliseconds timeout,
            network_response_callback_t handle_response);

    /// API: network/download_file
    ///
    /// Download a file from a given server destination.
    ///
    /// Inputs:
    /// - `server` -- [in] the server destination to download the file from.
    /// - `timeout` -- [in] timeout in milliseconds to use for the request.
    /// - `handle_response` -- [in] callback to be called with the result of the request.
    void download_file(
            onionreq::ServerDestination server,
            std::chrono::milliseconds timeout,
            network_response_callback_t handle_response);

    /// API: network/download_file
    ///
    /// Convenience function to download a file from a given url and x25519 pubkey combination.
    /// Calls through to the above `download_file` function after constructing a server destination
    /// from the provided values.
    ///
    /// Inputs:
    /// - `download_url` -- [in] the url to download the file from.
    /// - `x25519_pubkey` -- [in] the server destination to download the file from.
    /// - `timeout` -- [in] timeout in milliseconds to use for the request.
    /// - `handle_response` -- [in] callback to be called with the result of the request.
    void download_file(
            std::string_view download_url,
            onionreq::x25519_pubkey x25519_pubkey,
            std::chrono::milliseconds timeout,
            network_response_callback_t handle_response);

    /// API: network/get_client_version
    ///
    /// Retrieves the version information for the given platform.
    ///
    /// Inputs:
    /// - `platform` -- [in] the platform to retrieve the client version for.
    /// - `seckey` -- [in] the users ed25519 secret key (to generated blinded auth).
    /// - `timeout` -- [in] timeout in milliseconds to use for the request.
    /// - `handle_response` -- [in] callback to be called with the result of the request.
    void get_client_version(
            Platform platform,
            onionreq::ed25519_seckey seckey,
            std::chrono::milliseconds timeout,
            network_response_callback_t handle_response);

  private:
    /// API: network/paths_for_type
    ///
    /// Internal function to retrieve the onion paths for a given request type
    ///
    /// Inputs:
    /// - 'path_type' - [in] the type of paths to retrieve.
    std::vector<onion_path> paths_for_type(PathType type) const {
        if (single_path_mode)
            return standard_paths;

        switch (type) {
            case PathType::standard: return standard_paths;
            case PathType::upload: return upload_paths;
            case PathType::download: return download_paths;
        }
        return standard_paths;  // Default
    };

    /// API: network/all_path_nodes
    ///
    /// Internal function to retrieve all of the nodes current used in paths
    std::vector<service_node> all_path_nodes() const {
        std::vector<service_node> result;

        for (auto& paths : {&standard_paths, &upload_paths, &download_paths})
            for (auto& path : *paths)
                for (auto& node : path.nodes)
                    result.emplace_back(node);

        return result;
    };

    /// API: network/update_status
    ///
    /// Internal function to update the connection status and trigger the `status_changed` hook if
    /// provided, this method ignores invalid or unchanged status changes.
    ///
    /// Inputs:
    /// - 'updated_status' - [in] the updated connection status.
    void update_status(ConnectionStatus updated_status);

    /// API: network/disk_write_thread_loop
    ///
    /// Body of the disk writer which runs until signalled to stop.  This is intended to run in its
    /// own thread.  The thread monitors a number of private variables and persists the snode pool
    /// and swarm caches to disk if a `cache_path` was provided during initialization.
    void disk_write_thread_loop();

    /// API: network/load_cache_from_disk
    ///
    /// Loads the snode pool and swarm caches from disk if a `cache_path` was provided and cached
    /// data exists.
    void load_cache_from_disk();

    /// API: network/get_endpoint
    ///
    /// Retrieves or creates a new endpoint pointer.
    std::shared_ptr<oxen::quic::Endpoint> get_endpoint();

    /// API: network/get_connection_info
    ///
    /// Creates a connection for the target node and waits for the connection to be established (or
    /// closed in case it fails to establish) before returning the connection.
    ///
    /// Inputs:
    /// - 'request_id' - [in] id for the request which triggered the call.
    /// - 'path_type' - [in] the type of paths to retrieve.
    /// - `target` -- [in] the target service node to connect to.
    ///
    /// Returns:
    /// - A pair of the connection info for the target service node and an optional error if the
    /// connnection was unable to be established.
    std::pair<connection_info, std::optional<std::string>> get_connection_info(
            std::string request_id, PathType path_type, service_node target);

    /// API: network/with_paths_and_pool
    ///
    /// Retrieves the current onion request paths and service node pool from the cache.  If the
    /// cache is empty it will first be populated from the network.
    ///
    /// Inputs:
    /// - 'request_id' - [in] id for the request which triggered the call.
    /// - `path_type` -- [in] the type of path the request should be sent along.
    /// - `excluded_node` -- [in, optional] node which should not be included in the path.
    /// - `callback` -- [in] callback to be triggered once we have built the paths and service node
    /// pool.  NOTE: If we are unable to build the paths or retrieve the service node pool the
    /// callback will be triggered with empty lists and an error.
    void with_paths_and_pool(
            std::string request_id,
            PathType path_type,
            std::optional<service_node> excluded_node,
            std::function<
                    void(std::vector<onion_path> updated_paths,
                         std::vector<service_node> pool,
                         std::optional<std::string> error)> callback);

    void build_paths_and_pool_in_background(std::string caller, PathType path_type);

    /// API: network/with_path
    ///
    /// Retrieves a valid onion request path to perform a request on.  If there aren't currently any
    /// paths then new paths will be constructed by opening and testing connections to random
    /// service nodes in the snode pool.
    ///
    /// Inputs:
    /// - 'request_id' - [in] id for the request which triggered the call.
    /// - `path_type` -- [in] the type of path the request should be sent along.
    /// - `excluded_node` -- [in, optional] node which should not be included in the path.
    /// - `callback` -- [in] callback to be triggered once we have a valid path, NULL if we are
    /// unable to find a valid path.
    void with_path(
            std::string request_id,
            PathType path_type,
            std::optional<service_node> excluded_node,
            std::function<void(std::optional<onion_path> path, std::optional<std::string> error)>
                    callback);

    /// API: network/valid_paths
    ///
    /// Filters the provided paths down to a list of valid paths.
    ///
    /// Inputs:
    /// - `paths` -- [in] paths to validate.
    ///
    /// Outputs:
    /// - A list of valid paths.
    std::vector<onion_path> valid_paths(std::vector<onion_path> paths);

    /// API: network/validate_paths_and_pool_sizes
    ///
    /// Returns a pair of bools indicating whether the provided paths and pool are valid.
    ///
    /// Inputs:
    /// - `path_type` -- [in] the type of path to validate the size for.
    /// - `paths` -- [in] paths to validate size for.
    /// - `pool` -- [in] pool to validate size for.
    /// - `last_pool_update` -- [in] timestamp for when the pool was last updated.
    ///
    /// Outputs:
    /// - A pair of flags indicating whether the provided paths and pool have the correct sizes.
    std::pair<bool, bool> validate_paths_and_pool_sizes(
            PathType path_type,
            std::vector<onion_path> paths,
            std::vector<service_node> pool,
            std::chrono::system_clock::time_point last_pool_update);

    /// API: network/validate_response
    ///
    /// Processes a quic response to extract the status code and body or throw if it errored or
    /// received a non-successful status code.
    ///
    /// Inputs:
    /// - `resp` -- [in] the quic response.
    /// - `is_bencoded` -- [in] flag indicating whether the response will be bencoded or JSON.
    ///
    /// Returns:
    /// - `std::pair<uint16_t, std::string>` -- the status code and response body (for a bencoded
    /// response this is just the direct response body from quic as it simplifies consuming the
    /// response elsewhere).
    std::pair<uint16_t, std::string> validate_response(oxen::quic::message resp, bool is_bencoded);

    /// API: network/find_possible_path
    ///
    /// Picks a random path from the provided paths excluding the provided node if one is available.
    ///
    /// Inputs:
    /// - `excluded_node` -- [in, optional] node which should not be included in the paths.
    /// - `paths` -- [in] paths to select from.
    ///
    /// Outputs:
    /// - The possible path, if found, and the number of paths provided.
    std::pair<std::optional<onion_path>, uint8_t> find_possible_path(
            std::optional<service_node> excluded_node, std::vector<onion_path> paths);

    /// API: network/get_service_nodes_recursive
    ///
    /// A recursive function that will attempt to retrieve service nodes from a given node until it
    /// successfully retrieves nodes or the list is drained.
    ///
    /// Inputs:
    /// - 'request_id' - [in] id for the request which triggered the call.
    /// - `target_nodes` -- [in] list of nodes to send requests to until we get a result or it's
    /// drained.
    /// - `limit` -- [in, optional] the number of service nodes to retrieve.
    /// - `callback` -- [in] callback to be triggered once we receive nodes.  NOTE: If we drain the
    /// `target_nodes` and haven't gotten a successful response then the callback will be invoked
    /// with an empty vector and an error string.
    void get_service_nodes_recursive(
            std::string request_id,
            std::vector<service_node> target_nodes,
            std::optional<int> limit,
            std::function<void(std::vector<service_node> nodes, std::optional<std::string> error)>
                    callback);

    /// API: network/find_valid_guard_node_recursive
    ///
    /// A recursive function that sends a request to provided nodes until a successful response is
    /// received or the list is drained.
    ///
    /// Inputs:
    /// - 'request_id' - [in] id for the request which triggered the call.
    /// - `path_type` -- [in] the type of path to validate the size for.
    /// - `test_attempt` -- [in] the number of test which have occurred before this one.
    /// - `target_nodes` -- [in] list of nodes to send requests to until we get a result or it's
    /// drained.
    /// - `callback` -- [in] callback to be triggered once we make a successful request.  NOTE: If
    /// we drain the `target_nodes` and haven't gotten a successful response then the callback will
    /// be invoked with a std::nullopt `valid_guard_node` and `unused_nodes`.
    void find_valid_guard_node_recursive(
            std::string request_id,
            PathType path_type,
            int64_t test_attempt,
            std::vector<service_node> target_nodes,
            std::function<
                    void(std::optional<connection_info> valid_guard_node,
                         std::vector<service_node> unused_nodes,
                         std::optional<std::string>)> callback);

    /// API: network/get_service_nodes
    ///
    /// Retrieves all or a random subset of service nodes from the given node.
    ///
    /// Inputs:
    /// - 'request_id' - [in] id for the request which triggered the call.
    /// - `node` -- [in] node to retrieve the service nodes from.
    /// - `limit` -- [in, optional] the number of service nodes to retrieve.
    /// - `callback` -- [in] callback to be triggered once we receive nodes.  NOTE: If an error
    /// occurs an empty list and an error will be provided.
    void get_service_nodes(
            std::string request_id,
            service_node node,
            std::optional<int> limit,
            std::function<void(std::vector<service_node> nodes, std::optional<std::string> error)>
                    callback);

    /// API: network/get_version
    ///
    /// Retrieves the version information for a given service node.
    ///
    /// Inputs:
    /// - 'request_id' - [in] id for the request which triggered the call.
    /// - 'type' - [in] the type of paths to send the request across.
    /// - `node` -- [in] node to retrieve the version from.
    /// - `timeout` -- [in, optional] optional timeout for the request, if NULL the
    /// `quic::DEFAULT_TIMEOUT` will be used.
    /// - `callback` -- [in] callback to be triggered with the result of the request.  NOTE: If an
    /// error occurs an empty list and an error will be provided.
    void get_version(
            std::string request_id,
            PathType path_type,
            service_node node,
            std::optional<std::chrono::milliseconds> timeout,
            std::function<
                    void(std::vector<int> version,
                         connection_info info,
                         std::optional<std::string> error)> callback);

    /// API: network/send_onion_request
    ///
    /// Sends a request via onion routing to the provided service node or server destination.
    ///
    /// Inputs:
    /// - 'type' - [in] the type of paths to send the request across.
    /// - `destination` -- [in] service node or server destination information.
    /// - `body` -- [in] data to send to the specified destination.
    /// - `swarm_pubkey` -- [in, optional] pubkey for the swarm the request is associated with.
    /// Should be NULL if the request is not associated with a swarm.
    /// - `timeout` -- [in] timeout in milliseconds to use for the request.
    /// - `existing_request_id` -- [in] the request id for the existing request when this request is
    /// a retry. Mostly to simplify debugging.
    /// - `retry_reason` -- [in] the reason we are retrying the request (if it's a retry). Generally
    /// only used for internal purposes (like
    // receiving a `421`) in order to prevent subsequent retries.
    /// - `handle_response` -- [in] callback to be called with the result of the request.
    void send_onion_request(
            PathType type,
            onionreq::network_destination destination,
            std::optional<ustring> body,
            std::optional<session::onionreq::x25519_pubkey> swarm_pubkey,
            std::chrono::milliseconds timeout,
            std::optional<std::string> existing_request_id,
            std::optional<request_info::RetryReason> retry_reason,
            network_response_callback_t handle_response);

    /// API: network/process_v3_onion_response
    ///
    /// Processes a v3 onion request response.
    ///
    /// Inputs:
    /// - `builder` -- [in] the builder that was used to build the onion request.
    /// - `response` -- [in] the response data returned from the destination.
    ///
    /// Outputs:
    /// - A pair containing the status code and body of the decrypted onion request response.
    std::pair<int16_t, std::optional<std::string>> process_v3_onion_response(
            session::onionreq::Builder builder, std::string response);

    /// API: network/process_v4_onion_response
    ///
    /// Processes a v4 onion request response.
    ///
    /// Inputs:
    /// - `builder` -- [in] the builder that was used to build the onion request.
    /// - `response` -- [in] the response data returned from the destination.
    ///
    /// Outputs:
    /// - A pair containing the status code and body of the decrypted onion request response.
    std::pair<int16_t, std::optional<std::string>> process_v4_onion_response(
            session::onionreq::Builder builder, std::string response);

    /// API: network/handle_errors
    ///
    /// Processes a non-success response to automatically perform any standard operations based on
    /// the errors returned from the service node network (ie. updating the service node cache,
    /// dropping nodes and/or onion request paths).
    ///
    /// Inputs:
    /// - `info` -- [in] the information for the request that was made.
    /// - `path` -- [in] the onion path the request was sent along.
    /// - `timeout` -- [in, optional] flag indicating whether the request timed out.
    /// - `status_code` -- [in, optional] the status code returned from the network.
    /// - `response` -- [in, optional] response data returned from the network.
    /// - `handle_response` -- [in, optional] callback to be called with updated response
    /// information after processing the error.
    void handle_errors(
            request_info info,
            onion_path path,
            bool timeout,
            std::optional<int16_t> status_code,
            std::optional<std::string> response,
            std::optional<network_response_callback_t> handle_response);

    /// API: network/handle_node_error
    ///
    /// Convenience method to increment the failure count for a given node and path (if a node
    /// doesn't have an associated path then just create one with the single node).  This just calls
    /// into the 'handle_errors' function in a way that will trigger an update to the failure
    /// counts.
    ///
    /// Inputs:
    /// - `node` -- [in] the node to increment the failure count for.
    /// - `path_type` -- [in] type of path the node (or provided path) belong to.
    /// - `path` -- [in] path to increment the failure count for.
    void handle_node_error(service_node node, PathType path_type, onion_path path);
};

}  // namespace session::network
