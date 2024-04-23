#pragma once

#include <spdlog/pattern_formatter.h>

#include <oxen/quic.hpp>

#include "network_service_node.hpp"
#include "session/onionreq/builder.hpp"
#include "session/onionreq/key_types.hpp"
#include "session/types.hpp"

namespace session::network {

enum class ConnectionStatus {
    unknown = 0,
    connecting = 1,
    connected = 2,
    disconnected = 3,
};

struct connection_info {
    session::network::service_node node;
    std::shared_ptr<oxen::quic::connection_interface> conn;
    std::shared_ptr<oxen::quic::BTRequestStream> stream;

    bool is_valid() const { return conn && stream && !stream->is_closing(); };
};

struct onion_path {
    connection_info conn_info;
    std::vector<session::network::service_node> nodes;
    uint8_t failure_count;

    bool operator==(const onion_path& other) const {
        return nodes == other.nodes && failure_count == other.failure_count;
    }
};

struct request_info {
    service_node target;
    std::string endpoint;
    std::optional<ustring> body;
    std::optional<std::string> swarm_pubkey;
    onion_path path;
    bool is_retry;
};

using network_response_callback_t = std::function<void(
        bool success, bool timeout, int16_t status_code, std::optional<std::string> response)>;

class Network {
  private:
    const bool use_testnet;
    const bool should_cache_to_disk;
    const std::string cache_path;

    // Disk thread state
    std::mutex snode_cache_mutex;  // This guards all the below:
    std::condition_variable snode_cache_cv;
    bool shut_down_disk_thread = false;
    bool need_write = false;
    bool need_pool_write = false;
    bool need_swarm_write = false;
    bool need_clear_cache = false;

    // Values persisted to disk
    std::vector<service_node> snode_pool;
    std::chrono::system_clock::time_point last_snode_pool_update;
    std::unordered_map<std::string, std::vector<service_node>> swarm_cache;

    ConnectionStatus status;
    oxen::quic::Network net;
    std::vector<onion_path> paths;
    std::shared_ptr<oxen::quic::Loop> get_snode_pool_loop;
    std::shared_ptr<oxen::quic::Loop> build_paths_loop;

    std::shared_ptr<oxen::quic::Endpoint> endpoint;
    spdlog::pattern_formatter formatter;

  public:
    std::function<void(ConnectionStatus status)> status_changed;
    std::function<void(std::vector<std::vector<service_node>> paths)> paths_changed;

    // Constructs a new network with the given cache path and a flag indicating whether it should
    // use testnet or mainnet, all requests should be made via a single Network instance.
    Network(std::optional<std::string> cache_path, bool use_testnet, bool pre_build_paths);
    ~Network();

    /// API: network/add_logger
    ///
    /// Adds a logger to the network object.
    ///
    /// Inputs:
    /// - `callback` -- [in] callback to be called when a new message should be logged.
    void add_logger(std::function<void(const std::string&)> callback);

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
    /// 'swarm_pubkey_hex' - [in] includes the prefix.
    /// 'callback' - [in] callback to be called with the retrieved swarm (in the case of an error
    /// the callback will be called with an empty list).
    void get_swarm(
            std::string swarm_pubkey_hex,
            std::function<void(std::vector<service_node> swarm)> callback);

    /// API: network/get_random_nodes
    ///
    /// Retrieves a number of random nodes from the snode pool.  If the are no nodes in the pool a
    /// new pool will be populated and the nodes will be retrieved from that.
    ///
    /// Inputs:
    /// 'count' - [in] the number of nodes to retrieve.
    /// 'callback' - [in] callback to be called with the retrieved nodes (in the case of an error
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
    /// - `is_retry` -- [in] flag indicating whether this request is a retry. Generally only used
    /// for internal purposes for cases which should retry automatically (like receiving a `421`) in
    /// order to prevent subsequent retries.
    /// - `handle_response` -- [in] callback to be called with the result of the request.
    void send_onion_request(
            onionreq::network_destination destination,
            std::optional<ustring> body,
            bool is_retry,
            network_response_callback_t handle_response);

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

    /// API: network/handle_errors
    ///
    /// Processes a non-success response to automatically perform any standard operations based on
    /// the errors returned from the service node network (ie. updating the service node cache,
    /// dropping nodes and/or onion request paths).
    ///
    /// Inputs:
    /// - `info` -- [in] the information for the request that was made.
    /// - `status_code` -- [in, optional] the status code returned from the network.
    /// - `response` -- [in, optional] response data returned from the network.
    /// - `handle_response` -- [in, optional] callback to be called with updated response
    /// information after processing the error.
    void handle_errors(
            request_info info,
            std::optional<int16_t> status_code,
            std::optional<std::string> response,
            std::optional<network_response_callback_t> handle_response);

  private:
    /// API: network/update_status
    ///
    /// Internal function to update the connection status and trigger the `status_changed` hook if
    /// provided, this method ignores invalid or unchanged status changes.
    ///
    /// Inputs:
    /// 'updated_status' - [in] the updated connection status.
    void update_status(ConnectionStatus updated_status);

    /// API: network/start_disk_write_thread
    ///
    /// Starts the disk write thread which monitors a number of private variables and persists the
    /// snode pool and swarm caches to disk if a `cache_path` was provided during initialization.
    void start_disk_write_thread();

    /// API: network/load_cache_from_disk
    ///
    /// Loads the snode pool and swarm caches from disk if a `cache_path` was provided and cached
    /// data exists.
    void load_cache_from_disk();

    connection_info get_connection_info(
            service_node target,
            std::optional<oxen::quic::connection_established_callback> conn_established_cb);

    void with_snode_pool(std::function<void(std::vector<service_node>)> callback);
    void with_path(
            std::optional<service_node> excluded_node,
            std::function<void(std::optional<onion_path> path)> callback);
    void build_paths_if_needed(
            std::optional<service_node> excluded_node,
            std::function<void(std::vector<onion_path> updated_paths)> callback);

    void get_service_nodes_recursive(
            std::optional<int> limit,
            std::vector<service_node> nodes,
            std::function<void(std::vector<service_node> nodes, std::optional<std::string> error)>
                    callback);
    void find_valid_guard_node_recursive(
            std::vector<service_node> unused_nodes,
            std::function<
                    void(std::optional<connection_info> valid_guard_node,
                         std::vector<service_node> unused_nodes)> callback);

    void get_version(
            service_node node,
            std::optional<std::chrono::milliseconds> timeout,
            std::function<
                    void(std::vector<int> version,
                         connection_info info,
                         std::optional<std::string> error)> callback);
    void get_service_nodes(
            std::optional<int> limit,
            service_node node,
            std::function<void(std::vector<service_node> nodes, std::optional<std::string> error)>
                    callback);

    /// API: network/process_snode_response
    ///
    /// Processes the response from an onion request sent to a service node destination.
    ///
    /// Inputs:
    /// - `builder` -- [in] the builder that was used to build the onion request.
    /// - `response` -- [in] the response data returned from the destination.
    /// - `info` -- [in] the information for the request that was made.
    /// - `handle_response` -- [in] callback to be called with updated response information after
    /// processing the error.
    void process_snode_response(
            session::onionreq::Builder builder,
            std::string response,
            request_info info,
            network_response_callback_t handle_response);

    /// API: network/process_server_response
    ///
    /// Processes the response from an onion request sent to a server destination.
    ///
    /// Inputs:
    /// - `builder` -- [in] the builder that was used to build the onion request.
    /// - `response` -- [in] the response data returned from the destination.
    /// - `info` -- [in] the information for the request that was made.
    /// - `handle_response` -- [in] callback to be called with updated response information after
    /// processing the error.
    void process_server_response(
            session::onionreq::Builder builder,
            std::string response,
            request_info info,
            network_response_callback_t handle_response);
};

}  // namespace session::network
