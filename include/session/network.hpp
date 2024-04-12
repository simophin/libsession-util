#pragma once

#include <oxen/log/ring_buffer_sink.hpp>
#include <oxen/quic.hpp>

#include "network_service_node.hpp"
#include "session/onionreq/builder.hpp"
#include "session/onionreq/key_types.hpp"
#include "session/types.hpp"

namespace session::network {

enum class ServiceNodeChangeType {
    none = 0,
    invalid_path = 1,
    replace_swarm = 2,
    update_path = 3,
    update_node = 4,
};

struct onion_path {
    std::shared_ptr<oxen::quic::connection_interface> conn;
    std::vector<session::network::service_node> nodes;
    uint8_t failure_count;
};

struct service_node_changes {
    ServiceNodeChangeType type = ServiceNodeChangeType::none;
    std::vector<session::network::service_node> nodes = {};
    uint8_t path_failure_count = 0;
    bool path_invalid = false;
};

struct request_info {
    const service_node target;
    const std::string endpoint;
    const std::optional<ustring> body;
    const std::optional<std::vector<service_node>> swarm;
    const std::optional<onion_path> path;
    const bool is_retry;
};

using network_response_callback_t = std::function<void(
        bool success,
        bool timeout,
        int16_t status_code,
        std::optional<std::string> response,
        service_node_changes changes)>;

class Network {
  private:
    oxen::quic::Network net;
    std::shared_ptr<oxen::quic::GNUTLSCreds> creds;
    std::vector<onion_path> paths;

    std::shared_ptr<oxen::quic::Endpoint> endpoint;
    std::shared_ptr<oxen::log::RingBufferSink> buffer;

  public:
    // Constructs a new network for the given credentials, all requests should be made via a single
    // Network instance.
    Network(const session::onionreq::ed25519_seckey ed25519_seckey);

    /// API: network/add_logger
    ///
    /// Adds a logger to the network object.
    ///
    /// Inputs:
    /// - `callback` -- [in] callback to be called when a new message should be logged.
    void add_logger(std::function<void(const std::string&)> callback);

    /// API: network/add_path
    ///
    /// Adds a path to the list on the network object that is randomly selected from when making an
    /// onion request.
    ///
    /// Inputs:
    /// - `nodes` -- [in] nodes which make up the path to be added.
    /// - `failure_count` -- [in] number of times the path has previously failed to complete a request.
    void add_path(std::vector<session::network::service_node> nodes, uint8_t failure_count);

    /// API: network/remove_path
    ///
    /// Removes a path from the list on the network object that is randomly selected from when making an
    /// onion request.
    ///
    /// Inputs:
    /// - `node` -- [in] first node in the path to be removed.
    void remove_path(session::network::service_node node);

    /// API: network/remove_all_paths
    ///
    /// Removes all paths from the list on the network object that are randomly selected from when making an
    /// onion request.
    void remove_all_paths();

    /// API: network/send_request
    ///
    /// Send a request via the network.
    ///
    /// Inputs:
    /// - `info` -- [in] wrapper around all of the information required to send a request.
    /// - `handle_response` -- [in] callback to be called with the result of the request.
    void send_request(const request_info info, network_response_callback_t handle_response);

    /// API: network/send_request
    ///
    /// Sends a request directly to the provided service node.
    ///
    /// Inputs:
    /// - `target` -- [in] the address information for the service node to send the request to.
    /// - `endpoint` -- [in] endpoint for the request.
    /// - `body` -- [in] data to send to the specified endpoint.
    /// - `swarm` -- [in] current swarm information for the destination service node. Set to NULL if
    /// not used.
    /// - `handle_response` -- [in] callback to be called with the result of the request.
    void send_request(
            const session::network::service_node target,
            const std::string endpoint,
            const std::optional<ustring> body,
            const std::optional<std::vector<session::network::service_node>> swarm,
            network_response_callback_t handle_response);

    /// API: network/send_onion_request
    ///
    /// Sends a request via onion routing to the provided service node or server destination.
    ///
    /// Inputs:
    /// - `path` -- [in] the path of service nodes that the request should be routed through.
    /// - `destination` -- [in] service node or server destination information.
    /// - `body` -- [in] data to send to the specified destination.
    /// - `is_retry` -- [in] flag indicating whether this request is a retry. Generally only used
    /// for internal purposes for cases which should retry automatically (like receiving a `421`) in
    /// order to prevent subsequent retries.
    /// - `handle_response` -- [in] callback to be called with the result of the request.
    template <typename Destination>
    void send_onion_request(
            const Destination destination,
            const std::optional<ustring> body,
            const bool is_retry,
            network_response_callback_t handle_response);

    /// API: network/handle_errors
    ///
    /// Processes a non-success response to automatically perform any standard operations based on
    /// the errors returned from the service node network.
    ///
    /// Inputs:
    /// - `status_code` -- [in] the status code returned from the network.
    /// - `response` -- [in, optional] response data returned from the network.
    /// - `info` -- [in] the information for the request that was made.
    /// - `handle_response` -- [in] callback to be called with updated response information after
    /// processing the error.
    void handle_errors(
            const int16_t status_code,
            const std::optional<std::string> response,
            const request_info info,
            network_response_callback_t handle_response);

  private:
    std::shared_ptr<oxen::quic::connection_interface> get_connection(const service_node target);

    /// API: network/get_btstream
    ///
    /// Retrieves the `BTRequestStream` for the given target if there is an existing stream,
    /// otherwise creates a new stream.
    ///
    /// Inputs:
    /// - `target` -- [in] the service node we plan to send a request to.
    ///
    /// Outputs:
    /// - a shared pointer to the `BTRequestStream` for the target service node.
    std::shared_ptr<oxen::quic::BTRequestStream> get_btstream(const service_node target);

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
            const session::onionreq::Builder builder,
            const std::string response,
            const request_info info,
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
            const session::onionreq::Builder builder,
            const std::string response,
            const request_info info,
            network_response_callback_t handle_response);
};

}  // namespace session::network
