#pragma once

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
};

struct service_node_changes {
    ServiceNodeChangeType type = ServiceNodeChangeType::none;
    std::vector<session::network::service_node> nodes = {};
    uint8_t path_failure_count = 0;
};

using network_response_callback_t = std::function<void(
        bool success,
        bool timeout,
        int16_t status_code,
        std::optional<std::string> response,
        service_node_changes changes)>;

void send_request(
        const ustring_view ed_sk,
        const session::network::service_node target,
        const std::string endpoint,
        const std::optional<ustring> body,
        const std::optional<std::vector<session::network::service_node>> swarm,
        network_response_callback_t handle_response);

template <typename Destination>
void send_onion_request(
        const session::onionreq::onion_path path,
        const Destination destination,
        const std::optional<ustring> body,
        const ustring_view ed_sk,
        const bool is_retry,
        network_response_callback_t handle_response);

}  // namespace session::network