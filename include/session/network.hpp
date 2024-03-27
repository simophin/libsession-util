#pragma once

#include <oxen/quic.hpp>

#include "session/onionreq/builder.hpp"
#include "session/onionreq/key_types.hpp"
#include "session/types.hpp"

namespace session::network {

using network_response_callback_t = std::function<void(
        bool success, bool timeout, int16_t status_code, std::optional<std::string> response)>;
using network_onion_response_callback_t = std::function<void(
        bool success,
        bool timeout,
        int16_t status_code,
        std::optional<std::string> response,
        session::onionreq::onion_path updated_failures_path)>;

void send_request(
        ustring_view ed_sk,
        oxen::quic::RemoteAddress target,
        std::string endpoint,
        std::optional<oxen::quic::bstring_view> body,
        network_response_callback_t handle_response);

template <typename Destination>
void send_onion_request(
        const session::onionreq::onion_path path,
        const Destination destination,
        const std::optional<ustring> body,
        const ustring_view ed_sk,
        network_onion_response_callback_t handle_response);

}  // namespace session::network