#pragma once

#include <oxen/quic.hpp>

#include "session/types.hpp"

namespace session::network {

void send_request(
        ustring_view ed_sk,
        oxen::quic::RemoteAddress target,
        std::string endpoint,
        ustring body,
        std::function<void(bool success, int16_t status_code, std::optional<std::string> response)>
                handle_response);

}  // namespace session::network