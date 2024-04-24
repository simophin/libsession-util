#include "session/network_service_node.hpp"

#include <oxen/log/format.hpp>

#include "session/onionreq/key_types.hpp"

namespace session::network {

std::string service_node::serialise() const {
    auto ed25519_pubkey_hex = oxenc::to_hex(view_remote_key());

    return fmt::format(
            "{}|{}|{}|{}|{}|{}",
            host(),
            port(),
            x25519_pubkey.hex(),
            ed25519_pubkey_hex,
            failure_count,
            invalid ? "1" : "0");
}

}  // namespace session::network