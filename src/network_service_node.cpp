#include "session/network_service_node.hpp"

#include <sodium/crypto_sign_ed25519.h>

#include <oxen/log/format.hpp>
#include <string>
#include <string_view>

#include "session/onionreq/key_types.hpp"

using namespace session;
using namespace session::onionreq;

namespace session::network {

service_node::service_node(nlohmann::json json) {
    ip = split_ipv4(json["ip"].get<std::string>());
    quic_port = json["port_omq"].get<uint16_t>();
    x25519_pubkey = x25519_pubkey::from_hex(json["pubkey_x25519"].get<std::string>());
    ed25519_pubkey = ed25519_pubkey::from_hex(json["pubkey_ed25519"].get<std::string>());
}

service_node::service_node(std::string_view serialised) {
    auto parts = split(serialised, "|");
    if (parts.size() < 4)
        throw std::invalid_argument{
                "Invalid service node serialisation: " + std::to_string(parts.size()) + ", " +
                std::string(serialised)};

    ip = split_ipv4(parts[0]);
    quic_port = std::stoi(std::string{parts[1]});
    x25519_pubkey = x25519_pubkey::from_hex(parts[2]);
    ed25519_pubkey = ed25519_pubkey::from_hex(parts[3]);
    invalid = false;  // If a node is invalid we would have removed it from the pool

    // If we have a failure count then parse it
    if (parts.size() >= 5)
        failure_count = std::stoi(std::string{parts[4]});
    else
        failure_count = 0;
}

service_node::service_node(oxenc::bt_dict_consumer bencoded) {
    ed25519_pubkey = ed25519_pubkey::from_hex(bencoded.consume_string());
    x25519_pubkey = x25519_pubkey::from_hex(bencoded.consume_string());
    ip = split_ipv4(bencoded.consume_string());
    quic_port = bencoded.consume_integer<uint16_t>();
}

std::string service_node::serialise() const {
    return fmt::format(
            "{}.{}.{}.{}|{}|{}|{}|{}|{}",
            ip[0],
            ip[1],
            ip[2],
            ip[3],
            quic_port,
            x25519_pubkey.hex(),
            ed25519_pubkey.hex(),
            failure_count,
            invalid ? "1" : "0");
}

std::string service_node::pretty_description() const {
    return fmt::format("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], quic_port);
};

std::array<uint8_t, 4> split_ipv4(std::string_view ip) {
    std::array<uint8_t, 4> quad;
    auto nums = split(ip, ".");
    if (nums.size() != 4)
        throw "Invalid IPv4 address";
    for (int i = 0; i < 4; i++) {
        auto end = nums[i].data() + nums[i].size();
        if (auto [p, ec] = std::from_chars(nums[i].data(), end, quad[i]);
            ec != std::errc{} || p != end)
            throw "Invalid malformed IPv4 address";
    }

    return quad;
}

}  // namespace session::network