#pragma once

#include <oxenc/bt_serialize.h>

#include <nlohmann/json.hpp>
#include <oxen/quic.hpp>
#include <string>
#include <string_view>

#include "onionreq/key_types.hpp"
#include "util.hpp"

namespace session::network {

namespace {
    std::vector<std::string_view> split_snode(std::string_view str) {
        auto parts = split(str, "|");
        if (parts.size() < 4)
            throw std::invalid_argument("Invalid service node serialisation: " + std::string(str));

        return parts;
    }
}  // namespace

struct service_node : public oxen::quic::RemoteAddress {
  public:
    session::onionreq::x25519_pubkey x25519_pubkey;
    uint8_t failure_count;
    bool invalid;

    service_node(
            std::string_view ed25519_pubkey_hex,
            std::string_view x25519_pubkey_hex,
            std::string ip,
            uint16_t port,
            uint8_t failure_count = 0,
            bool invalid = false) :
            oxen::quic::RemoteAddress{oxenc::from_hex(ed25519_pubkey_hex), ip, port},
            x25519_pubkey{session::onionreq::x25519_pubkey::from_hex(x25519_pubkey_hex)},
            failure_count{failure_count},
            invalid{invalid} {}

    service_node(nlohmann::json json) :
            service_node(
                    json["pubkey_ed25519"].get<std::string>(),
                    json["pubkey_x25519"].get<std::string>(),
                    json["ip"].get<std::string>(),
                    json["port_omq"].get<uint16_t>()){};

    service_node(oxenc::bt_dict_consumer bencoded) :
            service_node(
                    bencoded.consume_string(),                // pubkey_ed25519
                    bencoded.consume_string(),                // pubkey_x25519
                    bencoded.consume_string(),                // public_ip
                    bencoded.consume_integer<uint16_t>()){};  // storage_lmq_port

    service_node(std::string_view serialised) : service_node(split_snode(serialised)){};

    std::string serialise() const;

    bool operator==(const service_node& other) const {
        return oxen::quic::RemoteAddress::operator==(other) &&
               x25519_pubkey == other.x25519_pubkey && failure_count == other.failure_count &&
               invalid == other.invalid;
    }

  private:
    service_node(std::vector<std::string_view> parts) :
            service_node(
                    parts[3],                          // ed25519_pubkey
                    parts[2],                          // x25519_pubkey
                    std::string(parts[0]),             // ip
                    std::stoi(std::string{parts[1]}),  // port
                    (parts.size() >= 5 ? std::stoi(std::string{parts[4]}) : 0)){};  // failure_count
};

}  // namespace session::network
