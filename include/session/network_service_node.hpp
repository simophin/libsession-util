#pragma once

#include <oxenc/bt_serialize.h>

#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

#include "onionreq/key_types.hpp"

namespace session::network {

struct service_node {
    std::array<uint8_t, 4> ip;
    uint16_t quic_port;
    session::onionreq::x25519_pubkey x25519_pubkey;
    session::onionreq::ed25519_pubkey ed25519_pubkey;
    uint8_t failure_count;
    bool invalid;

    service_node(
            std::array<uint8_t, 4> ip,
            uint16_t quic_port,
            session::onionreq::x25519_pubkey x25519_pubkey,
            session::onionreq::ed25519_pubkey ed25519_pubkey,
            uint8_t failure_count,
            bool invalid) :
            ip{ip},
            quic_port{quic_port},
            x25519_pubkey{std::move(x25519_pubkey)},
            ed25519_pubkey{std::move(ed25519_pubkey)},
            failure_count{failure_count},
            invalid{invalid} {}

    service_node(nlohmann::json json);
    service_node(std::string_view serialised);
    service_node(oxenc::bt_dict_consumer bencoded);

    std::string serialise() const;
    std::string pretty_description() const;

    bool operator==(const service_node& other) const {
        return ip == other.ip && quic_port == other.quic_port &&
               x25519_pubkey == other.x25519_pubkey && ed25519_pubkey == other.ed25519_pubkey &&
               failure_count == other.failure_count && invalid == other.invalid;
    }
};

std::array<uint8_t, 4> split_ipv4(std::string_view ip);

}  // namespace session::network
