#pragma once

#include <string>
#include <string_view>

#include "onionreq/key_types.hpp"

namespace session::network {

struct service_node {
    std::string ip;
    uint16_t lmq_port;
    session::onionreq::x25519_pubkey x25519_pubkey;
    session::onionreq::ed25519_pubkey ed25519_pubkey;
    uint8_t failure_count;
    bool invalid;

    service_node(
            std::string ip,
            uint16_t lmq_port,
            session::onionreq::x25519_pubkey x25519_pubkey,
            session::onionreq::ed25519_pubkey ed25519_pubkey,
            uint8_t failure_count,
            bool invalid) :
            ip{std::move(ip)},
            lmq_port{lmq_port},
            x25519_pubkey{std::move(x25519_pubkey)},
            ed25519_pubkey{std::move(ed25519_pubkey)},
            failure_count{failure_count},
            invalid{invalid} {}

    bool operator==(const service_node& other) const {
        return ip == other.ip && lmq_port == other.lmq_port &&
               x25519_pubkey == other.x25519_pubkey && ed25519_pubkey == other.ed25519_pubkey &&
               failure_count == other.failure_count && invalid == other.invalid;
    }
};

}  // namespace session::network
