#pragma once

#include <string>
#include <string_view>

#include "key_types.hpp"

namespace session::onionreq {

struct service_node {
    std::string ip;
    uint16_t lmq_port;
    session::onionreq::x25519_pubkey x25519_pubkey;
    session::onionreq::ed25519_pubkey ed25519_pubkey;
    uint8_t failure_count;

    service_node(
            std::string ip,
            uint16_t lmq_port,
            session::onionreq::x25519_pubkey x25519_pubkey,
            session::onionreq::ed25519_pubkey ed25519_pubkey,
            uint8_t failure_count) :
            ip{std::move(ip)},
            lmq_port{std::move(lmq_port)},
            x25519_pubkey{std::move(x25519_pubkey)},
            ed25519_pubkey{std::move(ed25519_pubkey)},
            failure_count{failure_count} {}
};

struct onion_path {
    std::vector<service_node> nodes;
    uint8_t failure_count;
};

class SnodeDestination {
  public:
    service_node node;

    // SnodeDestination(service_node node) : node{std::move(node)} {}

    ustring generate_payload(std::optional<ustring> body) const;
};

class ServerDestination {
  public:
    std::string host;
    std::string target;
    std::string protocol;
    session::onionreq::x25519_pubkey x25519_pubkey;
    std::string method;
    std::optional<uint16_t> port;
    std::optional<std::vector<std::pair<std::string, std::string>>> headers;

    ServerDestination(
            std::string host,
            std::string target,
            std::string protocol,
            session::onionreq::x25519_pubkey x25519_pubkey,
            std::string method = "GET",
            std::optional<uint16_t> port = std::nullopt,
            std::optional<std::vector<std::pair<std::string, std::string>>> headers =
                    std::nullopt) :
            host{std::move(host)},
            target{std::move(target)},
            protocol{std::move(protocol)},
            x25519_pubkey{std::move(x25519_pubkey)},
            port{std::move(port)},
            headers{std::move(headers)},
            method{std::move(method)} {}

    ustring generate_payload(std::optional<ustring> body) const;
};

enum class EncryptType {
    aes_gcm,
    xchacha20,
};

// Takes the encryption type as a string, returns the EncryptType value (or throws if invalid).
// Supported values: aes-gcm and xchacha20.  gcm is accepted as an aliases for aes-gcm.
EncryptType parse_enc_type(std::string_view enc_type);

inline constexpr std::string_view to_string(EncryptType type) {
    switch (type) {
        case EncryptType::xchacha20: return "xchacha20"sv;
        case EncryptType::aes_gcm: return "aes-gcm"sv;
    }
    return ""sv;
}

// Builder class for preparing onion request payloads.
class Builder {
  public:
    EncryptType enc_type;
    std::optional<x25519_pubkey> destination_x25519_public_key = std::nullopt;
    std::optional<x25519_keypair> final_hop_x25519_keypair = std::nullopt;

    Builder(EncryptType enc_type_ = EncryptType::xchacha20) : enc_type{enc_type_} {}

    void set_enc_type(EncryptType enc_type_) { enc_type = enc_type_; }

    template <typename Destination>
    void set_destination(Destination destination);

    template <typename Destination>
    ustring generate_payload(Destination destination, std::optional<ustring> body) const;

    void add_hop(std::pair<ed25519_pubkey, x25519_pubkey> keys) { hops_.push_back(keys); }

    ustring build(ustring payload);

  private:
    std::vector<std::pair<ed25519_pubkey, x25519_pubkey>> hops_ = {};

    // Snode request values

    std::optional<ed25519_pubkey> ed25519_public_key_ = std::nullopt;

    // Proxied request values

    std::optional<std::string> host_ = std::nullopt;
    std::optional<std::string> target_ = std::nullopt;
    std::optional<std::string> protocol_ = std::nullopt;
    std::optional<uint16_t> port_ = std::nullopt;
};

}  // namespace session::onionreq
