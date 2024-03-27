#include "session/network.hpp"

#include <oxenc/hex.h>
#include <sodium/core.h>
#include <sodium/crypto_sign_ed25519.h>

#include <nlohmann/json.hpp>
#include <oxen/quic.hpp>
#include <string>
#include <string_view>

#include "session/export.h"
#include "session/network.h"
#include "session/onionreq/builder.h"
#include "session/onionreq/builder.hpp"
#include "session/onionreq/key_types.hpp"
#include "session/onionreq/response_parser.hpp"
#include "session/util.hpp"

using namespace session;
using namespace oxen::quic;
using namespace session::onionreq;
using namespace std::literals;

namespace session::network {

namespace {
    ustring encode_size(uint32_t s) {
        ustring result;
        result.resize(4);
        oxenc::write_host_as_little(s, result.data());
        return result;
    }
}  // namespace

class Timeout : public std::exception {};

// The number of times a path can fail before it's replaced.
const uint16_t path_failure_threshold = 3;

// The number of times a snode can fail before it's replaced.
const uint16_t snode_failure_threshold = 3;

constexpr auto ALPN = "oxenstorage"sv;
const ustring uALPN{reinterpret_cast<const unsigned char*>(ALPN.data()), ALPN.size()};

void send_request(
        ustring_view ed_sk,
        RemoteAddress target,
        std::string endpoint,
        std::optional<bstring_view> body,
        network_response_callback_t handle_response) {
    try {
        Network net;
        std::promise<std::string> prom;
        auto creds = GNUTLSCreds::make_from_ed_seckey(std::string(from_unsigned_sv(ed_sk)));
        auto ep = net.endpoint(Address{"0.0.0.0", 0}, opt::outbound_alpns{{uALPN}});
        auto c = ep->connect(target, creds);
        auto s = c->open_stream<BTRequestStream>();
        bstring_view payload = {};

        if (body)
            payload = *body;

        s->command(std::move(endpoint), payload, [&target, &prom](message resp) {
            try {
                if (resp.timed_out)
                    throw Timeout{};

                std::string body = resp.body_str();
                if (resp.is_error() && !body.empty())
                    throw std::runtime_error{"Failed to fetch response with error: " + body};
                else if (resp.is_error())
                    throw std::runtime_error{"Failed to fetch response"};

                prom.set_value(body);
            } catch (...) {
                prom.set_exception(std::current_exception());
            }
        });

        std::string response = prom.get_future().get();
        int16_t status_code = 200;
        std::string response_data;

        try {
            nlohmann::json response_json = nlohmann::json::parse(response);

            if (response_json.is_array() && response_json.size() == 2) {
                status_code = response_json[0].get<int16_t>();
                response_data = response_json[1].dump();
            } else
                response_data = response;
        } catch (...) {
            response_data = response;
        }

        handle_response(true, false, status_code, response_data);
    } catch (const Timeout&) {
        handle_response(false, true, -1, "Request timed out");
    } catch (const std::exception& e) {
        handle_response(false, false, -1, e.what());
    }
}

template <typename Destination>
void process_response(
        const onion_path path,
        const Builder builder,
        const Destination destination,
        const std::string response,
        network_onion_response_callback_t handle_response) {
    handle_response(false, false, -1, "Invalid destination.", path);
}

template <>
void process_response(
        const onion_path path,
        const Builder builder,
        const SnodeDestination destination,
        const std::string response,
        network_onion_response_callback_t handle_response) {
    // The SnodeDestination runs via V3 onion requests
    try {
        std::string base64_iv_and_ciphertext;

        try {
            nlohmann::json response_json = nlohmann::json::parse(response);

            if (!response_json.contains("result") || !response_json["result"].is_string())
                throw std::runtime_error{"JSON missing result field."};

            base64_iv_and_ciphertext = response_json["result"].get<std::string>();
        } catch (...) {
            base64_iv_and_ciphertext = response;
        }

        if (!oxenc::is_base64(base64_iv_and_ciphertext))
            throw std::runtime_error{"Invalid base64 encoded IV and ciphertext."};

        ustring iv_and_ciphertext;
        oxenc::from_base64(
                base64_iv_and_ciphertext.begin(),
                base64_iv_and_ciphertext.end(),
                std::back_inserter(iv_and_ciphertext));
        auto parser = ResponseParser(builder);
        auto result = parser.decrypt(iv_and_ciphertext);
        auto result_json = nlohmann::json::parse(result);
        int16_t status_code;

        if (result_json.contains("status_code") && result_json["status_code"].is_number())
            status_code = result_json["status_code"].get<int16_t>();
        else if (result_json.contains("status") && result_json["status"].is_number())
            status_code = result_json["status"].get<int16_t>();
        else
            throw std::runtime_error{"Invalid JSON response, missing required status_code field."};

        if (result_json.contains("body") && result_json["body"].is_string())
            handle_response(true, false, status_code, result_json["body"].get<std::string>(), path);
        else
            handle_response(true, false, status_code, result_json.dump(), path);
    } catch (const std::exception& e) {
        handle_response(false, false, -1, e.what(), path);
    }
}

template <>
void process_response(
        const onion_path path,
        const Builder builder,
        const ServerDestination destination,
        const std::string response,
        network_onion_response_callback_t handle_response) {
    // The ServerDestination runs via V4 onion requests
    try {
        ustring response_data = {to_unsigned(response.data()), response.size()};
        auto parser = ResponseParser(builder);
        auto result = parser.decrypt(response_data);

        // Process the bencoded response
        auto result_sv = from_unsigned_sv(result.data());
        oxenc::bt_list_consumer result_bencode{result};

        if (result_bencode.is_finished() || !result_bencode.is_string())
            throw std::runtime_error{"Invalid bencoded response"};

        auto response_info_string = result_bencode.consume_string();
        auto response_info_json = nlohmann::json::parse(response_info_string);
        int16_t status_code;

        if (response_info_json.contains("code") && response_info_json["code"].is_number())
            status_code = response_info_json["code"].get<int16_t>();
        else
            throw std::runtime_error{"Invalid JSON response, missing required status_code field."};

        // If we have a status code that is not in the 2xx range, return the error
        if (status_code < 200 || status_code > 299) {
            if (result_bencode.is_finished()) {
                handle_response(true, false, status_code, std::string(result_sv), path);
                return;
            }

            std::string message = result_bencode.consume_string();
            handle_response(true, false, status_code, message, path);
            return;
        }

        auto response_string = result_bencode.consume_string();
        auto response_json = nlohmann::json::parse(response_string);
        handle_response(true, false, status_code, response_json.dump(), path);
    } catch (const std::exception& e) {
        handle_response(false, false, -1, e.what(), path);
    }
}

template <typename Destination>
void send_onion_request(
        const onion_path path,
        const Destination destination,
        const std::optional<ustring> body,
        const ustring_view ed_sk,
        network_onion_response_callback_t handle_response) {
    if (path.nodes.empty()) {
        handle_response(false, false, -1, "No nodes in the path", path);
        return;
    }

    try {
        // Construct the onion request
        auto builder = Builder();
        builder.set_destination(destination);

        for (const auto& node : path.nodes)
            builder.add_hop({node.ed25519_pubkey, node.x25519_pubkey});

        auto payload = builder.generate_payload(destination, body);
        auto onion_req_payload = builder.build(to_unsigned(payload.data()));
        bstring_view quic_payload = bstring_view{
                reinterpret_cast<const std::byte*>(onion_req_payload.data()),
                onion_req_payload.size()};
        send_request(
                ed_sk,
                RemoteAddress{
                        path.nodes[0].ed25519_pubkey.view(),
                        path.nodes[0].ip,
                        path.nodes[0].lmq_port},
                "onion_req",
                quic_payload,
                [builder = std::move(builder),
                 path = std::move(path),
                 destination = std::move(destination),
                 callback = std::move(handle_response)](
                        bool success,
                        bool timeout,
                        int16_t status_code,
                        std::optional<std::string> response) {
                    onion_path updated_path = path;

                    if (!success || timeout ||
                        !ResponseParser::response_long_enough(builder.enc_type, response->size())) {
                        switch (status_code) {
                            // A 404 or a 400 is likely due to a bad/missing SOGS or file so
                            // shouldn't mark a path or snode as invalid
                            case 400: break;
                            case 404: break;

                            // The user's clock is out of sync with the service node network (a
                            // snode will return 406, but V4 onion requests returns a 425)
                            case 406: break;
                            case 425: break;

                            // The snode isn't associated with the given public key anymore (the
                            // client needs to update the swarm, the response might contain updated
                            // swarm data)
                            case 421: updated_path.nodes[0].invalid = true; break;

                            default:
                                std::string node_not_found_prefix = "Next node not found: ";

                                if (response.has_value() &&
                                    response->substr(0, node_not_found_prefix.size()) ==
                                            node_not_found_prefix) {
                                    std::string ed25519PublicKey =
                                            response->substr(response->find(":") + 1);
                                    auto snode = std::find_if(
                                            updated_path.nodes.begin(),
                                            updated_path.nodes.end(),
                                            [&ed25519PublicKey](const auto& node) {
                                                return node.ed25519_pubkey.hex() ==
                                                       ed25519PublicKey;
                                            });

                                    // The node is invalid so mark is as such so it can be dropped
                                    snode->invalid = true;
                                } else {
                                    // Increment the path failure count
                                    updated_path.failure_count += 1;

                                    // Increment the failure count for each snode in the path
                                    // (skipping the first as it would be dropped if the path is
                                    // dropped)
                                    for (auto it = updated_path.nodes.begin() + 1;
                                         it != updated_path.nodes.end();
                                         ++it) {
                                        it->failure_count += 1;

                                        if (it->failure_count >= snode_failure_threshold)
                                            it->invalid = true;
                                    }

                                    // If the path has failed too many times, drop the guard snode
                                    if (updated_path.failure_count >= path_failure_threshold)
                                        updated_path.nodes[0].invalid = true;
                                }
                                break;
                        }

                        callback(success, timeout, status_code, response, updated_path);
                        return;
                    }

                    process_response(updated_path, builder, destination, *response, callback);
                });
    } catch (const std::exception& e) {
        handle_response(false, false, -1, e.what(), path);
    }
}

std::vector<onion_request_service_node> convert_service_nodes(const std::vector<service_node> nodes) {
    std::vector<onion_request_service_node> converted_nodes;
    for (const auto& node : nodes) {
        onion_request_service_node converted_node;
        strncpy(converted_node.ip, node.ip.c_str(), sizeof(converted_node.ip) - 1);
        converted_node.ip[sizeof(converted_node.ip) - 1] = '\0';  // Ensure null termination
        strncpy(converted_node.x25519_pubkey_hex, node.x25519_pubkey.hex().c_str(), 64);
        strncpy(converted_node.ed25519_pubkey_hex, node.ed25519_pubkey.hex().c_str(), 64);
        converted_node.lmq_port = node.lmq_port;
        converted_node.failure_count = node.failure_count;
        converted_node.invalid = node.invalid;
        converted_nodes.push_back(converted_node);
    }

    return converted_nodes;
}

}  // namespace session::network

extern "C" {

using namespace session::network;

LIBSESSION_C_API void network_add_logger(void (*callback)(const char*, size_t)) {
    assert(callback);
    add_network_logger([callback](const std::string& msg) { callback(msg.c_str(), msg.size()); });
}

LIBSESSION_C_API void network_send_request(
        const unsigned char* ed25519_secretkey_bytes,
        const remote_address remote,
        const char* endpoint,
        size_t endpoint_size,
        const unsigned char* body_,
        size_t body_size,
        void (*callback)(
                bool success,
                bool timeout,
                int16_t status_code,
                const char* response,
                size_t response_size,
                void*),
        void* ctx) {
    assert(ed25519_secretkey_bytes && endpoint && callback);

    std::optional<bstring_view> body;
    if (body_size > 0)
        body = bstring_view{reinterpret_cast<const std::byte*>(body_), body_size};

    std::string_view remote_pubkey_hex = {remote.pubkey, 64};
    session::ustring remote_pubkey;
    oxenc::from_hex(
            remote_pubkey_hex.begin(), remote_pubkey_hex.end(), std::back_inserter(remote_pubkey));

    send_request(
            {ed25519_secretkey_bytes, 64},
            {remote_pubkey, remote.ip, remote.port},
            {endpoint, endpoint_size},
            body,
            [callback, ctx](
                    bool success,
                    bool timeout,
                    int status_code,
                    std::optional<std::string> response) {
                callback(success, timeout, status_code, response->data(), response->size(), ctx);
            });
}

LIBSESSION_C_API void network_send_onion_request_to_snode_destination(
        const onion_request_path path_,
        const unsigned char* ed25519_secretkey_bytes,
        const onion_request_service_node node,
        const unsigned char* body_,
        size_t body_size,
        void (*callback)(
                bool success,
                bool timeout,
                int16_t status_code,
                const char* response,
                size_t response_size,
                onion_request_path updated_failures_path,
                void*),
        void* ctx) {
    assert(ed25519_secretkey_bytes && callback);

    try {
        std::vector<session::onionreq::service_node> nodes;
        for (size_t i = 0; i < path_.nodes_count; i++)
            nodes.emplace_back(
                    path_.nodes[i].ip,
                    path_.nodes[i].lmq_port,
                    x25519_pubkey::from_hex({path_.nodes[i].x25519_pubkey_hex, 64}),
                    ed25519_pubkey::from_hex({path_.nodes[i].ed25519_pubkey_hex, 64}),
                    path_.nodes[i].failure_count);

        session::onionreq::onion_path path = {nodes, path_.failure_count};

        std::optional<ustring> body;
        if (body_size > 0)
            body = {body_, body_size};

        send_onion_request(
                path,
                SnodeDestination{
                        {node.ip,
                         node.lmq_port,
                         x25519_pubkey::from_hex({node.x25519_pubkey_hex, 64}),
                         ed25519_pubkey::from_hex({node.ed25519_pubkey_hex, 64}),
                         node.failure_count}},
                body,
                {ed25519_secretkey_bytes, 64},
                [callback, ctx](
                        bool success,
                        bool timeout,
                        int status_code,
                        std::optional<std::string> response,
                        session::onionreq::onion_path updated_failures_path) {
                    auto nodes = session::network::convert_service_nodes(updated_failures_path.nodes);
                    auto updated_path = onion_request_path{nodes.data(), nodes.size(), updated_failures_path.failure_count};
                    callback(
                            success,
                            timeout,
                            status_code,
                            response->data(),
                            response->size(),
                            updated_path,
                            ctx);
                });
    } catch (const std::exception& e) {
        callback(false, false, -1, e.what(), std::strlen(e.what()), path_, ctx);
    }
}

LIBSESSION_C_API void network_send_onion_request_to_server_destination(
        const onion_request_path path_,
        const unsigned char* ed25519_secretkey_bytes,
        const char* method,
        const char* protocol,
        const char* host,
        const char* endpoint,
        uint16_t port,
        const char* x25519_pubkey,
        const char** headers_,
        const char** header_values,
        size_t headers_size,
        const unsigned char* body_,
        size_t body_size,
        void (*callback)(
                bool success,
                bool timeout,
                int16_t status_code,
                const char* response,
                size_t response_size,
                onion_request_path updated_failures_path,
                void*),
        void* ctx) {
    assert(ed25519_secretkey_bytes && method && protocol && host && endpoint && x25519_pubkey && callback);

    try {
        std::vector<session::onionreq::service_node> nodes;
        for (size_t i = 0; i < path_.nodes_count; i++)
            nodes.emplace_back(
                    path_.nodes[i].ip,
                    path_.nodes[i].lmq_port,
                    x25519_pubkey::from_hex({path_.nodes[i].x25519_pubkey_hex, 64}),
                    ed25519_pubkey::from_hex({path_.nodes[i].ed25519_pubkey_hex, 64}),
                    path_.nodes[i].failure_count);

        session::onionreq::onion_path path = {nodes, path_.failure_count};
        std::optional<std::vector<std::pair<std::string, std::string>>> headers;
        if (headers_size > 0) {
            headers = std::vector<std::pair<std::string, std::string>>{};

            for (size_t i = 0; i < headers_size; i++)
                headers->emplace_back(headers_[i], header_values[i]);
        }

        std::optional<ustring> body;
        if (body_size > 0)
            body = {body_, body_size};

        send_onion_request(
                path,
                ServerDestination{
                        protocol,
                        host,
                        endpoint,
                        x25519_pubkey::from_hex({x25519_pubkey, 64}),
                        method,
                        port,
                        headers},
                body,
                {ed25519_secretkey_bytes, 64},
                [callback, ctx](
                        bool success,
                        bool timeout,
                        int status_code,
                        std::optional<std::string> response,
                        session::onionreq::onion_path updated_failures_path) {
                    auto nodes = session::network::convert_service_nodes(updated_failures_path.nodes);
                    auto updated_path = onion_request_path{nodes.data(), nodes.size(), updated_failures_path.failure_count};
                    callback(
                            success,
                            timeout,
                            status_code,
                            response->data(),
                            response->size(),
                            updated_path,
                            ctx);
                });
    } catch (const std::exception& e) {
        callback(false, false, -1, e.what(), std::strlen(e.what()), path_, ctx);
    }
}

}  // extern "C"