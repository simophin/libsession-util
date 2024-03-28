#include "session/network.hpp"

#include <oxenc/hex.h>
#include <sodium/core.h>
#include <sodium/crypto_sign_ed25519.h>

#include <nlohmann/json.hpp>
#include <oxen/log.hpp>
#include <oxen/log/ring_buffer_sink.hpp>
#include <oxen/quic.hpp>
#include <random>
#include <string>
#include <string_view>

#include "session/export.h"
#include "session/network.h"
#include "session/network_service_node.h"
#include "session/network_service_node.hpp"
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
    struct request_info {
        const ustring_view ed_sk;
        const service_node target;
        const std::string endpoint;
        const std::optional<ustring> body;
        const std::optional<std::vector<service_node>> swarm;
        const std::optional<onion_path> path;
        const bool is_retry = false;
    };
}  // namespace

class Timeout : public std::exception {};

// The number of times a path can fail before it's replaced.
const uint16_t path_failure_threshold = 3;

// The number of times a snode can fail before it's replaced.
const uint16_t snode_failure_threshold = 3;

constexpr auto node_not_found_prefix = "Next node not found: "sv;
constexpr auto ALPN = "oxenstorage"sv;
const ustring uALPN{reinterpret_cast<const unsigned char*>(ALPN.data()), ALPN.size()};
std::shared_ptr<oxen::log::RingBufferSink> buffer;

void send_request(const request_info info, network_response_callback_t handle_response);

void add_network_logger(std::function<void(const std::string&)> callback) {
    buffer = std::make_shared<oxen::log::RingBufferSink>(100UL, callback);
    oxen::log::add_sink(buffer);
}

void handle_errors(
        const int16_t status_code,
        const std::optional<std::string> response,
        const request_info info,
        network_response_callback_t handle_response) {
    switch (status_code) {
        // A 404 or a 400 is likely due to a bad/missing SOGS or file so
        // shouldn't mark a path or snode as invalid
        case 400:
        case 404:
            return handle_response(false, false, status_code, response, service_node_changes{});

        // The user's clock is out of sync with the service node network (a
        // snode will return 406, but V4 onion requests returns a 425)
        case 406:
        case 425:
            return handle_response(false, false, status_code, response, service_node_changes{});

        // The snode is reporting that it isn't associated with the given public key anymore. If
        // this is the first 421 then we want to try another node in the swarm (just in case it was
        // reported incorrectly). If this is the second occurrence of the 421 then the client needs
        // to update the swarm (the response might contain updated swarm data)
        case 421:

            try {
                // If there is no response data or no swarm informaiton was provided then we should
                // just replace the swarm
                if (!response || !info.swarm)
                    throw std::invalid_argument{"Unable to handle redirect."};

                // If this was the first 421 then we want to retry using another node in the swarm
                // to get confirmation that we should switch to a different swarm
                if (!info.is_retry) {
                    std::random_device rd;
                    std::mt19937 g(rd());
                    std::vector<session::network::service_node> swarm_copy = *info.swarm;
                    std::shuffle(swarm_copy.begin(), swarm_copy.end(), g);

                    std::optional<session::network::service_node> random_node;

                    for (const auto& node : swarm_copy) {
                        if (node == info.target)
                            continue;

                        random_node = node;
                        break;
                    }

                    if (!random_node)
                        throw std::invalid_argument{"No other nodes in the swarm."};

                    if (info.path) {
                        oxen::log::info(log_cat, "retry onion request");
                        return send_onion_request(
                                *info.path,
                                SnodeDestination{*random_node, *info.swarm},
                                info.body,
                                info.ed_sk,
                                true,
                                handle_response);
                    }

                    return send_request(
                            {info.ed_sk,
                             *random_node,
                             info.endpoint,
                             info.body,
                             info.swarm,
                             std::nullopt,
                             true},
                            handle_response);
                }

                if (!response)
                    throw std::invalid_argument{"No response data."};

                auto response_json = nlohmann::json::parse(*response);
                auto snodes = response_json["snodes"];

                if (!snodes.is_array())
                    throw std::invalid_argument{"Invalid JSON response."};

                std::vector<session::network::service_node> swarm;

                for (auto snode : snodes)
                    swarm.emplace_back(
                            snode["ip"].get<std::string>(),
                            snode["port_omq"].get<uint16_t>(),
                            x25519_pubkey::from_hex(snode["pubkey_x25519"].get<std::string>()),
                            ed25519_pubkey::from_hex(snode["pubkey_ed25519"].get<std::string>()),
                            0,
                            false);

                if (swarm.empty())
                    throw std::invalid_argument{"No snodes in the response."};

                return handle_response(
                        false,
                        false,
                        status_code,
                        response,
                        service_node_changes{ServiceNodeChangeType::replace_swarm, swarm});
            } catch (...) {
                auto updated_path = info.path.value_or(onion_path{{info.target}, 0});
                updated_path.failure_count += 1;

                // If the path has failed too many times, drop the guard snode and increment the
                // failure count of each node in the path
                if (updated_path.failure_count >= path_failure_threshold) {
                    updated_path.nodes[0].invalid = true;

                    for (auto it : updated_path.nodes) {
                        it.failure_count += 1;

                        if (it.failure_count >= snode_failure_threshold)
                            it.invalid = true;
                    }
                }

                return handle_response(
                        false,
                        false,
                        status_code,
                        response,
                        service_node_changes{
                                ServiceNodeChangeType::update_path,
                                updated_path.nodes,
                                updated_path.failure_count});
            }

        default:
            auto updated_path = info.path.value_or(onion_path{{info.target}, 0});
            bool found_invalid_node = false;

            if (response && starts_with(*response, node_not_found_prefix)) {
                std::string_view ed25519PublicKey{response->data() + node_not_found_prefix.size()};

                if (ed25519PublicKey.size() == 64 && oxenc::is_hex(ed25519PublicKey)) {
                    session::onionreq::ed25519_pubkey edpk =
                            session::onionreq::ed25519_pubkey::from_hex(ed25519PublicKey);

                    auto snode_it = std::find_if(
                            updated_path.nodes.begin(),
                            updated_path.nodes.end(),
                            [&edpk](const auto& node) { return node.ed25519_pubkey == edpk; });

                    // Increment the failure count for the snode
                    if (snode_it != updated_path.nodes.end()) {
                        snode_it->failure_count += 1;
                        found_invalid_node = true;

                        if (snode_it->failure_count >= snode_failure_threshold)
                            snode_it->invalid = true;
                    }
                }
            }

            // If we didn't find the specific node that was invalid then increment the path failure
            // count
            if (!found_invalid_node) {
                // Increment the path failure count
                updated_path.failure_count += 1;

                // If the path has failed too many times, drop the guard snode and increment the
                // failure count of each node in the path
                if (updated_path.failure_count >= path_failure_threshold) {
                    updated_path.nodes[0].invalid = true;

                    for (auto it : updated_path.nodes) {
                        it.failure_count += 1;

                        if (it.failure_count >= snode_failure_threshold)
                            it.invalid = true;
                    }
                }
            }

            return handle_response(
                    false,
                    false,
                    status_code,
                    response,
                    service_node_changes{
                            ServiceNodeChangeType::update_path,
                            updated_path.nodes,
                            updated_path.failure_count});
    }
}

void send_request(const request_info info, network_response_callback_t handle_response) {
    try {
        Network net;
        std::promise<std::string> prom;
        auto remote = RemoteAddress{
                info.target.ed25519_pubkey.view(), info.target.ip, info.target.lmq_port};
        auto creds = GNUTLSCreds::make_from_ed_seckey(std::string(from_unsigned_sv(info.ed_sk)));
        auto ep = net.endpoint(Address{"0.0.0.0", 0}, opt::outbound_alpns{{uALPN}});
        auto c = ep->connect(remote, creds);
        auto s = c->open_stream<BTRequestStream>();
        bstring_view payload = {};

        if (info.body)
            payload = bstring_view{
                    reinterpret_cast<const std::byte*>(info.body->data()), info.body->size()};

        s->command(info.endpoint, payload, [&info, &prom](message resp) {
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

        // Default to a 200 success if the response is empty but didn't timeout or error
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

        // If we have a status code that is not in the 2xx range, return the error
        if (status_code < 200 || status_code > 299)
            return handle_errors(status_code, response_data, info, handle_response);

        handle_response(true, false, status_code, response_data, service_node_changes{});
    } catch (const Timeout&) {
        handle_response(false, true, -1, "Request timed out", service_node_changes{});
    } catch (const std::exception& e) {
        handle_response(false, false, -1, e.what(), service_node_changes{});
    }
}

void send_request(
        const ustring_view ed_sk,
        const session::network::service_node target,
        const std::string endpoint,
        const std::optional<ustring> body,
        const std::optional<std::vector<session::network::service_node>> swarm,
        network_response_callback_t handle_response) {
    send_request({ed_sk, target, endpoint, body, swarm, std::nullopt}, handle_response);
}

template <typename Destination>
std::optional<std::vector<session::network::service_node>> swarm_for_destination(
        const Destination destination) {
    return std::nullopt;
}

template <>
std::optional<std::vector<session::network::service_node>> swarm_for_destination(
        const SnodeDestination destination) {
    return destination.swarm;
}

template <typename Destination>
void process_response(
        const Builder builder,
        const Destination destination,
        const std::string response,
        const request_info info,
        network_response_callback_t handle_response) {
    handle_response(false, false, -1, "Invalid destination.", service_node_changes{});
}

template <>
void process_response(
        const Builder builder,
        const SnodeDestination destination,
        const std::string response,
        const request_info info,
        network_response_callback_t handle_response) {
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
        std::string body;

        if (result_json.contains("status_code") && result_json["status_code"].is_number())
            status_code = result_json["status_code"].get<int16_t>();
        else if (result_json.contains("status") && result_json["status"].is_number())
            status_code = result_json["status"].get<int16_t>();
        else
            throw std::runtime_error{"Invalid JSON response, missing required status_code field."};

        if (result_json.contains("body") && result_json["body"].is_string())
            body = result_json["body"].get<std::string>();
        else
            body = result_json.dump();

        // If we got a non 2xx status code, return the error
        if (status_code < 200 || status_code > 299)
            return handle_errors(status_code, body, info, handle_response);

        handle_response(true, false, status_code, body, service_node_changes{});
    } catch (const std::exception& e) {
        handle_response(false, false, -1, e.what(), service_node_changes{});
    }
}

template <>
void process_response(
        const Builder builder,
        const ServerDestination destination,
        const std::string response,
        const request_info info,
        network_response_callback_t handle_response) {
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
        int16_t status_code;
        nlohmann::json response_info_json = nlohmann::json::parse(response_info_string);

        if (response_info_json.contains("code") && response_info_json["code"].is_number())
            status_code = response_info_json["code"].get<int16_t>();
        else
            throw std::runtime_error{"Invalid JSON response, missing required status_code field."};

        // If we have a status code that is not in the 2xx range, return the error
        if (status_code < 200 || status_code > 299) {
            if (result_bencode.is_finished())
                return handle_errors(status_code, std::nullopt, info, handle_response);

            return handle_errors(
                    status_code, result_bencode.consume_string(), info, handle_response);
        }

        // If there is no body just return the success status
        if (result_bencode.is_finished())
            return handle_response(true, false, status_code, std::nullopt, service_node_changes{});

        // Otherwise return the result
        handle_response(
                true, false, status_code, result_bencode.consume_string(), service_node_changes{});
    } catch (const std::exception& e) {
        handle_response(false, false, -1, e.what(), service_node_changes{});
    }
}

template <typename Destination>
void send_onion_request(
        const onion_path path,
        const Destination destination,
        const std::optional<ustring> body,
        const ustring_view ed_sk,
        const bool is_retry,
        network_response_callback_t handle_response) {
    if (path.nodes.empty()) {
        handle_response(
                false,
                false,
                -1,
                "No nodes in the path",
                service_node_changes{ServiceNodeChangeType::invalid_path});
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

        request_info info = {
                ed_sk,
                path.nodes[0],
                "onion_req",
                onion_req_payload,
                swarm_for_destination(destination),
                path,
                is_retry};

        send_request(
                info,
                [builder = std::move(builder),
                 info,
                 destination = std::move(destination),
                 callback = std::move(handle_response)](
                        bool success,
                        bool timeout,
                        int16_t status_code,
                        std::optional<std::string> response,
                        service_node_changes changes) {
                    if (!success || timeout ||
                        !ResponseParser::response_long_enough(builder.enc_type, response->size()))
                        return handle_errors(status_code, response, info, callback);

                    process_response(builder, destination, *response, info, callback);
                });
    } catch (const std::exception& e) {
        handle_response(false, false, -1, e.what(), service_node_changes{});
    }
}

std::vector<network_service_node> convert_service_nodes(
        const std::vector<session::network::service_node> nodes) {
    std::vector<network_service_node> converted_nodes;
    for (const auto& node : nodes) {
        network_service_node converted_node;
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
        const network_service_node destination,
        const char* endpoint,
        const unsigned char* body_,
        size_t body_size,
        const network_service_node* swarm_,
        const size_t swarm_count,
        void (*callback)(
                bool success,
                bool timeout,
                int16_t status_code,
                const char* response,
                size_t response_size,
                network_service_node_changes changes,
                void*),
        void* ctx) {
    assert(ed25519_secretkey_bytes && endpoint && callback);

    std::optional<ustring> body;
    if (body_size > 0)
        body = {body_, body_size};

    std::optional<std::vector<session::network::service_node>> swarm;
    if (swarm_count > 0)
        for (size_t i = 0; i < swarm_count; i++)
            swarm->emplace_back(
                    swarm_[i].ip,
                    swarm_[i].lmq_port,
                    x25519_pubkey::from_hex({swarm_[i].x25519_pubkey_hex, 64}),
                    ed25519_pubkey::from_hex({swarm_[i].ed25519_pubkey_hex, 64}),
                    swarm_[i].failure_count,
                    false);

    send_request(
            {ed25519_secretkey_bytes, 64},
            session::network::service_node{
                    destination.ip,
                    destination.lmq_port,
                    x25519_pubkey::from_hex({destination.x25519_pubkey_hex, 64}),
                    ed25519_pubkey::from_hex({destination.ed25519_pubkey_hex, 64}),
                    destination.failure_count,
                    false},
            endpoint,
            body,
            swarm,
            [callback, ctx](
                    bool success,
                    bool timeout,
                    int status_code,
                    std::optional<std::string> response,
                    service_node_changes changes) {
                auto c_nodes = session::network::convert_service_nodes(changes.nodes);
                auto c_changes = network_service_node_changes{
                        static_cast<SERVICE_NODE_CHANGE_TYPE>(changes.type),
                        c_nodes.data(),
                        c_nodes.size(),
                        changes.path_failure_count};

                callback(
                        success,
                        timeout,
                        status_code,
                        response->data(),
                        response->size(),
                        c_changes,
                        ctx);
            });
}

LIBSESSION_C_API void network_send_onion_request_to_snode_destination(
        const onion_request_path path_,
        const unsigned char* ed25519_secretkey_bytes,
        const onion_request_service_node_destination node,
        const unsigned char* body_,
        size_t body_size,
        void (*callback)(
                bool success,
                bool timeout,
                int16_t status_code,
                const char* response,
                size_t response_size,
                network_service_node_changes changes,
                void*),
        void* ctx) {
    assert(ed25519_secretkey_bytes && callback);

    try {
        std::vector<session::network::service_node> nodes;
        for (size_t i = 0; i < path_.nodes_count; i++)
            nodes.emplace_back(
                    path_.nodes[i].ip,
                    path_.nodes[i].lmq_port,
                    x25519_pubkey::from_hex({path_.nodes[i].x25519_pubkey_hex, 64}),
                    ed25519_pubkey::from_hex({path_.nodes[i].ed25519_pubkey_hex, 64}),
                    path_.nodes[i].failure_count,
                    false);

        session::onionreq::onion_path path = {nodes, path_.failure_count};

        std::optional<ustring> body;
        if (body_size > 0)
            body = {body_, body_size};

        std::optional<std::vector<session::network::service_node>> swarm;
        if (node.swarm_count > 0)
            for (size_t i = 0; i < node.swarm_count; i++)
                swarm->emplace_back(
                        node.swarm[i].ip,
                        node.swarm[i].lmq_port,
                        x25519_pubkey::from_hex({node.swarm[i].x25519_pubkey_hex, 64}),
                        ed25519_pubkey::from_hex({node.swarm[i].ed25519_pubkey_hex, 64}),
                        node.swarm[i].failure_count,
                        false);

        send_onion_request(
                path,
                SnodeDestination{
                        {node.ip,
                         node.lmq_port,
                         x25519_pubkey::from_hex({node.x25519_pubkey_hex, 64}),
                         ed25519_pubkey::from_hex({node.ed25519_pubkey_hex, 64}),
                         node.failure_count,
                         false},
                        swarm},
                body,
                {ed25519_secretkey_bytes, 64},
                false,
                [callback, ctx](
                        bool success,
                        bool timeout,
                        int status_code,
                        std::optional<std::string> response,
                        service_node_changes changes) {
                    auto c_nodes = session::network::convert_service_nodes(changes.nodes);
                    auto c_changes = network_service_node_changes{
                            static_cast<SERVICE_NODE_CHANGE_TYPE>(changes.type),
                            c_nodes.data(),
                            c_nodes.size(),
                            changes.path_failure_count};

                    callback(
                            success,
                            timeout,
                            status_code,
                            response->data(),
                            response->size(),
                            c_changes,
                            ctx);
                });
    } catch (const std::exception& e) {
        callback(
                false,
                false,
                -1,
                e.what(),
                std::strlen(e.what()),
                network_service_node_changes{},
                ctx);
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
                network_service_node_changes changes,
                void*),
        void* ctx) {
    assert(ed25519_secretkey_bytes && method && protocol && host && endpoint && x25519_pubkey &&
           callback);

    try {
        std::vector<session::network::service_node> nodes;
        for (size_t i = 0; i < path_.nodes_count; i++)
            nodes.emplace_back(
                    path_.nodes[i].ip,
                    path_.nodes[i].lmq_port,
                    x25519_pubkey::from_hex({path_.nodes[i].x25519_pubkey_hex, 64}),
                    ed25519_pubkey::from_hex({path_.nodes[i].ed25519_pubkey_hex, 64}),
                    path_.nodes[i].failure_count,
                    false);

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
                false,
                [callback, ctx](
                        bool success,
                        bool timeout,
                        int status_code,
                        std::optional<std::string> response,
                        service_node_changes changes) {
                    auto c_nodes = session::network::convert_service_nodes(changes.nodes);
                    auto c_changes = network_service_node_changes{
                            static_cast<SERVICE_NODE_CHANGE_TYPE>(changes.type),
                            c_nodes.data(),
                            c_nodes.size(),
                            changes.path_failure_count};

                    callback(
                            success,
                            timeout,
                            status_code,
                            response->data(),
                            response->size(),
                            c_changes,
                            ctx);
                });
    } catch (const std::exception& e) {
        callback(
                false,
                false,
                -1,
                e.what(),
                std::strlen(e.what()),
                network_service_node_changes{},
                ctx);
    }
}

}  // extern "C"