#include "session/network.hpp"

#include <oxenc/hex.h>
#include <sodium/core.h>
#include <sodium/crypto_sign_ed25519.h>

#include <nlohmann/json.hpp>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/log/ring_buffer_sink.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/opt.hpp>
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
using namespace oxen::log::literals;

namespace session::network {

namespace {

    inline auto log_cat = oxen::log::Cat("network");

    class Timeout : public std::exception {};

    const std::chrono::seconds default_timeout = 5s;

    // The number of times a path can fail before it's replaced.
    const uint16_t path_failure_threshold = 3;

    // The number of times a snode can fail before it's replaced.
    const uint16_t snode_failure_threshold = 3;

    constexpr auto node_not_found_prefix = "Next node not found: "sv;
    constexpr auto ALPN = "oxenstorage"sv;
    const ustring uALPN{reinterpret_cast<const unsigned char*>(ALPN.data()), ALPN.size()};

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
}  // namespace

Network::Network(const session::onionreq::ed25519_seckey ed25519_seckey) {
    creds = GNUTLSCreds::make_from_ed_seckey(std::string(ed25519_seckey.view()));
    endpoint = net.endpoint(Address{"0.0.0.0", 0}, opt::outbound_alpns{{uALPN}});
}

void Network::add_logger(std::function<void(const std::string&)> callback) {
    buffer = std::make_shared<oxen::log::RingBufferSink>(100UL, callback);
    oxen::log::add_sink(buffer);
}

void Network::replace_key(const session::onionreq::ed25519_seckey ed25519_seckey) {
    creds = GNUTLSCreds::make_from_ed_seckey(std::string(ed25519_seckey.view()));

    // Since the key is getting replaced we need to remove any connections from the paths
    net.call([this]() mutable {
        for (auto& path : paths)
            path.conn.reset();
    });
}

void Network::add_path(std::vector<session::network::service_node> nodes, uint8_t failure_count) {
    if (nodes.empty())
        throw std::invalid_argument{"No nodes in the path"};

    auto existing_path = net.call_get([this, node = nodes.front()]() -> std::optional<onion_path> {
        auto target_path = std::find_if(paths.begin(), paths.end(), [&node](const auto& path) {
            return !path.nodes.empty() && node == path.nodes.front();
        });

        if (target_path == paths.end())
            return std::nullopt;

        return *target_path;
    });

    if (existing_path)
        throw std::invalid_argument{"Cannot have multiple paths with the same starting node"};

    auto c = get_connection(nodes.front());
    net.call([this, c, nodes, failure_count]() mutable {
        paths.emplace_back(onion_path{std::move(c), std::move(nodes), failure_count});
    });
}

void Network::remove_path(session::network::service_node node) {
    auto it = std::find_if(paths.begin(), paths.end(), [&node](const auto& path) {
        return path.nodes[0] == node;
    });

    if (it != paths.end())
        paths.erase(it);
}

void Network::remove_all_paths() {
    paths.clear();
}

std::shared_ptr<oxen::quic::connection_interface> Network::get_connection(
        const service_node target) {
    auto remote_ip = "{}"_format(fmt::join(target.ip, "."));
    auto remote = RemoteAddress{target.ed25519_pubkey.view(), remote_ip, target.quic_port};

    return endpoint->connect(
            remote,
            creds,
            oxen::quic::opt::keep_alive{10s},
            [this, target](connection_interface& conn, uint64_t) {
                auto target_path =
                        std::find_if(paths.begin(), paths.end(), [&target](const auto& path) {
                            return !path.nodes.empty() && target == path.nodes.front();
                        });

                if (target_path != paths.end() && target_path->conn &&
                    conn.reference_id() == target_path->conn->reference_id())
                    target_path->conn.reset();
            });
}

std::shared_ptr<oxen::quic::BTRequestStream> Network::get_btstream(const service_node target) {
    auto has_target_path = net.call_get([this, &target]() -> bool {
        auto target_path = std::find_if(paths.begin(), paths.end(), [&target](const auto& path) {
            return !path.nodes.empty() && target == path.nodes.front();
        });

        return target_path != paths.end();
    });

    // If we are targeting one of the paths then wait for `default_timeout` to give it a chance to
    // create an active connection
    std::chrono::milliseconds wait_time_ms = 0ms;
    while (has_target_path && wait_time_ms < default_timeout) {
        auto result = net.call_get(
                [this, &target]() -> std::pair<std::shared_ptr<oxen::quic::BTRequestStream>, bool> {
                    auto target_path =
                            std::find_if(paths.begin(), paths.end(), [&target](const auto& path) {
                                return !path.nodes.empty() && target == path.nodes.front();
                            });

                    if (target_path != paths.end() && target_path->conn &&
                        target_path->conn->remote_key() != to_usv(target.ed25519_pubkey.view())) {
                        if (auto str =
                                    target_path->conn->maybe_stream<oxen::quic::BTRequestStream>(0))
                            return {str, true};

                        return {nullptr, true};
                    }

                    return {nullptr, false};
                });

        // If we were able to get a valid connection then return it
        if (result.first)
            return result.first;

        // Otherwise if there was no connection at all then return nullptr immediately so a new
        // connection gets created (this can happen if the `conn` times out or fails initially so we
        // don't want to bother looping in that case)
        if (!result.second)
            break;

        std::this_thread::sleep_for(100ms);
        wait_time_ms += 100ms;
    }

    // We weren't able to get an existing connection so we need to create a new one
    auto c = get_connection(target);
    net.call([this, c, &target]() mutable {
        auto target_path = std::find_if(paths.begin(), paths.end(), [&target](const auto& path) {
            return !path.nodes.empty() && target == path.nodes.front();
        });

        if (target_path == paths.end())
            return;

        target_path->conn = std::move(c);
    });
    std::shared_ptr<oxen::quic::BTRequestStream> str =
            c->open_stream<oxen::quic::BTRequestStream>();

    return str;
}

void Network::send_request(const request_info info, network_response_callback_t handle_response) {
    try {
        std::promise<std::string> prom;
        bstring_view payload = {};

        if (info.body)
            payload = bstring_view{
                    reinterpret_cast<const std::byte*>(info.body->data()), info.body->size()};

        get_btstream(info.target)->command(info.endpoint, payload, [&prom](message resp) {
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

void Network::send_request(
        const session::network::service_node target,
        const std::string endpoint,
        const std::optional<ustring> body,
        const std::optional<std::vector<session::network::service_node>> swarm,
        network_response_callback_t handle_response) {
    send_request({target, endpoint, body, swarm, std::nullopt, false}, handle_response);
}

template <typename Destination>
std::optional<std::vector<session::network::service_node>> swarm_for_destination(
        const Destination) {
    return std::nullopt;
}

template <>
std::optional<std::vector<session::network::service_node>> swarm_for_destination(
        const SnodeDestination destination) {
    return destination.swarm;
}

// The SnodeDestination runs via V3 onion requests
void Network::process_snode_response(
        const Builder builder,
        const std::string response,
        const request_info info,
        network_response_callback_t handle_response) {
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

// The ServerDestination runs via V4 onion requests
void Network::process_server_response(
        const Builder builder,
        const std::string response,
        const request_info info,
        network_response_callback_t handle_response) {
    try {
        ustring response_data = {to_unsigned(response.data()), response.size()};
        auto parser = ResponseParser(builder);
        auto result = parser.decrypt(response_data);

        // Process the bencoded response
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
std::vector<onion_path> valid_paths_for_destination(
        const std::vector<onion_path> paths, const Destination /*destination*/) {
    return paths;
}

template <>
std::vector<onion_path> valid_paths_for_destination(
        const std::vector<onion_path> paths, const SnodeDestination destination) {
    std::vector<onion_path> valid_paths = paths;
    valid_paths.erase(
            std::remove_if(
                    valid_paths.begin(),
                    valid_paths.end(),
                    [destination](const onion_path& path) {
                        return std::any_of(
                                path.nodes.begin(),
                                path.nodes.end(),
                                [&destination](const service_node& node) {
                                    return node == destination.node;
                                });
                    }),
            valid_paths.end());
    return valid_paths;
}

template <typename Destination>
void Network::send_onion_request(
        const Destination destination,
        const std::optional<ustring> body,
        const bool is_retry,
        network_response_callback_t handle_response) {
    // Select a random path
    auto paths = net.call_get([this]() -> std::vector<onion_path> { return this->paths; });
    auto valid_paths = valid_paths_for_destination(paths, destination);
    onion_path path;

    if (valid_paths.empty()) {
        handle_response(
                false,
                false,
                -1,
                (paths.empty() ? "No onion paths" : "No valid onion paths"),
                service_node_changes{ServiceNodeChangeType::invalid_path});
        return;
    }

    if (valid_paths.size() == 1)
        path = valid_paths.front();
    else {
        std::random_device rd;
        std::uniform_int_distribution<uint32_t> dist(0, valid_paths.size() - 1);
        uint32_t random_index = dist(rd);
        path = valid_paths[random_index];
    }

    try {
        // Construct the onion request
        auto builder = Builder();
        builder.set_destination(destination);

        for (const auto& node : path.nodes)
            builder.add_hop({node.ed25519_pubkey, node.x25519_pubkey});

        auto payload = builder.generate_payload(body);
        auto onion_req_payload = builder.build(payload);

        request_info info = {
                path.nodes[0],
                "onion_req",
                onion_req_payload,
                swarm_for_destination(destination),
                path,
                is_retry};

        send_request(
                info,
                [this,
                 builder = std::move(builder),
                 info,
                 destination = std::move(destination),
                 callback = std::move(handle_response)](
                        bool success,
                        bool timeout,
                        int16_t status_code,
                        std::optional<std::string> response,
                        service_node_changes) {
                    if (!success || timeout ||
                        !ResponseParser::response_long_enough(builder.enc_type, response->size()))
                        return handle_errors(status_code, response, info, callback);

                    if constexpr (std::is_same_v<Destination, SnodeDestination>)
                        process_snode_response(builder, *response, info, callback);
                    else if constexpr (std::is_same_v<Destination, ServerDestination>)
                        process_server_response(builder, *response, info, callback);
                    else
                        callback(false, false, -1, "Invalid destination.", service_node_changes{});
                });
    } catch (const std::exception& e) {
        handle_response(false, false, -1, e.what(), service_node_changes{});
    }
}

void Network::handle_errors(
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
        // to update the swarm (if the response contains updated swarm data), or increment the path
        // failure count.
        case 421:
            try {
                // If there is no response data or no swarm informaiton was provided then we should
                // just replace the swarm
                if (!info.swarm)
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

                    if (info.path)
                        return send_onion_request(
                                SnodeDestination{*random_node, *info.swarm},
                                info.body,
                                true,
                                handle_response);

                    return send_request(
                            {*random_node,
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

                for (auto snode : snodes) {
                    swarm.emplace_back(
                            split_ipv4(snode["ip"].get<std::string>()),
                            snode["port_omq"].get<uint16_t>(),
                            x25519_pubkey::from_hex(snode["pubkey_x25519"].get<std::string>()),
                            ed25519_pubkey::from_hex(snode["pubkey_ed25519"].get<std::string>()),
                            0,
                            false);
                }

                if (swarm.empty())
                    throw std::invalid_argument{"No snodes in the response."};

                return handle_response(
                        false,
                        false,
                        status_code,
                        response,
                        service_node_changes{ServiceNodeChangeType::replace_swarm, swarm});
            } catch (...) {
                // If we don't have a path then this is a direct request so we can only update the
                // failure count for the target node
                if (!info.path) {
                    auto updated_node = info.target;
                    updated_node.failure_count += 1;

                    if (updated_node.failure_count >= snode_failure_threshold)
                        updated_node.invalid = true;

                    return handle_response(
                            false,
                            false,
                            status_code,
                            response,
                            service_node_changes{
                                    ServiceNodeChangeType::update_node, {updated_node}});
                }

                auto updated_path = *info.path;
                updated_path.failure_count += 1;

                // If the path has failed too many times we want to drop the guard snode (marking it
                // as invalid) and increment the failure count of each node in the path
                if (updated_path.failure_count >= path_failure_threshold) {
                    updated_path.nodes[0].invalid = true;

                    for (auto& it : updated_path.nodes) {
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
                                updated_path.failure_count,
                                (updated_path.failure_count >= path_failure_threshold)});
            }

        default:
            // If we don't have a path then this is a direct request so we can only update the
            // failure count for the target node
            if (!info.path) {
                auto updated_node = info.target;
                updated_node.failure_count += 1;

                if (updated_node.failure_count >= snode_failure_threshold)
                    updated_node.invalid = true;

                return handle_response(
                        false,
                        false,
                        status_code,
                        response,
                        service_node_changes{ServiceNodeChangeType::update_node, {updated_node}});
            }

            auto updated_path = *info.path;
            bool found_invalid_node = false;

            if (response && response->starts_with(node_not_found_prefix)) {
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

                // If the path has failed too many times we want to drop the guard snode (marking it
                // as invalid) and increment the failure count of each node in the path
                if (updated_path.failure_count >= path_failure_threshold) {
                    updated_path.nodes[0].invalid = true;

                    for (auto& it : updated_path.nodes) {
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
                            updated_path.failure_count,
                            (updated_path.failure_count >= path_failure_threshold)});
    }
}

std::vector<network_service_node> convert_service_nodes(
        const std::vector<session::network::service_node> nodes) {
    std::vector<network_service_node> converted_nodes;
    for (const auto& node : nodes) {
        network_service_node converted_node;
        std::memcpy(converted_node.ip, node.ip.data(), sizeof(converted_node.ip));
        strncpy(converted_node.x25519_pubkey_hex, node.x25519_pubkey.hex().c_str(), 64);
        strncpy(converted_node.ed25519_pubkey_hex, node.ed25519_pubkey.hex().c_str(), 64);
        converted_node.x25519_pubkey_hex[64] = '\0';   // Ensure null termination
        converted_node.ed25519_pubkey_hex[64] = '\0';  // Ensure null termination
        converted_node.quic_port = node.quic_port;
        converted_node.failure_count = node.failure_count;
        converted_node.invalid = node.invalid;
        converted_nodes.push_back(converted_node);
    }

    return converted_nodes;
}

}  // namespace session::network

namespace {

inline session::network::Network& unbox(network_object* network_) {
    assert(network_ && network_->internals);
    return *static_cast<session::network::Network*>(network_->internals);
}

inline bool set_error(char* error, const std::exception& e) {
    if (!error)
        return false;

    std::string msg = e.what();
    if (msg.size() > 255)
        msg.resize(255);
    std::memcpy(error, msg.c_str(), msg.size() + 1);
    return false;
}

}  // namespace

extern "C" {

using namespace session::network;

LIBSESSION_C_API bool network_init(
        network_object** network, const unsigned char* ed25519_secretkey_bytes, char* error) {
    try {
        auto n = std::make_unique<session::network::Network>(
                ed25519_seckey::from_bytes({ed25519_secretkey_bytes, 64}));
        auto n_object = std::make_unique<network_object>();

        n_object->internals = n.release();
        *network = n_object.release();
        return true;
    } catch (const std::exception& e) {
        return set_error(error, e);
    }
}

LIBSESSION_C_API void network_free(network_object* network) {
    delete network;
}

LIBSESSION_C_API void network_add_logger(
        network_object* network, void (*callback)(const char*, size_t)) {
    assert(callback);
    unbox(network).add_logger(
            [callback](const std::string& msg) { callback(msg.c_str(), msg.size()); });
}

LIBSESSION_C_API bool network_replace_key(
        network_object* network, const unsigned char* ed25519_secretkey_bytes, char* error) {
    try {
        unbox(network).replace_key(ed25519_seckey::from_bytes({ed25519_secretkey_bytes, 64}));
        return true;
    } catch (const std::exception& e) {
        return set_error(error, e);
    }
}

LIBSESSION_C_API bool network_add_path(
        network_object* network, const onion_request_path path, char* error) {
    try {
        std::vector<session::network::service_node> nodes;
        for (size_t i = 0; i < path.nodes_count; i++) {
            std::array<uint8_t, 4> ip;
            std::memcpy(ip.data(), path.nodes[i].ip, ip.size());
            nodes.emplace_back(
                    ip,
                    path.nodes[i].quic_port,
                    x25519_pubkey::from_hex({path.nodes[i].x25519_pubkey_hex, 64}),
                    ed25519_pubkey::from_hex({path.nodes[i].ed25519_pubkey_hex, 64}),
                    path.nodes[i].failure_count,
                    false);
        }

        unbox(network).add_path(nodes, path.failure_count);
        return true;
    } catch (const std::exception& e) {
        return set_error(error, e);
    }
}

LIBSESSION_C_API bool network_remove_path(
        network_object* network, const network_service_node node, char* error) {
    try {
        std::array<uint8_t, 4> ip;
        std::memcpy(ip.data(), node.ip, ip.size());
        unbox(network).remove_path(session::network::service_node{
                ip,
                node.quic_port,
                x25519_pubkey::from_hex({node.x25519_pubkey_hex, 64}),
                ed25519_pubkey::from_hex({node.ed25519_pubkey_hex, 64}),
                node.failure_count,
                false});
        return true;
    } catch (const std::exception& e) {
        return set_error(error, e);
    }
}

LIBSESSION_C_API void network_remove_all_paths(network_object* network) {
    unbox(network).remove_all_paths();
}

LIBSESSION_C_API void network_send_request(
        network_object* network,
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
    assert(endpoint && callback);

    std::optional<ustring> body;
    if (body_size > 0)
        body = {body_, body_size};

    std::optional<std::vector<session::network::service_node>> swarm;

    if (swarm_count > 0) {
        swarm = std::vector<session::network::service_node>{};
        swarm->reserve(swarm_count);

        for (size_t i = 0; i < swarm_count; i++) {
            std::array<uint8_t, 4> ip;
            std::memcpy(ip.data(), swarm_[i].ip, ip.size());
            swarm->emplace_back(
                    ip,
                    swarm_[i].quic_port,
                    x25519_pubkey::from_hex({swarm_[i].x25519_pubkey_hex, 64}),
                    ed25519_pubkey::from_hex({swarm_[i].ed25519_pubkey_hex, 64}),
                    swarm_[i].failure_count,
                    false);
        }
    }

    std::array<uint8_t, 4> ip;
    std::memcpy(ip.data(), destination.ip, ip.size());

    unbox(network).send_request(
            session::network::service_node{
                    ip,
                    destination.quic_port,
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
                        changes.path_failure_count,
                        changes.path_invalid};

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
        network_object* network,
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
    assert(callback);

    try {
        std::optional<ustring> body;
        if (body_size > 0)
            body = {body_, body_size};

        std::optional<std::vector<session::network::service_node>> swarm;

        if (node.swarm_count > 0) {
            swarm = std::vector<session::network::service_node>{};
            swarm->reserve(node.swarm_count);

            for (size_t i = 0; i < node.swarm_count; i++) {
                std::array<uint8_t, 4> ip;
                std::memcpy(ip.data(), node.swarm[i].ip, ip.size());
                swarm->emplace_back(
                        ip,
                        node.swarm[i].quic_port,
                        x25519_pubkey::from_hex({node.swarm[i].x25519_pubkey_hex, 64}),
                        ed25519_pubkey::from_hex({node.swarm[i].ed25519_pubkey_hex, 64}),
                        node.swarm[i].failure_count,
                        false);
            }
        }

        std::array<uint8_t, 4> ip;
        std::memcpy(ip.data(), node.ip, ip.size());

        unbox(network).send_onion_request(
                SnodeDestination{
                        {ip,
                         node.quic_port,
                         x25519_pubkey::from_hex({node.x25519_pubkey_hex, 64}),
                         ed25519_pubkey::from_hex({node.ed25519_pubkey_hex, 64}),
                         node.failure_count,
                         false},
                        swarm},
                body,
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
                            changes.path_failure_count,
                            changes.path_invalid};

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
        network_object* network,
        const char* method,
        const char* protocol,
        const char* host,
        const char* endpoint,
        uint16_t port,
        const char* x25519_pubkey,
        const char** query_param_keys,
        const char** query_param_values,
        size_t query_params_size,
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
    assert(method && protocol && host && endpoint && x25519_pubkey && callback);

    try {
        std::optional<std::vector<std::pair<std::string, std::string>>> headers;
        if (headers_size > 0) {
            headers = std::vector<std::pair<std::string, std::string>>{};

            for (size_t i = 0; i < headers_size; i++)
                headers->emplace_back(headers_[i], header_values[i]);
        }

        std::optional<std::vector<std::pair<std::string, std::string>>> query_params;
        if (query_params_size > 0) {
            query_params = std::vector<std::pair<std::string, std::string>>{};

            for (size_t i = 0; i < query_params_size; i++)
                query_params->emplace_back(query_param_keys[i], query_param_values[i]);
        }

        std::optional<ustring> body;
        if (body_size > 0)
            body = {body_, body_size};

        unbox(network).send_onion_request(
                ServerDestination{
                        protocol,
                        host,
                        endpoint,
                        x25519_pubkey::from_hex({x25519_pubkey, 64}),
                        method,
                        port,
                        headers,
                        query_params},
                body,
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
                            changes.path_failure_count,
                            changes.path_invalid};

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