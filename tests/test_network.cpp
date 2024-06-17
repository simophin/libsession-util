#include <session/network.h>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <session/network.hpp>
#include <session/onionreq/key_types.hpp>

#include "utils.hpp"

using namespace session;
using namespace session::onionreq;
using namespace session::network;

namespace {
struct Result {
    bool success;
    bool timeout;
    int16_t status_code;
    std::optional<std::string> response;
};
}  // namespace

namespace session::network {
class TestNetwork {
  public:
    Network network;

    TestNetwork(
            std::optional<fs::path> cache_path,
            bool use_testnet,
            bool single_path_mode,
            bool pre_build_paths) :
            network(cache_path, use_testnet, single_path_mode, pre_build_paths) {}

    void set_snode_pool(std::vector<service_node> pool) { network.snode_pool = pool; }

    void set_paths(PathType path_type, std::vector<onion_path> paths) {
        switch (path_type) {
            case PathType::standard: network.standard_paths = paths; break;
            case PathType::upload: network.upload_paths = paths; break;
            case PathType::download: network.download_paths = paths; break;
        }
    }

    void set_swarm(session::onionreq::x25519_pubkey swarm_pubkey, std::vector<service_node> swarm) {
        network.set_swarm(swarm_pubkey, swarm);
    }

    void get_swarm(
            session::onionreq::x25519_pubkey swarm_pubkey,
            std::function<void(std::vector<service_node> swarm)> callback) {
        network.get_swarm(swarm_pubkey, callback);
    }

    void set_failure_count(service_node node, uint8_t failure_count) {
        network.snode_failure_counts[node.to_string()] = failure_count;
    }

    uint8_t get_failure_count(service_node node) {
        return network.snode_failure_counts.try_emplace(node.to_string(), 0).first->second;
    }

    uint8_t get_failure_count(PathType path_type, onion_path path) {
        auto current_paths = network.paths_for_type(path_type);
        auto target_path = std::find_if(
                current_paths.begin(), current_paths.end(), [&path](const auto& path_it) {
                    return path_it.nodes[0] == path.nodes[0];
                });

        if (target_path != current_paths.end())
            return target_path->failure_count;

        return 0;
    }

    std::vector<onion_path> paths_for(PathType path_type) {
        return network.paths_for_type(path_type);
    }

    void handle_errors(
            request_info info,
            bool timeout,
            std::optional<int16_t> status_code,
            std::optional<std::string> response,
            std::optional<network_response_callback_t> handle_response) {
        network.handle_errors(info, timeout, status_code, response, handle_response);
    }
};
}  // namespace session::network

TEST_CASE("Network Url Parsing", "[network][parse_url]") {
    auto [proto1, host1, port1, path1] = parse_url("HTTPS://example.com/test");
    auto [proto2, host2, port2, path2] = parse_url("http://example2.com:1234/test/123456");
    auto [proto3, host3, port3, path3] = parse_url("https://example3.com");
    auto [proto4, host4, port4, path4] = parse_url("https://example4.com/test?value=test");

    CHECK(proto1 == "https://");
    CHECK(proto2 == "http://");
    CHECK(proto3 == "https://");
    CHECK(proto4 == "https://");
    CHECK(host1 == "example.com");
    CHECK(host2 == "example2.com");
    CHECK(host3 == "example3.com");
    CHECK(host4 == "example4.com");
    CHECK(port1.value_or(9999) == 9999);
    CHECK(port2.value_or(9999) == 1234);
    CHECK(port3.value_or(9999) == 9999);
    CHECK(port4.value_or(9999) == 9999);
    CHECK(path1.value_or("NULL") == "/test");
    CHECK(path2.value_or("NULL") == "/test/123456");
    CHECK(path3.value_or("NULL") == "NULL");
    CHECK(path4.value_or("NULL") == "/test?value=test");
}

TEST_CASE("Network error handling", "[network]") {
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    auto ed_pk2 = "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"_hexbytes;
    auto ed_sk =
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab78862834829a"
            "87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f"_hexbytes;
    auto x_pk_hex = "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72";
    auto target = service_node{ed_pk, "0.0.0.0", uint16_t{0}};
    auto target2 = service_node{ed_pk2, "0.0.0.1", uint16_t{1}};
    auto target3 = service_node{ed_pk2, "0.0.0.2", uint16_t{2}};
    auto target4 = service_node{ed_pk2, "0.0.0.3", uint16_t{3}};
    auto path = onion_path{{{target}, nullptr, nullptr}, {target, target2, target3}, 0};
    auto mock_request = request_info{
            "AAAA",
            target,
            "test",
            std::nullopt,
            std::nullopt,
            std::nullopt,
            path,
            PathType::standard,
            0ms,
            true,
            std::nullopt};
    Result result;
    auto network = TestNetwork(std::nullopt, true, true, false);

    // Check the handling of the codes which make no changes
    auto codes_with_no_changes = {400, 404, 406, 425};

    for (auto code : codes_with_no_changes) {
        network.set_paths(PathType::standard, {path});
        network.set_failure_count(target, 0);
        network.set_failure_count(target2, 0);
        network.set_failure_count(target3, 0);
        network.handle_errors(
                mock_request,
                false,
                code,
                std::nullopt,
                [&result](
                        bool success,
                        bool timeout,
                        int16_t status_code,
                        std::optional<std::string> response) {
                    result = {success, timeout, status_code, response};
                });

        CHECK_FALSE(result.success);
        CHECK_FALSE(result.timeout);
        CHECK(result.status_code == code);
        CHECK_FALSE(result.response.has_value());
        CHECK(network.get_failure_count(target) == 0);
        CHECK(network.get_failure_count(target2) == 0);
        CHECK(network.get_failure_count(target3) == 0);
        CHECK(network.get_failure_count(PathType::standard, path) == 0);
    }

    // Check general error handling (first failure)
    network.set_paths(PathType::standard, {path});
    network.set_failure_count(target, 0);
    network.set_failure_count(target2, 0);
    network.set_failure_count(target3, 0);
    network.handle_errors(
            mock_request,
            false,
            500,
            std::nullopt,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, response};
            });
    CHECK_FALSE(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 500);
    CHECK_FALSE(result.response.has_value());
    CHECK(network.get_failure_count(target) == 0);
    CHECK(network.get_failure_count(target2) == 0);
    CHECK(network.get_failure_count(target3) == 0);
    CHECK(network.get_failure_count(PathType::standard, path) == 1);

    // Check general error handling with no response (too many path failures)
    path = onion_path{{{target}, nullptr, nullptr}, {target, target2, target3}, 9};
    auto mock_request2 = request_info{
            "BBBB",
            target,
            "test",
            std::nullopt,
            std::nullopt,
            std::nullopt,
            path,
            PathType::standard,
            0ms,
            true,
            std::nullopt};
    network.set_paths(PathType::standard, {path});
    network.set_failure_count(target, 0);
    network.set_failure_count(target2, 0);
    network.set_failure_count(target3, 0);
    network.handle_errors(
            mock_request2,
            false,
            500,
            std::nullopt,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, response};
            });

    CHECK_FALSE(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 500);
    CHECK_FALSE(result.response.has_value());
    CHECK(network.get_failure_count(target) == 3);  // Guard node should be set to failure threshold
    CHECK(network.get_failure_count(target2) ==
          1);  // Other nodes get their failure count incremented
    CHECK(network.get_failure_count(target3) ==
          1);  // Other nodes get their failure count incremented
    CHECK(network.get_failure_count(PathType::standard, path) ==
          0);  // Path will have been dropped and reset

    // Check general error handling with a path and specific node failure (first failure)
    path = onion_path{{{target}, nullptr, nullptr}, {target, target2, target3}, 0};
    auto mock_request3 = request_info{
            "CCCC",
            target,
            "test",
            std::nullopt,
            std::nullopt,
            std::nullopt,
            path,
            PathType::standard,
            0ms,
            true,
            std::nullopt};
    auto response = std::string{"Next node not found: "} + ed25519_pubkey::from_bytes(ed_pk2).hex();
    network.set_paths(PathType::standard, {path});
    network.set_failure_count(target, 0);
    network.set_failure_count(target2, 0);
    network.set_failure_count(target3, 0);
    network.handle_errors(
            mock_request3,
            false,
            500,
            response,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, response};
            });

    CHECK_FALSE(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 500);
    CHECK(result.response == response);
    CHECK(network.get_failure_count(target) == 0);
    CHECK(network.get_failure_count(target2) == 1);
    CHECK(network.get_failure_count(target3) == 0);
    CHECK(network.get_failure_count(PathType::standard, path) ==
          1);  // Incremented because conn_info is invalid

    // Check general error handling with a path and specific node failure (too many failures)
    auto mock_request4 = request_info{
            "DDDD",
            target,
            "test",
            std::nullopt,
            std::nullopt,
            std::nullopt,
            path,
            PathType::standard,
            0ms,
            true,
            std::nullopt};
    network.set_snode_pool({target, target2, target3, target4});
    network.set_paths(PathType::standard, {path});
    network.set_failure_count(target, 0);
    network.set_failure_count(target2, 9);
    network.set_failure_count(target3, 0);
    network.handle_errors(
            mock_request4,
            false,
            500,
            response,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, response};
            });

    CHECK_FALSE(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 500);
    CHECK(result.response == response);
    CHECK(network.get_failure_count(target) == 0);
    CHECK(network.get_failure_count(target2) == 10);
    CHECK(network.get_failure_count(target3) == 0);
    CHECK(network.get_failure_count(PathType::standard, path) ==
          1);  // Incremented because conn_info is invalid

    // Check a 421 with no swarm data throws (no good way to handle this case)
    network.set_paths(PathType::standard, {path});
    network.set_failure_count(target, 0);
    network.set_failure_count(target2, 0);
    network.set_failure_count(target3, 0);
    network.handle_errors(
            mock_request,
            false,
            421,
            std::nullopt,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, response};
            });
    CHECK_FALSE(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 421);
    CHECK(network.get_failure_count(target) == 0);
    CHECK(network.get_failure_count(target2) == 0);
    CHECK(network.get_failure_count(target3) == 0);
    CHECK(network.get_failure_count(PathType::standard, path) == 1);

    // Check the retry request of a 421 with no response data is handled like any other error
    auto mock_request5 = request_info{
            "EEEE",
            target,
            "test",
            std::nullopt,
            std::nullopt,
            x25519_pubkey::from_hex(x_pk_hex),
            path,
            PathType::standard,
            0ms,
            true,
            request_info::RetryReason::redirect};
    network.set_paths(PathType::standard, {path});
    network.set_failure_count(target, 0);
    network.set_failure_count(target2, 0);
    network.set_failure_count(target3, 0);
    network.handle_errors(
            mock_request5,
            false,
            421,
            std::nullopt,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, response};
            });
    CHECK_FALSE(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 421);
    CHECK(network.get_failure_count(target) == 0);
    CHECK(network.get_failure_count(target2) == 0);
    CHECK(network.get_failure_count(target3) == 0);
    CHECK(network.get_failure_count(PathType::standard, path) == 1);

    // Check the retry request of a 421 with non-swarm response data is handled like any other error
    network.handle_errors(
            mock_request5,
            false,
            421,
            "Test",
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, response};
            });
    CHECK_FALSE(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 421);
    CHECK(network.get_failure_count(target) == 0);
    CHECK(network.get_failure_count(target2) == 0);
    CHECK(network.get_failure_count(target3) == 0);
    CHECK(network.get_failure_count(PathType::standard, path) == 1);

    // Check the retry request of a 421 instructs to replace the swarm
    auto snodes = nlohmann::json::array();
    snodes.push_back(
            {{"ip", "1.1.1.1"},
             {"port_omq", 1},
             {"pubkey_ed25519", ed25519_pubkey::from_bytes(ed_pk).hex()}});
    nlohmann::json swarm_json{{"snodes", snodes}};
    response = swarm_json.dump();
    network.set_swarm(x25519_pubkey::from_hex(x_pk_hex), {target});
    network.set_paths(PathType::standard, {path});
    network.set_failure_count(target, 0);
    network.set_failure_count(target2, 0);
    network.set_failure_count(target3, 0);
    network.handle_errors(
            mock_request5,
            false,
            421,
            response,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, response};
            });

    CHECK_FALSE(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 421);
    CHECK(network.get_failure_count(target) == 0);
    CHECK(network.get_failure_count(target2) == 0);
    CHECK(network.get_failure_count(target3) == 0);
    CHECK(network.get_failure_count(PathType::standard, path) == 0);

    network.get_swarm(x25519_pubkey::from_hex(x_pk_hex), [ed_pk](std::vector<service_node> swarm) {
        REQUIRE(swarm.size() == 1);
        CHECK(swarm.front().to_string() == "1.1.1.1:1");
        CHECK(oxenc::to_hex(swarm.front().view_remote_key()) == oxenc::to_hex(ed_pk));
    });

    // Check a timeout with a sever destination doesn't impact the failure counts
    auto mock_request6 = request_info{
            "FFFF",
            target,
            "test",
            std::nullopt,
            std::nullopt,
            x25519_pubkey::from_hex(x_pk_hex),
            path,
            PathType::standard,
            0ms,
            false,
            std::nullopt};
    network.handle_errors(
            mock_request6,
            true,
            std::nullopt,
            "Test",
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, response};
            });
    CHECK_FALSE(result.success);
    CHECK(result.timeout);
    CHECK(result.status_code == -1);
    CHECK(network.get_failure_count(target) == 0);
    CHECK(network.get_failure_count(target2) == 0);
    CHECK(network.get_failure_count(target3) == 0);
    CHECK(network.get_failure_count(PathType::standard, path) == 0);

    // Check a server response starting with '500 Internal Server Error' is reported as a `500`
    // error and doesn't affect the failure count
    network.handle_errors(
            mock_request6,
            false,
            std::nullopt,
            "500 Internal Server Error",
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, response};
            });
    CHECK_FALSE(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 500);
    CHECK(network.get_failure_count(target) == 0);
    CHECK(network.get_failure_count(target2) == 0);
    CHECK(network.get_failure_count(target3) == 0);
    CHECK(network.get_failure_count(PathType::standard, path) == 0);
}

TEST_CASE("Network onion request", "[send_onion_request][network]") {
    auto test_service_node = service_node{
            "decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9"_hexbytes,
            "144.76.164.202",
            uint16_t{35400}};
    auto network = Network(std::nullopt, true, true, false);
    std::promise<Result> result_promise;

    network.send_onion_request(
            test_service_node,
            ustring{to_usv("{\"method\":\"info\",\"params\":{}}")},
            std::nullopt,
            oxen::quic::DEFAULT_TIMEOUT,
            [&result_promise](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response) {
                result_promise.set_value({success, timeout, status_code, response});
            });

    // Wait for the result to be set
    auto result = result_promise.get_future().get();

    CHECK(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 200);
    REQUIRE(result.response.has_value());

    try {
        auto response = nlohmann::json::parse(*result.response);
        CHECK(response.contains("hf"));
        CHECK(response.contains("t"));
        CHECK(response.contains("version"));
    } catch (...) {
        REQUIRE(*result.response == "{VALID JSON}");
    }
}

TEST_CASE("Network direct request C API", "[network_send_request][network]") {
    network_object* network;
    network_init(&network, nullptr, true, true, false, nullptr);
    std::array<uint8_t, 4> target_ip = {144, 76, 164, 202};
    auto test_service_node = network_service_node{};
    test_service_node.quic_port = 35400;
    std::copy(target_ip.begin(), target_ip.end(), test_service_node.ip);
    std::strcpy(
            test_service_node.ed25519_pubkey_hex,
            "decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9");
    auto body = ustring{to_usv("{\"method\":\"info\",\"params\":{}}")};

    network_send_onion_request_to_snode_destination(
            network,
            test_service_node,
            body.data(),
            body.size(),
            nullptr,
            std::chrono::milliseconds{oxen::quic::DEFAULT_TIMEOUT}.count(),
            [](bool success,
               bool timeout,
               int16_t status_code,
               const char* c_response,
               size_t response_size,
               void* ctx) {
                CHECK(success);
                CHECK_FALSE(timeout);
                CHECK(status_code == 200);
                REQUIRE(response_size != 0);

                auto response_str = std::string(c_response, response_size);
                INFO("response_str is: " << response_str);
                REQUIRE_NOTHROW(nlohmann::json::parse(response_str));

                auto response = nlohmann::json::parse(response_str);
                CHECK(response.contains("hf"));
                CHECK(response.contains("t"));
                CHECK(response.contains("version"));
                network_free(static_cast<network_object*>(ctx));
            },
            network);
}
