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

TEST_CASE("Network error handling", "[network]") {
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    auto ed_pk2 = "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"_hexbytes;
    auto ed_sk =
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab78862834829a"
            "87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f"_hexbytes;
    auto x_pk_hex = "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72";
    auto target = service_node{ed_pk, "0.0.0.0", uint16_t{0}};
    auto target2 = service_node{ed_pk2, "0.0.0.1", uint16_t{1}};
    auto path = onion_path{{{target}, nullptr, nullptr}, {target}, 0};
    auto mock_request = request_info{target, "test", std::nullopt, std::nullopt, path, 0ms, false};
    Result result;
    auto network = Network(std::nullopt, true, false);

    // Check the handling of the codes which make no changes
    auto codes_with_no_changes = {400, 404, 406, 425};

    for (auto code : codes_with_no_changes) {
        network.set_paths({path});
        network.set_failure_count(target, 0);
        network.handle_errors(
                mock_request,
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
        CHECK(network.get_failure_count(path) == 0);
    }

    // Check general error handling (first failure)
    network.set_paths({path});
    network.set_failure_count(target, 0);
    network.handle_errors(
            mock_request,
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
    CHECK(network.get_failure_count(path) == 1);

    // Check general error handling with no response (too many path failures)
    path = onion_path{{{target}, nullptr, nullptr}, {target, target2}, 9};
    auto mock_request2 = request_info{target, "test", std::nullopt, std::nullopt, path, 0ms, false};
    network.set_paths({path});
    network.set_failure_count(target, 0);
    network.set_failure_count(target2, 0);
    network.handle_errors(
            mock_request2,
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
          1);                                     // Other nodes get their failure count incremented
    CHECK(network.get_failure_count(path) == 0);  // Path will have been dropped and reset

    // Check general error handling with a path and specific node failure (first failure)
    path = onion_path{{{target}, nullptr, nullptr}, {target, target2}, 0};
    auto mock_request3 = request_info{target, "test", std::nullopt, std::nullopt, path, 0ms, false};
    auto response = std::string{"Next node not found: "} + ed25519_pubkey::from_bytes(ed_pk2).hex();
    network.set_paths({path});
    network.set_failure_count(target, 0);
    network.set_failure_count(target2, 0);
    network.handle_errors(
            mock_request3,
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
    CHECK(network.get_failure_count(path) == 1);  // Incremented because conn_info is invalid

    // Check general error handling with a path and specific node failure (too many failures)
    auto mock_request4 = request_info{target, "test", std::nullopt, std::nullopt, path, 0ms, false};
    network.set_paths({path});
    network.set_failure_count(target, 0);
    network.set_failure_count(target2, 9);
    network.handle_errors(
            mock_request4,
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
    CHECK(network.get_failure_count(path) == 1);  // Incremented because conn_info is invalid

    // Check a 421 with no swarm data throws (no good way to handle this case)
    network.set_paths({path});
    network.set_failure_count(target, 0);
    network.set_failure_count(target2, 0);
    network.handle_errors(
            mock_request,
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
    CHECK(network.get_failure_count(path) == 0);

    // Check the retry request of a 421 with no response data is handled like any other error
    auto mock_request5 = request_info{
            target, "test", std::nullopt, x25519_pubkey::from_hex(x_pk_hex), path, 0ms, true};
    network.set_paths({path});
    network.set_failure_count(target, 0);
    network.handle_errors(
            mock_request5,
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
    CHECK(network.get_failure_count(path) == 1);

    // Check the retry request of a 421 with non-swarm response data is handled like any other error
    network.handle_errors(
            mock_request5,
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
    CHECK(network.get_failure_count(path) == 1);

    // Check the retry request of a 421 instructs to replace the swarm
    auto snodes = nlohmann::json::array();
    snodes.push_back(
            {{"ip", "1.1.1.1"},
             {"port_omq", 1},
             {"pubkey_ed25519", ed25519_pubkey::from_bytes(ed_pk).hex()}});
    nlohmann::json swarm_json{{"snodes", snodes}};
    response = swarm_json.dump();
    network.set_swarm(x25519_pubkey::from_hex(x_pk_hex), {target});
    network.set_paths({path});
    network.set_failure_count(target, 0);
    network.handle_errors(
            mock_request5,
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
    CHECK(network.get_failure_count(path) == 0);

    network.get_swarm(x25519_pubkey::from_hex(x_pk_hex), [ed_pk](std::vector<service_node> swarm) {
        REQUIRE(swarm.size() == 1);
        CHECK(swarm.front().to_string() == "1.1.1.1:1");
        CHECK(oxenc::to_hex(swarm.front().view_remote_key()) == oxenc::to_hex(ed_pk));
    });
}

TEST_CASE("Network onion request", "[send_onion_request][network]") {
    auto test_service_node = service_node{
            "decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9"_hexbytes,
            "144.76.164.202",
            uint16_t{35400}};
    auto network = Network(std::nullopt, true, false);
    std::promise<Result> result_promise;

    network.send_onion_request(
            test_service_node,
            ustring{to_usv("{\"method\":\"info\",\"params\":{}}")},
            std::nullopt,
            oxen::quic::DEFAULT_TIMEOUT,
            false,
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
        CHECK(*result.response == "{JSON}");
        REQUIRE_NOTHROW(nlohmann::json::parse(*result.response));
    }
}

TEST_CASE("Network direct request C API", "[network_send_request][network]") {
    network_object* network;
    network_init(&network, nullptr, true, false, nullptr);
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
            oxen::quic::DEFAULT_TIMEOUT.count(),
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
                REQUIRE_NOTHROW(nlohmann::json::parse(response_str));

                auto response = nlohmann::json::parse(response_str);
                CHECK(response.contains("hf"));
                CHECK(response.contains("t"));
                CHECK(response.contains("version"));
                network_free(static_cast<network_object*>(ctx));
            },
            network);
}
