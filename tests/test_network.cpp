#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <session/network.hpp>
#include <session/onionreq/key_types.hpp>

#include "utils.hpp"

using namespace session;
using namespace session::onionreq;
using namespace session::network;

TEST_CASE("Network error handling", "[network]") {
    struct Result {
        bool success;
        bool timeout;
        int16_t status_code;
        std::optional<std::string> response;
        service_node_changes changes;
    };
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    auto ed_pk2 = "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"_hexbytes;
    auto ed_sk =
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab78862834829a"
            "87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f"_hexbytes;
    auto x_pk = "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72"_hexbytes;
    auto x_pk2 = "aa654f00fc39fc69fd0db829410ca38177d7732a8d2f0934ab3872ac56d5aa74"_hexbytes;
    auto target = service_node{
            "0.0.0.0",
            0,
            x25519_pubkey::from_bytes(x_pk),
            ed25519_pubkey::from_bytes(ed_pk),
            0,
            false};
    auto mock_request =
            request_info{ed_sk, target, "test", std::nullopt, std::nullopt, std::nullopt, false};
    Result result;

    // Check the handling of the codes which make no changes
    auto codes_with_no_changes = {400, 404, 406, 425};

    for (auto code : codes_with_no_changes) {
        handle_errors(
                code,
                std::nullopt,
                mock_request,
                [&result](
                        bool success,
                        bool timeout,
                        int16_t status_code,
                        std::optional<std::string> response,
                        service_node_changes changes) {
                    result = {success, timeout, status_code, response, changes};
                });

        CHECK(result.success == false);
        CHECK(result.timeout == false);
        CHECK(result.status_code == code);
        CHECK_FALSE(result.response.has_value());
        CHECK(result.changes.type == ServiceNodeChangeType::none);
    }

    // Check general error handling with no provided path (first failure)
    handle_errors(
            500,
            std::nullopt,
            mock_request,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response,
                    service_node_changes changes) {
                result = {success, timeout, status_code, response, changes};
            });

    CHECK(result.success == false);
    CHECK(result.timeout == false);
    CHECK(result.status_code == 500);
    CHECK_FALSE(result.response.has_value());
    CHECK(result.changes.type == ServiceNodeChangeType::update_node);
    REQUIRE(result.changes.nodes.size() == 1);
    CHECK(result.changes.nodes[0].ip == target.ip);
    CHECK(result.changes.nodes[0].lmq_port == target.lmq_port);
    CHECK(result.changes.nodes[0].x25519_pubkey == target.x25519_pubkey);
    CHECK(result.changes.nodes[0].ed25519_pubkey == target.ed25519_pubkey);
    CHECK(result.changes.nodes[0].failure_count == 1);
    CHECK(result.changes.nodes[0].invalid == false);
    CHECK(result.changes.path_failure_count == 0);

    // Check general error handling with no provided path (too many failures)
    auto mock_request2 = request_info{
            ed_sk,
            service_node{
                    "0.0.0.0",
                    0,
                    x25519_pubkey::from_bytes(x_pk),
                    ed25519_pubkey::from_bytes(ed_pk),
                    9,
                    false},
            "test",
            std::nullopt,
            std::nullopt,
            std::nullopt,
            false};
    handle_errors(
            500,
            std::nullopt,
            mock_request2,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response,
                    service_node_changes changes) {
                result = {success, timeout, status_code, response, changes};
            });

    CHECK(result.success == false);
    CHECK(result.timeout == false);
    CHECK(result.status_code == 500);
    CHECK_FALSE(result.response.has_value());
    CHECK(result.changes.type == ServiceNodeChangeType::update_node);
    REQUIRE(result.changes.nodes.size() == 1);
    CHECK(result.changes.nodes[0].failure_count == 10);
    CHECK(result.changes.nodes[0].invalid == true);
    CHECK(result.changes.path_failure_count == 0);

    // Check general error handling with a path but no response (first failure)
    auto path = onion_path{{target}, 0};
    auto mock_request3 =
            request_info{ed_sk, target, "test", std::nullopt, std::nullopt, path, false};
    handle_errors(
            500,
            std::nullopt,
            mock_request3,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response,
                    service_node_changes changes) {
                result = {success, timeout, status_code, response, changes};
            });

    CHECK(result.success == false);
    CHECK(result.timeout == false);
    CHECK(result.status_code == 500);
    CHECK_FALSE(result.response.has_value());
    CHECK(result.changes.type == ServiceNodeChangeType::update_path);
    REQUIRE(result.changes.nodes.size() == 1);
    CHECK(result.changes.nodes[0].failure_count == 0);
    CHECK(result.changes.nodes[0].invalid == false);
    CHECK(result.changes.path_failure_count == 1);

    // Check general error handling with a path but no response (too many path failures)
    path = onion_path{
            {target,
             service_node{
                     "0.0.0.0",
                     0,
                     x25519_pubkey::from_bytes(x_pk),
                     ed25519_pubkey::from_bytes(ed_pk),
                     0,
                     false}},
            9};
    auto mock_request4 =
            request_info{ed_sk, target, "test", std::nullopt, std::nullopt, path, false};
    handle_errors(
            500,
            std::nullopt,
            mock_request4,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response,
                    service_node_changes changes) {
                result = {success, timeout, status_code, response, changes};
            });

    CHECK(result.success == false);
    CHECK(result.timeout == false);
    CHECK(result.status_code == 500);
    CHECK_FALSE(result.response.has_value());
    CHECK(result.changes.type == ServiceNodeChangeType::update_path);
    REQUIRE(result.changes.nodes.size() == 2);
    CHECK(result.changes.nodes[0].failure_count == 1);
    CHECK(result.changes.nodes[0].invalid == true);
    CHECK(result.changes.nodes[1].failure_count == 1);
    CHECK(result.changes.nodes[1].invalid == false);
    CHECK(result.changes.path_failure_count == 10);

    // Check general error handling with a path but no response (too many path & node failures)
    path = onion_path{
            {target,
             service_node{
                     "0.0.0.0",
                     0,
                     x25519_pubkey::from_bytes(x_pk),
                     ed25519_pubkey::from_bytes(ed_pk),
                     9,
                     false}},
            9};
    auto mock_request5 =
            request_info{ed_sk, target, "test", std::nullopt, std::nullopt, path, false};
    handle_errors(
            500,
            std::nullopt,
            mock_request5,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response,
                    service_node_changes changes) {
                result = {success, timeout, status_code, response, changes};
            });

    CHECK(result.success == false);
    CHECK(result.timeout == false);
    CHECK(result.status_code == 500);
    CHECK_FALSE(result.response.has_value());
    CHECK(result.changes.type == ServiceNodeChangeType::update_path);
    REQUIRE(result.changes.nodes.size() == 2);
    CHECK(result.changes.nodes[0].failure_count == 1);
    CHECK(result.changes.nodes[0].invalid == true);
    CHECK(result.changes.nodes[1].failure_count == 10);
    CHECK(result.changes.nodes[1].invalid == true);
    CHECK(result.changes.path_failure_count == 10);

    // Check general error handling with a path and a random response (first failure)
    path = onion_path{{target}, 0};
    auto mock_request6 =
            request_info{ed_sk, target, "test", std::nullopt, std::nullopt, path, false};
    auto response = std::string{"Test"};
    handle_errors(
            500,
            response,
            mock_request6,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response,
                    service_node_changes changes) {
                result = {success, timeout, status_code, response, changes};
            });

    CHECK(result.success == false);
    CHECK(result.timeout == false);
    CHECK(result.status_code == 500);
    CHECK(result.response == response);
    CHECK(result.changes.type == ServiceNodeChangeType::update_path);
    REQUIRE(result.changes.nodes.size() == 1);
    CHECK(result.changes.nodes[0].failure_count == 0);
    CHECK(result.changes.nodes[0].invalid == false);
    CHECK(result.changes.path_failure_count == 1);

    // Check general error handling with a path and specific node failure (first failure)
    path = onion_path{
            {target,
             service_node{
                     "0.0.0.0",
                     0,
                     x25519_pubkey::from_bytes(x_pk2),
                     ed25519_pubkey::from_bytes(ed_pk2),
                     0,
                     false}},
            0};
    auto mock_request7 =
            request_info{ed_sk, target, "test", std::nullopt, std::nullopt, path, false};
    response = std::string{"Next node not found: "} + ed25519_pubkey::from_bytes(ed_pk2).hex();
    handle_errors(
            500,
            response,
            mock_request7,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response,
                    service_node_changes changes) {
                result = {success, timeout, status_code, response, changes};
            });

    CHECK(result.success == false);
    CHECK(result.timeout == false);
    CHECK(result.status_code == 500);
    CHECK(result.response == response);
    CHECK(result.changes.type == ServiceNodeChangeType::update_path);
    REQUIRE(result.changes.nodes.size() == 2);
    CHECK(result.changes.nodes[0].ed25519_pubkey == target.ed25519_pubkey);
    CHECK(result.changes.nodes[0].failure_count == 0);
    CHECK(result.changes.nodes[0].invalid == false);
    CHECK(result.changes.nodes[1].ed25519_pubkey == ed25519_pubkey::from_bytes(ed_pk2));
    CHECK(result.changes.nodes[1].failure_count == 1);
    CHECK(result.changes.nodes[1].invalid == false);
    CHECK(result.changes.path_failure_count == 0);

    // Check general error handling with a path and specific node failure (too many failures)
    path = onion_path{
            {target,
             service_node{
                     "0.0.0.0",
                     0,
                     x25519_pubkey::from_bytes(x_pk2),
                     ed25519_pubkey::from_bytes(ed_pk2),
                     9,
                     false}},
            0};
    auto mock_request8 =
            request_info{ed_sk, target, "test", std::nullopt, std::nullopt, path, false};
    response = std::string{"Next node not found: "} + ed25519_pubkey::from_bytes(ed_pk2).hex();
    handle_errors(
            500,
            response,
            mock_request8,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response,
                    service_node_changes changes) {
                result = {success, timeout, status_code, response, changes};
            });

    CHECK(result.success == false);
    CHECK(result.timeout == false);
    CHECK(result.status_code == 500);
    CHECK(result.response == response);
    CHECK(result.changes.type == ServiceNodeChangeType::update_path);
    REQUIRE(result.changes.nodes.size() == 2);
    CHECK(result.changes.nodes[0].ed25519_pubkey == target.ed25519_pubkey);
    CHECK(result.changes.nodes[0].failure_count == 0);
    CHECK(result.changes.nodes[0].invalid == false);
    CHECK(result.changes.nodes[1].ed25519_pubkey == ed25519_pubkey::from_bytes(ed_pk2));
    CHECK(result.changes.nodes[1].failure_count == 10);
    CHECK(result.changes.nodes[1].invalid == true);
    CHECK(result.changes.path_failure_count == 0);

    // Check a 421 with no swarm data throws (no good way to handle this case)
    handle_errors(
            421,
            std::nullopt,
            mock_request,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response,
                    service_node_changes changes) {
                result = {success, timeout, status_code, response, changes};
            });
    CHECK(result.success == false);
    CHECK(result.timeout == false);
    CHECK(result.status_code == 421);
    CHECK(result.changes.type == ServiceNodeChangeType::update_node);

    // Check the retry request of a 421 with no response data throws (no good way to handle this
    // case)
    auto mock_request9 = request_info{ed_sk, target, "test", std::nullopt, std::vector<service_node>{target}, path, true};
    handle_errors(
            421,
            std::nullopt,
            mock_request9,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response,
                    service_node_changes changes) {
                result = {success, timeout, status_code, response, changes};
            });
    CHECK(result.success == false);
    CHECK(result.timeout == false);
    CHECK(result.status_code == 421);
    CHECK(result.changes.type == ServiceNodeChangeType::update_path);

    // Check the retry request of a 421 with non-swarm response data throws (no good way to handle
    // this case)
    handle_errors(
            421,
            "Test",
            mock_request9,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response,
                    service_node_changes changes) {
                result = {success, timeout, status_code, response, changes};
            });
    CHECK(result.success == false);
    CHECK(result.timeout == false);
    CHECK(result.status_code == 421);
    CHECK(result.changes.type == ServiceNodeChangeType::update_path);

    // Check the retry request of a 421 instructs to replace the swarm
    auto snodes = nlohmann::json::array();
    snodes.push_back(
            {{"ip", "1.1.1.1"},
             {"port_omq", 1},
             {"pubkey_x25519", x25519_pubkey::from_bytes(x_pk).hex()},
             {"pubkey_ed25519", x25519_pubkey::from_bytes(ed_pk).hex()}});
    nlohmann::json swarm_json{{"snodes", snodes}};
    response = swarm_json.dump();
    handle_errors(
            421,
            response,
            mock_request9,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response,
                    service_node_changes changes) {
                result = {success, timeout, status_code, response, changes};
            });

    CHECK(result.success == false);
    CHECK(result.timeout == false);
    CHECK(result.status_code == 421);
    CHECK(result.changes.type == ServiceNodeChangeType::replace_swarm);
    REQUIRE(result.changes.nodes.size() == 1);
    CHECK(result.changes.nodes[0].ip == "1.1.1.1");
    CHECK(result.changes.nodes[0].lmq_port == 1);
    CHECK(result.changes.nodes[0].x25519_pubkey == target.x25519_pubkey);
    CHECK(result.changes.nodes[0].ed25519_pubkey == target.ed25519_pubkey);
    CHECK(result.changes.nodes[0].failure_count == 0);
    CHECK(result.changes.nodes[0].invalid == false);
    CHECK(result.changes.path_failure_count == 0);
}
