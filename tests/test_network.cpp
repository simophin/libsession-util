#include <session/network.h>
#include <sodium/randombytes.h>

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <nlohmann/json.hpp>
#include <session/network.hpp>
#include <session/onionreq/key_types.hpp>
#include <tuple>

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
class TestNetwork : public Network {
  public:
    std::unordered_map<std::string, int> call_counts;
    std::vector<std::string> calls_to_ignore;
    std::chrono::milliseconds retry_delay_value = 0ms;
    std::optional<std::optional<onion_path>> find_valid_path_response;

    TestNetwork(
            std::optional<fs::path> cache_path,
            bool use_testnet,
            bool single_path_mode,
            bool pre_build_paths) :
            Network{cache_path, use_testnet, single_path_mode, pre_build_paths} {
        paths_changed = [this](std::vector<std::vector<service_node>>) {
            call_counts["paths_changed"]++;
        };
    }

    void set_suspended(bool suspended_) { suspended = suspended_; }

    bool get_suspended() { return suspended; }

    ConnectionStatus get_status() { return status; }

    void set_snode_cache(std::vector<service_node> cache) {
        // Need to set the `last_snode_cache_update` to `10s` ago because otherwise it'll be
        // considered invalid when checking the cache validity
        snode_cache = cache;
        last_snode_cache_update = (std::chrono::system_clock::now() - 10s);
    }

    void set_unused_connections(std::deque<connection_info> unused_connections_) {
        unused_connections = unused_connections_;
    }

    void set_in_progress_connections(std::unordered_set<std::string> in_progress_connections_) {
        in_progress_connections = in_progress_connections_;
    }

    void add_path(PathType path_type, std::vector<service_node> nodes) {
        paths[path_type].emplace_back(onion_path{{nodes[0], nullptr, nullptr}, nodes, 0});
    }

    void set_paths(PathType path_type, std::vector<onion_path> paths_) {
        paths[path_type] = paths_;
    }

    std::vector<onion_path> get_paths(PathType path_type) { return paths[path_type]; }

    void set_swarm(session::onionreq::x25519_pubkey swarm_pubkey, std::vector<service_node> swarm) {
        Network::set_swarm(swarm_pubkey, swarm);
    }

    std::vector<service_node> get_swarm_value(session::onionreq::x25519_pubkey swarm_pubkey) {
        return swarm_cache[swarm_pubkey.hex()];
    }

    void set_failure_count(service_node node, uint8_t failure_count) {
        snode_failure_counts[node.to_string()] = failure_count;
    }

    uint8_t get_failure_count(service_node node) {
        return snode_failure_counts.try_emplace(node.to_string(), 0).first->second;
    }

    uint8_t get_failure_count(PathType path_type, onion_path path) {
        auto current_paths = paths[path_type];
        auto target_path = std::find_if(
                current_paths.begin(), current_paths.end(), [&path](const auto& path_it) {
                    return path_it.nodes[0] == path.nodes[0];
                });

        if (target_path != current_paths.end())
            return target_path->failure_count;

        return 0;
    }

    void set_path_build_queue(std::deque<PathType> path_build_queue_) {
        path_build_queue = path_build_queue_;
    }

    std::deque<PathType> get_path_build_queue() { return path_build_queue; }

    void set_path_build_failures(int path_build_failures_) {
        path_build_failures = path_build_failures_;
    }

    int get_path_build_failures() { return path_build_failures; }

    void set_unused_connection_and_path_build_nodes(
            std::optional<std::vector<service_node>> unused_connection_and_path_build_nodes_) {
        unused_connection_and_path_build_nodes = unused_connection_and_path_build_nodes_;
    }

    std::optional<std::vector<service_node>> get_unused_connection_and_path_build_nodes() {
        return unused_connection_and_path_build_nodes;
    }

    void add_pending_request(PathType path_type, request_info info) {
        request_queue[path_type].emplace_back(
                std::move(info), [](bool, bool, int16_t, std::optional<std::string>) {});
    }

    // Overridden Functions

    std::chrono::milliseconds retry_delay(int, std::chrono::milliseconds) override {
        return retry_delay_value;
    }

    void update_disk_cache_throttled(bool force_immediate_write) override {
        const auto func_name = "update_disk_cache_throttled";

        if (check_should_ignore_and_log_call(func_name))
            return;

        Network::update_disk_cache_throttled(force_immediate_write);
    }

    void establish_and_store_connection(std::string request_id) override {
        const auto func_name = "establish_and_store_connection";

        if (check_should_ignore_and_log_call(func_name))
            return;

        Network::establish_and_store_connection(request_id);
    }

    void refresh_snode_cache(std::optional<std::string> existing_request_id) override {
        const auto func_name = "refresh_snode_cache";

        if (check_should_ignore_and_log_call(func_name))
            return;

        Network::refresh_snode_cache(existing_request_id);
    }

    void build_path(PathType path_type, std::optional<std::string> existing_request_id) override {
        const auto func_name = "build_path";

        if (check_should_ignore_and_log_call(func_name))
            return;

        Network::build_path(path_type, existing_request_id);
    }

    std::optional<onion_path> find_valid_path(
            request_info info, std::vector<onion_path> paths) override {
        const auto func_name = "find_valid_path";

        if (check_should_ignore_and_log_call(func_name))
            return std::nullopt;

        if (find_valid_path_response)
            return *find_valid_path_response;

        return Network::find_valid_path(info, paths);
    }

    void _send_onion_request(
            request_info info, network_response_callback_t handle_response) override {
        const auto func_name = "_send_onion_request";

        if (check_should_ignore_and_log_call(func_name))
            return;

        Network::_send_onion_request(std::move(info), std::move(handle_response));
    }

    // Exposing Private Functions

    void establish_connection(
            std::string request_id,
            service_node target,
            std::optional<std::chrono::milliseconds> timeout,
            std::function<void(connection_info info, std::optional<std::string> error)> callback) {
        Network::establish_connection(request_id, target, timeout, std::move(callback));
    }

    void enqueue_path_build_if_needed(
            PathType path_type, std::optional<onion_path> found_path) override {
        return Network::enqueue_path_build_if_needed(path_type, found_path);
    }

    void send_request(
            request_info info, connection_info conn, network_response_callback_t handle_response) {
        Network::send_request(info, conn, std::move(handle_response));
    }

    void handle_errors(
            request_info info,
            connection_info conn_info,
            bool timeout,
            std::optional<int16_t> status_code,
            std::optional<std::string> response,
            std::optional<network_response_callback_t> handle_response) override {
        call_counts["handle_errors"]++;
        Network::handle_errors(
                info, conn_info, timeout, status_code, response, std::move(handle_response));
    }

    // Mocking Functions

    template <typename... Strings>
    void ignore_calls_to(Strings&&... __args) {
        (calls_to_ignore.emplace_back(std::forward<Strings>(__args)), ...);
    }

    bool check_should_ignore_and_log_call(std::string func_name) {
        call_counts[func_name]++;

        return std::find(calls_to_ignore.begin(), calls_to_ignore.end(), func_name) !=
               calls_to_ignore.end();
    }

    void reset_calls() { return call_counts.clear(); }
    bool called(std::string func_name, int times = 1) { return (call_counts[func_name] >= times); }

    bool did_not_call(std::string func_name) { return !call_counts.contains(func_name); }
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
    auto target = service_node{ed_pk, {2, 8, 0}, "0.0.0.0", uint16_t{0}};
    auto target2 = service_node{ed_pk2, {2, 8, 0}, "0.0.0.1", uint16_t{1}};
    auto target3 = service_node{ed_pk2, {2, 8, 0}, "0.0.0.2", uint16_t{2}};
    auto target4 = service_node{ed_pk2, {2, 8, 0}, "0.0.0.3", uint16_t{3}};
    auto path = onion_path{{{target}, nullptr, nullptr}, {target, target2, target3}, 0};
    auto mock_request = request_info{
            "AAAA",
            target,
            "test",
            std::nullopt,
            std::nullopt,
            std::nullopt,
            PathType::standard,
            0ms,
            std::nullopt,
            true};
    Result result;
    auto network = TestNetwork(std::nullopt, true, true, false);
    network.set_suspended(true);  // Make no requests in this test
    network.ignore_calls_to("_send_onion_request", "update_disk_cache_throttled");

    // Check the handling of the codes which make no changes
    auto codes_with_no_changes = {400, 404, 406, 425};

    for (auto code : codes_with_no_changes) {
        network.set_paths(PathType::standard, {path});
        network.set_failure_count(target, 0);
        network.set_failure_count(target2, 0);
        network.set_failure_count(target3, 0);
        network.handle_errors(
                mock_request,
                {target, nullptr, nullptr},
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
            {target, nullptr, nullptr},
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
    network.set_paths(PathType::standard, {path});
    network.set_failure_count(target, 0);
    network.set_failure_count(target2, 0);
    network.set_failure_count(target3, 0);
    network.handle_errors(
            mock_request,
            {target, nullptr, nullptr},
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
    CHECK(network.get_failure_count(target) == 0);                    // Guard node dropped
    CHECK(network.get_failure_count(target2) == 1);                   // Other nodes incremented
    CHECK(network.get_failure_count(target3) == 1);                   // Other nodes incremented
    CHECK(network.get_failure_count(PathType::standard, path) == 0);  // Path dropped and reset

    // Check general error handling with a path and specific node failure
    path = onion_path{{{target}, nullptr, nullptr}, {target, target2, target3}, 0};
    auto response = std::string{"Next node not found: "} + ed25519_pubkey::from_bytes(ed_pk2).hex();
    network.set_snode_cache({target, target2, target3, target4});
    network.set_paths(PathType::standard, {path});
    network.set_failure_count(target, 0);
    network.set_failure_count(target2, 1);
    network.set_failure_count(target3, 0);
    network.handle_errors(
            mock_request,
            {target, nullptr, nullptr},
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
    CHECK(network.get_failure_count(target2) == 0);  // Node will have been dropped
    CHECK(network.get_failure_count(target3) == 0);
    CHECK(network.get_paths(PathType::standard).front().nodes[1] != target2);
    CHECK(network.get_failure_count(PathType::standard, path) ==
          1);  // Incremented because conn_info is invalid

    // Check a 421 with no swarm data throws (no good way to handle this case)
    network.set_paths(PathType::standard, {path});
    network.set_failure_count(target, 0);
    network.set_failure_count(target2, 0);
    network.set_failure_count(target3, 0);
    network.handle_errors(
            mock_request,
            {target, nullptr, nullptr},
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
    auto mock_request2 = request_info{
            "BBBB",
            target,
            "test",
            std::nullopt,
            std::nullopt,
            x25519_pubkey::from_hex(x_pk_hex),
            PathType::standard,
            0ms,
            request_info::RetryReason::redirect,
            true};
    network.set_paths(PathType::standard, {path});
    network.set_failure_count(target, 0);
    network.set_failure_count(target2, 0);
    network.set_failure_count(target3, 0);
    network.handle_errors(
            mock_request2,
            {target, nullptr, nullptr},
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
    network.set_paths(PathType::standard, {path});
    network.handle_errors(
            mock_request2,
            {target, nullptr, nullptr},
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
    snodes.push_back(
            {{"ip", "2.2.2.2"},
             {"port_omq", 2},
             {"pubkey_ed25519", ed25519_pubkey::from_bytes(ed_pk).hex()}});
    snodes.push_back(
            {{"ip", "3.3.3.3"},
             {"port_omq", 3},
             {"pubkey_ed25519", ed25519_pubkey::from_bytes(ed_pk).hex()}});
    nlohmann::json swarm_json{{"snodes", snodes}};
    response = swarm_json.dump();
    network.set_swarm(x25519_pubkey::from_hex(x_pk_hex), {target, target2, target3});
    network.set_paths(PathType::standard, {path});
    network.set_failure_count(target, 0);
    network.set_failure_count(target2, 0);
    network.set_failure_count(target3, 0);
    network.handle_errors(
            mock_request2,
            {target, nullptr, nullptr},
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
    REQUIRE(network.get_swarm_value(x25519_pubkey::from_hex(x_pk_hex)).size() == 3);
    CHECK(network.get_swarm_value(x25519_pubkey::from_hex(x_pk_hex)).front().to_string() ==
          "1.1.1.1:1");
    CHECK(oxenc::to_hex(network.get_swarm_value(x25519_pubkey::from_hex(x_pk_hex))
                                .front()
                                .view_remote_key()) == oxenc::to_hex(ed_pk));

    // Check a non redirect 421 with swam data triggers a retry
    auto mock_request3 = request_info{
            "BBBB",
            target,
            "test",
            std::nullopt,
            std::nullopt,
            x25519_pubkey::from_hex(x_pk_hex),
            PathType::standard,
            0ms,
            std::nullopt,
            true};
    network.set_swarm(x25519_pubkey::from_hex(x_pk_hex), {target, target2, target3});
    network.set_paths(PathType::standard, {path});
    network.set_failure_count(target, 0);
    network.set_failure_count(target2, 0);
    network.set_failure_count(target3, 0);
    network.reset_calls();
    network.handle_errors(
            mock_request3,
            {target, nullptr, nullptr},
            false,
            421,
            response,
            [](bool, bool, int16_t, std::optional<std::string>) {});
    CHECK(EVENTUALLY(10ms, network.called("_send_onion_request")));

    // Check a timeout with a sever destination doesn't impact the failure counts
    auto server = ServerDestination{
            "https",
            "open.getsession.org",
            "/rooms",
            x25519_pubkey::from_hex("a03c383cf63c3c4efe67acc52112a6dd734b3a946b9545f488aaa93da79912"
                                    "38"),
            443,
            std::nullopt,
            "GET"};
    auto mock_request4 = request_info{
            "CCCC",
            server,
            "test",
            std::nullopt,
            std::nullopt,
            x25519_pubkey::from_hex(x_pk_hex),
            PathType::standard,
            0ms,
            std::nullopt,
            false};
    network.set_failure_count(target, 0);
    network.set_failure_count(target2, 0);
    network.set_failure_count(target3, 0);
    network.handle_errors(
            mock_request4,
            {target, nullptr, nullptr},
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
    network.set_failure_count(target, 0);
    network.set_failure_count(target2, 0);
    network.set_failure_count(target3, 0);
    network.handle_errors(
            mock_request4,
            {target, nullptr, nullptr},
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

TEST_CASE("Network Path Building", "[network][build_path]") {
    const auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    std::optional<TestNetwork> network;
    std::vector<service_node> snode_cache;
    for (uint16_t i = 0; i < 12; ++i)
        snode_cache.emplace_back(service_node{ed_pk, {2, 8, 0}, fmt::format("0.0.0.{}", i), i});
    auto invalid_info = connection_info{snode_cache[0], nullptr, nullptr};

    // Nothing should happen if the network is suspended
    network.emplace(std::nullopt, true, false, false);
    network->set_suspended(true);
    network->build_path(PathType::standard, std::nullopt);
    CHECK(ALWAYS(10ms, network->did_not_call("establish_and_store_connection")));

    // If there are no unused connections it puts the path build in the queue and calls
    // establish_and_store_connection
    network.emplace(std::nullopt, true, false, false);
    network->ignore_calls_to("establish_and_store_connection");
    network->build_path(PathType::standard, "Test1");
    CHECK(network->get_path_build_queue() == std::deque<PathType>{PathType::standard});
    CHECK(EVENTUALLY(10ms, network->called("establish_and_store_connection")));

    // If the unused nodes are empty it refreshes them
    network.emplace(std::nullopt, true, false, false);
    network->set_snode_cache(snode_cache);
    network->set_unused_connections({invalid_info});
    network->set_in_progress_connections({"TestInProgress"});
    network->build_path(PathType::standard, "Test1");
    REQUIRE(network->get_unused_connection_and_path_build_nodes().has_value());
    CHECK(network->get_unused_connection_and_path_build_nodes()->size() == snode_cache.size() - 3);
    CHECK(network->get_path_build_queue().empty());

    // It should exclude nodes that are already in existing paths
    network.emplace(std::nullopt, true, false, false);
    network->set_snode_cache(snode_cache);
    network->set_unused_connections({invalid_info});
    network->set_in_progress_connections({"TestInProgress"});
    network->add_path(PathType::standard, {snode_cache.begin() + 1, snode_cache.begin() + 1 + 3});
    network->build_path(PathType::standard, "Test1");
    REQUIRE(network->get_unused_connection_and_path_build_nodes().has_value());
    CHECK(network->get_unused_connection_and_path_build_nodes()->size() ==
          (snode_cache.size() - 3 - 3));
    CHECK(network->get_path_build_queue().empty());

    // If there aren't enough unused nodes it resets the failure count, re-queues the path build and
    // triggers a snode cache refresh
    network.emplace(std::nullopt, true, false, false);
    network->ignore_calls_to("refresh_snode_cache");
    network->set_snode_cache(snode_cache);
    network->set_unused_connections({invalid_info});
    network->set_path_build_failures(10);
    network->add_path(PathType::standard, snode_cache);
    network->build_path(PathType::standard, "Test1");
    CHECK(network->get_path_build_failures() == 0);
    CHECK(network->get_path_build_queue() == std::deque<PathType>{PathType::standard});
    CHECK(EVENTUALLY(10ms, network->called("refresh_snode_cache")));

    // If it can't build a path after excluding nodes with the same IP it increments the
    // failure count and re-tries the path build after a small delay
    network.emplace(std::nullopt, true, false, false);
    network->set_snode_cache(snode_cache);
    network->set_unused_connections({invalid_info});
    network->set_unused_connection_and_path_build_nodes(std::vector<service_node>{
            snode_cache[0], snode_cache[0], snode_cache[0], snode_cache[0]});
    network->build_path(PathType::standard, "Test1");
    network->ignore_calls_to("build_path");  // Ignore the 2nd loop
    CHECK(network->get_path_build_failures() == 1);
    CHECK(network->get_path_build_queue().empty());
    CHECK(EVENTUALLY(10ms, network->called("build_path", 2)));

    // It stores a successful non-standard path and kicks of queued requests but doesn't update the
    // status or call the 'paths_changed' hook
    network.emplace(std::nullopt, true, false, false);
    network->find_valid_path_response =
            onion_path{invalid_info, {snode_cache.begin(), snode_cache.begin() + 3}, 0};
    network->ignore_calls_to("_send_onion_request");
    network->set_snode_cache(snode_cache);
    network->set_unused_connections({invalid_info});
    network->add_pending_request(
            PathType::download,
            request_info::make(
                    snode_cache.back(), 1s, std::nullopt, std::nullopt, PathType::download));
    network->build_path(PathType::download, "Test1");
    CHECK(EVENTUALLY(10ms, network->called("_send_onion_request")));
    CHECK(network->get_paths(PathType::download).size() == 1);

    // It stores a successful 'standard' path, updates the status, calls the 'paths_changed' hook
    // and kicks of queued requests
    network.emplace(std::nullopt, true, false, false);
    network->find_valid_path_response =
            onion_path{invalid_info, {snode_cache.begin(), snode_cache.begin() + 3}, 0};
    network->ignore_calls_to("_send_onion_request");
    network->set_snode_cache(snode_cache);
    network->set_unused_connections({invalid_info});
    network->add_pending_request(
            PathType::standard,
            request_info::make(
                    snode_cache.back(), 1s, std::nullopt, std::nullopt, PathType::standard));
    network->build_path(PathType::standard, "Test1");
    CHECK(EVENTUALLY(10ms, network->called("_send_onion_request")));
    CHECK(network->get_paths(PathType::standard).size() == 1);
    CHECK(network->get_status() == ConnectionStatus::connected);
    CHECK(network->called("paths_changed"));
}

TEST_CASE("Network Find Valid Path", "[network][find_valid_path]") {
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    auto target = service_node{ed_pk, {2, 8, 0}, "0.0.0.1", uint16_t{1}};
    auto test_service_node = service_node{
            "decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9"_hexbytes,
            {2, 8, 0},
            "144.76.164.202",
            uint16_t{35400}};
    auto network = TestNetwork(std::nullopt, true, false, false);
    auto info = request_info::make(target, 0ms, std::nullopt, std::nullopt);
    auto invalid_path =
            onion_path{{test_service_node, nullptr, nullptr}, {test_service_node}, uint8_t{0}};

    // It returns nothing when given no path options
    CHECK_FALSE(network.find_valid_path(info, {}).has_value());

    // It ignores invalid paths
    CHECK_FALSE(network.find_valid_path(info, {invalid_path}).has_value());

    // Need to get a valid path for subsequent tests
    std::promise<std::pair<connection_info, std::optional<std::string>>> prom;

    network.establish_connection(
            "Test",
            test_service_node,
            3s,
            [&prom](connection_info conn_info, std::optional<std::string> error) {
                prom.set_value({std::move(conn_info), error});
            });

    // Wait for the result to be set
    auto result = prom.get_future().get();
    REQUIRE(result.first.is_valid());
    auto valid_path = onion_path{
            std::move(result.first), std::vector<service_node>{test_service_node}, uint8_t{0}};

    // It excludes paths which include the IP of the target
    auto shared_ip_info = request_info::make(test_service_node, 0ms, std::nullopt, std::nullopt);
    CHECK_FALSE(network.find_valid_path(shared_ip_info, {valid_path}).has_value());

    // It returns a path when there is a valid one
    CHECK(network.find_valid_path(info, {valid_path}).has_value());

    // In 'single_path_mode' it does allow the path to include the IP of the target (so that
    // requests can still be made)
    auto network_single_path = TestNetwork(std::nullopt, true, true, false);
    CHECK(network_single_path.find_valid_path(shared_ip_info, {valid_path}).has_value());
}

TEST_CASE("Network Enqueue Path Build", "[network][enqueue_path_build_if_needed]") {
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    auto target = service_node{ed_pk, {2, 8, 0}, "0.0.0.0", uint16_t{0}};
    std::optional<TestNetwork> network;
    auto invalid_path = onion_path{connection_info{target, nullptr, nullptr}, {target}, uint8_t{0}};

    // It does not add additional path builds if there is already a path and it's in
    // 'single_path_mode'
    network.emplace(std::nullopt, true, true, false);
    network->ignore_calls_to("establish_and_store_connection");
    network->set_paths(PathType::standard, {invalid_path});
    network->enqueue_path_build_if_needed(PathType::standard, std::nullopt);
    CHECK(ALWAYS(10ms, network->did_not_call("establish_and_store_connection")));
    CHECK(network->get_path_build_queue().empty());

    // Adds a path build to the queue
    network.emplace(std::nullopt, true, false, false);
    network->ignore_calls_to("establish_and_store_connection");
    network->set_paths(PathType::standard, {});
    network->enqueue_path_build_if_needed(PathType::standard, std::nullopt);
    CHECK(EVENTUALLY(10ms, network->called("establish_and_store_connection")));
    CHECK(network->get_path_build_queue() == std::deque<PathType>{PathType::standard});

    // Can only add two path build to the queue
    network.emplace(std::nullopt, true, false, false);
    network->ignore_calls_to("establish_and_store_connection");
    network->enqueue_path_build_if_needed(PathType::standard, std::nullopt);
    network->enqueue_path_build_if_needed(PathType::standard, std::nullopt);
    CHECK(EVENTUALLY(10ms, network->called("establish_and_store_connection", 2)));
    network->reset_calls();  // This triggers 'call_soon' so we need to wait until they are enqueued
    network->enqueue_path_build_if_needed(PathType::standard, std::nullopt);
    CHECK(ALWAYS(10ms, network->did_not_call("establish_and_store_connection")));
    CHECK(network->get_path_build_queue() ==
          std::deque<PathType>{PathType::standard, PathType::standard});

    // Can add a second 'standard' path build even if there is an active 'standard' path
    network.emplace(std::nullopt, true, false, false);
    network->ignore_calls_to("establish_and_store_connection");
    network->set_paths(PathType::standard, {invalid_path});
    network->enqueue_path_build_if_needed(PathType::standard, std::nullopt);
    CHECK(EVENTUALLY(10ms, network->called("establish_and_store_connection")));
    CHECK(network->get_path_build_queue() == std::deque<PathType>{PathType::standard});

    // Can add more path builds if there are enough active paths of the same type, no pending paths
    // and no `found_path` was provided
    network.emplace(std::nullopt, true, false, false);
    network->ignore_calls_to("establish_and_store_connection");
    network->set_paths(PathType::standard, {invalid_path, invalid_path});
    network->enqueue_path_build_if_needed(PathType::standard, std::nullopt);
    CHECK(EVENTUALLY(10ms, network->called("establish_and_store_connection")));
    CHECK(network->get_path_build_queue() == std::deque<PathType>{PathType::standard});

    // Cannot add more path builds if there are already enough active paths of the same type and a
    // `found_path` was provided
    network.emplace(std::nullopt, true, false, false);
    network->ignore_calls_to("establish_and_store_connection");
    network->set_paths(PathType::standard, {invalid_path, invalid_path});
    network->enqueue_path_build_if_needed(PathType::standard, invalid_path);
    CHECK(ALWAYS(10ms, network->did_not_call("establish_and_store_connection")));
    CHECK(network->get_path_build_queue().empty());

    // Cannot add more path builds if there is already a build of the same type in the queue and the
    // number of active and pending builds of the same type meet the limit
    network.emplace(std::nullopt, true, false, false);
    network->ignore_calls_to("establish_and_store_connection");
    network->set_paths(PathType::standard, {invalid_path});
    network->set_path_build_queue({PathType::standard});
    network->enqueue_path_build_if_needed(PathType::standard, std::nullopt);
    CHECK(ALWAYS(10ms, network->did_not_call("establish_and_store_connection")));
    CHECK(network->get_path_build_queue() == std::deque<PathType>{PathType::standard});

    // Can only add a single 'download' path build
    network.emplace(std::nullopt, true, false, false);
    network->ignore_calls_to("establish_and_store_connection");
    network->set_paths(PathType::download, {});
    network->enqueue_path_build_if_needed(PathType::download, std::nullopt);
    CHECK(EVENTUALLY(10ms, network->called("establish_and_store_connection")));
    network->reset_calls();  // This triggers 'call_soon' so we need to wait until they are enqueued
    network->enqueue_path_build_if_needed(PathType::download, std::nullopt);
    CHECK(ALWAYS(10ms, network->did_not_call("establish_and_store_connection")));
    CHECK(network->get_path_build_queue() == std::deque<PathType>{PathType::download});

    // Can only add a single 'upload' path build
    network.emplace(std::nullopt, true, false, false);
    network->ignore_calls_to("establish_and_store_connection");
    network->set_paths(PathType::upload, {});
    network->enqueue_path_build_if_needed(PathType::upload, std::nullopt);
    CHECK(EVENTUALLY(10ms, network->called("establish_and_store_connection")));
    network->reset_calls();  // This triggers 'call_soon' so we need to wait until they are enqueued
    network->enqueue_path_build_if_needed(PathType::upload, std::nullopt);
    CHECK(ALWAYS(10ms, network->did_not_call("establish_and_store_connection")));
    CHECK(network->get_path_build_queue() == std::deque<PathType>{PathType::upload});
}

TEST_CASE("Network requests", "[network][establish_connection]") {
    auto test_service_node = service_node{
            "decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9"_hexbytes,
            {2, 8, 0},
            "144.76.164.202",
            uint16_t{35400}};
    auto network = TestNetwork(std::nullopt, true, true, false);
    std::promise<std::pair<connection_info, std::optional<std::string>>> prom;

    network.establish_connection(
            "Test",
            test_service_node,
            3s,
            [&prom](connection_info info, std::optional<std::string> error) {
                prom.set_value({info, error});
            });

    // Wait for the result to be set
    auto result = prom.get_future().get();

    CHECK(result.first.is_valid());
    CHECK_FALSE(result.second.has_value());
}

TEST_CASE("Network requests", "[network][send_request]") {
    auto test_service_node = service_node{
            "decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9"_hexbytes,
            {2, 8, 0},
            "144.76.164.202",
            uint16_t{35400}};
    auto network = TestNetwork(std::nullopt, true, true, false);
    std::promise<Result> prom;

    network.establish_connection(
            "Test",
            test_service_node,
            3s,
            [&prom, &network, test_service_node](
                    connection_info info, std::optional<std::string> error) {
                if (!info.is_valid())
                    return prom.set_value({false, false, -1, error.value_or("Unknown Error")});

                network.send_request(
                        request_info::make(
                                test_service_node,
                                3s,
                                ustring{to_usv("{}")},
                                std::nullopt,
                                PathType::standard,
                                std::nullopt,
                                "info"),
                        std::move(info),
                        [&prom](bool success,
                                bool timeout,
                                int16_t status_code,
                                std::optional<std::string> response) {
                            prom.set_value({success, timeout, status_code, response});
                        });
            });

    // Wait for the result to be set
    auto result = prom.get_future().get();

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

TEST_CASE("Network onion request", "[network][send_onion_request]") {
    auto test_service_node = service_node{
            "decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9"_hexbytes,
            {2, 8, 0},
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
    INFO("*result.response is: " << *result.response);
    REQUIRE_NOTHROW(nlohmann::json::parse(*result.response));

    auto response = nlohmann::json::parse(*result.response);
    CHECK(response.contains("hf"));
    CHECK(response.contains("t"));
    CHECK(response.contains("version"));
}

TEST_CASE("Network direct request C API", "[network][network_send_request]") {
    network_object* network;
    REQUIRE(network_init(&network, nullptr, true, true, false, nullptr));
    std::array<uint8_t, 4> target_ip = {144, 76, 164, 202};
    auto test_service_node = network_service_node{};
    test_service_node.quic_port = 35400;
    std::copy(target_ip.begin(), target_ip.end(), test_service_node.ip);
    std::strcpy(
            test_service_node.ed25519_pubkey_hex,
            "decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9");
    auto body = ustring{to_usv("{\"method\":\"info\",\"params\":{}}")};
    auto result_promise = std::make_shared<std::promise<Result>>();

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
                auto result_promise = static_cast<std::promise<Result>*>(ctx);
                auto response_str = std::string(c_response, response_size);
                result_promise->set_value({success, timeout, status_code, response_str});
            },
            static_cast<void*>(result_promise.get()));

    // Wait for the result to be set
    auto result = result_promise->get_future().get();

    CHECK(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 200);
    REQUIRE(result.response.has_value());
    INFO("*result.response is: " << *result.response);
    REQUIRE_NOTHROW(nlohmann::json::parse(*result.response));

    auto response = nlohmann::json::parse(*result.response);
    CHECK(response.contains("hf"));
    CHECK(response.contains("t"));
    CHECK(response.contains("version"));
    network_free(network);
}
