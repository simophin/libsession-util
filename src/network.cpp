#include "session/network.hpp"

#include <oxenc/hex.h>
#include <sodium/core.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/randombytes.h>

#include <fstream>
#include <nlohmann/json.hpp>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/opt.hpp>
#include <oxen/quic/utils.hpp>
#include <string>
#include <string_view>
#include <thread>

#include "session/blinding.hpp"
#include "session/ed25519.hpp"
#include "session/export.h"
#include "session/file.hpp"
#include "session/network.h"
#include "session/onionreq/builder.h"
#include "session/onionreq/builder.hpp"
#include "session/onionreq/key_types.hpp"
#include "session/onionreq/response_parser.hpp"
#include "session/util.hpp"

using namespace oxen;
using namespace session::onionreq;
using namespace std::literals;
using namespace oxen::log::literals;

namespace session::network {

namespace {

    inline auto cat = log::Cat("network");

    class load_cache_exception : public std::runtime_error {
      public:
        load_cache_exception(std::string message) : std::runtime_error(message) {}
    };
    class status_code_exception : public std::runtime_error {
      public:
        int16_t status_code;

        status_code_exception(int16_t status_code, std::string message) :
                std::runtime_error(message), status_code{status_code} {}
    };

    constexpr int16_t error_network_suspended = -10001;
    constexpr int16_t error_building_onion_request = -10002;

    // The minimum time which should pass between `resume_queues` executions
    constexpr auto resume_queues_throttle_duration = 100ms;

    // The amount of time the snode cache can be used before it needs to be refreshed
    constexpr auto snode_cache_expiration_duration = 2h;

    // The amount of time a swarm cache can be used before it needs to be refreshed
    constexpr auto swarm_cache_expiration_duration = (24h * 7);

    // The smallest size the snode cache can get to before we need to fetch more.
    constexpr size_t min_snode_cache_count = 12;

    // The number of snodes to use to refresh the cache.
    constexpr size_t num_snodes_to_refresh_cache_from = 3;

    // The number of times to retry refreshing the cache from each snode.
    constexpr size_t snode_cache_refresh_retries = 3;

    // The smallest size a swarm can get to before we need to fetch it again.
    constexpr uint16_t min_swarm_snode_count = 3;

    // The number of snodes (including the guard snode) in a path.
    constexpr uint8_t path_size = 3;

    // The number of times a path can fail before it's replaced.
    constexpr uint16_t path_failure_threshold = 3;

    // The number of times a snode can fail before it's replaced.
    constexpr uint16_t snode_failure_threshold = 3;

    // File names
    const fs::path file_testnet{u8"testnet"}, file_snode_pool{u8"snode_pool"},
            file_snode_pool_updated{u8"snode_pool_updated"}, swarm_dir{u8"swarm"},
            default_cache_path{u8"."}, file_snode_failure_counts{u8"snode_failure_counts"};

    constexpr auto node_not_found_prefix = "502 Bad Gateway\n\nNext node not found: "sv;
    constexpr auto node_not_found_prefix_no_status = "Next node not found: "sv;
    constexpr auto ALPN = "oxenstorage"sv;
    constexpr auto ONION = "onion_req";

    std::string path_type_name(PathType path_type, bool single_path_mode) {
        if (single_path_mode)
            return "single_path";

        switch (path_type) {
            case PathType::standard: return "standard";
            case PathType::upload: return "upload";
            case PathType::download: return "download";
        }
        return "standard";  // Default
    }

    // The mininum number of paths we want to maintain
    uint8_t min_path_count(PathType path_type, bool single_path_mode) {
        if (single_path_mode)
            return 1;

        switch (path_type) {
            case PathType::standard: return 2;
            case PathType::upload: return 1;
            case PathType::download: return 1;
        }
        return 2;  // Default
    }

    /// Converts a string such as "1.2.3" to a vector of ints {1,2,3}.  Throws if something
    /// in/around the .'s isn't parseable as an integer.
    std::vector<int> parse_version(std::string_view vers, bool trim_trailing_zero = true) {
        auto v_s = session::split(vers, ".");
        std::vector<int> result;
        for (const auto& piece : v_s)
            if (!quic::parse_int(piece, result.emplace_back()))
                throw std::invalid_argument{"Invalid version"};

        // Remove any trailing `0` values (but ensure we at least end up with a "0" version)
        if (trim_trailing_zero)
            while (result.size() > 1 && result.back() == 0)
                result.pop_back();

        return result;
    }

    service_node node_from_json(nlohmann::json json) {
        auto pk_ed = json["pubkey_ed25519"].get<std::string_view>();
        if (pk_ed.size() != 64 || !oxenc::is_hex(pk_ed))
            throw std::invalid_argument{
                    "Invalid service node json: pubkey_ed25519 is not a valid, hex pubkey"};

        // When parsing a node from JSON it'll generally be from the 'get_swarm` endpoint or a 421
        // error neither of which contain the `storage_server_version` - luckily we don't need the
        // version for these two cases so can just default it to `0`
        std::vector<int> storage_server_version = {0};
        if (json.contains("storage_server_version"))
            storage_server_version =
                    parse_version(json["storage_server_version"].get<std::string>());

        return {oxenc::from_hex(pk_ed),
                storage_server_version,
                json["ip"].get<std::string>(),
                json["port_omq"].get<uint16_t>()};
    }

    service_node node_from_disk(std::string_view str, bool can_ignore_version = false) {
        // Format is "{ip}|{port}|{version}|{ed_pubkey}
        auto parts = split(str, "|");
        if (parts.size() != 4)
            throw std::invalid_argument("Invalid service node serialisation: {}"_format(str));
        if (parts[3].size() != 64 || !oxenc::is_hex(parts[3]))
            throw std::invalid_argument{
                    "Invalid service node serialisation: pubkey is not hex or has wrong size"};

        uint16_t port;
        if (!quic::parse_int(parts[1], port))
            throw std::invalid_argument{"Invalid service node serialization: invalid port"};

        std::vector<int> storage_server_version = parse_version(parts[2]);
        if (!can_ignore_version && storage_server_version == std::vector<int>{0})
            throw std::invalid_argument{"Invalid service node serialization: invalid version"};

        return {
                oxenc::from_hex(parts[3]),  // ed25519_pubkey
                storage_server_version,     // storage_server_version
                std::string(parts[0]),      // ip
                port,                       // port
        };
    }

    const std::vector<service_node> seed_nodes_testnet{
            node_from_disk("144.76.164.202|35400|2.8.0|"
                           "decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9"sv)};
    const std::vector<service_node> seed_nodes_mainnet{
            node_from_disk("144.76.164.202|20200|2.8.0|"
                           "1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1fef"sv),
            node_from_disk("88.99.102.229|20201|2.8.0|"
                           "1f101f0acee4db6f31aaa8b4df134e85ca8a4878efaef7f971e88ab144c1a7ce"sv),
            node_from_disk("195.16.73.17|20202|2.8.0|"
                           "1f202f00f4d2d4acc01e20773999a291cf3e3136c325474d159814e06199919f"sv),
            node_from_disk("104.194.11.120|20203|2.8.0|"
                           "1f303f1d7523c46fa5398826740d13282d26b5de90fbae5749442f66afb6d78b"sv),
            node_from_disk("104.194.8.115|20204|2.8.0|"
                           "1f604f1c858a121a681d8f9b470ef72e6946ee1b9c5ad15a35e16b50c28db7b0"sv)};
    constexpr auto file_server = "filev2.getsession.org"sv;
    constexpr auto file_server_pubkey =
            "da21e1d886c6fbaea313f75298bd64aab03a97ce985b46bb2dad9f2089c8ee59"sv;

    /// rng type that uses llarp::randint(), which is cryptographically secure
    struct CSRNG {
        using result_type = uint64_t;

        static constexpr uint64_t min() { return std::numeric_limits<uint64_t>::min(); };

        static constexpr uint64_t max() { return std::numeric_limits<uint64_t>::max(); };

        uint64_t operator()() {
            uint64_t i;
            randombytes((uint8_t*)&i, sizeof(i));
            return i;
        };
    };

    std::string node_to_disk(service_node node) {
        // Format is "{ip}|{port}|{version}|{ed_pubkey}
        auto ed25519_pubkey_hex = oxenc::to_hex(node.view_remote_key());

        return fmt::format(
                "{}|{}|{}|{}",
                node.host(),
                node.port(),
                "{}"_format(fmt::join(node.storage_server_version, ".")),
                ed25519_pubkey_hex);
    }

    session::onionreq::x25519_pubkey compute_xpk(ustring_view ed25519_pk) {
        std::array<unsigned char, 32> xpk;
        if (0 != crypto_sign_ed25519_pk_to_curve25519(xpk.data(), ed25519_pk.data()))
            throw std::runtime_error{
                    "An error occured while attempting to convert Ed25519 pubkey to X25519; "
                    "is the pubkey valid?"};
        return session::onionreq::x25519_pubkey::from_bytes({xpk.data(), 32});
    }

    std::string consume_string(oxenc::bt_dict_consumer dict, std::string_view key) {
        if (!dict.skip_until(key))
            throw std::invalid_argument{
                    "Unable to find entry in dict for key '" + std::string(key) + "'"};
        return dict.consume_string();
    }

    template <typename IntType>
    auto consume_integer(oxenc::bt_dict_consumer dict, std::string_view key) {
        if (!dict.skip_until(key))
            throw std::invalid_argument{
                    "Unable to find entry in dict for key '" + std::string(key) + "'"};
        return dict.next_integer<IntType>().second;
    }
}  // namespace

namespace detail {
    std::optional<service_node> node_for_destination(network_destination destination) {
        if (auto* dest = std::get_if<service_node>(&destination))
            return *dest;

        return std::nullopt;
    }

    session::onionreq::x25519_pubkey pubkey_for_destination(network_destination destination) {
        if (auto* dest = std::get_if<service_node>(&destination))
            return compute_xpk(dest->view_remote_key());

        if (auto* dest = std::get_if<ServerDestination>(&destination))
            return dest->x25519_pubkey;

        throw std::runtime_error{"Invalid destination."};
    }
}  // namespace detail

request_info request_info::make(
        onionreq::network_destination _dest,
        std::chrono::milliseconds _timeout,
        std::optional<ustring> _original_body,
        std::optional<session::onionreq::x25519_pubkey> _swarm_pk,
        PathType _type,
        std::optional<std::string> _req_id,
        std::optional<std::string> _ep,
        std::optional<ustring> _body) {
    return request_info{
            _req_id.value_or(random::random_base32(4)),
            std::move(_dest),
            _ep.value_or(ONION),
            std::move(_body),
            std::move(_original_body),
            std::move(_swarm_pk),
            _type,
            _timeout};
}

// MARK: Initialization

Network::Network(
        std::optional<fs::path> cache_path,
        bool use_testnet,
        bool single_path_mode,
        bool pre_build_paths) :
        use_testnet{use_testnet},
        should_cache_to_disk{cache_path},
        single_path_mode{single_path_mode},
        cache_path{cache_path.value_or(default_cache_path)} {
    // Load the cache from disk and start the disk write thread
    if (should_cache_to_disk) {
        load_cache_from_disk();
        disk_write_thread = std::thread{&Network::disk_write_thread_loop, this};
    }

    // Kick off a separate thread to build paths (may as well kick this off early)
    if (pre_build_paths) {
        for (int i = 0; i < min_path_count(PathType::standard, single_path_mode); ++i)
            path_build_queue.emplace_back(PathType::standard);

        net.call_soon([this] { resume_queues(); });
    }
}

Network::~Network() {
    {
        std::lock_guard lock{snode_cache_mutex};
        shut_down_disk_thread = true;
    }
    snode_cache_cv.notify_one();
    if (disk_write_thread.joinable())
        disk_write_thread.join();
}

// MARK: Cache Management

void Network::load_cache_from_disk() {
    try {
        // If the cache is for the wrong network then delete everything
        auto testnet_stub = cache_path / file_testnet;
        if (use_testnet != fs::exists(testnet_stub) && fs::exists(testnet_stub))
            fs::remove_all(cache_path);

        // Create the cache directory (and swarm_dir, inside it) if needed
        auto swarm_path = cache_path / swarm_dir;
        fs::create_directories(swarm_path);

        // If we are using testnet then create a file to indicate that
        if (use_testnet)
            write_whole_file(testnet_stub);

        // Load the last time the snode pool was updated
        //
        // Note: We aren't just reading the write time of the file because Apple consider
        // accessing file timestamps a method that can be used to track the user (and we
        // want to avoid being flagged as using such)
        if (auto last_updated_path = cache_path / file_snode_pool_updated;
            fs::exists(last_updated_path)) {
            try {
                auto timestamp_str = read_whole_file(last_updated_path);
                while (timestamp_str.ends_with('\n'))
                    timestamp_str.pop_back();

                std::time_t timestamp;
                if (!quic::parse_int(timestamp_str, timestamp))
                    throw std::runtime_error{"invalid file data: expected timestamp first line"};

                last_snode_cache_update = std::chrono::system_clock::from_time_t(timestamp);
            } catch (const std::exception& e) {
                log::error(cat, "Ignoring invalid last update timestamp file: {}", e.what());
            }
        }

        // Load the snode pool
        if (auto pool_path = cache_path / file_snode_pool; fs::exists(pool_path)) {
            auto file = open_for_reading(pool_path);
            std::vector<service_node> loaded_cache;
            std::string line;
            auto invalid_entries = 0;

            while (std::getline(file, line)) {
                try {
                    loaded_cache.push_back(node_from_disk(line));
                } catch (...) {
                    ++invalid_entries;
                }
            }

            if (invalid_entries > 0)
                log::warning(
                        cat, "Skipped {} invalid entries in snode pool cache.", invalid_entries);

            snode_cache = loaded_cache;
        }

        // Load the failure counts
        if (auto failure_counts_path = cache_path / file_snode_failure_counts;
            fs::exists(failure_counts_path)) {
            auto file = open_for_reading(failure_counts_path);
            std::unordered_map<std::string, uint8_t> loaded_failure_count;
            std::string line;
            auto invalid_entries = 0;

            while (std::getline(file, line)) {
                try {
                    auto parts = split(line, "|");
                    uint8_t failure_count;

                    if (parts.size() != 2)
                        throw std::invalid_argument(
                                "Invalid failure count serialisation: {}"_format(line));
                    if (!quic::parse_int(parts[1], failure_count))
                        throw std::invalid_argument{
                                "Invalid failure count serialization: invalid failure count"};

                    // If we somehow already have a value then we should use whichever has the
                    // larger failure count (want to avoid keeping a bad node around longer than
                    // needed)
                    if (loaded_failure_count.try_emplace(std::string(parts[0]), failure_count)
                                .first->second < failure_count)
                        loaded_failure_count[std::string(parts[0])] = failure_count;
                } catch (...) {
                    ++invalid_entries;
                }
            }

            if (invalid_entries > 0)
                log::warning(
                        cat,
                        "Skipped {} invalid entries in snode failure count cache.",
                        invalid_entries);

            snode_failure_counts = loaded_failure_count;
        }

        // Load the swarm cache
        auto time_now = std::chrono::system_clock::now();
        std::unordered_map<std::string, std::vector<service_node>> loaded_cache;
        std::vector<fs::path> caches_to_remove;
        auto invalid_swarm_entries = 0;

        for (auto& entry : fs::directory_iterator(swarm_path)) {
            // If the pubkey was valid then process the content
            const auto& path = entry.path();
            auto file = open_for_reading(path);
            std::vector<service_node> nodes;
            std::string line;
            bool checked_swarm_expiration = false;
            std::chrono::seconds swarm_lifetime = 0s;
            auto filename = path.filename().string();

            while (std::getline(file, line)) {
                try {
                    // If we haven't checked if the swarm cache has expired then do so, removing
                    // any expired/invalid caches
                    if (!checked_swarm_expiration) {
                        std::time_t timestamp;
                        if (!quic::parse_int(line, timestamp))
                            throw std::runtime_error{
                                    "invalid file data: expected timestamp first line"};
                        auto swarm_last_updated = std::chrono::system_clock::from_time_t(timestamp);
                        swarm_lifetime = std::chrono::duration_cast<std::chrono::seconds>(
                                time_now - swarm_last_updated);
                        checked_swarm_expiration = true;

                        if (swarm_lifetime < swarm_cache_expiration_duration)
                            throw load_cache_exception{"Expired swarm cache."};
                    }

                    // Otherwise try to parse as a node (for the swarm cache we can ignore invalid
                    // versions as the `get_swarm` API doesn't return version info)
                    nodes.push_back(node_from_disk(line, true));

                } catch (const std::exception& e) {
                    // Don't bother logging for expired entries (we include the count separately at
                    // the end)
                    if (dynamic_cast<const load_cache_exception*>(&e) == nullptr) {
                        ++invalid_swarm_entries;
                    }

                    // The cache is invalid, we should remove it
                    if (!checked_swarm_expiration) {
                        caches_to_remove.emplace_back(path);
                        break;
                    }
                }
            }

            // If we got nodes the add it to the cache, otherwise we want to remove it
            if (!nodes.empty())
                loaded_cache[filename] = std::move(nodes);
            else
                caches_to_remove.emplace_back(path);
        }

        if (invalid_swarm_entries > 0)
            log::warning(cat, "Skipped {} invalid entries in swarm cache.", invalid_swarm_entries);

        swarm_cache = loaded_cache;

        // Remove any expired cache files
        for (auto& expired_cache : caches_to_remove)
            fs::remove_all(expired_cache);

        log::info(
                cat,
                "Loaded cache of {} snodes, {} swarms ({} expired swarms).",
                snode_cache.size(),
                swarm_cache.size(),
                caches_to_remove.size());
    } catch (const std::exception& e) {
        log::error(cat, "Failed to load snode cache, will rebuild ({}).", e.what());

        if (fs::exists(cache_path))
            fs::remove_all(cache_path);
    }
}

void Network::disk_write_thread_loop() {
    std::unique_lock lock{snode_cache_mutex};
    while (true) {
        snode_cache_cv.wait(lock, [this] { return need_write || shut_down_disk_thread; });

        if (need_write) {
            // Make local copies so that we can release the lock and not
            // worry about other threads wanting to change things:
            auto snode_cache_write = snode_cache;
            auto snode_failure_counts_write = snode_failure_counts;
            auto last_pool_update_write = last_snode_cache_update;
            auto swarm_cache_write = swarm_cache;

            lock.unlock();
            {
                try {
                    // Create the cache directories if needed
                    auto swarm_base = cache_path / swarm_dir;
                    fs::create_directories(swarm_base);

                    // Save the snode pool to disk
                    if (need_pool_write) {
                        auto pool_path = cache_path / file_snode_pool,
                             pool_tmp = pool_path / u8"_new";

                        {
                            std::stringstream ss;
                            for (auto& snode : snode_cache_write)
                                ss << node_to_disk(snode) << '\n';

                            std::ofstream file(pool_tmp, std::ios::binary);
                            file << ss.rdbuf();
                        }

                        fs::rename(pool_tmp, pool_path);

                        // Write the last update timestamp to disk
                        write_whole_file(
                                cache_path / file_snode_pool_updated,
                                "{}"_format(std::chrono::system_clock::to_time_t(
                                        last_pool_update_write)));
                        need_pool_write = false;
                        log::debug(cat, "Finished writing snode pool cache to disk.");
                    }

                    // Save the snode failure counts to disk
                    if (need_failure_counts_write) {
                        auto failure_counts_path = cache_path / file_snode_failure_counts;
                        auto failure_counts_tmp = failure_counts_path;
                        failure_counts_tmp += u8"_new";

                        {
                            std::stringstream ss;
                            for (auto& [key, count] : snode_failure_counts_write)
                                ss << fmt::format("{}|{}", key, count) << '\n';

                            std::ofstream file(failure_counts_tmp, std::ios::binary);
                            file << ss.rdbuf();
                        }

                        fs::rename(failure_counts_tmp, failure_counts_path);
                        need_failure_counts_write = false;
                        log::debug(cat, "Finished writing snode failure counts to disk.");
                    }

                    // Write the swarm cache to disk
                    if (need_swarm_write) {
                        auto time_now = std::chrono::system_clock::now();

                        for (auto& [key, swarm] : swarm_cache_write) {
                            auto swarm_path = swarm_base / key;
                            auto swarm_tmp = swarm_path;
                            swarm_tmp += u8"_new";

                            // Write the timestamp
                            std::stringstream ss;
                            ss << std::chrono::system_clock::to_time_t(time_now) << '\n';

                            // Write the nodes
                            for (auto& snode : swarm)
                                ss << node_to_disk(snode) << '\n';

                            // FIXME: In the future we should store the swarm info in the encrypted
                            // database instead of a plaintext file
                            std::ofstream swarm_file(swarm_tmp, std::ios::binary);
                            swarm_file << ss.rdbuf();

                            fs::rename(swarm_tmp, swarm_path);
                        }
                        need_swarm_write = false;
                        log::debug(cat, "Finished writing swarm cache to disk.");
                    }

                    need_write = false;
                } catch (const std::exception& e) {
                    log::error(cat, "Failed to write snode cache: {}", e.what());
                }
            }
            lock.lock();
        }
        if (need_clear_cache) {
            snode_cache = {};
            last_snode_cache_update = {};
            snode_failure_counts = {};
            swarm_cache = {};

            lock.unlock();
            if (fs::exists(cache_path))
                fs::remove_all(cache_path);
            lock.lock();
            need_clear_cache = false;
        }
        if (shut_down_disk_thread)
            return;
    }
}

void Network::clear_cache() {
    net.call([this]() mutable {
        {
            std::lock_guard lock{snode_cache_mutex};
            need_clear_cache = true;
        }
        snode_cache_cv.notify_one();
    });
}

// MARK: Connection

void Network::suspend() {
    net.call([this]() mutable {
        suspended = true;
        close_connections();
        log::info(cat, "Suspended.");
    });
}

void Network::resume() {
    net.call([this]() mutable {
        suspended = false;
        log::info(cat, "Resumed.");
    });
}

void Network::close_connections() {
    net.call([this]() mutable {
        // Explicitly reset the endpoint to close all connections
        endpoint.reset();

        // Explicitly reset the connection and stream (just in case)
        for (auto& [type, paths_for_type] : paths) {
            for (auto& path : paths_for_type) {
                path.conn_info.conn.reset();
                path.conn_info.stream.reset();
            }
        }

        update_status(ConnectionStatus::disconnected);
        log::info(cat, "Closed all connections.");
    });
}

void Network::update_status(ConnectionStatus updated_status) {
    // Ignore updates which don't change the status
    if (status == updated_status)
        return;

    // If we are already 'connected' then ignore 'connecting' status changes (if we drop one path
    // and build another in the background this can happen)
    if (status == ConnectionStatus::connected && updated_status == ConnectionStatus::connecting)
        return;

    // Store the updated status
    status = updated_status;

    if (!status_changed)
        return;

    status_changed(updated_status);
}

std::chrono::milliseconds Network::retry_delay(
        int num_failures, std::chrono::milliseconds max_delay) {
    return std::chrono::milliseconds(std::min(
            max_delay.count(),
            static_cast<typename std::chrono::milliseconds::rep>(100 * std::pow(2, num_failures))));
}

std::shared_ptr<quic::Endpoint> Network::get_endpoint() {
    return net.call_get([this]() mutable {
        if (!endpoint)
            endpoint = net.endpoint(quic::Address{"0.0.0.0", 0}, quic::opt::alpns{ALPN});

        return endpoint;
    });
}

void Network::establish_connection(
        std::string request_id,
        PathType path_type,
        service_node target,
        std::optional<std::chrono::milliseconds> timeout,
        std::function<void(connection_info info, std::optional<std::string> error)> callback) {
    log::trace(cat, "{} called for {}.", __PRETTY_FUNCTION__, request_id);
    auto currently_suspended = net.call_get([this]() -> bool { return suspended; });

    // If the network is currently suspended then don't try to open a connection
    if (currently_suspended)
        return callback({target, nullptr, nullptr}, "Network is suspended.");

    auto conn_key_pair = ed25519::ed25519_key_pair();
    auto creds = quic::GNUTLSCreds::make_from_ed_seckey(from_unsigned_sv(conn_key_pair.second));
    auto cb_called = std::make_shared<std::once_flag>();
    auto cb = std::make_shared<std::function<void(connection_info, std::optional<std::string>)>>(
            std::move(callback));
    auto conn_promise = std::promise<std::shared_ptr<oxen::quic::connection_interface>>();
    auto conn_future = conn_promise.get_future().share();
    auto handshake_timeout =
            timeout ? std::optional{quic::opt::handshake_timeout{
                              std::chrono::duration_cast<std::chrono::nanoseconds>(*timeout)}}
                    : std::nullopt;

    auto c = get_endpoint()->connect(
            target,
            creds,
            quic::opt::keep_alive{10s},
            handshake_timeout,
            [this, request_id, target, cb, cb_called, conn_future](
                    quic::connection_interface&) mutable {
                log::trace(cat, "Connection established for {}.", request_id);

                // Just in case, call it within a `net.call`
                net.call([&] {
                    std::call_once(*cb_called, [&]() {
                        if (cb) {
                            auto conn = conn_future.get();
                            (*cb)({target, conn, conn->open_stream<quic::BTRequestStream>()},
                                  std::nullopt);
                            cb.reset();
                        }
                    });
                });
            },
            [this, path_type, target, request_id, cb, cb_called, conn_future](
                    quic::connection_interface& conn, uint64_t error_code) mutable {
                log::trace(cat, "Connection closed for {}.", request_id);

                // Just in case, call it within a `net.call`
                net.call([&] {
                    // Trigger the callback first before updating the paths in case this was
                    // triggered when try to establish a connection
                    std::call_once(*cb_called, [&]() {
                        if (cb) {
                            (*cb)({target, nullptr, nullptr}, std::nullopt);
                            cb.reset();
                        }
                    });

                    // When the connection is closed we update the path and reset it's connection
                    // info so we can recover the path later if desired
                    auto conn_info = conn_future.get();
                    auto current_paths = paths[path_type];
                    auto target_path = std::find_if(
                            current_paths.begin(),
                            current_paths.end(),
                            [&target](const auto& path) {
                                return !path.nodes.empty() && target == path.nodes.front();
                            });

                    if (target_path != current_paths.end() && target_path->conn_info.conn &&
                        conn.reference_id() == target_path->conn_info.conn->reference_id()) {
                        target_path->conn_info.conn.reset();
                        target_path->conn_info.stream.reset();

                        handle_node_error(target, path_type, target_path->conn_info, request_id);
                    } else if (error_code == static_cast<uint64_t>(NGTCP2_ERR_HANDSHAKE_TIMEOUT))
                        // Depending on the state of the snode pool cache it's possible for certain
                        // errors to result in being permanently unable to establish a connection,
                        // to avoid this we handle those error codes and drop
                        handle_node_error(
                                target, path_type, {target, nullptr, nullptr}, request_id);
                });
            });

    conn_promise.set_value(c);
}

// MARK: Request Queues and Path Building

void Network::resume_queues() {
    if (suspended) {
        log::info(cat, "Ignoring resume queues as network is suspended.");

        // If we have any requests in the queue then we should trigger their callbacks
        for (auto& [path_type, requests] : request_queue)
            for (auto& [info, callback] : requests)
                callback(false, false, error_network_suspended, "Network is suspended.");

        // Clear the map after processing all callbacks
        request_queue.clear();
        return;
    }

    // Throttle this function as it can get called very frequently and running the logic excessively
    // could cause battery drain
    auto time_since_last_run = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now() - last_resume_queues_timestamp);
    if (time_since_last_run < resume_queues_throttle_duration) {
        if (!has_scheduled_resume_queues) {
            has_scheduled_resume_queues = true;

            auto delay = (resume_queues_throttle_duration - time_since_last_run);
            net.call_later(delay, [this]() {
                has_scheduled_resume_queues = false;
                resume_queues();
            });
        }

        return;
    }
    last_resume_queues_timestamp = std::chrono::system_clock::now();

    // Only generate the stats if we are actually going to log them
    if (log::get_level(cat) == log::Level::trace) {
        auto request_count = 0;
        std::vector<std::string> existing_path_type_names;
        std::vector<std::string> pending_path_type_names;
        std::vector<std::string> in_progress_path_type_names;
        for (const auto& [path_type, paths_for_type] : paths)
            existing_path_type_names.insert(
                    existing_path_type_names.end(),
                    paths_for_type.size(),
                    path_type_name(path_type, single_path_mode));
        std::transform(
                path_build_queue.begin(),
                path_build_queue.end(),
                std::back_inserter(pending_path_type_names),
                [this](const PathType& type) { return path_type_name(type, single_path_mode); });
        std::transform(
                in_progress_path_builds.begin(),
                in_progress_path_builds.end(),
                std::back_inserter(in_progress_path_type_names),
                [this](const auto& pending_build) {
                    return path_type_name(pending_build.second.first, single_path_mode);
                });
        auto format_names = [](std::vector<std::string> names) {
            return (names.empty() ? "0" : "{} ({})"_format(names.size(), fmt::join(names, ", ")));
        };
        for (const auto& [type, requests] : request_queue)
            request_count += requests.size();

        log::trace(
                cat,
                "Resuming queues snodes: {}, paths: {}, path_builds: "
                "{}, in_progress_path_builds: {}, requests: {}.",
                snode_cache.size(),
                format_names(existing_path_type_names),
                format_names(pending_path_type_names),
                format_names(in_progress_path_type_names),
                request_count);
    }

    // If we haven't set a connection status yet then do so now
    if (status == ConnectionStatus::unknown)
        update_status(ConnectionStatus::connecting);

    // If the snode cache is too small then we need to update it before we try to build any paths
    if (snode_cache.size() < min_snode_cache_count) {
        net.call_soon([this]() { refresh_snode_cache(); });
        return;
    }

    // Otherwise check if it's been too long since the last update and, if so, trigger a refresh
    auto cache_lifetime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now() - last_snode_cache_update);

    if (cache_lifetime < 0s || cache_lifetime > snode_cache_expiration_duration)
        net.call_soon([this]() { refresh_snode_cache(); });

    // Schedule any path builds (or recoveries)
    std::unordered_map<PathType, size_t> num_pending_paths;

    for (const auto& path_type : path_build_queue) {
        num_pending_paths[path_type]++;

        // If we have an existing path that is not valid then we should try to recover that instead
        // of trying to build a new path (after triggering the recovery we remove it from
        // `existing_paths` to ensure we don't try to recover it multiple times)
        auto& existing_paths = paths[path_type];
        if (!existing_paths.empty()) {
            auto it = std::find_if(
                    existing_paths.begin(), existing_paths.end(), [](const onion_path& path) {
                        return !path.is_valid();
                    });

            if (it != existing_paths.end()) {
                recover_path(path_type, *it);
                existing_paths.erase(it);
                continue;
            }
        }

        // Otherwise we need to build a new path
        build_path(std::nullopt, path_type);
    }

    // Now that we've triggered all request path builds/recoveries we can clear the path_build_queue
    path_build_queue.clear();

    // If there are left over invalid paths in `paths` and we have more than the minimum number of
    // required paths (including the builds/recoveries started above) then we can just drop the
    // extra invalid paths
    for (auto& [path_type, existing_paths] : paths) {
        size_t pending_count = num_pending_paths[path_type];
        size_t total_count = (existing_paths.size() + pending_count);
        size_t target_count = min_path_count(path_type, single_path_mode);

        // If we don't have enough paths then do nothing
        if (total_count <= target_count)
            continue;

        std::vector<onion_path> valid_paths;
        std::vector<onion_path> invalid_paths;
        valid_paths.reserve(existing_paths.size());
        invalid_paths.reserve(existing_paths.size());

        for (auto& path : existing_paths) {
            if (path.is_valid())
                valid_paths.emplace_back(path);
            else
                invalid_paths.emplace_back(path);
        }

        // Keep all valid paths and only enough invalid paths to meet the minimum requirements
        size_t remaining_slots =
                std::max(target_count - valid_paths.size(), static_cast<size_t>(0));
        existing_paths = std::move(valid_paths);
        existing_paths.insert(
                existing_paths.end(),
                invalid_paths.begin(),
                invalid_paths.begin() + std::min(remaining_slots, invalid_paths.size()));
    }

    // Now that we've scheduled any required path builds we should try to resume any pending
    // requests in case they now have a valid paths
    if (!paths.empty()) {
        std::unordered_set<PathType> already_enqueued_paths;

        for (auto& [path_type, requests] : request_queue)
            if (!paths[path_type].empty())
                std::erase_if(requests, [this, &already_enqueued_paths](const auto& request) {
                    // If there are no valid paths to send the request then enqueue a new path build
                    // (if needed) leave the request in the queue
                    if (!find_valid_path(request.first, paths[request.first.path_type])) {
                        if (!already_enqueued_paths.contains(request.first.path_type)) {
                            already_enqueued_paths.insert(request.first.path_type);
                            enqueue_path_build_if_needed(request.first.path_type, true);
                        }
                        net.call_soon([this]() { resume_queues(); });
                        return false;
                    }

                    net.call_soon([this, info = request.first, cb = std::move(request.second)]() {
                        _send_onion_request(std::move(info), std::move(cb));
                    });
                    return true;
                });
    }
}

void Network::refresh_snode_cache() {
    if (suspended) {
        log::info(cat, "Ignoring snode cache refresh as network is suspended.");
        return;
    }

    // Only allow a single cache refresh at a time
    if (refreshing_snode_cache) {
        log::info(cat, "Snode cache refresh ignored due to in progress refresh.");
        return;
    }

    refreshing_snode_cache = true;

    // If we don't have enough nodes in the current cached then we need to fetch
    // from the seed nodes which is a trusted source so we can update the cache
    // from a single response
    //
    // If the current cache is large enough then we want to getch from a number
    // of random nodes and use the intersection of their responses as the update
    auto use_seed_node = (snode_cache.size() < min_snode_cache_count);
    size_t num_requests = (use_seed_node ? 1 : num_snodes_to_refresh_cache_from);
    log::info(cat, "Refreshing snode cache{}.", (use_seed_node ? " from seed nodes" : ""));

    // Define a handler function
    auto processing_responses =
            [this, use_seed_node, num_requests](
                    std::shared_ptr<std::vector<std::vector<service_node>>> all_nodes) {
                // There are still pending requests so just wait
                if (all_nodes->size() != num_requests)
                    return;

                auto any_nodes_request_failed =
                        std::any_of(all_nodes->begin(), all_nodes->end(), [](const auto& n) {
                            return n.empty();
                        });

                if (any_nodes_request_failed) {
                    // If the current cache is still usable just send a warning and don't bother
                    // retrying
                    if (!use_seed_node) {
                        log::warning(
                                cat,
                                "Failed to refresh snode cache due to request failing to retrieve "
                                "nodes");
                        refreshing_snode_cache = false;
                        return;
                    }

                    // Otherwise schedule a retry after a short delay
                    snode_cache_refresh_failure_count++;
                    refreshing_snode_cache = false;

                    auto cache_refresh_retry_delay = retry_delay(snode_cache_refresh_failure_count);
                    log::error(
                            cat,
                            "Failed to refresh snode cache{} due to request failing to retrieve "
                            "nodes, will retry after: {}ms",
                            (use_seed_node ? " from seed nodes" : ""),
                            cache_refresh_retry_delay.count());
                    net.call_later(cache_refresh_retry_delay, [this]() { refresh_snode_cache(); });
                    return;
                }

                // Sort the vectors (so make it easier to find the intersection)
                for (auto& nodes : *all_nodes)
                    std::stable_sort(nodes.begin(), nodes.end());

                auto nodes = (*all_nodes)[0];

                // If we triggered multiple requests then get the intersection of all vectors
                if (all_nodes->size() > 1) {
                    for (size_t i = 1; i < all_nodes->size(); ++i) {
                        std::vector<service_node> temp;
                        std::set_intersection(
                                nodes.begin(),
                                nodes.end(),
                                (*all_nodes)[i].begin(),
                                (*all_nodes)[i].end(),
                                std::back_inserter(temp),
                                [](const auto& a, const auto& b) { return a == b; });
                        nodes = std::move(temp);
                    }
                }

                // Shuffle the nodes so we don't have a specific order
                CSRNG rng;
                std::shuffle(nodes.begin(), nodes.end(), rng);

                // Update the disk cache if the snode pool was updated
                {
                    std::lock_guard lock{snode_cache_mutex};
                    snode_cache = nodes;
                    last_snode_cache_update = std::chrono::system_clock::now();
                    need_pool_write = true;
                    need_write = true;
                }
                snode_cache_cv.notify_one();

                // Resume any queued processes
                log::info(cat, "Refreshing snode cache completed with {} nodes.", nodes.size());
                refreshing_snode_cache = false;

                for (const auto& callback : after_snode_cache_refresh)
                    net.call_soon([cb = std::move(callback)]() { cb(); });
                after_snode_cache_refresh.clear();
                net.call_soon([this]() { resume_queues(); });
            };
    auto handle_response =
            [processing_responses](
                    std::shared_ptr<std::vector<std::vector<service_node>>> all_nodes) {
                return [all_nodes, processing_responses](
                               std::vector<service_node> nodes, std::optional<std::string>) {
                    all_nodes->emplace_back(nodes);
                    processing_responses(all_nodes);
                };
            };

    std::vector<service_node> nodes;

    if (use_seed_node)
        nodes = (use_testnet ? seed_nodes_testnet : seed_nodes_mainnet);
    else
        nodes = snode_cache;

    // Just in case, make sure we actually have nodes to send requests to
    if (nodes.empty()) {
        log::error(cat, "Failed to refresh snode cache from seed nodes: Insufficient seed nodes.");
        refreshing_snode_cache = false;
        return;
    }

    // Shuffle to ensure we pick random nodes to fetch from
    CSRNG rng;
    std::shuffle(nodes.begin(), nodes.end(), rng);

    // Kick off the requests concurrently
    //
    // It's possible, even likely, that some of the nodes could be unavailable so
    // we want to try to cycle through a few nodes if any of the requests fail
    // so calculate how many we can cycle through
    size_t num_attempts = std::min(nodes.size() / num_requests, snode_cache_refresh_retries);
    auto all_nodes = std::make_shared<std::vector<std::vector<service_node>>>();
    all_nodes->reserve(num_requests);

    for (size_t i = 0; i < num_requests; ++i) {
        std::vector<service_node> chunk(
                nodes.begin() + (i * num_attempts), nodes.begin() + ((i + 1) * num_attempts));

        get_service_nodes_recursive(
                "Refresh Snode Cache (Node {})"_format(i + 1),
                chunk,
                std::nullopt,
                handle_response(all_nodes));
    }
}

void Network::build_path(std::optional<std::string> existing_request_id, PathType path_type) {
    if (suspended) {
        log::info(cat, "Ignoring path build request as network is suspended.");
        return;
    }

    auto request_id = existing_request_id.value_or(random::random_base32(4));
    auto path_name = path_type_name(path_type, single_path_mode);

    // Check that we have enough snodes before continuing (shouldn't be an issue but if something
    // calls `build_path` in the future then this drive it back into the standard loop)
    if (snode_cache.size() < min_snode_cache_count) {
        log::warning(
                cat,
                "Re-queing {} path build due to insufficient nodes ({}).",
                path_name,
                request_id);
        in_progress_path_builds.erase(request_id);
        path_build_queue.emplace_back(path_type);
        net.call_soon([this]() { resume_queues(); });
        return;
    }

    CSRNG rng;
    log::info(cat, "Building {} path ({}).", path_name, request_id);

    // If we don't have any in-progress path builds then reset the 'unused_path_build_nodes'
    // to be the `snode_cache` minus nodes in any current paths
    if (in_progress_path_builds.empty()) {
        std::vector<quic::ipv4> existing_path_node_ips = all_path_ips();
        std::copy_if(
                snode_cache.begin(),
                snode_cache.end(),
                std::back_inserter(unused_path_build_nodes),
                [&existing_path_node_ips](const auto& node) {
                    return std::find(
                                   existing_path_node_ips.begin(),
                                   existing_path_node_ips.end(),
                                   node.to_ipv4()) == existing_path_node_ips.end();
                });

        // Shuffle the `unused_path_build_nodes` value so we build paths from random nodes
        std::shuffle(unused_path_build_nodes.begin(), unused_path_build_nodes.end(), rng);
        general_path_build_failures = 0;
    }

    // Make sure we have possible guard nodes before continuing
    if (unused_path_build_nodes.empty()) {
        log::warning(
                cat,
                "Unable to build {} path due to lack of possible guard nodes ({}).",
                path_name,
                request_id);
        general_path_build_failures++;
        path_build_queue.emplace_back(path_type);

        auto delay = retry_delay(general_path_build_failures);
        net.call_later(delay, [this]() { resume_queues(); });
        return;
    }

    // Add this build to the `in_progress_path_builds` map if it doesn't already exist
    in_progress_path_builds.try_emplace(request_id, path_type, 0);

    // Exclude nodes targeted in the request_queue from the path (so any queued requests will be
    // able to be sent once the path is built)
    std::vector<service_node> nodes_to_exclude;

    for (const auto& [info, callback] : request_queue[path_type])
        if (auto* dest = std::get_if<service_node>(&info.destination))
            nodes_to_exclude.emplace_back(*dest);

    // Get the possible guard nodes
    service_node target_node = unused_path_build_nodes.back();

    if (nodes_to_exclude.empty())
        unused_path_build_nodes.pop_back();
    else {
        auto it = std::find_if(
                unused_path_build_nodes.begin(),
                unused_path_build_nodes.end(),
                [&nodes_to_exclude](const service_node& node) {
                    return std::find(nodes_to_exclude.begin(), nodes_to_exclude.end(), node) ==
                           nodes_to_exclude.end();
                });

        if (it == unused_path_build_nodes.end()) {
            log::warning(
                    cat,
                    "Unable to build paths due to lack of possible guard nodes ({}).",
                    request_id);
            general_path_build_failures++;
            path_build_queue.emplace_back(path_type);
            in_progress_path_builds.erase(request_id);

            auto delay = retry_delay(general_path_build_failures);
            net.call_later(delay, [this]() { resume_queues(); });
            return;
        }

        target_node = *it;
        unused_path_build_nodes.erase(it);
    }

    // Make a request to the guard node to ensure it's reachable
    log::info(cat, "Testing guard snode: {} for {}", target_node.to_string(), request_id);

    get_snode_version(
            request_id,
            path_type,
            target_node,
            3s,
            [this, path_name, path_type, target_node, request_id](
                    std::vector<int> version,
                    connection_info info,
                    std::optional<std::string> error) {
                log::trace(cat, "Got snode version response for {}.", request_id);

                try {
                    if (version.empty())
                        throw std::runtime_error{"Testing {} for {} failed with error: {}"_format(
                                target_node.to_string(),
                                request_id,
                                error.value_or("Unknown Error"))};

                    // Build the new paths
                    log::info(
                            cat,
                            "Guard snode {} valid for {}.",
                            target_node.to_string(),
                            request_id);
                    std::vector<service_node> path_nodes{info.node};

                    while (path_nodes.size() < path_size) {
                        if (unused_path_build_nodes.empty())
                            throw std::runtime_error{
                                    "Unable to build {} path due to lack of unused path build nodes ({})."_format(
                                            path_name, request_id)};

                        // Grab the next unused node to continue building the path
                        auto node = unused_path_build_nodes.back();
                        unused_path_build_nodes.pop_back();

                        // Ensure we don't put two nodes with the same IP into the same path
                        auto snode_with_ip_it = std::find_if(
                                path_nodes.begin(),
                                path_nodes.end(),
                                [&node](const auto& existing_node) {
                                    return existing_node.to_ipv4() == node.to_ipv4();
                                });

                        if (snode_with_ip_it == path_nodes.end())
                            path_nodes.push_back(node);
                    }

                    // Store the new path
                    auto path = onion_path{std::move(info), path_nodes, 0};
                    paths[path_type].emplace_back(path);

                    // Log that a path was built
                    std::vector<std::string> node_descriptions;
                    std::transform(
                            path_nodes.begin(),
                            path_nodes.end(),
                            std::back_inserter(node_descriptions),
                            [](const service_node& node) { return node.to_string(); });
                    auto path_description = "{}"_format(fmt::join(node_descriptions, ", "));
                    log::info(
                            cat,
                            "Built new {} onion request path ({}): [{}]",
                            path_name,
                            request_id,
                            path_description);

                    // If the connection info is valid and it's a standard path then update the
                    // connection status to connected
                    if (path_type == PathType::standard) {
                        update_status(ConnectionStatus::connected);

                        // If a paths_changed callback was provided then call it
                        if (paths_changed) {
                            std::vector<std::vector<service_node>> raw_paths;
                            for (auto& path : paths[path_type])
                                raw_paths.emplace_back(path.nodes);

                            paths_changed(raw_paths);
                        }
                    }

                    // If the network happened to get suspended just before the guard node was
                    // connected then we may need to reset the connection info so the new path is
                    // also in a suspended state
                    if (suspended) {
                        log::info(
                                cat,
                                "Network is suspended, suspending new {} path ({})",
                                path_name,
                                request_id);
                        info.conn.reset();
                        info.stream.reset();
                    }

                    // Resume any queued requests
                    in_progress_path_builds.erase(request_id);
                    net.call_soon([this]() { resume_queues(); });
                } catch (const std::exception& e) {
                    // Log the error and loop after a slight delay (don't want to drain the pool
                    // too quickly if the network goes down)
                    log::info(cat, "{}", e.what());

                    // Delay the next path build attempt based on the error we received
                    auto failure_count = in_progress_path_builds[request_id].second;
                    in_progress_path_builds[request_id] = {path_type, failure_count + 1};
                    auto delay = retry_delay(failure_count + 1);
                    net.call_later(delay, [this, request_id, path_type]() {
                        build_path(request_id, path_type);
                    });
                }
            });
}

void Network::recover_path(PathType path_type, onion_path path) {
    // Try to re-establish a connection to the guard node
    auto request_id = random::random_base32(4);
    log::trace(
            cat,
            "Connection to {} for {} path no longer valid, attempting reconnection ({}).",
            path.nodes.front(),
            path_type_name(path_type, single_path_mode),
            request_id);

    establish_connection(
            request_id,
            path_type,
            path.nodes.front(),
            3s,
            [this, request_id, path_type, old_path = path](
                    connection_info info, std::optional<std::string> error) {
                auto guard_node = old_path.nodes.front();

                if (!info.is_valid()) {
                    log::info(
                            cat,
                            "Reconnection to {} for {} path failed ({}) with error: {}.",
                            guard_node,
                            path_type_name(path_type, single_path_mode),
                            request_id,
                            error.value_or("Unknown error"));

                    // If we failed to reconnect to the path, and it was a standard path, then we
                    // should call 'paths_changed' as it is has now been "officially" dropped
                    if (path_type == PathType::standard && paths_changed) {
                        std::vector<std::vector<service_node>> raw_paths;
                        for (auto& path : paths[path_type])
                            raw_paths.emplace_back(path.nodes);

                        paths_changed(raw_paths);
                    }

                    // Now enqueue a new path build (if needed) for the type of path we dropped and
                    // resume the queues to trigger the path build (if needed)
                    enqueue_path_build_if_needed(path_type, false);
                    net.call_soon([this]() { resume_queues(); });
                    return;
                }

                // Knowing that the reconnection succeeded is helpful for debugging
                log::info(
                        cat,
                        "Reconnection to {} for {} path successful ({}).",
                        guard_node,
                        path_type_name(path_type, single_path_mode),
                        request_id);

                // If the connection info is valid and it's a standard path then update the
                // connection status back to connected
                if (path_type == PathType::standard)
                    update_status(ConnectionStatus::connected);

                // No need to call the 'paths_changed' callback as the paths haven't
                // actually changed, just their connection info
                paths[path_type].emplace_back(onion_path{std::move(info), old_path.nodes, 0});

                // Resume any queued requests
                net.call_soon([this]() { resume_queues(); });
            });
}

std::optional<onion_path> Network::find_valid_path(
        request_info info, std::vector<onion_path> paths) {
    if (paths.empty())
        return std::nullopt;

    // Only include paths with valid connections as options
    std::vector<onion_path> possible_paths;
    std::copy_if(
            paths.begin(), paths.end(), std::back_inserter(possible_paths), [&](const auto& path) {
                return path.is_valid();
            });

    // If the request destination is a node then only select a path that doesn't include the IP of
    // the destination
    if (auto target = detail::node_for_destination(info.destination)) {
        std::vector<onion_path> ip_excluded_paths;
        std::copy_if(
                possible_paths.begin(),
                possible_paths.end(),
                std::back_inserter(ip_excluded_paths),
                [excluded_ip = target->to_ipv4()](const auto& path) {
                    return std::none_of(
                            path.nodes.begin(), path.nodes.end(), [&excluded_ip](const auto& node) {
                                return node.to_ipv4() == excluded_ip;
                            });
                });

        if (single_path_mode && ip_excluded_paths.empty())
            log::warning(
                    cat,
                    "Path should have been excluded due to matching IP for {} but network is in "
                    "single path mode.",
                    info.request_id);
        else
            possible_paths = ip_excluded_paths;
    }

    if (possible_paths.empty())
        return std::nullopt;

    CSRNG rng;
    std::shuffle(possible_paths.begin(), possible_paths.end(), rng);

    return possible_paths.front();
};

void Network::enqueue_path_build_if_needed(PathType path_type, bool existing_paths_unsuitable) {
    auto current_paths = paths[path_type].size();

    // In `single_path_mode` we never build additional paths
    if (current_paths > 0 && single_path_mode)
        return;

    // Get the number pending paths
    auto pending_build_count =
            std::count(path_build_queue.begin(), path_build_queue.end(), path_type);
    auto in_progress_build_count = std::count_if(
            in_progress_path_builds.begin(),
            in_progress_path_builds.end(),
            [&path_type](const auto& pair) { return pair.second.first == path_type; });
    auto pending_paths = (pending_build_count + in_progress_build_count);

    // We only want to enqueue a new path build if:
    // - We don't have the minimum number of paths for the specified type
    // - We don't have any pending builds
    // - The current paths are unsuitable for the request
    auto min_paths = min_path_count(path_type, single_path_mode);

    if ((current_paths + pending_paths) < min_paths ||
        (existing_paths_unsuitable && pending_paths == 0))
        path_build_queue.emplace_back(path_type);
}

// MARK: Multi-request logic

void Network::get_service_nodes_recursive(
        std::string request_id,
        std::vector<service_node> target_nodes,
        std::optional<int> limit,
        std::function<void(std::vector<service_node> nodes, std::optional<std::string> error)>
                callback) {
    if (target_nodes.empty())
        return callback({}, "No nodes to fetch from provided.");

    auto target_node = target_nodes.front();
    get_service_nodes(
            request_id,
            target_node,
            limit,
            [this, limit, target_nodes, request_id, cb = std::move(callback)](
                    std::vector<service_node> nodes, std::optional<std::string> error) {
                // If we got nodes then stop looping and return them
                if (!nodes.empty()) {
                    cb(nodes, error);
                    return;
                }

                // Loop if we didn't get any nodes
                std::vector<service_node> remaining_nodes(
                        target_nodes.begin() + 1, target_nodes.end());
                net.call_soon([this, request_id, remaining_nodes, limit, cb = std::move(cb)]() {
                    get_service_nodes_recursive(request_id, remaining_nodes, limit, cb);
                });
            });
}

// MARK: Pre-Defined Requests

void Network::get_service_nodes(
        std::string request_id,
        service_node node,
        std::optional<int> limit,
        std::function<void(std::vector<service_node> nodes, std::optional<std::string> error)>
                callback) {
    log::trace(cat, "{} called for {}.", __PRETTY_FUNCTION__, request_id);

    establish_connection(
            request_id,
            PathType::standard,
            node,
            3s,
            [this, request_id, limit, cb = std::move(callback)](
                    connection_info info, std::optional<std::string> error) {
                if (!info.is_valid())
                    return cb({}, error.value_or("Unknown error."));

                nlohmann::json params{
                        {"active_only", true},
                        {"fields",
                         {{"public_ip", true},
                          {"pubkey_ed25519", true},
                          {"storage_lmq_port", true},
                          {"storage_server_version", true}}}};

                if (limit)
                    params["limit"] = *limit;

                oxenc::bt_dict_producer payload;
                payload.append("endpoint", "get_service_nodes");
                payload.append("params", params.dump());

                info.stream->command(
                        "oxend_request",
                        payload.view(),
                        [this, request_id, cb = std::move(cb)](quic::message resp) {
                            log::trace(
                                    cat,
                                    "{} got response for {}.",
                                    __PRETTY_FUNCTION__,
                                    request_id);
                            std::vector<service_node> result;

                            try {
                                auto [status_code, body] = validate_response(resp, true);

                                oxenc::bt_list_consumer result_bencode{body};
                                result_bencode
                                        .skip_value();  // Skip the status code (already validated)
                                auto response_dict = result_bencode.consume_dict_consumer();
                                response_dict.skip_until("result");

                                auto result_dict = response_dict.consume_dict_consumer();
                                result_dict.skip_until("service_node_states");

                                // Process the node list
                                auto node = result_dict.consume_list_consumer();

                                while (!node.is_finished()) {
                                    auto node_consumer = node.consume_dict_consumer();
                                    auto pubkey_ed25519 = oxenc::from_hex(
                                            consume_string(node_consumer, "pubkey_ed25519"));
                                    auto public_ip = consume_string(node_consumer, "public_ip");
                                    auto storage_lmq_port = consume_integer<uint16_t>(
                                            node_consumer, "storage_lmq_port");

                                    std::vector<int> storage_server_version;
                                    node_consumer.skip_until("storage_server_version");
                                    auto version_consumer = node_consumer.consume_list_consumer();

                                    while (!version_consumer.is_finished()) {
                                        storage_server_version.emplace_back(
                                                version_consumer.consume_integer<int>());
                                    }

                                    result.emplace_back(
                                            pubkey_ed25519,
                                            storage_server_version,
                                            public_ip,
                                            storage_lmq_port);
                                }
                            } catch (const std::exception& e) {
                                return cb({}, e.what());
                            }

                            // Output the result
                            cb(result, std::nullopt);
                        });
            });
}

void Network::get_snode_version(
        std::string request_id,
        PathType path_type,
        service_node node,
        std::optional<std::chrono::milliseconds> timeout,
        std::function<void(
                std::vector<int> version, connection_info info, std::optional<std::string> error)>
                callback) {
    log::trace(cat, "{} called for {}.", __PRETTY_FUNCTION__, request_id);
    establish_connection(
            request_id,
            path_type,
            node,
            timeout,
            [this, request_id, timeout, cb = std::move(callback)](
                    connection_info info, std::optional<std::string> error) {
                if (!info.is_valid())
                    return cb({}, info, error.value_or("Unknown error."));

                oxenc::bt_dict_producer payload;
                info.stream->command(
                        "info",
                        payload.view(),
                        timeout,
                        [this, info, request_id, cb = std::move(cb)](quic::message resp) {
                            log::trace(
                                    cat,
                                    "{} got response for {}.",
                                    __PRETTY_FUNCTION__,
                                    request_id);
                            std::vector<int> version;

                            try {
                                auto [status_code, body] = validate_response(resp, true);

                                oxenc::bt_list_consumer result_bencode{body};
                                result_bencode
                                        .skip_value();  // Skip the status code (already validated)
                                auto response_dict = result_bencode.consume_dict_consumer();
                                response_dict.skip_until("version");
                                auto version_list = response_dict.consume_list_consumer();

                                while (!version_list.is_finished())
                                    version.emplace_back(version_list.consume_integer<int>());
                            } catch (const std::exception& e) {
                                return cb({}, info, e.what());
                            }

                            // Output the result
                            cb(version, info, std::nullopt);
                        });
            });
}

void Network::get_swarm(
        session::onionreq::x25519_pubkey swarm_pubkey,
        std::function<void(std::vector<service_node> swarm)> callback) {
    auto request_id = random::random_base32(4);
    log::trace(cat, "{} called for {} as {}.", __PRETTY_FUNCTION__, swarm_pubkey.hex(), request_id);

    net.call([this, request_id, swarm_pubkey, cb = std::move(callback)]() {
        // If we have a cached swarm, and it meets the minimum size requirements, then return it
        if (swarm_cache[swarm_pubkey.hex()].size() > min_swarm_snode_count)
            return cb(swarm_cache[swarm_pubkey.hex()]);

        // Pick a random node from the snode pool to fetch the swarm from
        log::info(
                cat,
                "Get swarm had no valid cached swarm for {}, fetching from random node ({}).",
                swarm_pubkey.hex(),
                request_id);

        // If we have no snode cache then we need to rebuild the cache and run this request again
        // once it's rebuild
        if (snode_cache.empty()) {
            after_snode_cache_refresh.emplace_back(
                    [this, swarm_pubkey, cb = std::move(cb)]() { get_swarm(swarm_pubkey, cb); });
            net.call_soon([this]() { refresh_snode_cache(); });
            return;
        }

        CSRNG rng;
        auto random_cache = snode_cache;
        std::shuffle(random_cache.begin(), random_cache.end(), rng);

        nlohmann::json params{{"pubkey", "05" + swarm_pubkey.hex()}};
        nlohmann::json payload{
                {"method", "get_swarm"},
                {"params", params},
        };
        auto info = request_info::make(
                random_cache.front(),
                quic::DEFAULT_TIMEOUT,
                ustring{quic::to_usv(payload.dump())},
                swarm_pubkey,
                PathType::standard,
                std::nullopt,
                request_id);

        _send_onion_request(
                info,
                [this, swarm_pubkey, request_id, cb = std::move(cb)](
                        bool success, bool timeout, int16_t, std::optional<std::string> response) {
                    log::trace(
                            cat,
                            "{} got response for {} as {}.",
                            __PRETTY_FUNCTION__,
                            swarm_pubkey.hex(),
                            request_id);
                    if (!success || timeout || !response)
                        return cb({});

                    std::vector<service_node> swarm;

                    try {
                        nlohmann::json response_json = nlohmann::json::parse(*response);

                        if (!response_json.contains("snodes") ||
                            !response_json["snodes"].is_array())
                            throw std::runtime_error{"JSON missing swarm field."};

                        for (auto& snode : response_json["snodes"])
                            swarm.emplace_back(node_from_json(snode));
                    } catch (...) {
                        return cb({});
                    }

                    // Update the cache
                    log::info(cat, "Retrieved swarm for {} ({}).", swarm_pubkey.hex(), request_id);
                    net.call([this, hex_key = swarm_pubkey.hex(), swarm]() mutable {
                        {
                            std::lock_guard lock{snode_cache_mutex};
                            swarm_cache[hex_key] = swarm;
                            need_swarm_write = true;
                            need_write = true;
                        }
                        snode_cache_cv.notify_one();
                    });

                    cb(swarm);
                });
    });
}

void Network::set_swarm(
        session::onionreq::x25519_pubkey swarm_pubkey, std::vector<service_node> swarm) {
    net.call([this, hex_key = swarm_pubkey.hex(), swarm]() mutable {
        {
            std::lock_guard lock{snode_cache_mutex};
            swarm_cache[hex_key] = swarm;
            need_swarm_write = true;
            need_write = true;
        }
        snode_cache_cv.notify_one();
    });
}

void Network::get_random_nodes(
        uint16_t count, std::function<void(std::vector<service_node> nodes)> callback) {
    auto request_id = random::random_base32(4);
    log::trace(cat, "{} called for {}.", __PRETTY_FUNCTION__, request_id);

    net.call([this, request_id, count, cb = std::move(callback)]() mutable {
        // If we don't have sufficient nodes in the snode cache then add this to
        if (snode_cache.size() < count) {
            after_snode_cache_refresh.emplace_back(
                    [this, count, cb = std::move(cb)]() { get_random_nodes(count, cb); });
            net.call_soon([this]() { refresh_snode_cache(); });
            return;
        }

        // Otherwise callback with the requested random number of nodes
        CSRNG rng;
        auto random_cache = snode_cache;
        std::shuffle(random_cache.begin(), random_cache.end(), rng);
        cb(std::vector<service_node>(random_cache.begin(), random_cache.begin() + count));
    });
}

// MARK: Request Handling

void Network::send_request(
        request_info info, connection_info conn_info, network_response_callback_t handle_response) {
    log::trace(cat, "{} called for {}.", __PRETTY_FUNCTION__, info.request_id);

    if (!conn_info.is_valid())
        return handle_response(false, false, -1, "Network is unreachable.");

    quic::bstring_view payload{};

    if (info.body)
        payload = convert_sv<std::byte>(*info.body);

    conn_info.stream->command(
            info.endpoint,
            payload,
            info.timeout,
            [this, info, conn_info, cb = std::move(handle_response)](quic::message resp) {
                log::trace(cat, "{} got response for {}.", __PRETTY_FUNCTION__, info.request_id);

                try {
                    auto [status_code, body] = validate_response(resp, false);
                    cb(true, false, status_code, body);
                } catch (const status_code_exception& e) {
                    handle_errors(info, conn_info, false, e.status_code, e.what(), cb);
                } catch (const std::exception& e) {
                    handle_errors(info, conn_info, resp.timed_out, -1, e.what(), cb);
                }
            });
}

void Network::send_onion_request(
        onionreq::network_destination destination,
        std::optional<ustring> body,
        std::optional<session::onionreq::x25519_pubkey> swarm_pubkey,
        std::chrono::milliseconds timeout,
        network_response_callback_t handle_response,
        PathType type) {
    _send_onion_request(
            request_info::make(
                    std::move(destination),
                    timeout,
                    std::move(body),
                    std::move(swarm_pubkey),
                    type),
            std::move(handle_response));
}

void Network::_send_onion_request(request_info info, network_response_callback_t handle_response) {
    auto path_name = path_type_name(info.path_type, single_path_mode);
    log::trace(cat, "{} called for {} path ({}).", __PRETTY_FUNCTION__, path_name, info.request_id);

    // Try to retrieve a valid path for this request
    auto [path, callback] = net.call_get(
            [this, info, cb = std::move(handle_response)]() mutable
            -> std::pair<std::optional<onion_path>, std::optional<network_response_callback_t>> {
                // If the network is suspended then fail immediately
                if (suspended) {
                    cb(false, false, error_network_suspended, "Network is suspended.");
                    return {std::nullopt, std::nullopt};
                }

                // Otherwise try to retrieve a valid path
                if (auto path = find_valid_path(info, paths[info.path_type]))
                    return {path, std::move(cb)};

                // Currently there are no valid paths so enqueue a new build (if needed) and add the
                // request to the queue to be run one the path build completes
                request_queue[info.path_type].emplace_back(std::move(info), std::move(cb));
                enqueue_path_build_if_needed(info.path_type, true);
                net.call_soon([this]() { resume_queues(); });
                return {std::nullopt, std::nullopt};
            });

    // If either of these don't exist then we will have added this request to the queue to be run
    // one we have a valid path
    if (!path || !callback)
        return;

    log::trace(cat, "{} got {} path for {}.", __PRETTY_FUNCTION__, path_name, info.request_id);

    // Construct the onion request
    auto builder = Builder();
    try {
        builder.set_destination(info.destination);
        builder.set_destination_pubkey(detail::pubkey_for_destination(info.destination));

        for (auto& node : path->nodes)
            builder.add_hop(
                    {ed25519_pubkey::from_bytes(node.view_remote_key()),
                     compute_xpk(node.view_remote_key())});

        // Update the `request_info` to have the onion request payload
        auto payload = builder.generate_payload(info.original_body);
        info.body = builder.build(payload);
    } catch (const std::exception& e) {
        return (*callback)(false, false, error_building_onion_request, e.what());
    }

    // Actually send the request
    send_request(
            info,
            path->conn_info,
            [this, builder = std::move(builder), info, path = *path, cb = std::move(*callback)](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::optional<std::string> response) {
                log::trace(cat, "{} got response for {}.", __PRETTY_FUNCTION__, info.request_id);

                // If the request was reported as a failure or a timeout then we
                // will have already handled the errors so just trigger the callback
                if (!success || timeout)
                    return cb(success, timeout, status_code, response);

                try {
                    // Ensure the response is long enough to be processed, if not
                    // then handle it as an error
                    if (!ResponseParser::response_long_enough(builder.enc_type, response->size()))
                        throw status_code_exception{
                                status_code,
                                "Response is too short to be an onion request response: " +
                                        *response};

                    // Otherwise, process the onion request response
                    std::pair<int16_t, std::optional<std::string>> processed_response;

                    // The SnodeDestination runs via V3 onion requests and the
                    // ServerDestination runs via V4
                    if (std::holds_alternative<service_node>(info.destination))
                        processed_response = process_v3_onion_response(builder, *response);
                    else if (std::holds_alternative<ServerDestination>(info.destination))
                        processed_response = process_v4_onion_response(builder, *response);

                    // If we got a non 2xx status code, return the error
                    auto& [processed_status_code, processed_body] = processed_response;
                    if (processed_status_code < 200 || processed_status_code > 299)
                        throw status_code_exception{
                                processed_status_code,
                                processed_body.value_or("Request returned "
                                                        "non-success status "
                                                        "code.")};

                    // For debugging purposes if the error was a redirect retry then
                    // we want to log that the retry was successful as this will
                    // help identify how often we are receiving incorrect 421 errors
                    if (info.retry_reason == request_info::RetryReason::redirect)
                        log::info(
                                cat,
                                "Received valid response after 421 retry in "
                                "request {} for {}.",
                                info.request_id,
                                path_type_name(info.path_type, single_path_mode));

                    // Try process the body in case it was a batch request which
                    // failed
                    std::optional<nlohmann::json> results;
                    if (processed_body) {
                        try {
                            auto processed_body_json = nlohmann::json::parse(*processed_body);

                            // If it wasn't a batch/sequence request then assume it
                            // was successful and return no error
                            if (processed_body_json.contains("results"))
                                results = processed_body_json["results"];
                        } catch (...) {
                        }
                    }

                    // If there was no 'results' array then it wasn't a batch
                    // request so we can stop here and return
                    if (!results)
                        return cb(true, false, processed_status_code, processed_body);

                    // Otherwise we want to check if all of the results have the
                    // same status code and, if so, handle that failure case
                    // (default the 'error_body' to the 'processed_body' in case we
                    // don't get an explicit error)
                    int16_t single_status_code = -1;
                    std::optional<std::string> error_body = processed_body;
                    for (const auto& result : results->items()) {
                        if (result.value().contains("code") && result.value()["code"].is_number() &&
                            (single_status_code == -1 ||
                             result.value()["code"].get<int16_t>() != single_status_code))
                            single_status_code = result.value()["code"].get<int16_t>();
                        else {
                            // Either there was no code, or the code was different
                            // from a former code in which case there wasn't an
                            // individual detectable error (ie. it needs specific
                            // handling) so return no error
                            single_status_code = 200;
                            break;
                        }

                        if (result.value().contains("body") && result.value()["body"].is_string())
                            error_body = result.value()["body"].get<std::string>();
                    }

                    // If all results contained the same error then handle it as a
                    // single error
                    if (single_status_code < 200 || single_status_code > 299)
                        throw status_code_exception{
                                single_status_code,
                                error_body.value_or("Sub-request returned "
                                                    "non-success status code.")};

                    // Otherwise some requests succeeded and others failed so
                    // succeed with the processed data
                    return cb(true, false, processed_status_code, processed_body);
                } catch (const status_code_exception& e) {
                    handle_errors(info, path.conn_info, false, e.status_code, e.what(), cb);
                } catch (const std::exception& e) {
                    handle_errors(info, path.conn_info, false, -1, e.what(), cb);
                }
            });
}

void Network::upload_file_to_server(
        ustring data,
        onionreq::ServerDestination server,
        std::optional<std::string> file_name,
        std::chrono::milliseconds timeout,
        network_response_callback_t handle_response) {
    std::vector<std::pair<std::string, std::string>> headers;
    std::unordered_set<std::string> existing_keys;

    if (server.headers)
        for (auto& [key, value] : *server.headers) {
            headers.emplace_back(key, value);
            existing_keys.insert(key);
        }

    // Add the required headers if they weren't provided
    if (existing_keys.find("Content-Disposition") == existing_keys.end())
        headers.emplace_back(
                "Content-Disposition",
                (file_name ? "attachment; filename=\"{}\""_format(*file_name) : "attachment"));

    if (existing_keys.find("Content-Type") == existing_keys.end())
        headers.emplace_back("Content-Type", "application/octet-stream");

    send_onion_request(
            ServerDestination{
                    server.protocol,
                    server.host,
                    server.endpoint,
                    server.x25519_pubkey,
                    server.port,
                    headers,
                    server.method},
            data,
            std::nullopt,
            timeout,
            handle_response,
            PathType::upload);
}

void Network::download_file(
        std::string_view download_url,
        session::onionreq::x25519_pubkey x25519_pubkey,
        std::chrono::milliseconds timeout,
        network_response_callback_t handle_response) {
    const auto& [proto, host, port, path] = parse_url(download_url);

    if (!path)
        throw std::invalid_argument{"Invalid URL provided: Missing path"};

    download_file(
            ServerDestination{proto, host, *path, x25519_pubkey, port, std::nullopt, "GET"},
            timeout,
            handle_response);
}

void Network::download_file(
        onionreq::ServerDestination server,
        std::chrono::milliseconds timeout,
        network_response_callback_t handle_response) {
    send_onion_request(
            server, std::nullopt, std::nullopt, timeout, handle_response, PathType::download);
}

void Network::get_client_version(
        Platform platform,
        onionreq::ed25519_seckey seckey,
        std::chrono::milliseconds timeout,
        network_response_callback_t handle_response) {
    std::string endpoint;

    switch (platform) {
        case Platform::android: endpoint = "/session_version?platform=android"; break;
        case Platform::desktop: endpoint = "/session_version?platform=desktop"; break;
        case Platform::ios: endpoint = "/session_version?platform=ios"; break;
    }

    // Generate the auth signature
    auto blinded_keys = blind_version_key_pair(to_unsigned_sv(seckey.view()));
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                             (std::chrono::system_clock::now()).time_since_epoch())
                             .count();
    auto signature = blind_version_sign(to_unsigned_sv(seckey.view()), platform, timestamp);
    auto pubkey = x25519_pubkey::from_hex(file_server_pubkey);
    std::string blinded_pk_hex;
    blinded_pk_hex.reserve(66);
    blinded_pk_hex += "07";
    oxenc::to_hex(
            blinded_keys.first.begin(),
            blinded_keys.first.end(),
            std::back_inserter(blinded_pk_hex));

    auto headers = std::vector<std::pair<std::string, std::string>>{};
    headers.emplace_back("X-FS-Pubkey", blinded_pk_hex);
    headers.emplace_back("X-FS-Timestamp", "{}"_format(timestamp));
    headers.emplace_back("X-FS-Signature", oxenc::to_base64(signature));

    send_onion_request(
            ServerDestination{
                    "http", std::string(file_server), endpoint, pubkey, 80, headers, "GET"},
            std::nullopt,
            pubkey,
            timeout,
            handle_response,
            PathType::standard);
}

// MARK: Response Handling

std::pair<int16_t, std::optional<std::string>> Network::process_v3_onion_response(
        Builder builder, std::string response) {
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

    return {status_code, body};
}

std::pair<int16_t, std::optional<std::string>> Network::process_v4_onion_response(
        Builder builder, std::string response) {
    ustring response_data{to_unsigned(response.data()), response.size()};
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
        throw std::runtime_error{"Invalid JSON response, missing required code field."};

    if (result_bencode.is_finished())
        return {status_code, std::nullopt};

    return {status_code, result_bencode.consume_string()};
}

// MARK: Error Handling

std::pair<uint16_t, std::string> Network::validate_response(quic::message resp, bool is_bencoded) {
    std::string body = resp.body_str();

    if (resp.timed_out)
        throw std::runtime_error{"Timed out"};
    if (resp.is_error())
        throw std::runtime_error{body.empty() ? "Unknown error" : body};

    if (is_bencoded) {
        // Process the bencoded response
        oxenc::bt_list_consumer result_bencode{body};

        if (result_bencode.is_finished() || !result_bencode.is_integer())
            throw std::runtime_error{"Invalid bencoded response"};

        // If we have a status code that is not in the 2xx range, return the error
        auto status_code = result_bencode.consume_integer<int16_t>();

        if (status_code < 200 || status_code > 299) {
            if (result_bencode.is_finished() || !result_bencode.is_string())
                throw status_code_exception{
                        status_code,
                        "Request failed with status code: " + std::to_string(status_code)};

            throw status_code_exception{status_code, result_bencode.consume_string()};
        }

        // Can't convert the data to a string so just return the response body itself
        return {status_code, body};
    }

    // Default to a 200 success if the response is empty but didn't timeout or error
    int16_t status_code = 200;
    std::string response_string;

    try {
        nlohmann::json response_json = nlohmann::json::parse(body);

        if (response_json.is_array() && response_json.size() == 2) {
            status_code = response_json[0].get<int16_t>();
            response_string = response_json[1].dump();
        } else
            response_string = body;
    } catch (...) {
        response_string = body;
    }

    if (status_code < 200 || status_code > 299)
        throw status_code_exception{status_code, response_string};

    return {status_code, response_string};
}

void Network::handle_node_error(
        service_node node, PathType path_type, connection_info conn_info, std::string request_id) {
    handle_errors(
            request_info::make(
                    std::move(node), 0ms, std::nullopt, std::nullopt, path_type, request_id, ""),
            conn_info,
            false,
            std::nullopt,
            "Node Error",
            std::nullopt);
}

void Network::handle_errors(
        request_info info,
        connection_info conn_info,
        bool timeout_,
        std::optional<int16_t> status_code_,
        std::optional<std::string> response,
        std::optional<network_response_callback_t> handle_response) {
    bool timeout = timeout_;
    auto status_code = status_code_.value_or(-1);
    auto path_name = path_type_name(info.path_type, single_path_mode);

    // There is an issue which can occur where we get invalid data back and are unable to decrypt
    // it, if we do see this behaviour then we want to retry the request on the off chance it
    // resolves itself
    //
    // When testing this case the retry always resulted in a 421 error, if that occurs we want to go
    // through the standard 421 behaviour (which, in this case, would involve a 3rd retry against
    // another node in the swarm to confirm the redirect)
    if (!info.retry_reason && response && *response == session::onionreq::decryption_failed_error) {
        log::info(
                cat,
                "Received decryption failure in request {} on {} path, retrying.",
                info.request_id,
                path_name);
        auto updated_info = info;
        updated_info.retry_reason = request_info::RetryReason::decryption_failure;
        request_queue[updated_info.path_type].emplace_back(
                updated_info, std::move(*handle_response));
        net.call_soon([this]() { resume_queues(); });
        return;
    }

    // A number of server errors can return HTML data but no status code, we want to extract those
    // cases so they can be handled properly below
    if (status_code == -1 && response) {
        const std::unordered_map<std::string, std::pair<int16_t, bool>> response_map = {
                {"400 Bad Request", {400, false}},
                {"500 Internal Server Error", {500, false}},
                {"502 Bad Gateway", {502, false}},
                {"503 Service Unavailable", {503, false}},
                {"504 Gateway Timeout", {504, true}},
        };

        for (const auto& [prefix, result] : response_map) {
            if (response->starts_with(prefix)) {
                status_code = result.first;
                timeout = (timeout || result.second);
            }
        }
    }

    // In trace mode log all error info
    log::trace(
            cat,
            "Received network error in request {} on {} path, status_code: {}, timeout: {}, "
            "response: {}",
            info.request_id,
            path_name,
            status_code,
            timeout,
            response.value_or("(No Response)"));

    // A timeout could be caused because the destination is unreachable rather than the the path
    // (eg. if a user has an old SOGS which is no longer running on their device they will get a
    // timeout) so if we timed out while sending a proxied request we assume something is wrong on
    // the server side and don't update the path/snode state
    if (!info.node_destination && timeout) {
        if (handle_response)
            return (*handle_response)(false, true, status_code, response);
        return;
    }

    switch (status_code) {
        // A 404 or a 400 is likely due to a bad/missing SOGS or file so
        // shouldn't mark a path or snode as invalid
        case 400:
        case 404:
            if (handle_response)
                return (*handle_response)(false, false, status_code, response);
            return;

        // The user's clock is out of sync with the service node network (a
        // snode will return 406, but V4 onion requests returns a 425)
        case 406:
        case 425:
            if (handle_response)
                return (*handle_response)(false, false, status_code, response);
            return;

        // The snode is reporting that it isn't associated with the given public key anymore. If
        // this is the first 421 then we want to try another node in the swarm (just in case it
        // was reported incorrectly). If this is the second occurrence of the 421 then the
        // client needs to update the swarm (if the response contains updated swarm data), or
        // increment the path failure count.
        case 421:
            try {
                // If there is no response handler or no swarm information was provided then we
                // should just replace the swarm
                auto target = detail::node_for_destination(info.destination);

                if (!handle_response || !info.swarm_pubkey || !target)
                    throw std::invalid_argument{"Unable to handle redirect."};

                // If this was the first 421 then we want to retry using another node in the
                // swarm to get confirmation that we should switch to a different swarm
                if (!info.retry_reason ||
                    info.retry_reason != request_info::RetryReason::redirect) {
                    auto cached_swarm = swarm_cache[info.swarm_pubkey->hex()];

                    if (cached_swarm.empty())
                        throw std::invalid_argument{
                                "Unable to handle redirect due to lack of swarm."};

                    CSRNG rng;
                    std::vector<session::network::service_node> swarm_copy = cached_swarm;
                    std::shuffle(swarm_copy.begin(), swarm_copy.end(), rng);

                    std::optional<session::network::service_node> random_node;

                    for (auto& node : swarm_copy) {
                        if (node == *target)
                            continue;

                        random_node = node;
                        break;
                    }

                    if (!random_node)
                        throw std::invalid_argument{"No other nodes in the swarm."};

                    log::info(
                            cat,
                            "Received 421 error in request {} on {} path, retrying once before "
                            "updating swarm.",
                            info.request_id,
                            path_name);
                    auto updated_info = info;
                    updated_info.destination = *random_node;
                    updated_info.retry_reason = request_info::RetryReason::redirect;
                    request_queue[updated_info.path_type].emplace_back(
                            updated_info, std::move(*handle_response));
                    net.call_soon([this]() { resume_queues(); });
                    return;
                }

                if (!response)
                    throw std::invalid_argument{"No response data."};

                auto response_json = nlohmann::json::parse(*response);
                auto snodes = response_json["snodes"];

                if (!snodes.is_array())
                    throw std::invalid_argument{"Invalid JSON response."};

                std::vector<session::network::service_node> swarm;

                for (auto snode : snodes)
                    swarm.emplace_back(node_from_json(snode));

                if (swarm.empty())
                    throw std::invalid_argument{"No snodes in the response."};

                log::info(
                        cat,
                        "Retry for request {} resulted in another 421 on {} path, updating swarm.",
                        info.request_id,
                        path_name);

                // Update the cache
                {
                    std::lock_guard lock{snode_cache_mutex};
                    swarm_cache[info.swarm_pubkey->hex()] = swarm;
                    need_swarm_write = true;
                    need_write = true;
                }
                snode_cache_cv.notify_one();
                return (*handle_response)(false, false, status_code, response);
            } catch (...) {
            }

            // If we weren't able to retry or redirect the swarm then handle this like any other
            // error
            break;

        case 500:
        case 504:
            // If we are making a proxied request to a server then assume 500 errors are occurring
            // on the server rather than in the service node network and don't update the path/snode
            // state
            if (!info.node_destination) {
                if (handle_response)
                    return (*handle_response)(false, timeout, status_code, response);
                return;
            }
            break;

        default: break;
    }

    // Retrieve the path for the connection_info (no paths share the same guard node so we can use
    // that to find it)
    auto path_it = std::find_if(
            paths[info.path_type].begin(),
            paths[info.path_type].end(),
            [guard_node = conn_info.node](const auto& path) {
                return !path.nodes.empty() && path.nodes.front() == guard_node;
            });

    // If the path was already dropped then the snode pool would have already been
    // updated so just log the failure and call the callback
    if (path_it == paths[info.path_type].end()) {
        log::info(
                cat, "Request {} failed but {} path already dropped.", info.request_id, path_name);

        if (handle_response)
            (*handle_response)(false, false, status_code, response);
        return;
    }

    // Update the failure counts and paths
    auto updated_path = *path_it;
    auto updated_failure_counts = snode_failure_counts;
    bool found_invalid_node = false;
    std::vector<service_node> nodes_to_drop;

    if (response) {
        std::optional<std::string_view> ed25519PublicKey;

        // Check if the response has one of the 'node_not_found' prefixes
        if (response->starts_with(node_not_found_prefix))
            ed25519PublicKey = {response->data() + node_not_found_prefix.size()};
        else if (response->starts_with(node_not_found_prefix_no_status))
            ed25519PublicKey = {response->data() + node_not_found_prefix_no_status.size()};

        // If we found a result then try to extract the pubkey and process it
        if (ed25519PublicKey && ed25519PublicKey->size() == 64 &&
            oxenc::is_hex(*ed25519PublicKey)) {
            session::onionreq::ed25519_pubkey edpk =
                    session::onionreq::ed25519_pubkey::from_hex(*ed25519PublicKey);
            auto edpk_view = to_unsigned_sv(edpk.view());

            auto snode_it = std::find_if(
                    updated_path.nodes.begin(),
                    updated_path.nodes.end(),
                    [&edpk_view](const auto& node) { return node.view_remote_key() == edpk_view; });

            // If we found an invalid node then store it to increment the failure count
            if (snode_it != updated_path.nodes.end()) {
                found_invalid_node = true;

                auto failure_count = updated_failure_counts[snode_it->to_string()];
                updated_failure_counts[snode_it->to_string()] = failure_count + 1;

                // If the specific node has failed too many times then we should try to repair
                // the existing path by replace the bad node with another one
                if (failure_count + 1 >= snode_failure_threshold) {
                    nodes_to_drop.emplace_back(*snode_it);

                    try {
                        // If the node that's gone bad is the guard node then we just have to
                        // drop the path
                        if (snode_it == updated_path.nodes.begin())
                            throw std::runtime_error{"Cannot recover if guard node is bad"};

                        // Try to find an unused node to patch the path
                        std::vector<service_node> unused_snodes;
                        std::vector<quic::ipv4> existing_path_node_ips = all_path_ips();

                        std::copy_if(
                                snode_cache.begin(),
                                snode_cache.end(),
                                std::back_inserter(unused_snodes),
                                [&existing_path_node_ips](const auto& node) {
                                    return std::find(
                                                   existing_path_node_ips.begin(),
                                                   existing_path_node_ips.end(),
                                                   node.to_ipv4()) == existing_path_node_ips.end();
                                });

                        if (unused_snodes.empty())
                            throw std::runtime_error{"No remaining nodes"};

                        CSRNG rng;
                        std::shuffle(unused_snodes.begin(), unused_snodes.end(), rng);

                        std::replace(
                                updated_path.nodes.begin(),
                                updated_path.nodes.end(),
                                *snode_it,
                                unused_snodes.front());
                        log::info(cat, "Found bad node in {} path, replacing node.", path_name);
                    } catch (...) {
                        // There aren't enough unused nodes remaining so we need to drop the
                        // path
                        updated_path.failure_count = path_failure_threshold;
                        log::info(cat, "Unable to replace bad node in {} path.", path_name);
                    }
                }
            }
        }
    }

    // If we didn't find the specific node or the paths connection was closed then increment the
    // path failure count
    if (!found_invalid_node || !updated_path.conn_info.is_valid()) {
        updated_path.failure_count += 1;

        // If the path has failed too many times we want to drop the guard snode (marking it as
        // invalid) and increment the failure count of each node in the path)
        if (updated_path.failure_count >= path_failure_threshold) {
            for (auto& it : updated_path.nodes) {
                auto failure_count = updated_failure_counts[it.to_string()];
                updated_failure_counts[it.to_string()] = failure_count + 1;

                if (failure_count + 1 >= snode_failure_threshold)
                    nodes_to_drop.emplace_back(it);
            }

            // Set the failure count of the guard node to match the threshold so we drop it
            updated_failure_counts[updated_path.nodes[0].to_string()] = snode_failure_threshold;
            nodes_to_drop.emplace_back(updated_path.nodes[0]);
        } else if (updated_path.nodes.size() < path_size) {
            // If the path doesn't have enough nodes then it's likely that this failure was
            // triggered when trying to establish a new path and, as such, we should increase
            // the failure count of the guard node since it is probably invalid
            auto failure_count = updated_failure_counts[updated_path.nodes[0].to_string()];
            updated_failure_counts[updated_path.nodes[0].to_string()] = failure_count + 1;

            if (failure_count + 1 >= snode_failure_threshold)
                nodes_to_drop.emplace_back(updated_path.nodes[0]);
        }
    }

    // Remove any nodes from 'nodes_to_drop' which don't actually need to be dropped
    auto updated_swarm_cache = swarm_cache;
    bool requires_swarm_cache_update = false;

    if (!nodes_to_drop.empty()) {
        for (auto& [key, nodes] : updated_swarm_cache) {
            for (const auto& drop_node : nodes_to_drop) {
                auto it = std::remove(nodes.begin(), nodes.end(), drop_node);
                if (it != nodes.end()) {
                    nodes.erase(it, nodes.end());
                    requires_swarm_cache_update = true;
                }
            }
        }
    }

    // No need to track the failure counts of nodes which have been dropped, or haven't failed
    std::erase_if(updated_failure_counts, [](const auto& item) {
        return item.second == 0 || item.second >= snode_failure_threshold;
    });

    // Drop the path if invalid
    if (updated_path.failure_count >= path_failure_threshold) {
        // Close the connection immediately (just in case there are other requests happening)
        if (path_it->conn_info.conn)
            path_it->conn_info.conn->close_connection();

        auto path_nodes = path_it->nodes;
        path_it->conn_info.conn.reset();
        path_it->conn_info.stream.reset();
        paths[info.path_type].erase(path_it);

        std::vector<std::string> node_descriptions;
        std::transform(
                path_nodes.begin(),
                path_nodes.end(),
                std::back_inserter(node_descriptions),
                [](service_node& node) { return node.to_string(); });
        auto path_description = "{}"_format(fmt::join(node_descriptions, ", "));
        log::info(cat, "Dropping {} path ({}): [{}]", path_name, info.request_id, path_description);
    } else
        std::replace(
                paths[info.path_type].begin(), paths[info.path_type].end(), *path_it, updated_path);

    // Update the network status if we've removed all standard paths
    if (paths[PathType::standard].empty())
        update_status(ConnectionStatus::disconnected);

    // Update the snode cache
    {
        std::lock_guard lock{snode_cache_mutex};

        // Update the snode failure counts
        snode_failure_counts = updated_failure_counts;
        need_failure_counts_write = true;
        need_swarm_write = requires_swarm_cache_update;

        if (requires_swarm_cache_update)
            swarm_cache = updated_swarm_cache;

        for (const auto& node : nodes_to_drop) {
            snode_cache.erase(
                    std::remove(snode_cache.begin(), snode_cache.end(), node), snode_cache.end());
            need_pool_write = true;
        }

        need_write = true;
    }
    snode_cache_cv.notify_one();

    if (handle_response)
        (*handle_response)(false, false, status_code, response);
}

std::vector<network_service_node> convert_service_nodes(
        std::vector<session::network::service_node> nodes) {
    std::vector<network_service_node> converted_nodes;
    for (auto& node : nodes) {
        auto ed25519_pubkey_hex = oxenc::to_hex(node.view_remote_key());
        auto ipv4 = node.to_ipv4();
        network_service_node converted_node;
        converted_node.ip[0] = (ipv4.addr >> 24) & 0xFF;
        converted_node.ip[1] = (ipv4.addr >> 16) & 0xFF;
        converted_node.ip[2] = (ipv4.addr >> 8) & 0xFF;
        converted_node.ip[3] = ipv4.addr & 0xFF;
        strncpy(converted_node.ed25519_pubkey_hex, ed25519_pubkey_hex.c_str(), 64);
        converted_node.ed25519_pubkey_hex[64] = '\0';  // Ensure null termination
        converted_node.quic_port = node.port();
        converted_nodes.push_back(converted_node);
    }

    return converted_nodes;
}

ServerDestination convert_server_destination(const network_server_destination server) {
    std::optional<std::vector<std::pair<std::string, std::string>>> headers;
    if (server.headers_size > 0) {
        headers = std::vector<std::pair<std::string, std::string>>{};

        for (size_t i = 0; i < server.headers_size; i++)
            headers->emplace_back(server.headers[i], server.header_values[i]);
    }

    return ServerDestination{
            server.protocol,
            server.host,
            server.endpoint,
            x25519_pubkey::from_hex({server.x25519_pubkey, 64}),
            server.port,
            headers,
            server.method};
}

}  // namespace session::network

// MARK: C API

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

using namespace session;
using namespace session::network;

LIBSESSION_C_API bool network_init(
        network_object** network,
        const char* cache_path_,
        bool use_testnet,
        bool single_path_mode,
        bool pre_build_paths,
        char* error) {
    try {
        std::optional<std::string> cache_path;
        if (cache_path_)
            cache_path = cache_path_;

        auto n = std::make_unique<session::network::Network>(
                cache_path, use_testnet, single_path_mode, pre_build_paths);
        auto n_object = std::make_unique<network_object>();

        n_object->internals = n.release();
        *network = n_object.release();
        return true;
    } catch (const std::exception& e) {
        return set_error(error, e);
    }
}

LIBSESSION_C_API void network_free(network_object* network) {
    delete static_cast<session::network::Network*>(network->internals);
    delete network;
}

LIBSESSION_C_API void network_suspend(network_object* network) {
    unbox(network).suspend();
}

LIBSESSION_C_API void network_resume(network_object* network) {
    unbox(network).resume();
}

LIBSESSION_C_API void network_close_connections(network_object* network) {
    unbox(network).close_connections();
}

LIBSESSION_C_API void network_clear_cache(network_object* network) {
    unbox(network).clear_cache();
}

LIBSESSION_C_API void network_set_status_changed_callback(
        network_object* network, void (*callback)(CONNECTION_STATUS status, void* ctx), void* ctx) {
    if (!callback)
        unbox(network).status_changed = nullptr;
    else
        unbox(network).status_changed = [cb = std::move(callback), ctx](ConnectionStatus status) {
            cb(static_cast<CONNECTION_STATUS>(status), ctx);
        };
}

LIBSESSION_C_API void network_set_paths_changed_callback(
        network_object* network,
        void (*callback)(onion_request_path* paths, size_t paths_len, void* ctx),
        void* ctx) {
    if (!callback)
        unbox(network).paths_changed = nullptr;
    else
        unbox(network).paths_changed = [cb = std::move(callback),
                                        ctx](std::vector<std::vector<service_node>> paths) {
            size_t paths_mem_size = 0;
            for (auto& nodes : paths)
                paths_mem_size +=
                        sizeof(onion_request_path) + (sizeof(network_service_node) * nodes.size());

            // Allocate the memory for the onion_request_paths* array
            auto* c_paths_array = static_cast<onion_request_path*>(std::malloc(paths_mem_size));
            for (size_t i = 0; i < paths.size(); ++i) {
                auto c_nodes = session::network::convert_service_nodes(paths[i]);

                // Allocate memory that persists outside the loop
                size_t node_array_size = sizeof(network_service_node) * c_nodes.size();
                auto* c_nodes_array =
                        static_cast<network_service_node*>(std::malloc(node_array_size));
                std::copy(c_nodes.begin(), c_nodes.end(), c_nodes_array);
                new (c_paths_array + i) onion_request_path{c_nodes_array, c_nodes.size()};
            }

            cb(c_paths_array, paths.size(), ctx);
        };
}

LIBSESSION_C_API void network_get_swarm(
        network_object* network,
        const char* swarm_pubkey_hex,
        void (*callback)(network_service_node* nodes, size_t nodes_len, void*),
        void* ctx) {
    assert(swarm_pubkey_hex && callback);
    unbox(network).get_swarm(
            x25519_pubkey::from_hex({swarm_pubkey_hex, 64}),
            [cb = std::move(callback), ctx](std::vector<service_node> nodes) {
                auto c_nodes = session::network::convert_service_nodes(nodes);
                cb(c_nodes.data(), c_nodes.size(), ctx);
            });
}

LIBSESSION_C_API void network_get_random_nodes(
        network_object* network,
        uint16_t count,
        void (*callback)(network_service_node*, size_t, void*),
        void* ctx) {
    assert(callback);
    unbox(network).get_random_nodes(
            count, [cb = std::move(callback), ctx](std::vector<service_node> nodes) {
                auto c_nodes = session::network::convert_service_nodes(nodes);
                cb(c_nodes.data(), c_nodes.size(), ctx);
            });
}

LIBSESSION_C_API void network_send_onion_request_to_snode_destination(
        network_object* network,
        const network_service_node node,
        const unsigned char* body_,
        size_t body_size,
        const char* swarm_pubkey_hex,
        int64_t timeout_ms,
        network_onion_response_callback_t callback,
        void* ctx) {
    assert(callback);

    try {
        std::optional<ustring> body;
        if (body_size > 0)
            body = {body_, body_size};

        std::optional<x25519_pubkey> swarm_pubkey;
        if (swarm_pubkey_hex)
            swarm_pubkey = x25519_pubkey::from_hex({swarm_pubkey_hex, 64});

        std::array<uint8_t, 4> ip;
        std::memcpy(ip.data(), node.ip, ip.size());

        unbox(network).send_onion_request(
                service_node{
                        oxenc::from_hex({node.ed25519_pubkey_hex, 64}),
                        {0},  // For a destination node we don't care about the version
                        "{}"_format(fmt::join(ip, ".")),
                        node.quic_port},
                body,
                swarm_pubkey,
                std::chrono::milliseconds{timeout_ms},
                [cb = std::move(callback), ctx](
                        bool success,
                        bool timeout,
                        int status_code,
                        std::optional<std::string> response) {
                    if (response)
                        cb(success,
                           timeout,
                           status_code,
                           (*response).c_str(),
                           (*response).size(),
                           ctx);
                    else
                        cb(success, timeout, status_code, nullptr, 0, ctx);
                });
    } catch (const std::exception& e) {
        callback(false, false, -1, e.what(), std::strlen(e.what()), ctx);
    }
}

LIBSESSION_C_API void network_send_onion_request_to_server_destination(
        network_object* network,
        const network_server_destination server,
        const unsigned char* body_,
        size_t body_size,
        int64_t timeout_ms,
        network_onion_response_callback_t callback,
        void* ctx) {
    assert(server.method && server.protocol && server.host && server.endpoint &&
           server.x25519_pubkey && callback);

    try {
        std::optional<ustring> body;
        if (body_size > 0)
            body = {body_, body_size};

        unbox(network).send_onion_request(
                convert_server_destination(server),
                body,
                std::nullopt,
                std::chrono::milliseconds{timeout_ms},
                [cb = std::move(callback), ctx](
                        bool success,
                        bool timeout,
                        int status_code,
                        std::optional<std::string> response) {
                    if (response)
                        cb(success,
                           timeout,
                           status_code,
                           (*response).c_str(),
                           (*response).size(),
                           ctx);
                    else
                        cb(success, timeout, status_code, nullptr, 0, ctx);
                });
    } catch (const std::exception& e) {
        callback(false, false, -1, e.what(), std::strlen(e.what()), ctx);
    }
}

LIBSESSION_C_API void network_upload_to_server(
        network_object* network,
        const network_server_destination server,
        const unsigned char* data,
        size_t data_len,
        const char* file_name_,
        int64_t timeout_ms,
        network_onion_response_callback_t callback,
        void* ctx) {
    assert(data && server.method && server.protocol && server.host && server.endpoint &&
           server.x25519_pubkey && callback);

    try {
        std::optional<std::string> file_name;
        if (file_name_)
            file_name = file_name_;

        unbox(network).upload_file_to_server(
                {data, data_len},
                convert_server_destination(server),
                file_name,
                std::chrono::milliseconds{timeout_ms},
                [cb = std::move(callback), ctx](
                        bool success,
                        bool timeout,
                        int status_code,
                        std::optional<std::string> response) {
                    if (response)
                        cb(success,
                           timeout,
                           status_code,
                           (*response).c_str(),
                           (*response).size(),
                           ctx);
                    else
                        cb(success, timeout, status_code, nullptr, 0, ctx);
                });
    } catch (const std::exception& e) {
        callback(false, false, -1, e.what(), std::strlen(e.what()), ctx);
    }
}

LIBSESSION_C_API void network_download_from_server(
        network_object* network,
        const network_server_destination server,
        int64_t timeout_ms,
        network_onion_response_callback_t callback,
        void* ctx) {
    assert(server.method && server.protocol && server.host && server.endpoint &&
           server.x25519_pubkey && callback);

    try {
        unbox(network).download_file(
                convert_server_destination(server),
                std::chrono::milliseconds{timeout_ms},
                [cb = std::move(callback), ctx](
                        bool success,
                        bool timeout,
                        int status_code,
                        std::optional<std::string> response) {
                    if (response)
                        cb(success,
                           timeout,
                           status_code,
                           (*response).c_str(),
                           (*response).size(),
                           ctx);
                    else
                        cb(success, timeout, status_code, nullptr, 0, ctx);
                });
    } catch (const std::exception& e) {
        callback(false, false, -1, e.what(), std::strlen(e.what()), ctx);
    }
}

LIBSESSION_C_API void network_get_client_version(
        network_object* network,
        CLIENT_PLATFORM platform,
        const unsigned char* ed25519_secret,
        int64_t timeout_ms,
        network_onion_response_callback_t callback,
        void* ctx) {
    assert(platform && callback);

    try {
        unbox(network).get_client_version(
                static_cast<Platform>(platform),
                onionreq::ed25519_seckey::from_bytes({ed25519_secret, 64}),
                std::chrono::milliseconds{timeout_ms},
                [cb = std::move(callback), ctx](
                        bool success,
                        bool timeout,
                        int status_code,
                        std::optional<std::string> response) {
                    if (response)
                        cb(success,
                           timeout,
                           status_code,
                           (*response).c_str(),
                           (*response).size(),
                           ctx);
                    else
                        cb(success, timeout, status_code, nullptr, 0, ctx);
                });
    } catch (const std::exception& e) {
        callback(false, false, -1, e.what(), std::strlen(e.what()), ctx);
    }
}

}  // extern "C"
