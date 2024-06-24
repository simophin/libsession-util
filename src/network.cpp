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
#include "session/random.hpp"
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

    // The amount of time the snode cache can be used before it needs to be refreshed
    constexpr auto snode_cache_expiration_duration = 2h;

    // The amount of time a swarm cache can be used before it needs to be refreshed
    constexpr auto swarm_cache_expiration_duration = (24h * 7);

    // The smallest size the snode pool can get to before we need to fetch more.
    constexpr uint16_t min_snode_pool_count = 12;

    // The number of snodes (including the guard snode) in a path.
    constexpr uint8_t path_size = 3;

    // The number of times a path can fail before it's replaced.
    constexpr uint16_t path_failure_threshold = 3;

    // The number of times a path can timeout before it's replaced.
    constexpr uint16_t path_timeout_threshold = 10;

    // The number of times a snode can fail before it's replaced.
    constexpr uint16_t snode_failure_threshold = 3;

    // File names
    const fs::path file_testnet{u8"testnet"}, file_snode_pool{u8"snode_pool"},
            file_snode_pool_updated{u8"snode_pool_updated"}, swarm_dir{u8"swarm"},
            default_cache_path{u8"."};

    constexpr auto node_not_found_prefix = "502 Bad Gateway\n\nNext node not found: "sv;
    constexpr auto node_not_found_prefix_no_status = "Next node not found: "sv;
    constexpr auto ALPN = "oxenstorage"sv;

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

    // The number of paths we want to maintain.
    uint8_t target_path_count(PathType path_type, bool single_path_mode) {
        if (single_path_mode)
            return 1;

        switch (path_type) {
            case PathType::standard: return 2;
            case PathType::upload: return 1;
            case PathType::download: return 1;
        }
        return 2;  // Default
    }

    service_node node_from_json(nlohmann::json json) {
        auto pk_ed = json["pubkey_ed25519"].get<std::string_view>();
        if (pk_ed.size() != 64 || !oxenc::is_hex(pk_ed))
            throw std::invalid_argument{
                    "Invalid service node json: pubkey_ed25519 is not a valid, hex pubkey"};
        return {oxenc::from_hex(pk_ed),
                json["ip"].get<std::string>(),
                json["port_omq"].get<uint16_t>()};
    }

    std::pair<service_node, uint8_t> node_from_disk(std::string_view str) {
        auto parts = split(str, "|");
        if (parts.size() != 4)
            throw std::invalid_argument("Invalid service node serialisation: {}"_format(str));
        if (parts[2].size() != 64 || !oxenc::is_hex(parts[2]))
            throw std::invalid_argument{
                    "Invalid service node serialisation: pubkey is not hex or has wrong size"};

        uint16_t port;
        if (!quic::parse_int(parts[1], port))
            throw std::invalid_argument{"Invalid service node serialization: invalid port"};

        uint8_t failure_count;
        if (!quic::parse_int(parts[3], failure_count))
            throw std::invalid_argument{"Invalid service node serialization: invalid port"};

        return {
                {
                        oxenc::from_hex(parts[2]),  // ed25519_pubkey
                        std::string(parts[0]),      // ip
                        port,                       // port
                },
                failure_count  // failure_count
        };
    }

    const std::vector<service_node> seed_nodes_testnet{
            node_from_disk("144.76.164.202|35400|"
                           "decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9|0"sv)
                    .first};
    const std::vector<service_node> seed_nodes_mainnet{
            node_from_disk("144.76.164.202|20200|"
                           "1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1fef|0"sv)
                    .first,
            node_from_disk("88.99.102.229|20201|"
                           "1f101f0acee4db6f31aaa8b4df134e85ca8a4878efaef7f971e88ab144c1a7ce|0"sv)
                    .first,
            node_from_disk("195.16.73.17|20202|"
                           "1f202f00f4d2d4acc01e20773999a291cf3e3136c325474d159814e06199919f|0"sv)
                    .first,
            node_from_disk("104.194.11.120|20203|"
                           "1f303f1d7523c46fa5398826740d13282d26b5de90fbae5749442f66afb6d78b|0"sv)
                    .first,
            node_from_disk("104.194.8.115|20204|"
                           "1f604f1c858a121a681d8f9b470ef72e6946ee1b9c5ad15a35e16b50c28db7b0|0"sv)
                    .first};
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

    /// Converts a string such as "1.2.3" to a vector of ints {1,2,3}.  Throws if something
    /// in/around
    /// the .'s isn't parseable as an integer.
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

    std::string node_to_disk(
            service_node node, std::unordered_map<std::string, uint8_t> failure_counts) {
        auto ed25519_pubkey_hex = oxenc::to_hex(node.view_remote_key());

        return fmt::format(
                "{}|{}|{}|{}",
                node.host(),
                node.port(),
                ed25519_pubkey_hex,
                failure_counts.try_emplace(node.to_string(), 0).first->second);
    }

    session::onionreq::x25519_pubkey compute_xpk(ustring_view ed25519_pk) {
        std::array<unsigned char, 32> xpk;
        if (0 != crypto_sign_ed25519_pk_to_curve25519(xpk.data(), ed25519_pk.data()))
            throw std::runtime_error{
                    "An error occured while attempting to convert Ed25519 pubkey to X25519; "
                    "is the pubkey valid?"};
        return session::onionreq::x25519_pubkey::from_bytes({xpk.data(), 32});
    }

    std::optional<service_node> node_for_destination(network_destination destination) {
        if (auto* dest = std::get_if<quic::RemoteAddress>(&destination))
            return *dest;

        return std::nullopt;
    }

    session::onionreq::x25519_pubkey pubkey_for_destination(network_destination destination) {
        if (auto* dest = std::get_if<quic::RemoteAddress>(&destination))
            return compute_xpk(dest->view_remote_key());

        if (auto* dest = std::get_if<ServerDestination>(&destination))
            return dest->x25519_pubkey;

        throw std::runtime_error{"Invalid destination."};
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
    paths_and_pool_loop = std::make_shared<quic::Loop>();

    // Load the cache from disk and start the disk write thread
    if (should_cache_to_disk) {
        load_cache_from_disk();
        disk_write_thread = std::thread{&Network::disk_write_thread_loop, this};
    }

    // Kick off a separate thread to build paths (may as well kick this off early)
    if (pre_build_paths) {
        std::thread build_paths_thread(
                &Network::with_paths_and_pool,
                this,
                "Constructor",
                PathType::standard,
                std::nullopt,
                [](std::vector<onion_path>, std::vector<service_node>, std::optional<std::string>) {
                });
        build_paths_thread.detach();
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
        bool cache_is_for_testnet = fs::exists(testnet_stub);
        if (use_testnet != cache_is_for_testnet)
            fs::remove_all(cache_path);

        // Create the cache directory (and swarm_dir, inside it) if needed
        auto swarm_path = cache_path / swarm_dir;
        fs::create_directories(swarm_path);

        // If we are using testnet then create a file to indicate that
        if (use_testnet)
            write_whole_file(testnet_stub, "");

        // Load the last time the snode pool was updated
        //
        // Note: We aren't just reading the write time of the file because Apple consider
        // accessing file timestamps a method that can be used to track the user (and we
        // want to avoid being flagged as using such)
        auto last_updated_path = cache_path / file_snode_pool_updated;
        if (fs::exists(last_updated_path)) {
            try {
                auto timestamp_str = read_whole_file(last_updated_path);
                while (timestamp_str.ends_with('\n'))
                    timestamp_str.pop_back();

                std::time_t timestamp;
                if (!quic::parse_int(timestamp_str, timestamp))
                    throw std::runtime_error{"invalid file data: expected timestamp first line"};

                last_snode_pool_update = std::chrono::system_clock::from_time_t(timestamp);
            } catch (const std::exception& e) {
                log::error(cat, "Ignoring invalid last update timestamp file: {}", e.what());
            }
        }

        // Load the snode pool
        auto pool_path = cache_path / file_snode_pool;
        if (fs::exists(pool_path)) {
            auto file = open_for_reading(pool_path);
            std::vector<service_node> loaded_pool;
            std::unordered_map<std::string, uint8_t> loaded_failure_count;
            std::string line;

            while (std::getline(file, line)) {
                try {
                    auto [node, failure_count] = node_from_disk(line);
                    loaded_pool.push_back(node);
                    loaded_failure_count[node.to_string()] = failure_count;
                } catch (...) {
                    log::warning(cat, "Skipping invalid entry in snode pool cache.");
                }
            }

            snode_pool = loaded_pool;
            snode_failure_counts = loaded_failure_count;
        }

        // Load the swarm cache
        auto time_now = std::chrono::system_clock::now();
        std::unordered_map<std::string, std::vector<service_node>> loaded_cache;
        std::vector<fs::path> caches_to_remove;

        for (auto& entry : fs::directory_iterator(swarm_path)) {
            // If the pubkey was valid then process the content
            auto file = open_for_reading(entry.path());
            std::vector<service_node> nodes;
            std::string line;
            bool checked_swarm_expiration = false;
            std::chrono::seconds swarm_lifetime = 0s;
            const auto& path = entry.path();
            std::string filename{convert_sv<char>(path.filename().u8string())};

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

                    // Otherwise try to parse as a node
                    nodes.push_back(node_from_disk(line).first);

                } catch (const std::exception& e) {
                    // Don't bother logging for expired entries (we include the count separately at
                    // the end)
                    if (dynamic_cast<const load_cache_exception*>(&e) == nullptr) {
                        log::warning(cat, "Skipping invalid entry in swarm cache: {}", e.what());
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

        swarm_cache = loaded_cache;

        // Remove any expired cache files
        for (auto& cache_path : caches_to_remove)
            fs::remove_all(cache_path);

        log::info(
                cat,
                "Loaded cache of {} snodes, {} swarms ({} expired swarms).",
                snode_pool.size(),
                swarm_cache.size(),
                caches_to_remove.size());
    } catch (const std::exception& e) {
        log::error(cat, "Failed to load snode cache, will rebuild ({}).", e.what());
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
            auto snode_pool_write = snode_pool;
            auto snode_failure_counts_write = snode_failure_counts;
            auto last_pool_update_write = last_snode_pool_update;
            auto swarm_cache_write = swarm_cache;

            lock.unlock();
            {
                try {
                    // Create the cache directories if needed
                    auto swarm_base = cache_path / swarm_dir;
                    fs::create_directories(swarm_base);

                    // Save the snode pool to disk
                    if (need_pool_write) {
                        auto pool_path = cache_path / file_snode_pool;
                        auto pool_tmp = pool_path;
                        pool_tmp += u8"_new";

                        {
                            auto file = open_for_writing(pool_tmp);
                            for (auto& snode : snode_pool_write)
                                file << node_to_disk(snode, snode_failure_counts_write) << '\n';
                        }

                        fs::rename(pool_tmp, pool_path);

                        // Write the last update timestamp to disk
                        write_whole_file(
                                cache_path / file_snode_pool_updated,
                                "{}"_format(std::chrono::system_clock::to_time_t(
                                        last_pool_update_write)));
                        log::debug(cat, "Finished writing snode pool cache to disk.");
                    }

                    // Write the swarm cache to disk
                    if (need_swarm_write) {
                        auto time_now = std::chrono::system_clock::now();

                        for (auto& [key, swarm] : swarm_cache_write) {
                            auto swarm_path = swarm_base / key;
                            auto swarm_tmp = swarm_path;
                            swarm_tmp += u8"_new";
                            auto swarm_file = open_for_writing(swarm_tmp);

                            // Write the timestamp to the file
                            swarm_file << std::chrono::system_clock::to_time_t(time_now) << '\n';

                            // Write the nodes to the file
                            for (auto& snode : swarm)
                                swarm_file << node_to_disk(snode, snode_failure_counts_write)
                                           << '\n';

                            fs::rename(swarm_tmp, swarm_path);
                        }
                        log::debug(cat, "Finished writing swarm cache to disk.");
                    }

                    need_pool_write = false;
                    need_swarm_write = false;
                    need_write = false;
                } catch (const std::exception& e) {
                    log::error(cat, "Failed to write snode cache: {}", e.what());
                }
            }
            lock.lock();
        }
        if (need_clear_cache) {
            snode_pool = {};
            last_snode_pool_update = {};
            swarm_cache = {};

            lock.unlock();
            fs::remove_all(cache_path);
            lock.lock();
            need_clear_cache = false;
        }
        if (shut_down_disk_thread)
            return;
    }
}

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
        endpoint.reset();

        for (auto& paths : {&standard_paths, &upload_paths, &download_paths}) {
            for (auto& path : *paths) {
                path.conn_info.conn.reset();
                path.conn_info.stream.reset();
            }
        }

        update_status(ConnectionStatus::disconnected);
        log::info(cat, "Closed all connections.");
    });
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

std::shared_ptr<quic::Endpoint> Network::get_endpoint() {
    return net.call_get([this]() mutable {
        if (!endpoint)
            endpoint = net.endpoint(quic::Address{"0.0.0.0", 0}, quic::opt::alpns{ALPN});

        return endpoint;
    });
}

std::pair<connection_info, std::optional<std::string>> Network::get_connection_info(
        std::string request_id, PathType path_type, service_node target) {
    log::trace(cat, "{} called for {}.", __PRETTY_FUNCTION__, request_id);
    auto currently_suspended = net.call_get([this]() -> bool { return suspended; });

    // If the network is currently suspended then don't try to open a connection
    if (currently_suspended)
        return {{target, nullptr, nullptr}, "Network is suspended."};

    auto cb_called = std::make_shared<std::once_flag>();
    auto mutex = std::make_shared<std::mutex>();
    auto cv = std::make_shared<std::condition_variable>();
    auto connection_established = std::make_shared<bool>(false);
    auto done = std::make_shared<bool>(false);
    auto connection_key_pair = ed25519::ed25519_key_pair();
    auto creds =
            quic::GNUTLSCreds::make_from_ed_seckey(from_unsigned_sv(connection_key_pair.second));

    auto c = get_endpoint()->connect(
            target,
            creds,
            quic::opt::keep_alive{10s},
            [mutex, cv, connection_established, done, request_id, cb_called](
                    quic::connection_interface&) {
                log::trace(
                        cat, "{} connection established for {}.", __PRETTY_FUNCTION__, request_id);

                if (cb_called)
                    std::call_once(*cb_called, [&]() {
                        {
                            std::lock_guard<std::mutex> lock(*mutex);
                            *connection_established = true;
                            *done = true;
                        }
                        cv->notify_one();
                    });
            },
            [this, path_type, target, mutex, cv, done, request_id, cb_called](
                    quic::connection_interface& conn, uint64_t error_code) {
                log::trace(cat, "{} connection closed for {}.", __PRETTY_FUNCTION__, request_id);

                // Trigger the callback first before updating the paths in case this was triggered
                // when try to establish a connection
                if (cb_called) {
                    std::call_once(*cb_called, [&]() {
                        {
                            std::lock_guard<std::mutex> lock(*mutex);
                            *done = true;
                        }
                        cv->notify_one();
                    });
                }

                // When the connection is closed, update the path and connection status
                auto current_paths = net.call_get([this, path_type]() -> std::vector<onion_path> {
                    return paths_for_type(path_type);
                });
                auto target_path = std::find_if(
                        current_paths.begin(), current_paths.end(), [&target](const auto& path) {
                            return !path.nodes.empty() && target == path.nodes.front();
                        });

                if (target_path != current_paths.end() && target_path->conn_info.conn &&
                    conn.reference_id() == target_path->conn_info.conn->reference_id()) {
                    target_path->conn_info.conn.reset();
                    target_path->conn_info.stream.reset();
                    handle_node_error(target, path_type, *target_path);
                } else if (error_code == static_cast<uint64_t>(NGTCP2_ERR_HANDSHAKE_TIMEOUT))
                    // Depending on the state of the snode pool cache it's possible for certain
                    // errors to result in being permanently unable to establish a connection, to
                    // avoid this we handle those error codes and drop
                    handle_node_error(
                            target, path_type, {{target, nullptr, nullptr}, {target}, 0, 0});
            });

    if (!*done) {
        std::unique_lock<std::mutex> lock(*mutex);
        cv->wait(lock, [&done] { return *done; });
    }

    if (!*connection_established)
        return {{target, nullptr, nullptr}, "Network is unreachable."};

    return {{target, c, c->open_stream<quic::BTRequestStream>()}, std::nullopt};
}

// MARK: Snode Pool and Onion Path

using paths_and_pool_result =
        std::tuple<std::vector<onion_path>, std::vector<service_node>, std::optional<std::string>>;
using paths_and_pool_info = std::tuple<
        std::vector<onion_path>,
        std::vector<service_node>,
        std::chrono::system_clock::time_point,
        bool>;

void Network::with_paths_and_pool(
        std::string request_id,
        PathType path_type,
        std::optional<service_node> excluded_node,
        std::function<
                void(std::vector<onion_path> updated_paths,
                     std::vector<service_node> pool,
                     std::optional<std::string> error)> callback) {
    log::trace(cat, "{} called for {}.", __PRETTY_FUNCTION__, request_id);
    auto [current_paths, pool, last_pool_update, currently_suspended] =
            net.call_get([this, path_type]() -> paths_and_pool_info {
                return {paths_for_type(path_type), snode_pool, last_snode_pool_update, suspended};
            });

    // If the network is currently suspended then fail immediately
    if (currently_suspended)
        return callback({}, {}, "Network is suspended");

    // Check if the current data is valid, and if so just return it
    auto current_valid_paths = valid_paths(current_paths);
    auto [paths_valid, pool_valid] =
            validate_paths_and_pool_sizes(path_type, current_valid_paths, pool, last_pool_update);

    if (paths_valid && pool_valid) {
        log::trace(
                cat,
                "{} returning valid cached paths and pool for {}.",
                __PRETTY_FUNCTION__,
                request_id);
        return callback(current_valid_paths, pool, std::nullopt);
    }

    auto [updated_paths, updated_pool, error] = paths_and_pool_loop->call_get(
            [this, path_type, request_id, excluded_node]() mutable -> paths_and_pool_result {
                auto [current_paths, pool, last_pool_update, currently_suspended] =
                        net.call_get([this, path_type]() -> paths_and_pool_info {
                            return {paths_for_type(path_type),
                                    snode_pool,
                                    last_snode_pool_update,
                                    suspended};
                        });

                // If the network is currently suspended then fail immediately
                if (currently_suspended)
                    return {{}, {}, "Network is suspended"};

                // Check if the current data is valid, and if so just return it
                auto current_valid_paths = valid_paths(current_paths);
                auto [paths_valid, pool_valid] = validate_paths_and_pool_sizes(
                        path_type, current_valid_paths, pool, last_pool_update);

                if (paths_valid && pool_valid) {
                    log::trace(
                            cat,
                            "{} whithin loop cache has already been updated for {}.",
                            __PRETTY_FUNCTION__,
                            request_id);
                    return {current_valid_paths, pool, std::nullopt};
                }

                // Update the network status
                if (path_type == PathType::standard)
                    net.call([this]() mutable { update_status(ConnectionStatus::connecting); });

                // If the pool isn't valid then we should update it
                CSRNG rng;
                std::vector<service_node> pool_result = pool;
                std::vector<onion_path> paths_result = current_valid_paths;

                // Populate the snode pool if needed
                if (!pool_valid) {
                    log::info(
                            cat,
                            "Snode pool cache no longer valid for {}, need to refetch.",
                            request_id);

                    // Define the response handler to avoid code duplication
                    auto handle_nodes_response =
                            [](std::promise<std::vector<service_node>>&& prom) {
                                return [&prom](std::vector<service_node> nodes,
                                               std::optional<std::string> error) {
                                    try {
                                        if (nodes.empty())
                                            throw std::runtime_error{
                                                    error.value_or("No nodes received.")};
                                        prom.set_value(nodes);
                                    } catch (...) {
                                        prom.set_exception(std::current_exception());
                                    }
                                };
                            };

                    try {
                        // If we don't have enough nodes in the current cached pool then we need to
                        // fetch from the seed nodes
                        if (pool_result.size() < min_snode_pool_count) {
                            log::info(cat, "Fetching from seed nodes for {}.", request_id);
                            pool_result = (use_testnet ? seed_nodes_testnet : seed_nodes_mainnet);

                            // Just in case, make sure the seed nodes are have values
                            if (pool_result.empty())
                                throw std::runtime_error{"Insufficient seed nodes."};

                            std::shuffle(pool_result.begin(), pool_result.end(), rng);
                            std::promise<std::vector<service_node>> prom;
                            std::future<std::vector<service_node>> prom_future = prom.get_future();

                            get_service_nodes(
                                    request_id,
                                    pool_result.front(),
                                    256,
                                    handle_nodes_response(std::move(prom)));

                            // We want to block the `get_snode_pool_loop` until we have retrieved
                            // the snode pool so we don't double up on requests
                            pool_result = prom_future.get();
                            log::info(
                                    cat, "Retrieved snode pool from seed node for {}.", request_id);
                        } else {
                            // Pick ~9 random snodes from the current cache to fetch nodes from (we
                            // want to fetch from 3 snodes and retry up to 3 times if needed)
                            std::shuffle(pool_result.begin(), pool_result.end(), rng);
                            size_t num_retries =
                                    std::min(pool_result.size() / 3, static_cast<size_t>(3));

                            log::info(
                                    cat,
                                    "Fetching from random expired cache nodes for {}.",
                                    request_id);
                            std::vector<service_node> nodes1(
                                    pool_result.begin(), pool_result.begin() + num_retries);
                            std::vector<service_node> nodes2(
                                    pool_result.begin() + num_retries,
                                    pool_result.begin() + (num_retries * 2));
                            std::vector<service_node> nodes3(
                                    pool_result.begin() + (num_retries * 2),
                                    pool_result.begin() + (num_retries * 3));
                            std::promise<std::vector<service_node>> prom1;
                            std::promise<std::vector<service_node>> prom2;
                            std::promise<std::vector<service_node>> prom3;
                            std::future<std::vector<service_node>> prom_future1 =
                                    prom1.get_future();
                            std::future<std::vector<service_node>> prom_future2 =
                                    prom2.get_future();
                            std::future<std::vector<service_node>> prom_future3 =
                                    prom3.get_future();

                            // Kick off 3 concurrent requests
                            get_service_nodes_recursive(
                                    "{}-1"_format(request_id),
                                    nodes1,
                                    std::nullopt,
                                    handle_nodes_response(std::move(prom1)));
                            get_service_nodes_recursive(
                                    "{}-2"_format(request_id),
                                    nodes2,
                                    std::nullopt,
                                    handle_nodes_response(std::move(prom2)));
                            get_service_nodes_recursive(
                                    "{}-3"_format(request_id),
                                    nodes3,
                                    std::nullopt,
                                    handle_nodes_response(std::move(prom3)));

                            // We want to block the `get_snode_pool_loop` until we have retrieved
                            // the snode pool so we don't double up on requests
                            auto result_nodes1 = prom_future1.get();
                            auto result_nodes2 = prom_future2.get();
                            auto result_nodes3 = prom_future3.get();

                            // Sort the vectors (so make it easier to find the
                            // intersection)
                            std::stable_sort(result_nodes1.begin(), result_nodes1.end());
                            std::stable_sort(result_nodes2.begin(), result_nodes2.end());
                            std::stable_sort(result_nodes3.begin(), result_nodes3.end());

                            // Get the intersection of the vectors
                            std::vector<service_node> intersection1_2;
                            std::vector<service_node> intersection;

                            std::set_intersection(
                                    result_nodes1.begin(),
                                    result_nodes1.end(),
                                    result_nodes2.begin(),
                                    result_nodes2.end(),
                                    std::back_inserter(intersection1_2),
                                    [](const auto& a, const auto& b) { return a == b; });
                            std::set_intersection(
                                    intersection1_2.begin(),
                                    intersection1_2.end(),
                                    result_nodes3.begin(),
                                    result_nodes3.end(),
                                    std::back_inserter(intersection),
                                    [](const auto& a, const auto& b) { return a == b; });

                            // Since we sorted it we now need to shuffle it again
                            std::shuffle(intersection.begin(), intersection.end(), rng);

                            // Update the cache to be the first 256 nodes from
                            // the intersection
                            auto size = std::min(256, static_cast<int>(intersection.size()));
                            pool_result = std::vector<service_node>(
                                    intersection.begin(), intersection.begin() + size);
                            log::info(cat, "Retrieved snode pool for {}.", request_id);
                        }
                    } catch (const std::exception& e) {
                        log::info(cat, "Failed to get snode pool for {}: {}", request_id, e.what());
                        return {{}, {}, e.what()};
                    }
                }

                // Build new paths if needed
                if (!paths_valid) {
                    try {
                        // Get the possible guard nodes
                        log::info(
                                cat,
                                "Building paths of type {} for {}.",
                                path_type_name(path_type, single_path_mode),
                                request_id);
                        std::vector<service_node> nodes_to_exclude;
                        std::vector<service_node> possible_guard_nodes;

                        if (excluded_node)
                            nodes_to_exclude.push_back(*excluded_node);

                        for (auto& path : paths_result)
                            nodes_to_exclude.insert(
                                    nodes_to_exclude.end(), path.nodes.begin(), path.nodes.end());

                        if (nodes_to_exclude.empty())
                            possible_guard_nodes = pool_result;
                        else
                            std::copy_if(
                                    pool_result.begin(),
                                    pool_result.end(),
                                    std::back_inserter(possible_guard_nodes),
                                    [&nodes_to_exclude](const auto& node) {
                                        return std::find(
                                                       nodes_to_exclude.begin(),
                                                       nodes_to_exclude.end(),
                                                       node) == nodes_to_exclude.end();
                                    });

                        if (possible_guard_nodes.empty())
                            throw std::runtime_error{
                                    "Unable to build paths due to lack of possible guard nodes."};

                        // Now that we have a list of possible guard nodes we need to build the
                        // paths, first off we need to find valid guard nodes for the paths
                        std::shuffle(possible_guard_nodes.begin(), possible_guard_nodes.end(), rng);

                        // Split the possible nodes list into a list of lists (one list could run
                        // out before the other but in most cases this should work fine)
                        size_t required_paths =
                                (target_path_count(path_type, single_path_mode) -
                                 current_valid_paths.size());
                        size_t chunk_size = (possible_guard_nodes.size() / required_paths);
                        std::vector<std::vector<service_node>> nodes_to_test;
                        auto start = 0;

                        for (size_t i = 0; i < required_paths; ++i) {
                            auto end = std::min(start + chunk_size, possible_guard_nodes.size());

                            if (i == required_paths - 1)
                                end = possible_guard_nodes.size();

                            nodes_to_test.emplace_back(
                                    possible_guard_nodes.begin() + start,
                                    possible_guard_nodes.begin() + end);
                            start = end;
                        }

                        // Start testing guard nodes based on the number of paths we want to build
                        std::vector<
                                std::future<std::pair<connection_info, std::vector<service_node>>>>
                                futures;
                        futures.reserve(required_paths);

                        for (size_t i = 0; i < required_paths; ++i) {
                            std::promise<std::pair<connection_info, std::vector<service_node>>>
                                    guard_node_prom;
                            futures.emplace_back(guard_node_prom.get_future());

                            auto prom = std::make_shared<std::promise<
                                    std::pair<connection_info, std::vector<service_node>>>>(
                                    std::move(guard_node_prom));

                            find_valid_guard_node_recursive(
                                    request_id,
                                    path_type,
                                    nodes_to_test[i],
                                    [prom](std::optional<connection_info> valid_guard_node,
                                           std::vector<service_node> unused_nodes,
                                           std::optional<std::string> error) {
                                        try {
                                            if (!valid_guard_node)
                                                throw std::runtime_error{
                                                        error.value_or("Failed to find valid guard "
                                                                       "node.")};
                                            prom->set_value({*valid_guard_node, unused_nodes});
                                        } catch (...) {
                                            prom->set_exception(std::current_exception());
                                        }
                                    });
                        }

                        // Combine the results (we want to block the `paths_and_pool_loop` until we
                        // have retrieved the valid guard nodes so we don't double up on requests
                        std::vector<connection_info> valid_nodes;
                        std::vector<service_node> unused_nodes;

                        for (auto& fut : futures) {
                            auto result = fut.get();
                            valid_nodes.emplace_back(result.first);
                            unused_nodes.insert(
                                    unused_nodes.begin(),
                                    result.second.begin(),
                                    result.second.end());
                        }

                        // Make sure we ended up getting enough valid nodes
                        auto have_enough_guard_nodes =
                                (current_valid_paths.size() + valid_nodes.size() >=
                                 target_path_count(path_type, single_path_mode));
                        auto have_enough_unused_nodes =
                                (unused_nodes.size() >=
                                 ((path_size - 1) *
                                  target_path_count(path_type, single_path_mode)));

                        if (!have_enough_guard_nodes || !have_enough_unused_nodes)
                            throw std::runtime_error{"Not enough remaining nodes."};

                        // Build the new paths
                        for (auto& info : valid_nodes) {
                            std::vector<service_node> path{info.node};

                            for (auto i = 0; i < path_size - 1; i++) {
                                auto node = unused_nodes.back();
                                unused_nodes.pop_back();
                                path.push_back(node);
                            }

                            paths_result.emplace_back(onion_path{std::move(info), path, 0, 0});

                            // Log that a path was built
                            std::vector<std::string> node_descriptions;
                            std::transform(
                                    path.begin(),
                                    path.end(),
                                    std::back_inserter(node_descriptions),
                                    [](service_node& node) { return node.to_string(); });
                            auto path_description = "{}"_format(fmt::join(node_descriptions, ", "));
                            log::info(
                                    cat,
                                    "Built new onion request path of type {} for {}: [{}]",
                                    path_type_name(path_type, single_path_mode),
                                    request_id,
                                    path_description);
                        }
                    } catch (const std::exception& e) {
                        log::info(
                                cat,
                                "Unable to build paths of type {} for {} due to error: {}",
                                path_type_name(path_type, single_path_mode),
                                request_id,
                                e.what());
                        return {{}, {}, e.what()};
                    }
                }

                // Store to instance variables
                net.call([this,
                          path_type,
                          pool_result,
                          paths_result,
                          pool_valid,
                          paths_valid]() mutable {
                    if (!paths_valid) {
                        switch (path_type) {
                            case PathType::standard: standard_paths = paths_result; break;
                            case PathType::upload: upload_paths = paths_result; break;
                            case PathType::download: download_paths = paths_result; break;
                        }

                        // Call the paths_changed callback if provided
                        if (path_type == PathType::standard && paths_changed) {
                            std::vector<std::vector<service_node>> raw_paths;
                            for (auto& path : paths_result)
                                raw_paths.emplace_back(path.nodes);

                            paths_changed(raw_paths);
                        }
                    }

                    // Only update the disk cache if the snode pool was updated
                    if (!pool_valid) {
                        {
                            std::lock_guard lock{snode_cache_mutex};
                            snode_pool = pool_result;
                            last_snode_pool_update = std::chrono::system_clock::now();
                            need_pool_write = true;
                            need_write = true;
                        }
                        snode_cache_cv.notify_one();
                    }

                    // Standard paths were successfully built, update the connection status
                    if (path_type == PathType::standard)
                        update_status(ConnectionStatus::connected);
                });

                return {paths_result, pool_result, std::nullopt};
            });

    return callback(updated_paths, updated_pool, error);
}

std::vector<onion_path> Network::valid_paths(std::vector<onion_path> paths) {
    auto valid_paths = paths;
    auto valid_paths_end =
            std::remove_if(valid_paths.begin(), valid_paths.end(), [](onion_path path) {
                return !path.conn_info.is_valid();
            });
    valid_paths.erase(valid_paths_end, valid_paths.end());

    return valid_paths;
}

std::pair<bool, bool> Network::validate_paths_and_pool_sizes(
        PathType path_type,
        std::vector<onion_path> paths,
        std::vector<service_node> pool,
        std::chrono::system_clock::time_point last_pool_update) {
    auto cache_duration = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now() - last_pool_update);
    auto cache_has_expired =
            (cache_duration <= 0s && cache_duration > snode_cache_expiration_duration);

    return {(paths.size() >= target_path_count(path_type, single_path_mode)),
            (pool.size() >= min_snode_pool_count && !cache_has_expired)};
}

void Network::with_path(
        std::string request_id,
        PathType path_type,
        std::optional<service_node> excluded_node,
        std::function<void(std::optional<onion_path> path, std::optional<std::string> error)>
                callback) {
    log::trace(cat, "{} called for {}.", __PRETTY_FUNCTION__, request_id);
    auto [current_paths, currently_suspended] =
            net.call_get([this, path_type]() -> std::pair<std::vector<onion_path>, bool> {
                return {paths_for_type(path_type), suspended};
            });

    // If the network is currently suspended then fail immediately
    if (currently_suspended)
        return callback(std::nullopt, "Network is suspended");

    std::pair<std::optional<onion_path>, uint8_t> path_info =
            find_possible_path(excluded_node, current_paths);
    auto& [target_path, paths_count] = path_info;

    // The path doesn't have a valid connection so we should try to reconnect (we will end
    // up updating the `paths` value so should do this in a blocking way)
    if (target_path && !target_path->conn_info.is_valid()) {
        log::trace(
                cat,
                "{} found invalid connection for {}, will try to recover.",
                __PRETTY_FUNCTION__,
                request_id);

        path_info = paths_and_pool_loop->call_get(
                [this, path_type, request_id, path = *target_path]() mutable
                -> std::pair<std::optional<onion_path>, uint8_t> {
                    // Since this may have been blocked by another thread we should start by
                    // making sure the target path is still one of the current paths
                    auto current_paths =
                            net.call_get([this, path_type]() -> std::vector<onion_path> {
                                return paths_for_type(path_type);
                            });
                    auto target_path_it =
                            std::find(current_paths.begin(), current_paths.end(), path);

                    // If we didn't find the path then don't bother continuing
                    if (target_path_it == current_paths.end()) {
                        log::trace(
                                cat,
                                "{} path with invalid connection for {} no longer exists.",
                                __PRETTY_FUNCTION__,
                                request_id);
                        return {std::nullopt, current_paths.size()};
                    }

                    // It's possible that multiple requests were queued up waiting on the connection
                    // the be reestablished so check to see if the path is now valid and return it
                    // if it is
                    if (target_path_it->conn_info.is_valid()) {
                        log::trace(
                                cat,
                                "{} connection to {} for {} has already been recovered.",
                                __PRETTY_FUNCTION__,
                                target_path_it->nodes[0],
                                request_id);
                        return {*target_path_it, current_paths.size()};
                    }

                    // Try to retrieve a valid connection for the guard node
                    log::info(
                            cat,
                            "Connection to {} with type {} for {} path no longer valid, attempting "
                            "reconnection.",
                            target_path_it->nodes[0],
                            path_type_name(path_type, single_path_mode),
                            request_id);
                    auto [info, error] = get_connection_info(request_id, path_type, path.nodes[0]);

                    // It's possible that the connection was created successfully, and reported as
                    // valid, but isn't actually valid (eg. it was shutdown immediately due to the
                    // network being unreachable) so to avoid this we wait for either the connection
                    // to be established or the connection to fail before continuing
                    if (!info.is_valid()) {
                        log::info(
                                cat,
                                "Reconnection to {} with type {} for {} path failed with error: "
                                "{}.",
                                target_path_it->nodes[0],
                                path_type_name(path_type, single_path_mode),
                                request_id,
                                error.value_or("Unknown error."));
                        return {std::nullopt, current_paths.size()};
                    }

                    // Knowing that the reconnection succeeded is helpful for debugging
                    log::info(
                            cat,
                            "Reconnection to {} with type {} for {} path successful.",
                            target_path_it->nodes[0],
                            path_type_name(path_type, single_path_mode),
                            request_id);

                    // If the connection info is valid and it's a standard path then update the
                    // connection status back to connected
                    if (path_type == PathType::standard)
                        update_status(ConnectionStatus::connected);

                    // No need to call the 'paths_changed' callback as the paths haven't
                    // actually changed, just their connection info
                    auto updated_path = onion_path{std::move(info), path.nodes, 0, 0};
                    auto paths_count = net.call_get(
                            [this, path_type, path, updated_path]() mutable -> uint8_t {
                                switch (path_type) {
                                    case PathType::standard:
                                        std::replace(
                                                standard_paths.begin(),
                                                standard_paths.end(),
                                                path,
                                                updated_path);
                                        return standard_paths.size();

                                    case PathType::upload:
                                        std::replace(
                                                upload_paths.begin(),
                                                upload_paths.end(),
                                                path,
                                                updated_path);
                                        return upload_paths.size();

                                    case PathType::download:
                                        std::replace(
                                                download_paths.begin(),
                                                download_paths.end(),
                                                path,
                                                updated_path);
                                        return download_paths.size();
                                }
                            });

                    return {updated_path, paths_count};
                });
    }

    // If we didn't get a target path then we have to build paths
    if (!target_path) {
        log::trace(cat, "{} no path found for {}.", __PRETTY_FUNCTION__, request_id);
        return with_paths_and_pool(
                request_id,
                path_type,
                excluded_node,
                [this, excluded_node, cb = std::move(callback)](
                        std::vector<onion_path> updated_paths,
                        std::vector<service_node>,
                        std::optional<std::string> error) {
                    if (error)
                        return cb(std::nullopt, *error);

                    auto [target_path, paths_count] =
                            find_possible_path(excluded_node, updated_paths);

                    if (!target_path)
                        return cb(std::nullopt, "Unable to find valid path.");

                    cb(*target_path, std::nullopt);
                });
    }

    // Build additional paths in the background if we don't have enough
    if (paths_count < target_path_count(path_type, single_path_mode)) {
        auto new_request_id = random::random_base32(4);
        log::trace(
                cat,
                "{} found path, but we don't have the desired number so starting a background path "
                "build from {} with new id: {}.",
                __PRETTY_FUNCTION__,
                request_id,
                new_request_id);
        std::thread build_additional_paths_thread(
                &Network::with_paths_and_pool,
                this,
                new_request_id,
                path_type,
                std::nullopt,
                [](std::optional<std::vector<onion_path>>,
                   std::vector<service_node>,
                   std::optional<std::string>) {});
        build_additional_paths_thread.detach();
    }

    // We have a valid path for the standard path type then update the status in case we had
    // flagged it as disconnected for some reason
    if (path_type == PathType::standard)
        net.call([this]() mutable { update_status(ConnectionStatus::connected); });

    callback(target_path, std::nullopt);
}

std::pair<std::optional<onion_path>, uint8_t> Network::find_possible_path(
        std::optional<service_node> excluded_node, std::vector<onion_path> paths) {
    if (paths.empty())
        return {std::nullopt, paths.size()};

    std::vector<onion_path> possible_paths;

    if (!excluded_node)
        possible_paths = paths;
    else
        std::copy_if(
                paths.begin(),
                paths.end(),
                std::back_inserter(possible_paths),
                [&excluded_node](const auto& path) {
                    return !path.nodes.empty() &&
                           (!excluded_node ||
                            std::find(path.nodes.begin(), path.nodes.end(), excluded_node) ==
                                    path.nodes.end());
                });

    if (possible_paths.empty())
        return {std::nullopt, paths.size()};

    CSRNG rng;
    std::shuffle(possible_paths.begin(), possible_paths.end(), rng);

    return {possible_paths.front(), paths.size()};
};

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
                if (!nodes.empty())
                    return cb(nodes, error);

                // Loop if we didn't get any nodes
                std::vector<service_node> remaining_nodes(
                        target_nodes.begin() + 1, target_nodes.end());
                get_service_nodes_recursive(request_id, remaining_nodes, limit, cb);
            });
}

void Network::find_valid_guard_node_recursive(
        std::string request_id,
        PathType path_type,
        std::vector<service_node> target_nodes,
        std::function<
                void(std::optional<connection_info> valid_guard_node,
                     std::vector<service_node> unused_nodes,
                     std::optional<std::string>)> callback) {
    log::trace(cat, "{} called for {}.", __PRETTY_FUNCTION__, request_id);
    if (target_nodes.empty())
        return callback(std::nullopt, {}, "Failed to find valid guard node.");

    // If the network is currently suspended then fail immediately
    auto currently_suspended = net.call_get([this]() -> bool { return suspended; });
    if (currently_suspended)
        return callback(std::nullopt, {}, "Network is suspended");

    auto target_node = target_nodes.front();
    log::info(cat, "Testing guard snode: {} for {}", target_node.to_string(), request_id);

    get_version(
            request_id,
            path_type,
            target_node,
            3s,
            [this, path_type, target_node, target_nodes, request_id, cb = std::move(callback)](
                    std::vector<int> version,
                    connection_info info,
                    std::optional<std::string> error) {
                log::trace(cat, "{} got response for {}.", __PRETTY_FUNCTION__, request_id);
                std::vector<service_node> remaining_nodes(
                        target_nodes.begin() + 1, target_nodes.end());

                try {
                    if (error)
                        throw std::runtime_error{*error};

                    // Ensure the node meets the minimum version requirements after a slight
                    // delay (don't want to drain the pool if the network goes down)
                    std::vector<int> min_version = parse_version("2.0.7");
                    if (version < min_version)
                        throw std::runtime_error{
                                "Outdated node version ({})"_format(fmt::join(version, "."))};

                    log::info(
                            cat,
                            "Guard snode {} valid for {}.",
                            target_node.to_string(),
                            request_id);
                    cb(info, remaining_nodes, std::nullopt);
                } catch (const std::exception& e) {
                    // Log the error and loop after a slight delay (don't want to drain the pool
                    // too quickly if the network goes down)
                    log::info(
                            cat,
                            "Testing {} for {} failed with error: {}",
                            target_node.to_string(),
                            request_id,
                            e.what());
                    std::thread retry_thread(
                            [this, path_type, remaining_nodes, request_id, cb = std::move(cb)] {
                                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                                find_valid_guard_node_recursive(
                                        request_id, path_type, remaining_nodes, cb);
                            });
                    retry_thread.detach();
                }
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
    auto [info, error] = get_connection_info(request_id, PathType::standard, node);

    if (!info.is_valid())
        return callback({}, error.value_or("Unknown error."));

    nlohmann::json params{
            {"active_only", true},
            {"fields",
             {{"public_ip", true}, {"pubkey_ed25519", true}, {"storage_lmq_port", true}}}};

    if (limit)
        params["limit"] = *limit;

    oxenc::bt_dict_producer payload;
    payload.append("endpoint", "get_service_nodes");
    payload.append("params", params.dump());

    info.stream->command(
            "oxend_request",
            payload.view(),
            [this, request_id, cb = std::move(callback)](quic::message resp) {
                log::trace(cat, "{} got response for {}.", __PRETTY_FUNCTION__, request_id);
                try {
                    auto [status_code, body] = validate_response(resp, true);

                    oxenc::bt_list_consumer result_bencode{body};
                    result_bencode.skip_value();  // Skip the status code (already validated)
                    auto response_dict = result_bencode.consume_dict_consumer();
                    response_dict.skip_until("result");

                    auto result_dict = response_dict.consume_dict_consumer();
                    result_dict.skip_until("service_node_states");

                    // Process the node list
                    std::vector<service_node> result;
                    auto node = result_dict.consume_list_consumer();

                    while (!node.is_finished()) {
                        auto node_consumer = node.consume_dict_consumer();
                        result.emplace_back(
                                oxenc::from_hex(consume_string(node_consumer, "pubkey_ed25519")),
                                consume_string(node_consumer, "public_ip"),
                                consume_integer<uint16_t>(node_consumer, "storage_lmq_port"));
                    }

                    // Output the result
                    cb(result, std::nullopt);
                } catch (const std::exception& e) {
                    cb({}, e.what());
                }
            });
}

void Network::get_version(
        std::string request_id,
        PathType path_type,
        service_node node,
        std::optional<std::chrono::milliseconds> timeout,
        std::function<void(
                std::vector<int> version, connection_info info, std::optional<std::string> error)>
                callback) {
    log::trace(cat, "{} called for {}.", __PRETTY_FUNCTION__, request_id);
    auto [info, error] = get_connection_info(request_id, path_type, node);

    if (!info.is_valid())
        return callback({}, info, error.value_or("Unknown error."));

    oxenc::bt_dict_producer payload;
    info.stream->command(
            "info",
            payload.view(),
            timeout,
            [this, info, request_id, cb = std::move(callback)](quic::message resp) {
                log::trace(cat, "{} got response for {}.", __PRETTY_FUNCTION__, request_id);
                try {
                    auto [status_code, body] = validate_response(resp, true);

                    oxenc::bt_list_consumer result_bencode{body};
                    result_bencode.skip_value();  // Skip the status code (already validated)
                    auto response_dict = result_bencode.consume_dict_consumer();
                    response_dict.skip_until("result");

                    std::vector<int> version;
                    response_dict.skip_until("version");
                    auto version_list = response_dict.consume_list_consumer();

                    while (!version_list.is_finished())
                        version.emplace_back(version_list.consume_integer<int>());

                    cb(version, info, std::nullopt);
                } catch (const std::exception& e) {
                    return cb({}, info, e.what());
                }
            });
}

void Network::get_swarm(
        session::onionreq::x25519_pubkey swarm_pubkey,
        std::function<void(std::vector<service_node> swarm)> callback) {
    auto request_id = random::random_base32(4);
    log::trace(cat, "{} called for {} as {}.", __PRETTY_FUNCTION__, swarm_pubkey.hex(), request_id);
    auto cached_swarm =
            net.call_get([this, swarm_pubkey]() -> std::optional<std::vector<service_node>> {
                if (!swarm_cache.contains(swarm_pubkey.hex()))
                    return std::nullopt;
                return swarm_cache[swarm_pubkey.hex()];
            });

    // If we have a cached swarm then return it
    if (cached_swarm)
        return callback(*cached_swarm);

    // Pick a random node from the snode pool to fetch the swarm from
    log::info(
            cat,
            "No cached swarm for {} as {}, fetching from random node.",
            swarm_pubkey.hex(),
            request_id);

    with_paths_and_pool(
            request_id,
            PathType::standard,
            std::nullopt,
            [this, swarm_pubkey, request_id, cb = std::move(callback)](
                    std::vector<onion_path>,
                    std::vector<service_node> pool,
                    std::optional<std::string>) {
                if (pool.empty())
                    return cb({});

                auto updated_pool = pool;
                CSRNG rng;
                std::shuffle(updated_pool.begin(), updated_pool.end(), rng);
                auto node = updated_pool.front();

                nlohmann::json params{{"pubkey", "05" + swarm_pubkey.hex()}};
                nlohmann::json payload{
                        {"method", "get_swarm"},
                        {"params", params},
                };

                send_onion_request(
                        PathType::standard,
                        node,
                        ustring{quic::to_usv(payload.dump())},
                        swarm_pubkey,
                        quic::DEFAULT_TIMEOUT,
                        std::nullopt,
                        std::nullopt,
                        [this, swarm_pubkey, request_id, cb = std::move(cb)](
                                bool success,
                                bool timeout,
                                int16_t,
                                std::optional<std::string> response) {
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
                            net.call([this, swarm_pubkey, swarm]() mutable {
                                {
                                    std::lock_guard lock{snode_cache_mutex};
                                    swarm_cache[swarm_pubkey.hex()] = swarm;
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
    net.call([this, swarm_pubkey, swarm]() mutable {
        {
            std::lock_guard lock{snode_cache_mutex};
            swarm_cache[swarm_pubkey.hex()] = swarm;
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
    with_paths_and_pool(
            request_id,
            PathType::standard,
            std::nullopt,
            [count, request_id, cb = std::move(callback)](
                    std::vector<onion_path>,
                    std::vector<service_node> pool,
                    std::optional<std::string>) {
                log::trace(cat, "{} got response for {}.", __PRETTY_FUNCTION__, request_id);
                if (pool.size() < count)
                    return cb({});

                auto random_pool = pool;
                CSRNG rng;
                std::shuffle(random_pool.begin(), random_pool.end(), rng);

                std::vector<service_node> result(random_pool.begin(), random_pool.begin() + count);
                cb(result);
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
            [this, info, cb = std::move(handle_response)](quic::message resp) {
                log::trace(cat, "{} got response for {}.", __PRETTY_FUNCTION__, info.request_id);
                try {
                    auto [status_code, body] = validate_response(resp, false);
                    cb(true, false, status_code, body);
                } catch (const status_code_exception& e) {
                    handle_errors(info, false, e.status_code, e.what(), cb);
                } catch (const std::exception& e) {
                    handle_errors(info, resp.timed_out, -1, e.what(), cb);
                }
            });
}

void Network::send_onion_request(
        PathType path_type,
        network_destination destination,
        std::optional<ustring> body,
        std::optional<session::onionreq::x25519_pubkey> swarm_pubkey,
        std::chrono::milliseconds timeout,
        std::optional<std::string> existing_request_id,
        std::optional<request_info::RetryReason> retry_reason,
        network_response_callback_t handle_response) {
    auto request_id = existing_request_id.value_or(random::random_base32(4));
    log::trace(cat, "{} called for {}.", __PRETTY_FUNCTION__, request_id);
    with_path(
            request_id,
            path_type,
            node_for_destination(destination),
            [this,
             path_type,
             destination = std::move(destination),
             body,
             swarm_pubkey,
             timeout,
             request_id,
             retry_reason,
             cb = std::move(handle_response)](
                    std::optional<onion_path> path, std::optional<std::string> error) {
                log::trace(cat, "{} got path for {}.", __PRETTY_FUNCTION__, request_id);
                if (!path)
                    return cb(false, false, -1, error.value_or("No valid onion paths."));

                try {
                    // Construct the onion request
                    auto builder = Builder();
                    builder.set_destination(destination);
                    builder.set_destination_pubkey(pubkey_for_destination(destination));

                    for (auto& node : path->nodes)
                        builder.add_hop(
                                {ed25519_pubkey::from_bytes(node.view_remote_key()),
                                 compute_xpk(node.view_remote_key())});

                    auto payload = builder.generate_payload(body);
                    auto onion_req_payload = builder.build(payload);

                    request_info info{
                            request_id,
                            path->nodes[0],
                            "onion_req",
                            onion_req_payload,
                            body,
                            swarm_pubkey,
                            *path,
                            path_type,
                            timeout,
                            node_for_destination(destination).has_value(),
                            retry_reason};

                    send_request(
                            info,
                            path->conn_info,
                            [this,
                             builder = std::move(builder),
                             info,
                             destination = std::move(destination),
                             cb = std::move(cb)](
                                    bool success,
                                    bool timeout,
                                    int16_t status_code,
                                    std::optional<std::string> response) {
                                log::trace(
                                        cat,
                                        "{} got response for {}.",
                                        __PRETTY_FUNCTION__,
                                        info.request_id);

                                // If the request was reported as a failure or a timeout then we
                                // will have already handled the errors so just trigger the callback
                                if (!success || timeout)
                                    return cb(success, timeout, status_code, response);

                                try {
                                    // Ensure the response is long enough to be processed, if not
                                    // then handle it as an error
                                    if (!ResponseParser::response_long_enough(
                                                builder.enc_type, response->size()))
                                        throw status_code_exception{
                                                status_code,
                                                "Response is too short to be an onion request "
                                                "response: " +
                                                        *response};

                                    // Otherwise, process the onion request response
                                    std::pair<int16_t, std::optional<std::string>>
                                            processed_response;

                                    // The SnodeDestination runs via V3 onion requests and the
                                    // ServerDestination runs via V4
                                    if (std::holds_alternative<service_node>(destination))
                                        processed_response =
                                                process_v3_onion_response(builder, *response);
                                    else if (std::holds_alternative<ServerDestination>(destination))
                                        processed_response =
                                                process_v4_onion_response(builder, *response);

                                    // If we got a non 2xx status code, return the error
                                    auto& [processed_status_code, processed_body] =
                                            processed_response;
                                    if (processed_status_code < 200 || processed_status_code > 299)
                                        throw status_code_exception{
                                                processed_status_code,
                                                processed_body.value_or("Request returned "
                                                                        "non-success status "
                                                                        "code.")};

                                    // Try process the body in case it was a batch request which
                                    // failed
                                    std::optional<nlohmann::json> results;
                                    if (processed_body) {
                                        try {
                                            auto processed_body_json =
                                                    nlohmann::json::parse(*processed_body);

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
                                        return cb(
                                                true, false, processed_status_code, processed_body);

                                    // Otherwise we want to check if all of the results have the
                                    // same status code and, if so, handle that failure case
                                    // (default the 'error_body' to the 'processed_body' in case we
                                    // don't get an explicit error)
                                    int16_t single_status_code = -1;
                                    std::optional<std::string> error_body = processed_body;
                                    for (const auto& result : results->items()) {
                                        if (result.value().contains("code") &&
                                            result.value()["code"].is_number() &&
                                            (single_status_code == -1 ||
                                             result.value()["code"].get<int16_t>() !=
                                                     single_status_code))
                                            single_status_code =
                                                    result.value()["code"].get<int16_t>();
                                        else {
                                            // Either there was no code, or the code was different
                                            // from a former code in which case there wasn't an
                                            // individual detectable error (ie. it needs specific
                                            // handling) so return no error
                                            single_status_code = 200;
                                            break;
                                        }

                                        if (result.value().contains("body") &&
                                            result.value()["body"].is_string())
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
                                    handle_errors(info, false, e.status_code, e.what(), cb);
                                } catch (const std::exception& e) {
                                    handle_errors(info, false, -1, e.what(), cb);
                                }
                            });
                } catch (const std::exception& e) {
                    cb(false, false, -1, e.what());
                }
            });
}

void Network::send_onion_request(
        network_destination destination,
        std::optional<ustring> body,
        std::optional<session::onionreq::x25519_pubkey> swarm_pubkey,
        std::chrono::milliseconds timeout,
        network_response_callback_t handle_response) {
    send_onion_request(
            PathType::standard,
            destination,
            body,
            swarm_pubkey,
            timeout,
            std::nullopt,
            std::nullopt,
            handle_response);
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
            PathType::upload,
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
            std::nullopt,
            std::nullopt,
            handle_response);
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
            PathType::download,
            server,
            std::nullopt,
            std::nullopt,
            timeout,
            std::nullopt,
            std::nullopt,
            handle_response);
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
    auto timestamp = std::chrono::system_clock::now().time_since_epoch().count();
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
            PathType::standard,
            ServerDestination{
                    "http", std::string(file_server), endpoint, pubkey, 80, headers, "GET"},
            std::nullopt,
            pubkey,
            timeout,
            std::nullopt,
            std::nullopt,
            handle_response);
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

void Network::handle_node_error(service_node node, PathType path_type, onion_path path) {
    handle_errors(
            {"Node Error",
             node,
             "",
             std::nullopt,
             std::nullopt,
             std::nullopt,
             path,
             path_type,
             0ms,
             false,
             std::nullopt},
            false,
            std::nullopt,
            std::nullopt,
            std::nullopt);
}

void Network::handle_errors(
        request_info info,
        bool timeout_,
        std::optional<int16_t> status_code_,
        std::optional<std::string> response,
        std::optional<network_response_callback_t> handle_response) {
    bool timeout = timeout_;
    auto status_code = status_code_.value_or(-1);

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
                "Received decryption failure in request {} for {}, retrying.",
                info.request_id,
                path_type_name(info.path_type, single_path_mode));
        return send_onion_request(
                info.path_type,
                info.target,
                info.original_body,
                info.swarm_pubkey,
                info.timeout,
                info.request_id,
                request_info::RetryReason::decryption_failure,
                (*handle_response));
    }

    // A number of server errors can return HTML data but no status code, we want to extract those
    // cases so they can be handled properly below
    if (status_code == -1 && response) {
        const std::unordered_map<std::string, std::pair<int16_t, bool>> response_map = {
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
                if (!handle_response || !info.swarm_pubkey)
                    throw std::invalid_argument{"Unable to handle redirect."};

                auto cached_swarm = net.call_get(
                        [this, swarm_pubkey = *info.swarm_pubkey]() -> std::vector<service_node> {
                            return swarm_cache[swarm_pubkey.hex()];
                        });

                if (cached_swarm.empty())
                    throw std::invalid_argument{"Unable to handle redirect."};

                // If this was the first 421 then we want to retry using another node in the
                // swarm to get confirmation that we should switch to a different swarm
                if (!info.retry_reason ||
                    info.retry_reason != request_info::RetryReason::redirect) {
                    CSRNG rng;
                    std::vector<session::network::service_node> swarm_copy = cached_swarm;
                    std::shuffle(swarm_copy.begin(), swarm_copy.end(), rng);

                    std::optional<session::network::service_node> random_node;

                    for (auto& node : swarm_copy) {
                        if (node == info.target)
                            continue;

                        random_node = node;
                        break;
                    }

                    if (!random_node)
                        throw std::invalid_argument{"No other nodes in the swarm."};

                    log::info(
                            cat,
                            "Received 421 error in request {} for {}, retrying once before "
                            "updating swarm.",
                            info.request_id,
                            path_type_name(info.path_type, single_path_mode));
                    return send_onion_request(
                            info.path_type,
                            *random_node,
                            info.original_body,
                            info.swarm_pubkey,
                            info.timeout,
                            info.request_id,
                            request_info::RetryReason::redirect,
                            (*handle_response));
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
                        "Retry for request {} resulted in another 421 for {}, updating swarm.",
                        info.request_id,
                        path_type_name(info.path_type, single_path_mode));

                // Update the cache
                net.call([this, swarm_pubkey = *info.swarm_pubkey, swarm]() mutable {
                    {
                        std::lock_guard lock{snode_cache_mutex};
                        swarm_cache[swarm_pubkey.hex()] = swarm;
                        need_swarm_write = true;
                        need_write = true;
                    }
                    snode_cache_cv.notify_one();
                });

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

    // Check if we got an error specifying the specific node that failed
    std::vector<service_node> nodes_to_drop;
    auto updated_failure_counts = net.call_get(
            [this]() -> std::unordered_map<std::string, uint8_t> { return snode_failure_counts; });
    auto updated_path = info.path;
    bool found_invalid_node = false;

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

                auto failure_count =
                        updated_failure_counts.try_emplace(snode_it->to_string(), 0).first->second;
                updated_failure_counts[snode_it->to_string()] = failure_count + 1;

                // If the specific node has failed too many times then we should try to repair the
                // existing path by replace the bad node with another one
                if (failure_count + 1 >= snode_failure_threshold) {
                    nodes_to_drop.emplace_back(*snode_it);

                    try {
                        // If the node that's gone bad is the guard node then we just have to drop
                        // the path
                        if (snode_it == updated_path.nodes.begin())
                            throw std::runtime_error{"Cannot recover if guard node is bad"};

                        // Try to find an unused node to patch the path
                        auto [path_nodes, unused_snodes] = net.call_get(
                                [this]() -> std::pair<
                                                 std::vector<service_node>,
                                                 std::vector<service_node>> {
                                    return {all_path_nodes(), snode_pool};
                                });

                        unused_snodes.erase(
                                std::remove_if(
                                        unused_snodes.begin(),
                                        unused_snodes.end(),
                                        [&](const service_node& node) {
                                            return std::find(
                                                           path_nodes.begin(),
                                                           path_nodes.end(),
                                                           node) != path_nodes.end();
                                        }),
                                unused_snodes.end());

                        if (unused_snodes.empty())
                            throw std::runtime_error{"No remaining nodes"};

                        CSRNG rng;
                        std::shuffle(unused_snodes.begin(), unused_snodes.end(), rng);

                        std::replace(
                                updated_path.nodes.begin(),
                                updated_path.nodes.end(),
                                *snode_it,
                                unused_snodes.front());
                        log::info(
                                cat,
                                "Found bad node in path for {}, replacing node.",
                                path_type_name(info.path_type, single_path_mode));
                    } catch (...) {
                        // There aren't enough unused nodes remaining so we need to drop the path
                        updated_path.failure_count = path_failure_threshold;

                        log::info(
                                cat,
                                "Unable to replace bad node in path for {}.",
                                path_type_name(info.path_type, single_path_mode));
                    }
                }
            }
        }
    }

    // If we didn't find the specific node or the paths connection was closed then increment the
    // path failure count
    if (!found_invalid_node || !updated_path.conn_info.is_valid()) {
        if (timeout)
            updated_path.timeout_count += 1;
        else
            updated_path.failure_count += 1;

        // If the path has failed or timed out too many times we want to drop the guard
        // snode (marking it as invalid) and increment the failure count of each node in
        // the path)
        if (updated_path.failure_count >= path_failure_threshold ||
            updated_path.timeout_count >= path_timeout_threshold) {
            for (auto& it : updated_path.nodes) {
                auto failure_count =
                        updated_failure_counts.try_emplace(it.to_string(), 0).first->second;
                updated_failure_counts[it.to_string()] = failure_count + 1;

                if (failure_count + 1 >= snode_failure_threshold)
                    nodes_to_drop.emplace_back(it);
            }

            // Set the failure count of the guard node to match the threshold so we drop it
            updated_failure_counts[updated_path.nodes[0].to_string()] = snode_failure_threshold;
            nodes_to_drop.emplace_back(updated_path.nodes[0]);
        } else if (updated_path.nodes.size() < path_size) {
            // If the path doesn't have enough nodes then it's likely that this failure was
            // triggered when trying to establish a new path and, as such, we should increase the
            // failure count of the guard node since it is probably invalid
            auto failure_count =
                    updated_failure_counts.try_emplace(updated_path.nodes[0].to_string(), 0)
                            .first->second;
            updated_failure_counts[updated_path.nodes[0].to_string()] = failure_count + 1;

            if (failure_count + 1 >= snode_failure_threshold)
                nodes_to_drop.emplace_back(updated_path.nodes[0]);
        }
    }

    // If the target node has become invalid then add it to the list for removal
    if (updated_failure_counts[info.target.to_string()] >= snode_failure_threshold)
        nodes_to_drop.emplace_back(info.target);

    // Update the cache (want to wait until this has been completed incase)
    std::condition_variable cv;
    std::mutex mtx;
    bool done = false;

    net.call([this,
              request_id = info.request_id,
              path_type = info.path_type,
              target_node = info.target,
              swarm_pubkey = info.swarm_pubkey,
              old_path = info.path,
              updated_failure_counts,
              updated_path,
              nodes_to_drop,
              &cv,
              &mtx,
              &done]() mutable {
        auto already_handled_failure = false;

        // Drop the path if invalid
        if (updated_path.failure_count >= path_failure_threshold ||
            updated_path.timeout_count >= path_timeout_threshold) {
            auto old_paths_size = paths_for_type(path_type).size();

            // Close the connection immediately (just in case there are other requests happening)
            if (old_path.conn_info.conn)
                old_path.conn_info.conn->close_connection();

            old_path.conn_info.conn.reset();
            old_path.conn_info.stream.reset();

            switch (path_type) {
                case PathType::standard:
                    standard_paths.erase(
                            std::remove(standard_paths.begin(), standard_paths.end(), old_path),
                            standard_paths.end());
                    break;

                case PathType::upload:
                    upload_paths.erase(
                            std::remove(upload_paths.begin(), upload_paths.end(), old_path),
                            upload_paths.end());
                    break;

                case PathType::download:
                    download_paths.erase(
                            std::remove(download_paths.begin(), download_paths.end(), old_path),
                            download_paths.end());
                    break;
            }

            std::vector<std::string> node_descriptions;
            std::transform(
                    old_path.nodes.begin(),
                    old_path.nodes.end(),
                    std::back_inserter(node_descriptions),
                    [](service_node& node) { return node.to_string(); });
            auto path_description = "{}"_format(fmt::join(node_descriptions, ", "));
            auto new_paths_size = paths_for_type(path_type).size();

            if (new_paths_size != old_paths_size)
                log::info(
                        cat,
                        "Dropping path of type {} for {}: [{}]",
                        path_type_name(path_type, single_path_mode),
                        request_id,
                        path_description);
            else {
                // If the path was already dropped then the snode pool would have already been
                // updated so update the `already_handled_failure` to avoid double-handle the
                // failure
                already_handled_failure = true;
                log::info(
                        cat,
                        "Path of type: {} already dropped for {}: [{}]",
                        path_type_name(path_type, single_path_mode),
                        request_id,
                        path_description);
            }
        } else {
            switch (path_type) {
                case PathType::standard:
                    std::replace(
                            standard_paths.begin(), standard_paths.end(), old_path, updated_path);
                    break;

                case PathType::upload:
                    std::replace(upload_paths.begin(), upload_paths.end(), old_path, updated_path);
                    break;

                case PathType::download:
                    std::replace(
                            download_paths.begin(), download_paths.end(), old_path, updated_path);
                    break;
            }
        }

        // If we hadn't already handled the failure then update the failure counts and connection
        // status
        if (!already_handled_failure) {
            // Update the snode failure counts
            snode_failure_counts = updated_failure_counts;

            // Update the network status if we've removed all standard paths
            if (standard_paths.empty())
                update_status(ConnectionStatus::disconnected);
        }

        // Since we've finished updating the path and failure count states we can stop blocking
        // the caller (no need to wait for the snode cache to update)
        {
            std::lock_guard<std::mutex> lock(mtx);
            done = true;
        }
        cv.notify_one();

        // We've already handled the failure so don't update the cache
        if (already_handled_failure)
            return;

        // Update the snode cache
        {
            std::lock_guard lock{snode_cache_mutex};

            // Update the snode pool with the updated node failure counts
            for (size_t i = 0; i < updated_path.nodes.size(); ++i)
                std::replace(
                        snode_pool.begin(),
                        snode_pool.end(),
                        old_path.nodes[i],
                        updated_path.nodes[i]);

            // Drop any nodes which have been added to the list to drop
            for (auto& node : nodes_to_drop) {
                snode_pool.erase(
                        std::remove(snode_pool.begin(), snode_pool.end(), node), snode_pool.end());

                if (swarm_pubkey)
                    if (swarm_cache.contains(swarm_pubkey->hex())) {
                        auto updated_swarm = swarm_cache[swarm_pubkey->hex()];
                        updated_swarm.erase(
                                std::remove(updated_swarm.begin(), updated_swarm.end(), node),
                                updated_swarm.end());
                        swarm_cache[swarm_pubkey->hex()] = updated_swarm;
                    }
            }

            need_pool_write = true;
            need_swarm_write = (swarm_pubkey && swarm_cache.contains(swarm_pubkey->hex()));
            need_write = true;
        }
        snode_cache_cv.notify_one();
    });

    // Wait for the failure states to complete updating before triggering the callback
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [&] { return done; });
    }

    if (handle_response)
        (*handle_response)(false, false, status_code, response);
}

std::vector<network_service_node> convert_service_nodes(
        std::vector<session::network::service_node> nodes) {
    std::vector<network_service_node> converted_nodes;
    for (auto& node : nodes) {
        auto ed25519_pubkey_hex = oxenc::to_hex(node.view_remote_key());
        network_service_node converted_node;
        std::memcpy(converted_node.ip, node.host().data(), sizeof(converted_node.ip));
        strncpy(converted_node.ed25519_pubkey_hex, ed25519_pubkey_hex.c_str(), 64);
        converted_node.ed25519_pubkey_hex[64] = '\0';  // Ensure null termination
        converted_node.quic_port = node.port();
        converted_nodes.push_back(converted_node);
    }

    return converted_nodes;
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
        std::optional<std::vector<std::pair<std::string, std::string>>> headers;
        if (server.headers_size > 0) {
            headers = std::vector<std::pair<std::string, std::string>>{};

            for (size_t i = 0; i < server.headers_size; i++)
                headers->emplace_back(server.headers[i], server.header_values[i]);
        }

        std::optional<ustring> body;
        if (body_size > 0)
            body = {body_, body_size};

        unbox(network).send_onion_request(
                ServerDestination{
                        server.protocol,
                        server.host,
                        server.endpoint,
                        x25519_pubkey::from_hex({server.x25519_pubkey, 64}),
                        server.port,
                        headers,
                        server.method},
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
        std::optional<std::vector<std::pair<std::string, std::string>>> headers;
        if (server.headers_size > 0) {
            headers = std::vector<std::pair<std::string, std::string>>{};

            for (size_t i = 0; i < server.headers_size; i++)
                headers->emplace_back(server.headers[i], server.header_values[i]);
        }

        std::optional<std::string> file_name;
        if (file_name_)
            file_name = file_name_;

        unbox(network).upload_file_to_server(
                {data, data_len},
                ServerDestination{
                        server.protocol,
                        server.host,
                        server.endpoint,
                        x25519_pubkey::from_hex({server.x25519_pubkey, 64}),
                        server.port,
                        headers,
                        server.method},
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
                ServerDestination{
                        server.protocol,
                        server.host,
                        server.endpoint,
                        x25519_pubkey::from_hex({server.x25519_pubkey, 64}),
                        server.port,
                        std::nullopt,
                        server.method},
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
