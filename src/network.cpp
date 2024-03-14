#include "session/network.hpp"

#include <sodium/core.h>
#include <sodium/crypto_sign_ed25519.h>

#include <nlohmann/json.hpp>
#include <oxen/quic.hpp>

#include "session/export.h"
#include "session/network.h"
#include "session/util.hpp"

using namespace session;
using namespace oxen::quic;
using namespace oxenc::literals;

namespace session::network {

constexpr auto ALPN = "oxenstorage"sv;
const ustring uALPN{reinterpret_cast<const unsigned char*>(ALPN.data()), ALPN.size()};

void send_request(
        ustring_view ed_sk,
        RemoteAddress target,
        std::string endpoint,
        std::optional<ustring> body,
        std::function<void(bool success, int16_t status_code, std::optional<std::string> response)>
                handle_response) {
    Network net;
    std::promise<nlohmann::json> sns_prom;
    auto creds = GNUTLSCreds::make_from_ed_seckey(std::string(from_unsigned_sv(ed_sk)));
    auto ep = net.endpoint(Address{"0.0.0.0", 0}, opt::outbound_alpns{{uALPN}});
    auto c = ep->connect(target, creds);
    auto s = c->open_stream<BTRequestStream>();
    bstring_view payload = {};

    if (body)
        payload = convert_sv<std::byte>(from_unsigned_sv(*body));

    s->command(std::move(endpoint), payload, [&target, &sns_prom](message resp) {
        try {
            if (resp.is_error())
                throw std::runtime_error{"Failed to fetch service node list from seed node"};

            sns_prom.set_value(nlohmann::json::parse(resp.body()));
        } catch (...) {
            sns_prom.set_exception(std::current_exception());
        }
    });

    nlohmann::json sns;
    try {
        sns = sns_prom.get_future().get();
        if (!(sns.is_array() && sns.size() == 2 && sns[0].get<int16_t>() == 200)) {
            handle_response(
                    false, sns[0].get<int16_t>(), sns.dump());  // TODO: Check for response data
            return;
        }

        handle_response(true, sns[0].get<int16_t>(), sns.dump());

    } catch (const std::exception& e) {
        std::cerr << "\e[3mFailed to obtain service node list: " << e.what() << "\e[0m\n";
        // result.clear();
        handle_response(false, -1, e.what());
    }
}

}  // namespace session::network

extern "C" {

using namespace session::network;

LIBSESSION_C_API void network_send_request(
        const unsigned char* ed25519_secretkey_bytes,
        const remote_address remote,
        const char* endpoint,
        size_t endpoint_size,
        const unsigned char* body_,
        size_t body_size,
        void (*callback)(
                bool success,
                int16_t status_code,
                const char* response,
                size_t response_size,
                void*),
        void* ctx) {
    assert(ed25519_secretkey_bytes && endpoint && callback);
    try {
        std::optional<ustring> body;
        if (body_size > 0)
            body = {body_, body_size};

        send_request(
                {ed25519_secretkey_bytes, 66},
                {remote.pubkey, remote.ip, remote.port},
                {endpoint, endpoint_size},
                body,
                [callback, ctx](
                        bool success, int16_t status_code, std::optional<std::string> response) {
                    callback(success, status_code, response->data(), response->size(), ctx);
                });
    } catch (const std::exception& e) {
        std::string_view error = e.what();
        callback(false, -1, e.what(), error.size(), ctx);
    }
}

}  // extern "C"