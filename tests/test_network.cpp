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

