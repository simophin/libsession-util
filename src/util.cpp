#include <session/util.hpp>

namespace session {

std::vector<std::string_view> split(std::string_view str, const std::string_view delim, bool trim) {
    std::vector<std::string_view> results;
    // Special case for empty delimiter: splits on each character boundary:
    if (delim.empty()) {
        results.reserve(str.size());
        for (size_t i = 0; i < str.size(); i++)
            results.emplace_back(str.data() + i, 1);
        return results;
    }

    for (size_t pos = str.find(delim); pos != std::string_view::npos; pos = str.find(delim)) {
        if (!trim || !results.empty() || pos > 0)
            results.push_back(str.substr(0, pos));
        str.remove_prefix(pos + delim.size());
    }
    if (!trim || str.size())
        results.push_back(str);
    else
        while (!results.empty() && results.back().empty())
            results.pop_back();
    return results;
}

}  // namespace session
