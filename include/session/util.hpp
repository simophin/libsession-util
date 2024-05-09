#pragma once

#include <array>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
#include <type_traits>
#include <vector>

#include "types.hpp"

namespace session {

// Helper function to go to/from char pointers to unsigned char pointers:
inline const unsigned char* to_unsigned(const char* x) {
    return reinterpret_cast<const unsigned char*>(x);
}
inline unsigned char* to_unsigned(char* x) {
    return reinterpret_cast<unsigned char*>(x);
}
inline const unsigned char* to_unsigned(const std::byte* x) {
    return reinterpret_cast<const unsigned char*>(x);
}
inline unsigned char* to_unsigned(std::byte* x) {
    return reinterpret_cast<unsigned char*>(x);
}
// These do nothing, but having them makes template metaprogramming easier:
inline const unsigned char* to_unsigned(const unsigned char* x) {
    return x;
}
inline unsigned char* to_unsigned(unsigned char* x) {
    return x;
}
inline const char* from_unsigned(const unsigned char* x) {
    return reinterpret_cast<const char*>(x);
}
inline char* from_unsigned(unsigned char* x) {
    return reinterpret_cast<char*>(x);
}
// Helper function to switch between basic_string_view<C> and ustring_view
inline ustring_view to_unsigned_sv(std::string_view v) {
    return {to_unsigned(v.data()), v.size()};
}
inline ustring_view to_unsigned_sv(std::basic_string_view<std::byte> v) {
    return {to_unsigned(v.data()), v.size()};
}
inline ustring_view to_unsigned_sv(ustring_view v) {
    return v;  // no-op, but helps with template metaprogamming
}
inline std::string_view from_unsigned_sv(ustring_view v) {
    return {from_unsigned(v.data()), v.size()};
}
template <size_t N>
inline std::string_view from_unsigned_sv(const std::array<unsigned char, N>& v) {
    return {from_unsigned(v.data()), v.size()};
}
template <typename T, typename A>
inline std::string_view from_unsigned_sv(const std::vector<T, A>& v) {
    return {from_unsigned(v.data()), v.size()};
}
template <typename Char, size_t N>
inline std::basic_string_view<Char> to_sv(const std::array<Char, N>& v) {
    return {v.data(), N};
}

inline uint64_t get_timestamp() {
    return std::chrono::steady_clock::now().time_since_epoch().count();
}

/// Returns true if the first string is equal to the second string, compared case-insensitively.
inline bool string_iequal(std::string_view s1, std::string_view s2) {
    return std::equal(s1.begin(), s1.end(), s2.begin(), s2.end(), [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) ==
               std::tolower(static_cast<unsigned char>(b));
    });
}

using uc32 = std::array<unsigned char, 32>;
using uc33 = std::array<unsigned char, 33>;
using uc64 = std::array<unsigned char, 64>;

/// Takes a container of string-like binary values and returns a vector of ustring_views viewing
/// those values.  This can be used on a container of any type with a `.data()` and a `.size()`
/// where `.data()` is a one-byte value pointer; std::string, std::string_view, ustring,
/// ustring_view, etc. apply, as does std::array of 1-byte char types.
///
/// This is useful in various libsession functions that require such a vector.  Note that the
/// returned vector's views are valid only as the original container remains alive; this is
/// typically used inline rather than stored, such as:
///
///     session::function_taking_a_view_vector(session::to_view_vector(mydata));
///
/// There are two versions of this: the first takes a generic iterator pair; the second takes a
/// single container.
template <typename It>
std::vector<ustring_view> to_view_vector(It begin, It end) {
    std::vector<ustring_view> vec;
    vec.reserve(std::distance(begin, end));
    for (; begin != end; ++begin) {
        if constexpr (std::is_same_v<std::remove_cv_t<decltype(*begin)>, char*>)  // C strings
            vec.emplace_back(*begin);
        else {
            static_assert(
                    sizeof(*begin->data()) == 1,
                    "to_view_vector can only be used with containers of string-like types of "
                    "1-byte characters");
            vec.emplace_back(reinterpret_cast<const unsigned char*>(begin->data()), begin->size());
        }
    }
    return vec;
}

template <typename Container>
std::vector<ustring_view> to_view_vector(const Container& c) {
    return to_view_vector(c.begin(), c.end());
}

/// Splits a string on some delimiter string and returns a vector of string_view's pointing into the
/// pieces of the original string.  The pieces are valid only as long as the original string remains
/// valid.  Leading and trailing empty substrings are not removed.  If delim is empty you get back a
/// vector of string_views each viewing one character.  If `trim` is true then leading and trailing
/// empty values will be suppressed.
///
///     auto v = split("ab--c----de", "--"); // v is {"ab", "c", "", "de"}
///     auto v = split("abc", ""); // v is {"a", "b", "c"}
///     auto v = split("abc", "c"); // v is {"ab", ""}
///     auto v = split("abc", "c", true); // v is {"ab"}
///     auto v = split("-a--b--", "-"); // v is {"", "a", "", "b", "", ""}
///     auto v = split("-a--b--", "-", true); // v is {"a", "", "b"}
///
std::vector<std::string_view> split(
        std::string_view str, std::string_view delim, bool trim = false);

}  // namespace session
