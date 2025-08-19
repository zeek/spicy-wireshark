#pragma once

#include <algorithm>

#include <hilti/rt/util.h>

namespace spicy::wireshark::util {

template<typename T>
class StaticStorage {
public:
    StaticStorage() = default;

    T* store(T&& t) {
        if ( _storage.empty() || _storage.back().size() >= SLICE_SIZE ) {
            _storage.emplace_back();
            _storage.back().reserve(SLICE_SIZE);
        }

        _storage.back().emplace_back(std::move(t));
        return &_storage.back().back();
    }

    StaticStorage(const StaticStorage& other) = delete;
    StaticStorage(StaticStorage&& other) = delete;
    StaticStorage& operator=(const StaticStorage& other) = delete;
    StaticStorage& operator=(StaticStorage&& other) = delete;

private:
    static const size_t SLICE_SIZE = 10;
    std::vector<std::vector<T>> _storage;
};

inline std::string toLower(const std::string& s) {
    std::string t = s;
    std::transform(t.begin(), t.end(), t.begin(), [](unsigned char c) { return std::tolower(c); });
    return t;
}

inline std::string stripScope(const std::string& fqid) { return hilti::rt::rsplit1(fqid, "::").second; }

/**
 * Pairs up the elements of two vectors.
 *
 * From http://stackoverflow.com/questions/10420380/c-zip-variadic-templates.
 */
template<typename A, typename B>
std::vector<std::pair<A, B>> zip2(const std::vector<A>& lhs, const std::vector<B>& rhs) {
    std::vector<std::pair<A, B>> result;
    for ( std::pair<typename std::vector<A>::const_iterator, typename std::vector<B>::const_iterator> iter =
              std::pair<typename std::vector<A>::const_iterator, typename std::vector<B>::const_iterator>(lhs.cbegin(),
                                                                                                          rhs.cbegin());
          iter.first != lhs.end() and iter.second != rhs.end(); ++iter.first, ++iter.second )
        result.emplace_back(*iter.first, *iter.second);
    return result;
}

} // namespace spicy::wireshark::util
