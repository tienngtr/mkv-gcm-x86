#pragma once
#include "internal.hpp"

namespace mkv::detail {

// VGF2P8AFFINEQB takes one output row per byte, in reverse byte order.
template <class Map> constexpr std::uint64_t gfni_matrix(Map map) {
    std::uint64_t matrix = 0;
    for (unsigned i = 0; i < 8; ++i) {
        const auto column = map(Byte(1u << i));
        for (unsigned j = 0; j < 8; ++j)
            matrix |= std::uint64_t((column >> j) & 1u) << (8 * (7 - j) + i);
    }
    return matrix;
}

inline constexpr auto xtime_matrix =
    gfni_matrix([](Byte x) { return ((x << 1) ^ ((x >> 7) * 0x2b)) & 0xff; });
} // namespace mkv::detail
