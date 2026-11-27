#pragma once
#include "internal.hpp"
#include <immintrin.h>

namespace mkv::detail::clmul {
using V = __m128i;

inline V load(const Byte* p) { return _mm_loadu_si128(reinterpret_cast<const V*>(p)); }

struct Product {
    V lo, middle, hi;
    void add(Product other) {
        lo ^= other.lo;
        middle ^= other.middle;
        hi ^= other.hi;
    }
};

inline Product multiply(V a, V b) {
    auto cross_a = a ^ _mm_shuffle_epi32(a, 0x4e);
    auto cross_b = b ^ _mm_shuffle_epi32(b, 0x4e);
    return {_mm_clmulepi64_si128(a, b, 0), _mm_clmulepi64_si128(cross_a, cross_b, 0),
            _mm_clmulepi64_si128(a, b, 0x11)};
}

inline V finish(Product p) {
    auto middle = p.middle ^ p.lo ^ p.hi;
    auto lower = p.lo ^ _mm_slli_si128(middle, 8);
    auto upper = p.hi ^ _mm_srli_si128(middle, 8);
    const auto polynomial = _mm_cvtsi32_si128(0x87);
    auto high = _mm_clmulepi64_si128(upper, polynomial, 0x01);
    auto overflow = _mm_clmulepi64_si128(high, polynomial, 0x01);
    return lower ^ _mm_clmulepi64_si128(upper, polynomial, 0) ^ _mm_slli_si128(high, 8) ^ overflow;
}
} // namespace mkv::detail::clmul
