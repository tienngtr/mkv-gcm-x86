#include "internal.hpp"
#include <immintrin.h>

namespace mkv::detail {
namespace {
using V = __m128i;

V reverse_bits(V x) {
    for (unsigned shift : {1u, 2u, 4u}) {
        const int masks[] = {0, 0x55, 0x33, 0, 0x0f};
        auto mask = _mm_set1_epi8(static_cast<char>(masks[shift]));
        x = _mm_sll_epi16(x & mask, _mm_cvtsi32_si128(shift)) |
            (_mm_srl_epi16(x, _mm_cvtsi32_si128(shift)) & mask);
    }
    return x;
}

V load(const Byte* p) { return _mm_loadu_si128(reinterpret_cast<const V*>(p)); }

struct Product {
    V lo, middle, hi;
    void add(Product other) {
        lo ^= other.lo;
        middle ^= other.middle;
        hi ^= other.hi;
    }
};

Product multiply(V a, V b) {
    auto cross_a = a ^ _mm_shuffle_epi32(a, 0x4e);
    auto cross_b = b ^ _mm_shuffle_epi32(b, 0x4e);
    return {_mm_clmulepi64_si128(a, b, 0), _mm_clmulepi64_si128(cross_a, cross_b, 0),
            _mm_clmulepi64_si128(a, b, 0x11)};
}

V finish(Product p) {
    auto middle = p.middle ^ p.lo ^ p.hi;
    auto lower = p.lo ^ _mm_slli_si128(middle, 8);
    auto upper = p.hi ^ _mm_srli_si128(middle, 8);
    const auto polynomial = _mm_cvtsi32_si128(0x87);
    auto high = _mm_clmulepi64_si128(upper, polynomial, 0x01);
    auto overflow = _mm_clmulepi64_si128(high, polynomial, 0x01);
    return lower ^ _mm_clmulepi64_si128(upper, polynomial, 0) ^ _mm_slli_si128(high, 8) ^ overflow;
}
} // namespace

void pclmul_powers(Tag* powers) noexcept {
    auto base = reverse_bits(load(powers[0].data()));
    auto adj = base;
    for (unsigned i = 0; i < 4; ++i) {
        _mm_storeu_si128(reinterpret_cast<V*>(powers[i].data()), adj);
        if (i != 3)
            adj = finish(multiply(adj, base));
    }
}

void pclmul_hash(Tag& state, const Tag* powers, const Byte* data, std::size_t count) noexcept {
    auto value = reverse_bits(load(state.data()));
    const auto h1 = load(powers[0].data());
    const auto h2 = load(powers[1].data());
    const auto h3 = load(powers[2].data());
    const auto h4 = load(powers[3].data());
    while (count >= 4) {
        auto sum = multiply(value ^ reverse_bits(load(data)), h4);
        sum.add(multiply(reverse_bits(load(data + 16)), h3));
        sum.add(multiply(reverse_bits(load(data + 32)), h2));
        sum.add(multiply(reverse_bits(load(data + 48)), h1));
        value = finish(sum);
        data += 64;
        count -= 4;
    }
    while (count--) {
        value = finish(multiply(value ^ reverse_bits(load(data)), h1));
        data += 16;
    }
    _mm_storeu_si128(reinterpret_cast<V*>(state.data()), reverse_bits(value));
}
} // namespace mkv::detail
