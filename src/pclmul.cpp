#include "pclmul_common.hpp"

namespace mkv::detail {
using namespace clmul;
namespace {
V reverse_bits(V x) {
    for (unsigned shift : {1u, 2u, 4u}) {
        const int masks[] = {0, 0x55, 0x33, 0, 0x0f};
        auto mask = _mm_set1_epi8(static_cast<char>(masks[shift]));
        x = _mm_sll_epi16(x & mask, _mm_cvtsi32_si128(shift)) |
            (_mm_srl_epi16(x, _mm_cvtsi32_si128(shift)) & mask);
    }
    return x;
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
