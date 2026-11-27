#include "pclmul_common.hpp"

namespace mkv::detail {
using namespace clmul;
namespace {
__m256i reverse_bits(__m256i x) noexcept {
    const auto nibble = _mm256_set1_epi8(15);
    const auto table128 = _mm_setr_epi8(0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15);
    const auto table = _mm256_broadcastsi128_si256(table128);
    return _mm256_slli_epi16(_mm256_shuffle_epi8(table, x & nibble), 4) |
           _mm256_shuffle_epi8(table, _mm256_srli_epi16(x, 4) & nibble);
}

V fold(__m256i x) noexcept { return _mm256_castsi256_si128(x) ^ _mm256_extracti128_si256(x, 1); }
} // namespace

void vpclmul_hash(Tag& state, const Tag* powers, const Byte* data, std::size_t count) noexcept {
    // AAD, final blocks and short records stay on the 128-bit path.
    if (count < 4) {
        pclmul_hash(state, powers, data, count);
        return;
    }
    auto value = _mm256_castsi256_si128(reverse_bits(_mm256_zextsi128_si256(load(state.data()))));
    const auto h34 = _mm256_set_m128i(load(powers[2].data()), load(powers[3].data()));
    const auto h12 = _mm256_set_m128i(load(powers[0].data()), load(powers[1].data()));
    const auto karatsuba = [](__m256i x) { return x ^ _mm256_shuffle_epi32(x, 0x4e); };
    const auto cross34 = karatsuba(h34);
    const auto cross12 = karatsuba(h12);
    while (count >= 4) {
        const auto a = reverse_bits(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(data))) ^
                       _mm256_zextsi128_si256(value);
        const auto b =
            reverse_bits(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + 32)));
        const auto lo = _mm256_clmulepi64_epi128(a, h34, 0) ^ _mm256_clmulepi64_epi128(b, h12, 0);
        const auto mid = _mm256_clmulepi64_epi128(karatsuba(a), cross34, 0) ^
                         _mm256_clmulepi64_epi128(karatsuba(b), cross12, 0);
        const auto hi =
            _mm256_clmulepi64_epi128(a, h34, 0x11) ^ _mm256_clmulepi64_epi128(b, h12, 0x11);
        value = finish({fold(lo), fold(mid), fold(hi)});
        data += 64;
        count -= 4;
    }
    const auto h1 = load(powers[0].data());
    while (count--) {
        const auto x = reverse_bits(_mm256_zextsi128_si256(load(data)));
        value = finish(multiply(value ^ _mm256_castsi256_si128(x), h1));
        data += 16;
    }
    const auto result = reverse_bits(_mm256_zextsi128_si256(value));
    _mm_storeu_si128(reinterpret_cast<V*>(state.data()), _mm256_castsi256_si128(result));
}
} // namespace mkv::detail
