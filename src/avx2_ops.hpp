#pragma once
#include "shuffle_box.hpp"

namespace mkv::detail {
struct Avx2 {
    using Vector = __m256i;
    static Vector xor_(Vector a, Vector b) { return _mm256_xor_si256(a, b); }
    static Vector and_(Vector a, Vector b) { return _mm256_and_si256(a, b); }
    static Vector or_(Vector a, Vector b) { return _mm256_or_si256(a, b); }
    static Vector equal(Vector a, Vector b) { return _mm256_cmpeq_epi8(a, b); }
    static Vector add(Vector a, Vector b) { return _mm256_add_epi8(a, b); }
    static Vector adds(Vector a, Vector b) { return _mm256_adds_epu8(a, b); }
    static Vector sub(Vector a, Vector b) { return _mm256_sub_epi8(a, b); }
    static Vector min(Vector a, Vector b) { return _mm256_min_epu8(a, b); }
    static Vector shuffle(Vector a, Vector b) { return _mm256_shuffle_epi8(a, b); }
    static Vector byte(int b) { return _mm256_set1_epi8(static_cast<char>(b)); }
    static Vector shr4(Vector x) { return _mm256_srli_epi16(x, 4); }
    static Vector shl4(Vector x) { return _mm256_slli_epi16(x, 4); }
    static Vector table(const Tag& t) {
        return _mm256_broadcastsi128_si256(
            _mm_load_si128(reinterpret_cast<const __m128i*>(t.data())));
    }
    static constexpr unsigned width = 32;
    static Vector xtime(Vector x) {
        return add(x, x) ^ (_mm256_cmpgt_epi8(_mm256_setzero_si256(), x) & byte(0x2b));
    }
    template <unsigned Group, bool High> static Vector unpack(Vector a, Vector b) {
        if constexpr (Group == 1)
            return High ? _mm256_unpackhi_epi8(a, b) : _mm256_unpacklo_epi8(a, b);
        else if constexpr (Group == 2)
            return High ? _mm256_unpackhi_epi16(a, b) : _mm256_unpacklo_epi16(a, b);
        else if constexpr (Group == 4)
            return High ? _mm256_unpackhi_epi32(a, b) : _mm256_unpacklo_epi32(a, b);
        else
            return High ? _mm256_unpackhi_epi64(a, b) : _mm256_unpacklo_epi64(a, b);
    }
    static Vector load_lanes(const Byte* data) {
        return _mm256_load_si256(reinterpret_cast<const __m256i*>(data));
    }
    static void store_row(Byte* out, Vector x) {
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out), _mm256_castsi256_si128(x));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 256), _mm256_extracti128_si256(x, 1));
    }
    static void xor_row(Byte* out, const Byte* in, Vector x) {
        const auto write = [](Byte* dest, const Byte* source, __m128i stream) {
            const auto block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(source));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(dest), block ^ stream);
        };
        write(out, in, _mm256_castsi256_si128(x));
        write(out + 256, in + 256, _mm256_extracti128_si256(x, 1));
    }
};

} // namespace mkv::detail
