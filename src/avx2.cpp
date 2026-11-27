#include "shuffle_box.hpp"

namespace mkv::detail {
namespace {
struct Avx {
    using Vector = __m256i;
    static Vector xor_(Vector a, Vector b) { return _mm256_xor_si256(a, b); }
    static Vector and_(Vector a, Vector b) { return _mm256_and_si256(a, b); }
    static Vector or_(Vector a, Vector b) { return _mm256_or_si256(a, b); }
    static Vector andnot(Vector a, Vector b) { return _mm256_andnot_si256(a, b); }
    static Vector equal(Vector a, Vector b) { return _mm256_cmpeq_epi8(a, b); }
    static Vector add(Vector a, Vector b) { return _mm256_add_epi8(a, b); }
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
};

void transform(__m256i* state, unsigned word, const Tag* keys) {
    __m256i substituted[4];
    for (unsigned i = 0; i < 4; ++i) {
        unsigned rotated = (word + i) & 3;
        substituted[i] = substitute<Avx>(state[rotated] ^ Avx::byte(keys[0][4 * word + rotated]));
    }
    auto a = substituted[0], b = substituted[1], c = substituted[2], d = substituted[3];
    for (unsigned step = 0; step < 4; ++step) {
        auto feedback = b ^ d;
        auto reduction = _mm256_cmpgt_epi8(_mm256_setzero_si256(), feedback) & Avx::byte(0x2b);
        auto next = a ^ c ^ d ^ (_mm256_add_epi8(feedback, feedback) ^ reduction);
        a = b;
        b = c;
        c = d;
        d = next;
    }
    state[0] = substitute<Avx>(a ^ Avx::byte(keys[1][4 * word]));
    state[1] = substitute<Avx>(b ^ Avx::byte(keys[1][4 * word + 1]));
    state[2] = substitute<Avx>(c ^ Avx::byte(keys[1][4 * word + 2]));
    state[3] = substitute<Avx>(d ^ Avx::byte(keys[1][4 * word + 3]));
}

void cross_words(__m256i (&state)[16]) {
    for (unsigned i = 0; i < 4; ++i) {
        auto sum = state[i] ^ state[4 + i] ^ state[8 + i] ^ state[12 + i];
        for (unsigned j = i; j < 16; j += 4)
            state[j] ^= sum;
    }
}

template <unsigned Group> void transpose_step(__m256i (&out)[16], const __m256i (&in)[16]) {
    for (unsigned row = 0; row < 16; row += 2 * Group) {
        for (unsigned i = 0; i < Group; ++i) {
            auto a = in[row + i], b = in[row + Group + i];
            if constexpr (Group == 1) {
                out[row + 2 * i] = _mm256_unpacklo_epi8(a, b);
                out[row + 2 * i + 1] = _mm256_unpackhi_epi8(a, b);
            } else if constexpr (Group == 2) {
                out[row + 2 * i] = _mm256_unpacklo_epi16(a, b);
                out[row + 2 * i + 1] = _mm256_unpackhi_epi16(a, b);
            } else if constexpr (Group == 4) {
                out[row + 2 * i] = _mm256_unpacklo_epi32(a, b);
                out[row + 2 * i + 1] = _mm256_unpackhi_epi32(a, b);
            } else {
                out[row + 2 * i] = _mm256_unpacklo_epi64(a, b);
                out[row + 2 * i + 1] = _mm256_unpackhi_epi64(a, b);
            }
        }
    }
}
template <bool Cached>
void ctr32(const Tag* keys, const Nonce& nonce, const Tag& prefix, std::uint32_t counter,
           Byte* out) noexcept {
    // Each vector represents one byte of 32 independent counter blocks.
    __m256i state[16];
    for (unsigned i = 0; i < 12; ++i)
        state[i] = Avx::byte(Cached ? prefix[i] : nonce[i]);
    for (unsigned i = 12; i < 16; ++i) {
        alignas(32) Byte lanes[32];
        for (unsigned j = 0; j < 32; ++j)
            lanes[j] = static_cast<Byte>((counter + j) >> (8 * (15 - i)));
        state[i] = _mm256_load_si256(reinterpret_cast<const __m256i*>(lanes));
    }
    if constexpr (Cached) {
        transform(state + 12, 3, keys);
        cross_words(state);
        for (unsigned word = 0; word < 3; ++word)
            transform(state + 4 * word, word, keys + 2);
        for (unsigned i = 12; i < 16; ++i)
            state[i] = Avx::byte(prefix[i]);
        cross_words(state);
    }
    for (unsigned round = Cached ? 4 : 0; round < 18; round += 2) {
        for (unsigned word = 0; word < 4; ++word)
            transform(state + 4 * word, word, keys + round);
        cross_words(state);
    }
    for (unsigned i = 0; i < 16; ++i)
        state[i] ^= Avx::byte(keys[18][i]);
    __m256i scratch[16];
    transpose_step<1>(scratch, state);
    transpose_step<2>(state, scratch);
    transpose_step<4>(scratch, state);
    transpose_step<8>(state, scratch);
    for (unsigned i = 0; i < 16; ++i) {
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 16 * i),
                         _mm256_castsi256_si128(state[i]));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 16 * (i + 16)),
                         _mm256_extracti128_si256(state[i], 1));
    }
}
} // namespace

void avx2_ctr32(const Tag* keys, const Nonce& nonce, const Tag& prefix, std::uint32_t counter,
                Byte* out) noexcept {
    ctr32<false>(keys, nonce, prefix, counter, out);
}

void avx2_prefix_ctr32(const Tag* keys, const Nonce& nonce, const Tag& prefix,
                       std::uint32_t counter, Byte* out) noexcept {
    ctr32<true>(keys, nonce, prefix, counter, out);
}
} // namespace mkv::detail
