#include "shuffle_box.hpp"

namespace mkv::detail {
namespace {
struct Sse {
    using Vector = __m128i;
    static Vector xor_(Vector a, Vector b) { return _mm_xor_si128(a, b); }
    static Vector and_(Vector a, Vector b) { return _mm_and_si128(a, b); }
    static Vector or_(Vector a, Vector b) { return _mm_or_si128(a, b); }
    static Vector andnot(Vector a, Vector b) { return _mm_andnot_si128(a, b); }
    static Vector equal(Vector a, Vector b) { return _mm_cmpeq_epi8(a, b); }
    static Vector add(Vector a, Vector b) { return _mm_add_epi8(a, b); }
    static Vector sub(Vector a, Vector b) { return _mm_sub_epi8(a, b); }
    static Vector min(Vector a, Vector b) { return _mm_min_epu8(a, b); }
    static Vector shuffle(Vector a, Vector b) { return _mm_shuffle_epi8(a, b); }
    static Vector byte(int b) { return _mm_set1_epi8(static_cast<char>(b)); }
    static Vector shr4(Vector x) { return _mm_srli_epi16(x, 4); }
    static Vector shl4(Vector x) { return _mm_slli_epi16(x, 4); }
    static Vector table(const Tag& t) {
        return _mm_load_si128(reinterpret_cast<const __m128i*>(t.data()));
    }
};

__m128i load(const Tag& block) {
    return _mm_loadu_si128(reinterpret_cast<const __m128i*>(block.data()));
}

__m128i local(__m128i x, __m128i first, __m128i second) {
    x = substitute<Sse>(Sse::xor_(x, first));
    x = _mm_shuffle_epi8(x, _mm_setr_epi8(0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14));
    const auto a_index = _mm_setr_epi8(0, 0, 0, 0, 4, 4, 4, 4, 8, 8, 8, 8, 12, 12, 12, 12);
    auto a = Sse::shuffle(x, a_index);
    auto b = Sse::shuffle(x, Sse::add(a_index, Sse::byte(1)));
    auto c = Sse::shuffle(x, Sse::add(a_index, Sse::byte(2)));
    auto d = Sse::shuffle(x, Sse::add(a_index, Sse::byte(3)));
    for (unsigned step = 0; step < 4; ++step) {
        auto feedback = Sse::xor_(b, d);
        auto reduction = Sse::and_(Sse::byte(0x2b), _mm_cmpgt_epi8(Sse::byte(0), feedback));
        auto next = a ^ c ^ d ^ (Sse::add(feedback, feedback) ^ reduction);
        a = b;
        b = c;
        c = d;
        d = next;
    }
    // Pick one byte of each replicated word component.
    x = (a & _mm_set1_epi32(0xff)) | (b & _mm_set1_epi32(0xff00)) | (c & _mm_set1_epi32(0xff0000)) |
        (d & _mm_set1_epi32(-16777216));
    return substitute<Sse>(x ^ second);
}

__m128i layer(__m128i x, __m128i first, __m128i second) {
    x = local(x, first, second);
    auto sum = x ^ _mm_shuffle_epi32(x, 0x4e);
    sum ^= _mm_shuffle_epi32(sum, 0xb1);
    return x ^ sum;
}

Tag save(__m128i x) {
    Tag result;
    _mm_storeu_si128(reinterpret_cast<__m128i*>(result.data()), x);
    return result;
}
} // namespace

Tag prepare_prefix(const Tag* keys, const Nonce& nonce) noexcept {
    auto cached = save(local(load(counter_block(nonce, 0)), load(keys[0]), load(keys[1])));
    Tag next{};
    for (unsigned i = 0; i < 4; ++i)
        next[12 + i] = cached[i] ^ cached[4 + i] ^ cached[8 + i];
    next = save(local(load(next), load(keys[2]), load(keys[3])));
    for (unsigned i = 12; i < 16; ++i)
        cached[i] = next[i];
    return cached;
}

Tag ssse3_twice(const Tag* constant, Tag state) noexcept {
    const auto zero = _mm_setzero_si128();
    return save(layer(layer(load(state), load(*constant), zero), zero, zero));
}

Tag ssse3_block(const Tag* schedule, Tag state) noexcept {
    auto x = load(state);
    for (unsigned round = 0; round < 18; round += 2)
        x = layer(x, load(schedule[round]), load(schedule[round + 1]));
    return save(x ^ load(schedule[18]));
}
} // namespace mkv::detail
