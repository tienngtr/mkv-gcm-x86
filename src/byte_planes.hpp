#pragma once
#include "internal.hpp"

namespace mkv::detail {
template <class Ops> void transform(typename Ops::Vector* state, unsigned word, const Tag* keys) {
    typename Ops::Vector substituted[4];
    for (unsigned i = 0; i < 4; ++i) {
        unsigned rotated = (word + i) & 3;
        substituted[i] = Ops::substitute(state[rotated] ^ Ops::byte(keys[0][4 * word + rotated]));
    }
    auto a = substituted[0], b = substituted[1], c = substituted[2], d = substituted[3];
    for (unsigned step = 0; step < 4; ++step) {
        auto feedback = b ^ d;
        auto next = a ^ c ^ d ^ Ops::xtime(feedback);
        a = b;
        b = c;
        c = d;
        d = next;
    }
    state[0] = Ops::substitute(a ^ Ops::byte(keys[1][4 * word]));
    state[1] = Ops::substitute(b ^ Ops::byte(keys[1][4 * word + 1]));
    state[2] = Ops::substitute(c ^ Ops::byte(keys[1][4 * word + 2]));
    state[3] = Ops::substitute(d ^ Ops::byte(keys[1][4 * word + 3]));
}

template <class Ops> void cross_words(typename Ops::Vector (&state)[16]) {
    for (unsigned i = 0; i < 4; ++i) {
        auto sum = state[i] ^ state[4 + i] ^ state[8 + i] ^ state[12 + i];
        for (unsigned j = i; j < 16; j += 4)
            state[j] ^= sum;
    }
}

template <class Ops, unsigned Group>
void transpose_step(typename Ops::Vector (&out)[16], const typename Ops::Vector (&in)[16]) {
    for (unsigned row = 0; row < 16; row += 2 * Group) {
        for (unsigned i = 0; i < Group; ++i) {
            auto a = in[row + i], b = in[row + Group + i];
            out[row + 2 * i] = Ops::template unpack<Group, false>(a, b);
            out[row + 2 * i + 1] = Ops::template unpack<Group, true>(a, b);
        }
    }
}
template <class Ops, bool Cached>
void ctr_planes(const Tag* keys, const Nonce& nonce, const Tag& prefix, std::uint32_t counter,
                Byte* out, const Byte* in) noexcept {
    // Each vector represents one byte of independent counter blocks.
    typename Ops::Vector state[16];
    for (unsigned i = 0; i < 12; ++i)
        state[i] = Ops::byte(Cached ? prefix[i] : nonce[i]);
    for (unsigned i = 12; i < 16; ++i) {
        alignas(Ops::width) Byte lanes[Ops::width];
        for (unsigned j = 0; j < Ops::width; ++j)
            lanes[j] = static_cast<Byte>((counter + j) >> (8 * (15 - i)));
        state[i] = Ops::load_lanes(lanes);
    }
    if constexpr (Cached) {
        transform<Ops>(state + 12, 3, keys);
        cross_words<Ops>(state);
        for (unsigned word = 0; word < 3; ++word)
            transform<Ops>(state + 4 * word, word, keys + 2);
        for (unsigned i = 12; i < 16; ++i)
            state[i] = Ops::byte(prefix[i]);
        cross_words<Ops>(state);
    }
    for (unsigned round = Cached ? 4 : 0; round < 18; round += 2) {
        for (unsigned word = 0; word < 4; ++word)
            transform<Ops>(state + 4 * word, word, keys + round);
        cross_words<Ops>(state);
    }
    for (unsigned i = 0; i < 16; ++i)
        state[i] ^= Ops::byte(keys[18][i]);
    typename Ops::Vector scratch[16];
    transpose_step<Ops, 1>(scratch, state);
    transpose_step<Ops, 2>(state, scratch);
    transpose_step<Ops, 4>(scratch, state);
    transpose_step<Ops, 8>(state, scratch);
    if (in) {
        for (unsigned i = 0; i < 16; ++i)
            Ops::xor_row(out + 16 * i, in + 16 * i, state[i]);
    } else {
        for (unsigned i = 0; i < 16; ++i)
            Ops::store_row(out + 16 * i, state[i]);
    }
}
} // namespace mkv::detail
