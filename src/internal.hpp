#pragma once
#include <mkv/gcm.hpp>

namespace mkv::detail {

constexpr Byte field4(Byte a, Byte b) {
    unsigned result = 0;
    unsigned x = a;
    for (unsigned bit = 0; bit < 4; ++bit) {
        result ^= x & (0u - ((b >> bit) & 1u));
        x = (x << 1) ^ (0x13u & (0u - (x >> 3)));
    }
    return static_cast<Byte>(result);
}

constexpr Byte power4(Byte a, unsigned exponent) {
    Byte result = 1;
    for (; exponent; exponent >>= 1) {
        if (exponent & 1u)
            result = field4(result, a);
        a = field4(a, a);
    }
    return result;
}

constexpr Byte box(Byte x) {
    Byte hi = x >> 4, lo = x & 15;
    Byte low_part = field4(power4(hi, 11), lo) ^ (power4(hi, 14) & (0u - unsigned(lo == 0)));
    Byte high_part =
        field4(power4(hi, 8), power4(lo, 11)) ^ (power4(lo, 14) & (0u - unsigned(hi == 0)));
    return static_cast<Byte>((high_part << 4) ^ low_part ^ 1);
}

void expand(const Key& key, Tag* schedule, Tag (*encrypt)(const Tag*, Tag) noexcept) noexcept;
Tag scalar_twice(const Tag*, Tag) noexcept;
Tag ssse3_twice(const Tag*, Tag) noexcept;
Tag scalar_block(const Tag*, Tag) noexcept;
Tag ssse3_block(const Tag*, Tag) noexcept;
inline void fold_box_constant(Tag* keys) noexcept {
    // Both linear layers preserve a uniform byte of 0x01. Absorb the output
    // offset of each S-box layer in the next key, including final whitening.
    for (unsigned round = 1; round <= 18; ++round)
        for (auto& byte : keys[round])
            byte ^= 1;
}

// Prefix shared by the cached counter kernels. The counter kernels store
// keystream if the input is null, or XOR a full tile directly with the input.
Tag prepare_prefix(const Tag*, const Nonce&) noexcept;
void ssse3_ctr16(const Tag*, const Nonce&, const Tag&, std::uint32_t, Byte*, const Byte*) noexcept;
void ssse3_prefix_ctr16(const Tag*, const Nonce&, const Tag&, std::uint32_t, Byte*,
                        const Byte*) noexcept;
void avx2_ctr32(const Tag*, const Nonce&, const Tag&, std::uint32_t, Byte*, const Byte*) noexcept;
void avx2_prefix_ctr32(const Tag*, const Nonce&, const Tag&, std::uint32_t, Byte*,
                       const Byte*) noexcept;
void gfni_prefix_ctr32(const Tag*, const Nonce&, const Tag&, std::uint32_t, Byte*,
                       const Byte*) noexcept;
void vbmi_prefix_ctr64(const Tag*, const Nonce&, const Tag&, std::uint32_t, Byte*,
                       const Byte*) noexcept;
void scalar_hash(Tag&, const Tag*, const Byte*, std::size_t) noexcept;
void pclmul_hash(Tag&, const Tag*, const Byte*, std::size_t) noexcept;
void vpclmul_hash(Tag&, const Tag*, const Byte*, std::size_t) noexcept;
void pclmul_powers(Tag*) noexcept;

inline Tag xor_block(Tag left, const Tag& right) noexcept {
    for (std::size_t i = 0; i < left.size(); ++i)
        left[i] ^= right[i];
    return left;
}

inline Tag counter_block(const Nonce& nonce, std::uint32_t count) noexcept {
    Tag block{};
    for (std::size_t i = 0; i < nonce.size(); ++i)
        block[i] = nonce[i];
    for (unsigned i = 0; i < 4; ++i)
        block[12 + i] = static_cast<Byte>(count >> (24 - 8 * i));
    return block;
}
} // namespace mkv::detail
