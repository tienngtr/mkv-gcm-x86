#include "avx2_ops.hpp"
#include "byte_planes.hpp"
#include "gfni_matrix.hpp"

namespace mkv::detail {
namespace {

constexpr Byte aes_field_multiply(Byte left, Byte right) {
    unsigned a = left, b = right, result = 0;
    for (unsigned i = 0; i < 8; ++i) {
        if (b & 1)
            result ^= a;
        a = (a << 1) ^ (0x11b * (a >> 7));
        b >>= 1;
    }
    return static_cast<Byte>(result);
}

constexpr Byte embed(Byte nibble) {
    // The AES-field element 0x5c is a root of the MKV nibble polynomial
    // x^4 + x + 1. Map the four polynomial basis elements to its powers.
    Byte out = 0, basis = 1;
    for (unsigned i = 0; i < 4; ++i) {
        if ((nibble >> i) & 1)
            out ^= basis;
        basis = aes_field_multiply(basis, 0x5c);
    }
    return out;
}

constexpr Byte fourth_power(Byte byte) {
    const auto square = aes_field_multiply(byte, byte);
    return aes_field_multiply(square, square);
}

constexpr auto encode_high = gfni_matrix([](Byte x) { return embed(x >> 4); });
constexpr auto encode_low = gfni_matrix([](Byte x) { return embed(x & 15); });
constexpr auto encode_high_eighth = gfni_matrix([](Byte x) { return embed(power4(x >> 4, 8)); });
constexpr auto frobenius_fourth = gfni_matrix(fourth_power);

// Find four dual basis rows. The map is used only on subfield elements,
// so any full-byte linear extension with these outputs is equivalent.
constexpr std::uint64_t decode_matrix() {
    std::uint64_t result = 0;
    for (unsigned i = 0; i < 4; ++i) {
        for (unsigned row = 1; row < 256; ++row) {
            bool match = true;
            for (unsigned j = 0; j < 4; ++j) {
                unsigned bits = row & embed(Byte(1u << j));
                bits ^= bits >> 4;
                bits ^= bits >> 2;
                bits ^= bits >> 1;
                match &= (bits & 1u) == unsigned(i == j);
            }
            if (match) {
                result |= std::uint64_t(row) << (8 * (7 - i));
                break;
            }
        }
    }
    return result;
}

constexpr auto decode_low = decode_matrix();
constexpr auto decode_high = decode_low >> 32;

struct Gfni : Avx2 {
    static Vector matrix(std::uint64_t x) { return _mm256_set1_epi64x(static_cast<long long>(x)); }
    static Vector xtime(Vector x) {
        return _mm256_gf2p8affine_epi64_epi8(x, matrix(xtime_matrix), 0);
    }
    static Vector substitute(Vector x) {
        const auto zero = _mm256_setzero_si256();
        const auto a = _mm256_gf2p8affine_epi64_epi8(x, matrix(encode_high), 0);
        const auto b = _mm256_gf2p8affine_epi64_epi8(x, matrix(encode_low), 0);
        // Invert and raise to the fourth power: x^(-4) == x^11 for x != 0.
        // GFNI inversion sends zero to zero as required by the MKV S-box.
        const auto a11 = _mm256_gf2p8affineinv_epi64_epi8(a, matrix(frobenius_fourth), 0);
        const auto b11 = _mm256_gf2p8affineinv_epi64_epi8(b, matrix(frobenius_fourth), 0);
        const auto a8 = _mm256_gf2p8affine_epi64_epi8(x, matrix(encode_high_eighth), 0);
        const auto inverse_a = _mm256_gf2p8affine_epi64_epi8(a11, matrix(frobenius_fourth), 0);
        const auto inverse_b = _mm256_gf2p8affine_epi64_epi8(b11, matrix(frobenius_fourth), 0);
        const auto low = _mm256_gf2p8mul_epi8(a11, b) | (inverse_a & equal(b, zero));
        const auto high = _mm256_gf2p8mul_epi8(a8, b11) | (inverse_b & equal(a, zero));
        return _mm256_gf2p8affine_epi64_epi8(low, matrix(decode_low), 0) |
               _mm256_gf2p8affine_epi64_epi8(high, matrix(decode_high), 0);
    }
};
} // namespace

void gfni_prefix_ctr32(const Tag* keys, const Nonce& nonce, const Tag& prefix,
                       std::uint32_t counter, Byte* out, const Byte* in) noexcept {
    ctr_planes<Gfni, true>(keys, nonce, prefix, counter, out, in);
}
} // namespace mkv::detail
