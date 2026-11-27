#include "byte_planes.hpp"
#include "gfni_matrix.hpp"
#include <immintrin.h>

namespace mkv::detail {
namespace {
constexpr std::array<Byte, 256> make_boxes() {
    std::array<Byte, 256> result{};
    for (unsigned i = 0; i < result.size(); ++i)
        result[i] = box(static_cast<Byte>(i)) ^ 1;
    return result;
}

alignas(64) constexpr auto boxes = make_boxes();

struct Vbmi {
    using Vector = __m512i;
    static constexpr unsigned width = 64;

    static Vector byte(int b) { return _mm512_set1_epi8(static_cast<char>(b)); }
    static Vector load_lanes(const Byte* data) { return _mm512_load_si512(data); }
    static Vector xtime(Vector x) {
        return _mm512_gf2p8affine_epi64_epi8(
            x, _mm512_set1_epi64(static_cast<long long>(xtime_matrix)), 0);
    }
    static Vector substitute(Vector x) {
        // Each permute uses the low seven bits within one pair of registers.
        // The top bit chooses the half using a mask register.
        const auto low =
            _mm512_permutex2var_epi8(load_lanes(boxes.data()), x, load_lanes(boxes.data() + 64));
        const auto high = _mm512_permutex2var_epi8(load_lanes(boxes.data() + 128), x,
                                                   load_lanes(boxes.data() + 192));
        return _mm512_mask_blend_epi8(_mm512_movepi8_mask(x), low, high);
    }
    template <unsigned Group, bool High> static Vector unpack(Vector a, Vector b) {
        if constexpr (Group == 1)
            return High ? _mm512_unpackhi_epi8(a, b) : _mm512_unpacklo_epi8(a, b);
        else if constexpr (Group == 2)
            return High ? _mm512_unpackhi_epi16(a, b) : _mm512_unpacklo_epi16(a, b);
        else if constexpr (Group == 4)
            return High ? _mm512_unpackhi_epi32(a, b) : _mm512_unpacklo_epi32(a, b);
        else
            return High ? _mm512_unpackhi_epi64(a, b) : _mm512_unpacklo_epi64(a, b);
    }
    static void store_row(Byte* out, Vector x) {
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out), _mm512_castsi512_si128(x));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 256), _mm512_extracti32x4_epi32(x, 1));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 512), _mm512_extracti32x4_epi32(x, 2));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 768), _mm512_extracti32x4_epi32(x, 3));
    }
    static void xor_row(Byte* out, const Byte* in, Vector x) {
        const auto write = [](Byte* dest, const Byte* source, __m128i stream) {
            const auto block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(source));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(dest), block ^ stream);
        };
        write(out, in, _mm512_castsi512_si128(x));
        write(out + 256, in + 256, _mm512_extracti32x4_epi32(x, 1));
        write(out + 512, in + 512, _mm512_extracti32x4_epi32(x, 2));
        write(out + 768, in + 768, _mm512_extracti32x4_epi32(x, 3));
    }
};
} // namespace

void vbmi_prefix_ctr64(const Tag* keys, const Nonce& nonce, const Tag& prefix,
                       std::uint32_t counter, Byte* out, const Byte* in) noexcept {
    ctr_planes<Vbmi, true>(keys, nonce, prefix, counter, out, in);
}
} // namespace mkv::detail
