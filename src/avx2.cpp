#include "avx2_ops.hpp"
#include "byte_planes.hpp"

namespace mkv::detail {
namespace {
struct Avx : Avx2 {
    static Vector substitute(Vector x) { return detail::substitute<Avx2>(x); }
};
} // namespace

void avx2_ctr32(const Tag* keys, const Nonce& nonce, const Tag& prefix, std::uint32_t counter,
                Byte* out, const Byte* in) noexcept {
    ctr_planes<Avx, false>(keys, nonce, prefix, counter, out, in);
}

void avx2_prefix_ctr32(const Tag* keys, const Nonce& nonce, const Tag& prefix,
                       std::uint32_t counter, Byte* out, const Byte* in) noexcept {
    ctr_planes<Avx, true>(keys, nonce, prefix, counter, out, in);
}
} // namespace mkv::detail
