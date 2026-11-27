#include "internal.hpp"

#include <algorithm>
#include <cstring>
#include <emmintrin.h>
#include <limits>
#include <stdexcept>

namespace mkv {
namespace {

constexpr std::uint64_t max_payload = (std::uint64_t{0xffffffff} - 1) * 16;
constexpr std::uint64_t max_aad = std::numeric_limits<std::uint64_t>::max() / 8;

bool valid(const Byte* aad, std::size_t aad_size, const Byte* in, const Byte* out,
           std::size_t size) noexcept {
    return size <= max_payload && aad_size <= max_aad && (aad_size == 0 || aad != nullptr) &&
           (size == 0 || (in && out));
}

void encode_length(Byte* out, std::uint64_t bits) noexcept {
    for (unsigned i = 0; i < 8; ++i)
        out[i] = static_cast<Byte>(bits >> (56 - 8 * i));
}

void wipe(void* address, std::size_t size) noexcept {
    auto out = static_cast<volatile Byte*>(address);
    while (size--)
        *out++ = 0;
}
} // namespace

bool available(Cipher cipher) noexcept {
    switch (cipher) {
    case Cipher::automatic:
    case Cipher::scalar:
        return true;
    case Cipher::ssse3:
        return __builtin_cpu_supports("ssse3");
    case Cipher::avx2:
    case Cipher::avx2_prefix:
        return __builtin_cpu_supports("avx2") && available(Cipher::ssse3);
    case Cipher::gfni:
        return available(Cipher::avx2) && __builtin_cpu_supports("gfni");
    case Cipher::vbmi:
        return available(Cipher::gfni) && __builtin_cpu_supports("avx512f") &&
               __builtin_cpu_supports("avx512bw") && __builtin_cpu_supports("avx512vbmi");
    }
    return false;
}

bool available(Hash hash) noexcept {
    switch (hash) {
    case Hash::automatic:
    case Hash::scalar:
        return true;
    case Hash::pclmul:
        return __builtin_cpu_supports("pclmul");
    case Hash::vpclmul:
        return available(Hash::pclmul) && __builtin_cpu_supports("avx2") &&
               __builtin_cpu_supports("vpclmulqdq");
    }
    return false;
}

const char* name(Cipher cipher) noexcept {
    switch (cipher) {
    case Cipher::automatic:
        return "auto";
    case Cipher::scalar:
        return "scalar";
    case Cipher::ssse3:
        return "ssse3";
    case Cipher::avx2:
        return "avx2";
    case Cipher::avx2_prefix:
        return "avx2-prefix";
    case Cipher::gfni:
        return "gfni";
    case Cipher::vbmi:
        return "vbmi";
    }
    return "unknown";
}

const char* name(Hash hash) noexcept {
    switch (hash) {
    case Hash::automatic:
        return "auto";
    case Hash::scalar:
        return "scalar";
    case Hash::pclmul:
        return "pclmul";
    case Hash::vpclmul:
        return "vpclmul";
    }
    return "unknown";
}

Gcm::Gcm(const Key& key, Cipher cipher, Hash hash)
    : keys_{}, powers_{}, cipher_(cipher), hash_(hash), block_{}, bulk_{}, update_{} {
    if (cipher_ == Cipher::automatic)
        cipher_ = available(Cipher::avx2_prefix) ? Cipher::avx2_prefix
                  : available(Cipher::ssse3)     ? Cipher::ssse3
                                                 : Cipher::scalar;
    if (hash_ == Hash::automatic)
        hash_ = available(Hash::vpclmul)  ? Hash::vpclmul
                : available(Hash::pclmul) ? Hash::pclmul
                                          : Hash::scalar;
    if (!available(cipher_) || !available(hash_))
        throw std::invalid_argument("requested MKV-GCM backend is unavailable");

    block_ = cipher_ == Cipher::scalar ? detail::scalar_block : detail::ssse3_block;
    if (cipher_ == Cipher::avx2)
        bulk_ = detail::avx2_ctr32;
    if (cipher_ == Cipher::avx2_prefix)
        bulk_ = detail::avx2_prefix_ctr32;
    if (cipher_ == Cipher::gfni || cipher_ == Cipher::vbmi)
        bulk_ = detail::gfni_prefix_ctr32;
    update_ = hash_ == Hash::scalar    ? detail::scalar_hash
              : hash_ == Hash::vpclmul ? detail::vpclmul_hash
                                       : detail::pclmul_hash;
    detail::expand(key, keys_.data(),
                   cipher_ == Cipher::scalar ? detail::scalar_twice : detail::ssse3_twice);
    if (cipher_ != Cipher::scalar)
        detail::fold_box_constant(keys_.data());
    powers_[0] = block_(keys_.data(), Tag{});
    if (hash_ != Hash::scalar)
        detail::pclmul_powers(powers_.data());
}

Gcm::~Gcm() noexcept {
    wipe(keys_.data(), sizeof(keys_));
    wipe(powers_.data(), sizeof(powers_));
}

Tag Gcm::authenticate(const Byte* aad, std::size_t aad_size, const Byte* data,
                      std::size_t size) const noexcept {
    Tag state{};
    auto padded = [&](const Byte* bytes, std::size_t length) {
        if (length >= 16)
            update_(state, powers_.data(), bytes, length / 16);
        if (auto tail = length % 16) {
            Tag last{};
            std::memcpy(last.data(), bytes + length - tail, tail);
            update_(state, powers_.data(), last.data(), 1);
        }
    };
    padded(aad, aad_size);
    padded(data, size);
    Tag lengths;
    encode_length(lengths.data(), std::uint64_t(aad_size) * 8);
    encode_length(lengths.data() + 8, std::uint64_t(size) * 8);
    update_(state, powers_.data(), lengths.data(), 1);
    return state;
}

void Gcm::ctr(const Nonce& nonce, const Byte* in, Byte* out, std::size_t size,
              Tag* tag_mask) const noexcept {
    std::uint32_t counter = 2;
    auto blocks = (size + 15) / 16;
    constexpr unsigned sse_threshold = 6;
    if (cipher_ != Cipher::scalar && blocks >= sse_threshold) {
        const bool cached = cipher_ != Cipher::avx2;
        const auto narrow = cached ? detail::ssse3_prefix_ctr16 : detail::ssse3_ctr16;
        const auto prefix = cached ? detail::prepare_prefix(keys_.data(), nonce) : Tag{};
        const bool wide = cipher_ == Cipher::vbmi;
        const auto batch_width = [&](std::size_t count) {
            if (wide && count > 32)
                return 64u;
            return bulk_ && count > 16 ? 32u : 16u;
        };
        // Start at J0 when a spare lane lets sealing use the same number of
        // SIMD batches. Opening computes J0 separately to keep rejection fast.
        const unsigned period = wide ? 64 : bulk_ ? 32 : 16;
        const auto tail = blocks % period;
        bool include_tag = tag_mask && tail >= sse_threshold && tail < batch_width(tail);
        std::array<Byte, 1024> stream;
        while (blocks >= sse_threshold) {
            const auto width = batch_width(blocks);
            const auto generate = width == 64   ? detail::vbmi_prefix_ctr64
                                  : width == 32 ? bulk_
                                                : narrow;
            const unsigned skip = include_tag ? 16 : 0;
            const auto chunk = std::min(size, 16 * std::size_t(width) - skip);
            if (chunk == width * 16) {
                generate(keys_.data(), nonce, prefix, counter, out, in);
            } else {
                generate(keys_.data(), nonce, prefix, counter - include_tag, stream.data(),
                         nullptr);
                if (include_tag) {
                    std::copy_n(stream.data(), 16, tag_mask->data());
                    include_tag = false;
                    tag_mask = nullptr;
                }
                for (std::size_t i = 0; i < chunk; ++i)
                    out[i] = in[i] ^ stream[skip + i];
            }
            size -= chunk;
            if (!size)
                break;
            counter += static_cast<std::uint32_t>(chunk / 16);
            in += chunk;
            out += chunk;
            blocks -= chunk / 16;
        }
    }
    if (tag_mask)
        *tag_mask = block_(keys_.data(), detail::counter_block(nonce, 1));
    while (size) {
        auto stream = block_(keys_.data(), detail::counter_block(nonce, counter++));
        const auto chunk = std::min(size, stream.size());
        for (std::size_t i = 0; i < chunk; ++i)
            out[i] = in[i] ^ stream[i];
        in += chunk;
        out += chunk;
        size -= chunk;
    }
}

bool Gcm::seal(const Nonce& nonce, const Byte* aad, std::size_t aad_size, const Byte* plaintext,
               Byte* ciphertext, std::size_t size, Tag& tag) const noexcept {
    if (!valid(aad, aad_size, plaintext, ciphertext, size))
        return false;
    Tag mask;
    ctr(nonce, plaintext, ciphertext, size, &mask);
    tag = detail::xor_block(authenticate(aad, aad_size, ciphertext, size), mask);
    return true;
}

bool Gcm::open(const Nonce& nonce, const Byte* aad, std::size_t aad_size, const Byte* ciphertext,
               Byte* plaintext, std::size_t size, const Tag& tag) const noexcept {
    if (!valid(aad, aad_size, ciphertext, plaintext, size))
        return false;
    const auto expected = detail::xor_block(authenticate(aad, aad_size, ciphertext, size),
                                            block_(keys_.data(), detail::counter_block(nonce, 1)));
    const auto want = _mm_loadu_si128(reinterpret_cast<const __m128i*>(expected.data()));
    const auto got = _mm_loadu_si128(reinterpret_cast<const __m128i*>(tag.data()));
    if (_mm_movemask_epi8(_mm_cmpeq_epi8(want, got)) != 0xffff)
        return false;
    ctr(nonce, ciphertext, plaintext, size);
    return true;
}
} // namespace mkv
