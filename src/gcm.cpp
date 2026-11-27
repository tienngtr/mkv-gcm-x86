#include "internal.hpp"

#include <algorithm>
#include <cstring>
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
        hash_ = available(Hash::pclmul) ? Hash::pclmul : Hash::scalar;
    if (!available(cipher_) || !available(hash_))
        throw std::invalid_argument("requested MKV-GCM backend is unavailable");

    block_ = cipher_ == Cipher::scalar ? detail::scalar_block : detail::ssse3_block;
    if (cipher_ == Cipher::avx2)
        bulk_ = detail::avx2_ctr32;
    if (cipher_ == Cipher::avx2_prefix)
        bulk_ = detail::avx2_prefix_ctr32;
    update_ = hash_ == Hash::scalar ? detail::scalar_hash : detail::pclmul_hash;
    detail::expand(key, keys_.data(),
                   cipher_ == Cipher::scalar ? detail::scalar_twice : detail::ssse3_twice);
    powers_[0] = block_(keys_.data(), Tag{});
    if (hash_ == Hash::pclmul)
        detail::pclmul_powers(powers_.data());
}

Gcm::~Gcm() noexcept {
    wipe(keys_.data(), sizeof(keys_));
    wipe(powers_.data(), sizeof(powers_));
}

Tag Gcm::authenticate(const Nonce& nonce, const Byte* aad, std::size_t aad_size, const Byte* data,
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
    return detail::xor_block(state, block_(keys_.data(), detail::counter_block(nonce, 1)));
}

void Gcm::ctr(const Nonce& nonce, const Byte* in, Byte* out, std::size_t size) const noexcept {
    std::uint32_t counter = 2;
    if (bulk_ && size >= 512) {
        Tag prefix{};
        if (cipher_ == Cipher::avx2_prefix)
            prefix = detail::prepare_prefix(keys_.data(), nonce);
        std::array<Byte, 512> stream;
        while (size >= stream.size()) {
            bulk_(keys_.data(), nonce, prefix, counter, stream.data());
            for (std::size_t i = 0; i < stream.size(); ++i)
                out[i] = in[i] ^ stream[i];
            counter += 32;
            in += stream.size();
            out += stream.size();
            size -= stream.size();
        }
    }
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
    ctr(nonce, plaintext, ciphertext, size);
    tag = authenticate(nonce, aad, aad_size, ciphertext, size);
    return true;
}

bool Gcm::open(const Nonce& nonce, const Byte* aad, std::size_t aad_size, const Byte* ciphertext,
               Byte* plaintext, std::size_t size, const Tag& tag) const noexcept {
    if (!valid(aad, aad_size, ciphertext, plaintext, size))
        return false;
    const auto expected = authenticate(nonce, aad, aad_size, ciphertext, size);
    unsigned diff = 0;
    for (std::size_t i = 0; i < tag.size(); ++i)
        diff |= expected[i] ^ tag[i];
    if (diff != 0)
        return false;
    ctr(nonce, ciphertext, plaintext, size);
    return true;
}
} // namespace mkv
