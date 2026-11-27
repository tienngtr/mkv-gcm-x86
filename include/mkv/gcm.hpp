#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace mkv {

using Byte = std::uint8_t;
using Key = std::array<Byte, 32>;
using Nonce = std::array<Byte, 12>;
using Tag = std::array<Byte, 16>;

enum class Cipher { automatic, scalar, ssse3, avx2, avx2_prefix };
enum class Hash { automatic, scalar, pclmul };

bool available(Cipher cipher) noexcept;
bool available(Hash hash) noexcept;
const char* name(Cipher cipher) noexcept;
const char* name(Hash hash) noexcept;

// A reusable MKV-128-256-GCM key. Supply a unique nonce for every seal with
// the same key, including across instances and processes. The caller manages
// nonce allocation. Concurrent calls are allowed on an initialized object.
//
// Buffers may be exactly in-place or disjoint. The nonce, tag and AAD must be separate
// from the output. A null pointer is allowed for a zero-length buffer.
// Failed authentication leaves the output untouched.
class Gcm {
  public:
    explicit Gcm(const Key& key, Cipher cipher = Cipher::automatic, Hash hash = Hash::automatic);
    ~Gcm() noexcept;
    Gcm(const Gcm&) = delete;
    Gcm& operator=(const Gcm&) = delete;

    bool seal(const Nonce& nonce, const Byte* aad, std::size_t aad_size, const Byte* plaintext,
              Byte* ciphertext, std::size_t size, Tag& tag) const noexcept;
    bool open(const Nonce& nonce, const Byte* aad, std::size_t aad_size, const Byte* ciphertext,
              Byte* plaintext, std::size_t size, const Tag& tag) const noexcept;

    Cipher cipher() const noexcept { return cipher_; }
    Hash hash() const noexcept { return hash_; }

  private:
    alignas(16) std::array<Tag, 19> keys_;
    alignas(16) std::array<Tag, 4> powers_;
    Cipher cipher_;
    Hash hash_;
    using Block = Tag (*)(const Tag*, Tag) noexcept;
    using Bulk = void (*)(const Tag*, const Nonce&, const Tag&, std::uint32_t, Byte*) noexcept;
    using Update = void (*)(Tag&, const Tag*, const Byte*, std::size_t) noexcept;
    Block block_;
    Bulk bulk_;
    Update update_;

    Tag authenticate(const Nonce&, const Byte*, std::size_t, const Byte*,
                     std::size_t) const noexcept;
    void ctr(const Nonce&, const Byte*, Byte*, std::size_t) const noexcept;
};
} // namespace mkv
