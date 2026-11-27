#include "fixtures.hpp"
#include "internal.hpp"

#include <algorithm>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {
using namespace mkv;

void require(bool good, const char* message) {
    if (!good)
        throw std::runtime_error(message);
}

std::vector<Byte> hex(std::string_view input) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::vector<Byte> bytes;
    for (std::size_t i = 0; i < input.size(); i += 2)
        bytes.push_back(static_cast<Byte>(16 * digits.find(input[i]) + digits.find(input[i + 1])));
    return bytes;
}

void test(Cipher cipher, Hash hash) {
    Key key;
    Nonce nonce;
    std::array<Byte, 20> aad;
    for (unsigned i = 0; i < key.size(); ++i)
        key[i] = static_cast<Byte>(i);
    for (unsigned i = 0; i < nonce.size(); ++i)
        nonce[i] = static_cast<Byte>(0x20 + i);
    for (unsigned i = 0; i < aad.size(); ++i)
        aad[i] = static_cast<Byte>(0x40 + i);

    Gcm gcm(key, cipher, hash);
    cipher = gcm.cipher();
    for (const auto& sample : fixtures) {
        std::vector<Byte> input(sample.size);
        for (unsigned i = 0; i < sample.size; ++i)
            input[i] = static_cast<Byte>(7 + 13 * i);
        const auto aad_size = sample.size ? aad.size() : 0;
        auto buffer = input;
        Tag tag;
        require(
            gcm.seal(nonce, aad.data(), aad_size, buffer.data(), buffer.data(), buffer.size(), tag),
            "seal rejected valid input");
        require(buffer == hex(sample.ciphertext), "reference ciphertext mismatch");
        auto expected_tag = hex(sample.tag);
        require(std::equal(tag.begin(), tag.end(), expected_tag.begin()), "reference tag mismatch");

        auto untouched = buffer;
        auto bad_tag = tag;
        bad_tag.back() ^= 1;
        require(!gcm.open(nonce, aad.data(), aad_size, buffer.data(), buffer.data(), buffer.size(),
                          bad_tag),
                "forged tag accepted");
        require(buffer == untouched, "forgery modified output");
        if (sample.size) {
            buffer[0] ^= 1;
            const auto changed = buffer;
            require(!gcm.open(nonce, aad.data(), aad_size, buffer.data(), buffer.data(),
                              buffer.size(), tag),
                    "modified ciphertext accepted");
            require(buffer == changed, "modified ciphertext changed output");
            buffer = untouched;
        }
        require(
            gcm.open(nonce, aad.data(), aad_size, buffer.data(), buffer.data(), buffer.size(), tag),
            "open rejected a valid tag");
        require(buffer == input, "in-place plaintext mismatch");
    }
    Tag tag;
    require(!gcm.seal(nonce, nullptr, 1, nullptr, nullptr, 0, tag), "null AAD accepted");
    require(!gcm.seal(nonce, nullptr, 0, nullptr, nullptr, 1, tag), "null record accepted");
    constexpr std::size_t too_long = (std::uint64_t{0xffffffff} - 1) * 16 + 1;
    Byte dummy = 0;
    require(!gcm.seal(nonce, nullptr, 0, &dummy, &dummy, too_long, tag),
            "counter-overflow length accepted");
    require(gcm.seal(nonce, nullptr, 0, nullptr, nullptr, 0, tag), "empty record rejected");

    // MKV-128-256 block test vector also used by the reference implementation.
    std::array<Tag, 19> round_keys;
    const auto block = cipher == Cipher::scalar ? detail::scalar_block : detail::ssse3_block;
    detail::expand(key, round_keys.data(),
                   cipher == Cipher::scalar ? detail::scalar_twice : detail::ssse3_twice);
    if (cipher != Cipher::scalar)
        detail::fold_box_constant(round_keys.data());
    Tag plaintext;
    for (unsigned i = 0; i < plaintext.size(); ++i)
        plaintext[i] = static_cast<Byte>(255 - 17 * i);
    const auto ciphertext = block(round_keys.data(), plaintext);
    const auto known = hex("893f15625e29414002725c12781a7a34");
    require(std::equal(ciphertext.begin(), ciphertext.end(), known.begin()), "block KAT mismatch");

    if (cipher != Cipher::scalar) {
        const auto cache = detail::prepare_prefix(round_keys.data(), nonce);
        const auto bulk = cipher == Cipher::avx2_prefix ? detail::avx2_prefix_ctr32
                          : cipher == Cipher::avx2      ? detail::avx2_ctr32
                          : cipher == Cipher::gfni      ? detail::gfni_prefix_ctr32
                          : cipher == Cipher::vbmi      ? detail::vbmi_prefix_ctr64
                                                        : detail::ssse3_prefix_ctr16;
        const unsigned width = cipher == Cipher::ssse3 ? 16 : cipher == Cipher::vbmi ? 64 : 32;
        std::array<Tag, 19> canonical_keys;
        detail::expand(key, canonical_keys.data(), detail::scalar_twice);
        std::array<Byte, 1024> output;
        for (std::uint32_t first : {1u, 0xf0u, 0xfff0u, 0xfffff0u, 0xffffffe0u}) {
            bulk(round_keys.data(), nonce, cache, first, output.data(), nullptr);
            for (unsigned i = 0; i < width; ++i) {
                const auto expected = detail::scalar_block(canonical_keys.data(),
                                                           detail::counter_block(nonce, first + i));
                require(std::equal(expected.begin(), expected.end(), output.begin() + 16 * i),
                        "SIMD lane or counter carry mismatch");
            }
        }
    }
}
void packets() {
    Key key{};
    Nonce nonce{};
    std::vector<Byte> input(4098), aad(96);
    for (unsigned i = 0; i < input.size(); ++i)
        input[i] = static_cast<Byte>((i * 137) ^ (i >> 3));
    for (unsigned i = 0; i < aad.size(); ++i)
        aad[i] = static_cast<Byte>(i * 19 + 11);
    for (unsigned i = 0; i < key.size(); ++i)
        key[i] = static_cast<Byte>(i * 13 + 71);

    Gcm portable(key, Cipher::scalar, Hash::scalar);
    std::vector<std::unique_ptr<Gcm>> candidates;
    for (auto cipher : {Cipher::automatic, Cipher::ssse3, Cipher::avx2, Cipher::avx2_prefix,
                        Cipher::gfni, Cipher::vbmi})
        for (auto hash : {Hash::automatic, Hash::scalar, Hash::pclmul, Hash::vpclmul})
            if (available(cipher) && available(hash))
                candidates.push_back(std::make_unique<Gcm>(key, cipher, hash));

    for (unsigned size :
         {1u,   63u,  64u,  65u,  79u,  80u,  81u,   239u,  240u,  241u,  255u,  256u,  257u, 511u,
          512u, 513u, 575u, 576u, 577u, 768u, 1023u, 1024u, 1025u, 1200u, 1536u, 2048u, 4097u}) {
        std::vector<Byte> expected(size);
        // Vary the AAD length and deliberately use unaligned input and output.
        const auto associated = size % (aad.size() - 1);
        nonce = {
            0xa5, 0, 0, 0, 0, 0, 0, 0, 0, 0, static_cast<Byte>(size >> 8), static_cast<Byte>(size)};
        Tag expected_tag;
        require(portable.seal(nonce, aad.data() + 1, associated, input.data() + 1, expected.data(),
                              size, expected_tag),
                "portable seal failed");
        for (const auto& gcm : candidates) {
            std::vector<Byte> ciphertext(size + 2, 0xb3), plaintext(size + 2, 0xc7);
            Tag tag;
            require(gcm->seal(nonce, aad.data() + 1, associated, input.data() + 1,
                              ciphertext.data() + 1, size, tag),
                    "packet seal failed");
            require(tag == expected_tag &&
                        std::equal(expected.begin(), expected.end(), ciphertext.begin() + 1),
                    "packet differs from portable path");
            require(ciphertext.front() == 0xb3 && ciphertext.back() == 0xb3,
                    "seal wrote outside packet");
            for (unsigned i = 0; i < tag.size(); ++i) {
                auto forged = tag;
                forged[i] ^= 1;
                require(!gcm->open(nonce, aad.data() + 1, associated, ciphertext.data() + 1,
                                   plaintext.data() + 1, size, forged),
                        "forged packet accepted");
            }
            require(
                std::all_of(plaintext.begin(), plaintext.end(), [](Byte x) { return x == 0xc7; }),
                "forged packet modified disjoint output");
            require(gcm->open(nonce, aad.data() + 1, associated, ciphertext.data() + 1,
                              plaintext.data() + 1, size, tag),
                    "packet open failed");
            require(std::equal(input.begin() + 1, input.begin() + 1 + size, plaintext.begin() + 1),
                    "packet plaintext mismatch");
            require(plaintext.front() == 0xc7 && plaintext.back() == 0xc7,
                    "open wrote outside packet");
            require(gcm->open(nonce, aad.data() + 1, associated, ciphertext.data() + 1,
                              ciphertext.data() + 1, size, tag),
                    "in-place packet open failed");
            require(
                ciphertext.front() == 0xb3 && ciphertext.back() == 0xb3 &&
                    std::equal(input.begin() + 1, input.begin() + 1 + size, ciphertext.begin() + 1),
                "in-place packet plaintext mismatch");
        }
    }
}
} // namespace

int main() try {
    unsigned checked = 0;
    for (auto cipher : {Cipher::automatic, Cipher::scalar, Cipher::ssse3, Cipher::avx2,
                        Cipher::avx2_prefix, Cipher::gfni, Cipher::vbmi}) {
        for (auto hash : {Hash::scalar, Hash::pclmul, Hash::vpclmul}) {
            if (available(cipher) && available(hash)) {
                test(cipher, hash);
                ++checked;
            }
        }
    }
    packets();
    std::cout << "Passed " << checked << " cipher/hash configurations\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
