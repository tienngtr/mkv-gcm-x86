#include "fixtures.hpp"
#include "internal.hpp"

#include <algorithm>
#include <iostream>
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
    Tag plaintext;
    for (unsigned i = 0; i < plaintext.size(); ++i)
        plaintext[i] = static_cast<Byte>(255 - 17 * i);
    const auto ciphertext = block(round_keys.data(), plaintext);
    const auto known = hex("893f15625e29414002725c12781a7a34");
    require(std::equal(ciphertext.begin(), ciphertext.end(), known.begin()), "block KAT mismatch");

    if (cipher == Cipher::avx2 || cipher == Cipher::avx2_prefix) {
        const auto cache = detail::prepare_prefix(round_keys.data(), nonce);
        const auto bulk =
            cipher == Cipher::avx2_prefix ? detail::avx2_prefix_ctr32 : detail::avx2_ctr32;
        std::array<Byte, 512> output;
        for (std::uint32_t first : {1u, 0xf0u, 0xfff0u, 0xfffff0u, 0xffffffe0u}) {
            bulk(round_keys.data(), nonce, cache, first, output.data());
            for (unsigned i = 0; i < 32; ++i) {
                const auto expected = detail::scalar_block(round_keys.data(),
                                                           detail::counter_block(nonce, first + i));
                require(std::equal(expected.begin(), expected.end(), output.begin() + 16 * i),
                        "AVX2 lane or counter carry mismatch");
            }
        }
    }
}
} // namespace

int main() try {
    unsigned checked = 0;
    for (auto cipher :
         {Cipher::automatic, Cipher::scalar, Cipher::ssse3, Cipher::avx2, Cipher::avx2_prefix}) {
        for (auto hash : {Hash::scalar, Hash::pclmul}) {
            if (available(cipher) && available(hash)) {
                test(cipher, hash);
                ++checked;
            }
        }
    }
    std::cout << "Passed " << checked << " cipher/hash configurations\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
