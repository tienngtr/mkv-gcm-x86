#include "internal.hpp"
#include <algorithm>
#include <cstring>

namespace mkv::detail {
namespace {

constexpr Tag left_constant{0x93, 0x02, 0xee, 0x91, 0x1a, 0x2a, 0xd9, 0x8c,
                            0xad, 0x13, 0xe7, 0x94, 0x8a, 0xd8, 0xb3, 0xb2};
constexpr Tag right_constant{0xd4, 0xda, 0x00, 0xf3, 0x3f, 0x11, 0xfd, 0x88,
                             0x22, 0x16, 0x6b, 0xb9, 0xcd, 0x18, 0x7c, 0x55};

Tag round(Tag input, const Tag& first, const Tag& second) noexcept {
    Tag words;
    for (unsigned word = 0; word < 4; ++word) {
        Byte x[4];
        for (unsigned i = 0; i < 4; ++i) {
            unsigned index = 4 * word + ((word + i) & 3);
            x[i] = box(input[index] ^ first[index]);
        }
        for (unsigned step = 0; step < 4; ++step) {
            unsigned feedback = x[1] ^ x[3];
            unsigned twice = (feedback << 1) ^ (0x2bu & (0u - (feedback >> 7)));
            Byte next = static_cast<Byte>(x[0] ^ x[2] ^ x[3] ^ twice);
            x[0] = x[1];
            x[1] = x[2];
            x[2] = x[3];
            x[3] = next;
        }
        for (unsigned i = 0; i < 4; ++i)
            words[4 * word + i] = box(x[i] ^ second[4 * word + i]);
    }
    for (unsigned i = 0; i < 4; ++i) {
        Byte sum = words[i] ^ words[i + 4] ^ words[i + 8] ^ words[i + 12];
        for (unsigned j = i; j < 16; j += 4)
            words[j] ^= sum;
    }
    return words;
}
} // namespace

Tag scalar_twice(const Tag* schedule, Tag state) noexcept {
    return round(round(state, schedule[0], Tag{}), Tag{}, Tag{});
}

Tag scalar_block(const Tag* schedule, Tag state) noexcept {
    for (unsigned i = 0; i < 18; i += 2)
        state = round(state, schedule[i], schedule[i + 1]);
    return xor_block(state, schedule[18]);
}

void expand(const Key& key, Tag* schedule, Tag (*double_round)(const Tag*, Tag) noexcept) noexcept {
    auto derive = [double_round](Tag value, Tag constant, unsigned index) {
        constant.back() ^= static_cast<Byte>(index);
        return double_round(&constant, value);
    };
    Tag first, master_right;
    std::copy_n(key.begin(), 16, first.begin());
    std::copy_n(key.begin() + 16, 16, master_right.begin());
    Tag older = first;
    Tag newer = derive(master_right, right_constant, 2);
    for (unsigned i = 0; i < 9; ++i) {
        schedule[2 * i] = first;
        schedule[2 * i + 1] = newer;
        first = xor_block(derive(older, left_constant, 2 * i + 1), newer);
        if (i != 8) {
            older = newer;
            newer = derive(first, right_constant, 2 * i + 4);
        }
    }
    schedule[18] = first;
}

namespace {
std::uint64_t load_be(const Byte* bytes) noexcept {
    std::uint64_t limb;
    std::memcpy(&limb, bytes, sizeof(limb));
    return __builtin_bswap64(limb);
}

void store_be(Byte* bytes, std::uint64_t limb) noexcept {
    limb = __builtin_bswap64(limb);
    std::memcpy(bytes, &limb, sizeof(limb));
}
} // namespace

// NIST bit ordering, with the polynomial and accumulator in two 64-bit limbs.
void scalar_hash(Tag& value, const Tag* h, const Byte* data, std::size_t blocks) noexcept {
    auto hi = load_be(value.data());
    auto lo = load_be(value.data() + 8);
    const auto h_hi = load_be(h[0].data());
    const auto h_lo = load_be(h[0].data() + 8);
    while (blocks--) {
        const auto x_hi = hi ^ load_be(data);
        const auto x_lo = lo ^ load_be(data + 8);
        auto v_hi = h_hi;
        auto v_lo = h_lo;
        hi = lo = 0;
        for (auto bits : {x_hi, x_lo}) {
            for (unsigned i = 0; i < 64; ++i) {
                auto mask = std::uint64_t{0} - (bits >> 63);
                // Keep Clang from converting the masked XOR to a branch.
                asm("" : "+r"(mask));
                hi ^= v_hi & mask;
                lo ^= v_lo & mask;
                const auto carry = std::uint64_t{0} - (v_lo & 1);
                v_lo = (v_lo >> 1) | (v_hi << 63);
                v_hi = (v_hi >> 1) ^ (carry & 0xe100000000000000ULL);
                bits <<= 1;
            }
        }
        data += 16;
    }
    store_be(value.data(), hi);
    store_be(value.data() + 8, lo);
}
} // namespace mkv::detail
