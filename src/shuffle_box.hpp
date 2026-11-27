#pragma once
#include "internal.hpp"
#include <immintrin.h>

namespace mkv::detail {

struct BoxTables {
    Tag log1{}, log11{}, log13{}, inverse{}, exp1{}, exp11{};
    constexpr BoxTables() {
        // A saturated sum and the subsequent subtraction of 15 both preserve
        // the high bit of a zero operand, so PSHUFB zeros that product.
        log1[0] = log11[0] = log13[0] = 0xc0;
        Byte x = 1;
        for (unsigned e = 0; e < 15; ++e) {
            exp1[e] = x;
            exp11[e] = power4(x, 11);
            log1[x] = static_cast<Byte>(e);
            log11[x] = static_cast<Byte>((11 * e) % 15);
            log13[x] = static_cast<Byte>((13 * e) % 15);
            inverse[x] = power4(x, 14);
            x = field4(x, 2);
        }
    }
};

alignas(16) inline constexpr BoxTables box_tables{};

template <class Ops, bool Canonical = false>
inline typename Ops::Vector substitute(typename Ops::Vector x) noexcept {
    const auto mask = Ops::byte(15);
    const auto a = Ops::and_(Ops::shr4(x), mask);
    const auto b = Ops::and_(x, mask);
    const auto a_zero = Ops::equal(a, Ops::byte(0));
    const auto b_zero = Ops::equal(b, Ops::byte(0));
    const auto b_log = Ops::shuffle(Ops::table(box_tables.log1), b);
    const auto low_log = Ops::adds(Ops::shuffle(Ops::table(box_tables.log11), a), b_log);
    // 13 * 11 = 8 mod 15. The second exponential table avoids a second log of b.
    const auto high_log = Ops::adds(Ops::shuffle(Ops::table(box_tables.log13), a), b_log);
    const auto inv = Ops::table(box_tables.inverse);
    const auto low = Ops::or_(
        Ops::shuffle(Ops::table(box_tables.exp1), Ops::min(low_log, Ops::sub(low_log, mask))),
        Ops::and_(b_zero, Ops::shuffle(inv, a)));
    const auto high = Ops::or_(
        Ops::shuffle(Ops::table(box_tables.exp11), Ops::min(high_log, Ops::sub(high_log, mask))),
        Ops::and_(a_zero, Ops::shuffle(inv, b)));
    const auto result = Ops::or_(low, Ops::shl4(high));
    if constexpr (Canonical)
        return Ops::xor_(result, Ops::byte(1));
    return result;
}
} // namespace mkv::detail
