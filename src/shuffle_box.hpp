#pragma once
#include "internal.hpp"
#include <immintrin.h>

namespace mkv::detail {

struct BoxTables {
    Tag log1{}, log8{}, log11{}, inverse{}, exp{};
    constexpr BoxTables() {
        Byte x = 1;
        for (unsigned e = 0; e < 15; ++e) {
            exp[e] = x;
            log1[x] = static_cast<Byte>(e);
            log8[x] = static_cast<Byte>((8 * e) % 15);
            log11[x] = static_cast<Byte>((11 * e) % 15);
            inverse[x] = power4(x, 14);
            x = field4(x, 2);
        }
        exp[15] = 1;
    }
};

alignas(16) inline constexpr BoxTables box_tables{};

template <class Ops> inline typename Ops::Vector substitute(typename Ops::Vector x) noexcept {
    using V = typename Ops::Vector;
    const V mask = Ops::byte(15);
    const V a = Ops::and_(Ops::shr4(x), mask);
    const V b = Ops::and_(x, mask);
    const V a_zero = Ops::equal(a, Ops::byte(0));
    const V b_zero = Ops::equal(b, Ops::byte(0));
    const V zero = Ops::or_(a_zero, b_zero);
    const V exp = Ops::table(box_tables.exp);
    const V inv = Ops::table(box_tables.inverse);
    const V log11 = Ops::table(box_tables.log11);
    const V low_log =
        Ops::add(Ops::shuffle(log11, a), Ops::shuffle(Ops::table(box_tables.log1), b));
    const V high_log =
        Ops::add(Ops::shuffle(Ops::table(box_tables.log8), a), Ops::shuffle(log11, b));
    const V low =
        Ops::or_(Ops::andnot(zero, Ops::shuffle(exp, Ops::min(low_log, Ops::sub(low_log, mask)))),
                 Ops::and_(b_zero, Ops::shuffle(inv, a)));
    const V high =
        Ops::or_(Ops::andnot(zero, Ops::shuffle(exp, Ops::min(high_log, Ops::sub(high_log, mask)))),
                 Ops::and_(a_zero, Ops::shuffle(inv, b)));
    return Ops::xor_(Ops::or_(low, Ops::shl4(high)), Ops::byte(1));
}
} // namespace mkv::detail
