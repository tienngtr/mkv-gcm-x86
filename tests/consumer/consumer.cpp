#include <mkv/gcm.hpp>

bool mkv_round_trip() {
    const mkv::Gcm gcm(mkv::Key{});
    const mkv::Nonce nonce{};
    auto buffer = std::array<mkv::Byte, 545>{};
    buffer.front() = 17;
    const auto original = buffer;
    mkv::Tag tag{};
    return gcm.seal(nonce, nullptr, 0, buffer.data(), buffer.data(), buffer.size(), tag) &&
           gcm.open(nonce, nullptr, 0, buffer.data(), buffer.data(), buffer.size(), tag) &&
           buffer == original;
}
