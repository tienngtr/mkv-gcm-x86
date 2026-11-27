#include <mkv/gcm.hpp>
#include <openssl/evp.h>

#include <algorithm>
#include <chrono>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using namespace mkv;
using Clock = std::chrono::steady_clock;
using Operation = std::function<void(const Nonce&, const Byte*, Byte*, std::size_t, Tag&)>;
using Aad = std::array<Byte, 20>;

void require(bool good) {
    if (!good)
        throw std::runtime_error("benchmark AEAD operation failed");
}

struct Aes {
    using Context = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
    Context context{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};
    const Aad aad;
    const bool opening;

    Aes(const Key& key, const Aad& associated, bool open) : aad(associated), opening(open) {
        require(bool(context));
        require(EVP_CipherInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, key.data(), nullptr,
                                  !opening) == 1);
    }

    void run(const Nonce& nonce, const Byte* in, Byte* out, std::size_t size, Tag& tag) {
        int length = 0;
        int written = 0;
        auto* ctx = context.get();
        require(EVP_CipherInit_ex(ctx, nullptr, nullptr, nullptr, nonce.data(), !opening) == 1);
        require(EVP_CipherUpdate(ctx, nullptr, &length, aad.data(), int(aad.size())) == 1);
        require(EVP_CipherUpdate(ctx, out, &written, in, int(size)) == 1);
        if (opening)
            require(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, int(tag.size()), tag.data()) ==
                    1);
        require(EVP_CipherFinal_ex(ctx, out + written, &length) == 1);
        require(std::size_t(written + length) == size);
        if (!opening)
            require(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, int(tag.size()), tag.data()) ==
                    1);
    }
};

struct Candidate {
    std::string label;
    Operation seal, open;
    std::vector<Byte> sealed;
    Nonce nonce{};
    Tag tag{};
    std::vector<double> trials;
};

volatile unsigned checksum = 0;

void increment(Nonce& nonce) {
    for (auto it = nonce.rbegin(); it != nonce.rend(); ++it)
        if (++*it != 0)
            break;
}

double measure(Candidate& candidate, bool opening, const std::vector<Byte>& input,
               std::vector<Byte>& output, int milliseconds) {
    const auto deadline_interval = std::chrono::milliseconds(milliseconds);
    const auto& operation = opening ? candidate.open : candidate.seal;
    const auto& source = opening ? candidate.sealed : input;
    auto start = Clock::now();
    auto stop = start;
    std::size_t records = 0;
    do {
        // Amortize clock reads for short records, with at most 4 KiB per group.
        const auto group = std::max<std::size_t>(1, 4096 / input.size());
        for (std::size_t i = 0; i < group; ++i) {
            if (!opening)
                increment(candidate.nonce);
            operation(candidate.nonce, source.data(), output.data(), input.size(), candidate.tag);
        }
        records += group;
        stop = Clock::now();
    } while (stop - start < deadline_interval);
    checksum ^= output.front();
    return std::chrono::duration<double, std::nano>(stop - start).count() / double(records);
}

void run_case(std::size_t size, bool opening, unsigned rounds, int milliseconds,
              std::mt19937& random) {
    Key key{};
    // Synthetic keys, distinct across record sizes and operations.
    key[0] = static_cast<Byte>(opening);
    for (unsigned i = 0; i < 4; ++i)
        key[1 + i] = static_cast<Byte>(size >> (8 * i));
    Aad aad{};
    std::vector<Byte> input(size), output(size + 16);
    for (std::size_t i = 0; i < size; ++i)
        input[i] = static_cast<Byte>(7 + 13 * i);
    std::vector<Candidate> candidates;
    for (auto cipher : {Cipher::scalar, Cipher::ssse3, Cipher::avx2, Cipher::avx2_prefix}) {
        if (!available(cipher))
            continue;
        for (auto hash : {Hash::scalar, Hash::pclmul}) {
            if (!available(hash))
                continue;
            auto gcm = std::make_shared<Gcm>(key, cipher, hash);
            candidates.push_back(
                {std::string(name(cipher)) + "+" + name(hash),
                 [gcm, aad](const Nonce& nonce, const Byte* in, Byte* out, std::size_t n,
                            Tag& tag) {
                     require(gcm->seal(nonce, aad.data(), aad.size(), in, out, n, tag));
                 },
                 [gcm, aad](const Nonce& nonce, const Byte* in, Byte* out, std::size_t n,
                            Tag& tag) {
                     require(gcm->open(nonce, aad.data(), aad.size(), in, out, n, tag));
                 },
                 {},
                 {},
                 {},
                 {}});
        }
    }
    auto aes_seal = std::make_shared<Aes>(key, aad, false);
    auto aes_open = std::make_shared<Aes>(key, aad, true);
    candidates.push_back({"openssl-aes-256-gcm",
                          [aes_seal](const Nonce& nonce, const Byte* in, Byte* out, std::size_t n,
                                     Tag& tag) { aes_seal->run(nonce, in, out, n, tag); },
                          [aes_open](const Nonce& nonce, const Byte* in, Byte* out, std::size_t n,
                                     Tag& tag) { aes_open->run(nonce, in, out, n, tag); },
                          {},
                          {},
                          {},
                          {}});

    std::vector<std::size_t> order(candidates.size());
    std::iota(order.begin(), order.end(), 0);
    std::shuffle(order.begin(), order.end(), random);
    for (auto i : order) {
        auto& candidate = candidates[i];
        candidate.nonce[0] = static_cast<Byte>(i);
        candidate.sealed.resize(size + 16);
        candidate.seal(candidate.nonce, input.data(), candidate.sealed.data(), size, candidate.tag);
        candidate.open(candidate.nonce, candidate.sealed.data(), output.data(), size,
                       candidate.tag);
        require(std::equal(input.begin(), input.end(), output.begin()));
        measure(candidate, opening, input, output, 5);
    }
    for (unsigned round = 0; round < rounds; ++round) {
        if (round % 2 == 0)
            std::shuffle(order.begin(), order.end(), random);
        else
            std::reverse(order.begin(), order.end());
        for (auto i : order)
            candidates[i].trials.push_back(
                measure(candidates[i], opening, input, output, milliseconds));
    }

    for (auto& candidate : candidates) {
        const auto& trials = candidate.trials;
        auto sorted = trials;
        std::sort(sorted.begin(), sorted.end());
        const auto mid = sorted.size() / 2;
        const double median = sorted.size() % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
        std::cout << candidate.label << ',' << (opening ? "open" : "seal") << ',' << size << ','
                  << median << ',' << size * 1e9 / (median * 1048576);
        for (double ns : trials)
            std::cout << ',' << ns;
        std::cout << '\n';
    }
}
} // namespace

int main(int argc, char** argv) try {
    if (argc > 2)
        throw std::invalid_argument("usage: mkv_bench [32-bit decimal seed]");
    std::uint32_t seed = 0;
    if (argc == 2) {
        std::string input(argv[1]);
        if (input.empty() || input.find_first_not_of("0123456789") != std::string::npos)
            throw std::invalid_argument("expected a decimal seed in 0..4294967295");
        auto parsed = std::stoull(input);
        if (parsed > UINT32_MAX)
            throw std::invalid_argument("seed exceeds 4294967295");
        seed = static_cast<std::uint32_t>(parsed);
    } else {
        seed = std::random_device{}();
    }
    constexpr unsigned rounds = 6;
    constexpr int milliseconds = 35;
    std::mt19937 random(seed);
    std::vector<std::pair<std::size_t, bool>> cases;
    for (auto size : {64u, 1024u, 16384u, 262144u}) {
        cases.emplace_back(size, false);
        cases.emplace_back(size, true);
    }
    std::shuffle(cases.begin(), cases.end(), random);
    std::cerr << OpenSSL_version(OPENSSL_VERSION) << ", seed " << seed << ", " << rounds
              << " trials of at least " << milliseconds << " ms\n";
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "backend,operation,bytes,median_ns,mib_per_second";
    for (unsigned round = 1; round <= rounds; ++round)
        std::cout << ",trial_" << round << "_ns";
    std::cout << '\n';
    for (auto [size, opening] : cases)
        run_case(size, opening, rounds, milliseconds, random);
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
