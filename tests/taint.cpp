#include <cstdio>
#include <mkv/gcm.hpp>
#include <valgrind/memcheck.h>
#include <vector>

int main() {
    for (auto cipher :
         {mkv::Cipher::scalar, mkv::Cipher::ssse3, mkv::Cipher::avx2, mkv::Cipher::avx2_prefix})
        for (auto hash : {mkv::Hash::scalar, mkv::Hash::pclmul}) {
            if (!mkv::available(cipher) || !mkv::available(hash))
                continue;
            std::fprintf(stderr, "Checking %s + %s\n", mkv::name(cipher), mkv::name(hash));
            mkv::Key key{};
            mkv::Nonce nonce{};
            mkv::Tag tag{};
            std::vector<mkv::Byte> in(1059, 19), out(in.size()), aad(23, 29);
            VALGRIND_MAKE_MEM_UNDEFINED(key.data(), key.size());
            VALGRIND_MAKE_MEM_UNDEFINED(in.data(), in.size());
            VALGRIND_MAKE_MEM_UNDEFINED(aad.data(), aad.size());
            mkv::Gcm gcm(key, cipher, hash);
            if (!gcm.seal(nonce, aad.data(), aad.size(), in.data(), out.data(), in.size(), tag))
                return 1;
            VALGRIND_MAKE_MEM_DEFINED(in.data(), in.size());
            VALGRIND_MAKE_MEM_DEFINED(out.data(), out.size());
            VALGRIND_MAKE_MEM_DEFINED(aad.data(), aad.size());
        }
}
