# MKV-128-256-GCM for x86-64

A standalone C++17 implementation of MKV-GCM with 128-bit blocks, a 256-bit
key, a 96-bit nonce and a 128-bit tag. The library has no external dependency.
It grew out of the libmkvpp benchmarking work. This repository contains the
x86 implementation and synthetic test fixtures. The reference implementation
was used for local cross-checks.

| Component | Minimum hardware | Implementation |
|---|---|---|
| Scalar MKV and GHASH | Baseline x86-64 | Masked GF(16) S-box arithmetic and bit-serial GHASH |
| SSSE3 MKV | SSSE3 | One block using fixed-address constants and register shuffles |
| AVX2 MKV | SSSE3, AVX2 and OS support for YMM state | 32 counter blocks in byte planes, with an SSSE3 tail |
| AVX2 MKV with prefix caching | Same as AVX2 MKV | Shares the first two rounds' invariant word work across full batches |
| PCLMUL GHASH | PCLMULQDQ | Four-block folding with precomputed powers of H |

Cipher and hash dispatch independently. The AVX2 prefix path prepares its
cache once per record containing at least 32 data blocks. Three word
transformations in the first MKV round and one in the second depend only on
the fixed 96-bit counter prefix for that record. GHASH uses the same path
whether or not the cipher caches those values. All backends use one caller
thread.

## Build and use

Use CMake 3.20 or later, GCC or Clang, and an x86-64 target. Linux is the tested
platform. Link the CMake target `mkv::gcm` and include `<mkv/gcm.hpp>`.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

```cpp
#include <mkv/gcm.hpp>

// key and nonce are initialized by the caller. Each seal needs a unique nonce
// under its key. This example operates in-place on an existing byte buffer.
bool encrypt_record(const mkv::Gcm& gcm, const mkv::Nonce& nonce,
                    mkv::Byte* buffer, std::size_t size, mkv::Tag& tag) {
    return gcm.seal(nonce, nullptr, 0, buffer, buffer, size, tag);
}
```

Construct `mkv::Gcm gcm(key)` to select backends at runtime. Tests or benchmarks
can pass a `mkv::Cipher` and `mkv::Hash` explicitly. `mkv::available` checks
support before construction. Pass AAD, if used, identically to `seal` and
`open`. Use disjoint or exactly in-place input/output buffers, and keep the
nonce, AAD and detached tag separate from the output. `open` verifies the
full tag before writing any plaintext. The caller owns nonce allocation.

## Timing and validation

The MKV paths use fixed-work arithmetic or register shuffles. Secret values
select bytes within registers and never address tables in memory. GHASH
uses fixed-work masks or carryless multiplication. Tag verification checks
all 16 bytes before branching on authentication success.

The tests cover a block known-answer vector, reference-generated AEAD
fixtures, in-place operation, counter carries, batch tails, invalid lengths
and rejection of altered ciphertext and tags. A separate local differential
run compared eight cipher/hash combinations against libmkvpp for 80 records.
The fallback ran under QEMU with SSSE3 and PCLMULQDQ disabled.

The optional Memcheck probe checks key expansion and sealing for secret-dependent
branches or addresses in each available backend. In the example below, static
linking lets Valgrind run on Linux systems with stripped loader symbols.

```sh
c++ -O2 -static -std=c++17 -Iinclude tests/taint.cpp build/libmkv_gcm.a \
  -o build/mkv_taint
valgrind --error-exitcode=1 build/mkv_taint
```

This is experimental cryptographic software and has had no independent
security audit. The probe covers executed code on the tested compiler builds
and does not establish constant timing across every processor or build.

## Benchmark

Install the OpenSSL development headers to enable the optional benchmark.
It compares all supported cipher/hash pairs with OpenSSL AES-256-GCM, for
64 B, 1 KiB, 16 KiB and 256 KiB records. Each randomized trial order is paired
with its reverse. The program records the seed on stderr and emits medians
and individual trial times as CSV on stdout. Key setup stays outside the
timed interval. Timed sealing includes nonce increments and AVX2 per-record
prefix preparation. Timed opening includes tag verification.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DMKV_BUILD_BENCHMARK=ON
cmake --build build --parallel
build/mkv_bench 14263 > results.csv
```

See [Ryzen 7 PRO 6850HS results](bench/ryzen-6850hs.csv) for a single-worker Linux
run pinned with `taskset -c 3`. GCC 16.2.1, OpenSSL 4.1.0, six trials per case
with at least 35 ms per trial, seed 14263. These figures measure the listed
software and hardware configuration.

MKV is specified in [TCVN 14263:2024](https://tieuchuan.vsqi.gov.vn/tieuchuan/view?sohieu=TCVN+14263%3A2024).
The GCM construction follows [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).
Source is available under the [MIT License](LICENSE).
