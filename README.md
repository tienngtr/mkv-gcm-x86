# MKV-128-256-GCM for x86-64

A standalone C++17 implementation of MKV-GCM with 128-bit blocks, a 256-bit
key, a 96-bit nonce and a 128-bit tag. The library has no external dependency.
It grew out of the libmkvpp benchmarking work. This repository contains the
x86 implementation and synthetic test fixtures. The reference implementation
was used for local cross-checks.

| Component | Minimum hardware | Implementation |
|---|---|---|
| Scalar MKV and GHASH | Baseline x86-64 | Masked GF(16) S-box arithmetic and two-limb bit-serial GHASH |
| `Cipher::ssse3` | SSSE3 | Single-block and 16-block CTR kernels with register shuffles and prefix caching for batches |
| `Cipher::avx2` | SSSE3, AVX2, OS support for YMM state | 32-block CTR kernel, with SSSE3 for short packets and tails |
| `Cipher::avx2_prefix` | Same as `Cipher::avx2` | Adds shared word transformations for the fixed 96-bit counter prefix |
| `Cipher::gfni` | SSSE3, AVX2, GFNI, OS support for YMM state | 32-block cached CTR using GFNI for the S-box and MixWords |
| `Cipher::vbmi` | SSSE3, AVX2, GFNI, AVX-512F, AVX-512BW, AVX-512VBMI, OS support for ZMM and opmask state | 64-block cached CTR with the S-box held in four registers and GFNI for MixWords. Smaller batches use the GFNI and SSSE3 kernels |
| `Hash::pclmul` | PCLMULQDQ | Four-block folding with precomputed powers of H |
| `Hash::vpclmul` | AVX2, VPCLMULQDQ, PCLMULQDQ, OS support for YMM state | Two parallel 128-bit lanes for four-block folding. Short updates use PCLMULQDQ |

Cipher and hash dispatch independently. Automatic selection prefers
`Cipher::avx2_prefix` and `Hash::vpclmul` when available. GFNI and VBMI can
be selected explicitly. They passed tests under emulation and still need
real-hardware performance measurements.

A cached CTR batch reuses three nonce-dependent word transformations in its
first round pair and one in its second. Full batches XOR data while writing
blocks out of the SIMD registers. Sealing can compute the tag mask from a
spare counter lane. Opening authenticates the ciphertext before starting CTR
decryption. All backends use one caller thread.

## Use as a library

Use CMake 3.20 or later, GCC or Clang, and an x86-64 target. Linux is the tested
platform. The public API is in `<mkv/gcm.hpp>`. Both integration methods provide
the `mkv::gcm` static library target, which can also be linked into a shared
library.

`add_subdirectory` compiles the sources as part of your project. For example,
put the checkout in `third_party/mkv-gcm-x86` and link your existing target.

```cmake
add_subdirectory(third_party/mkv-gcm-x86)
target_link_libraries(my_app PRIVATE mkv::gcm)
```

Source integration builds the library by default. Parent projects can opt in
to the benchmark, tests or install rules with `MKV_BUILD_BENCHMARK`,
`MKV_GCM_BUILD_TESTS` or `MKV_GCM_INSTALL`, respectively.

For an installed package, build and install to a prefix of your choice.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build build --parallel
cmake --install build --prefix /path/to/prefix
```

Configure your consuming project with `-DCMAKE_PREFIX_PATH=/path/to/prefix`
and use the installed target.

```cmake
find_package(mkv_gcm 0.1 CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE mkv::gcm)
```

With another build system, compile the `src/*.cpp` files as separate C++17
translation units and expose the `include/` directory. Use `-march=x86-64`
for every source file and add the following flags by file to preserve runtime
dispatch. OpenSSL is used by the optional benchmark.

| Source file | Additional flags |
|---|---|
| `ssse3.cpp` | `-mssse3` |
| `avx2.cpp` | `-mavx2` |
| `gfni.cpp` | `-mavx2 -mgfni` |
| `vbmi.cpp` | `-mavx512f -mavx512bw -mavx512vbmi -mgfni` |
| `pclmul.cpp` | `-mpclmul` |
| `vpclmul.cpp` | `-mavx2 -mpclmul -mvpclmulqdq` |

To build and run the standalone tests, enable `BUILD_TESTING`.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
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
fixtures, counter carries, unaligned buffers, batch boundaries, invalid lengths
and rejection of altered ciphertext and tags. They check that successful
in-place opening recovers the plaintext and that failed authentication leaves
the output untouched. Baseline and SSSE3 ran under QEMU. GFNI and VBMI ran under
[Intel SDE](https://www.intel.com/content/www/us/en/download/684897/intel-software-development-emulator.html).

The optional Memcheck probe checks key expansion and sealing for secret-dependent
branches or addresses in backends supported by Memcheck’s CPU emulation.
Local SDE trace comparisons checked instruction and memory-address sequences
across different keys and data on the GFNI, VBMI and VPCLMUL paths. Static
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
64 B, 511 B, 512 B, 1 KiB, 1,200 B, 16 KiB and 256 KiB records. Each randomized
trial order is paired with its reverse. The program records the seed on stderr
and emits medians and individual trial times as CSV on stdout. Key setup stays
outside the timed interval. Timed sealing includes nonce increments and
per-record CTR prefix preparation. Timed opening includes tag verification.
The OpenSSL benchmark uses EVP's usual streaming decrypt API and discards the
output buffer if verification fails.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DMKV_BUILD_BENCHMARK=ON
cmake --build build --parallel
build/mkv_bench 14263 > results.csv
```

See [Ryzen 7 PRO 6850HS results](bench/ryzen-6850hs.csv) for a single-worker Linux
run pinned with `taskset -c 3`. GCC 16.2.1, OpenSSL 4.1.0, six trials per case
with at least 35 ms per trial, seed 14263. These figures measure the listed
software and hardware configuration.

See [public references](docs/README.md) for the MKV Internet-Draft, the
Math-Net design paper, the Vietnamese standard and the GCM specification.

Project source is available under the [MIT License](LICENSE).
