cmake_minimum_required(VERSION 3.20)
project(mkv_gcm_x86 VERSION 0.1.0 LANGUAGES CXX)

if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$"
   OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8
   OR NOT CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$"
   OR MSVC)
  message(FATAL_ERROR "Use x86-64 with GCC or Clang and a GNU-style driver")
endif()

add_library(mkv_gcm STATIC
  src/gcm.cpp src/scalar.cpp src/ssse3.cpp src/avx2.cpp src/pclmul.cpp)
add_library(mkv::gcm ALIAS mkv_gcm)
target_include_directories(mkv_gcm PUBLIC include)
target_compile_features(mkv_gcm PUBLIC cxx_std_17)
target_compile_options(mkv_gcm PRIVATE -Wall -Wextra -Wpedantic -march=x86-64)
# Keep the optional instructions out of the baseline dispatch paths.
set_target_properties(mkv_gcm PROPERTIES INTERPROCEDURAL_OPTIMIZATION OFF)
set_source_files_properties(src/ssse3.cpp PROPERTIES COMPILE_OPTIONS "-mssse3")
set_source_files_properties(src/avx2.cpp PROPERTIES COMPILE_OPTIONS "-mavx2")
set_source_files_properties(src/pclmul.cpp PROPERTIES COMPILE_OPTIONS "-mpclmul")

include(CTest)
if(BUILD_TESTING)
  add_executable(mkv_tests tests/test.cpp)
  target_include_directories(mkv_tests PRIVATE src)
  target_link_libraries(mkv_tests PRIVATE mkv::gcm)
  add_test(NAME mkv_gcm COMMAND mkv_tests)
endif()

option(MKV_BUILD_BENCHMARK "Build the OpenSSL comparison benchmark" OFF)
if(MKV_BUILD_BENCHMARK)
  find_package(OpenSSL REQUIRED COMPONENTS Crypto)
  add_executable(mkv_bench bench/bench.cpp)
  target_link_libraries(mkv_bench PRIVATE mkv::gcm OpenSSL::Crypto)
endif()
