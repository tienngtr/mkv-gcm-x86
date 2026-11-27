cmake_minimum_required(VERSION 3.20)
project(mkv_gcm_x86 VERSION 0.1.0 LANGUAGES CXX)

if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$"
   OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8
   OR NOT CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$"
   OR MSVC)
  message(FATAL_ERROR "Use x86-64 with GCC or Clang and a GNU-style driver")
endif()

add_library(mkv_gcm STATIC
  src/gcm.cpp src/scalar.cpp src/ssse3.cpp src/avx2.cpp
  src/gfni.cpp src/vbmi.cpp src/pclmul.cpp src/vpclmul.cpp)
add_library(mkv::gcm ALIAS mkv_gcm)
target_include_directories(mkv_gcm PUBLIC
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>")
target_compile_features(mkv_gcm PUBLIC cxx_std_17)
target_compile_options(mkv_gcm PRIVATE -Wall -Wextra -Wpedantic -march=x86-64)
# Keep the optional instructions out of the baseline dispatch paths.
set_target_properties(mkv_gcm PROPERTIES
  EXPORT_NAME gcm
  INTERPROCEDURAL_OPTIMIZATION OFF
  POSITION_INDEPENDENT_CODE ON)
set_source_files_properties(src/ssse3.cpp PROPERTIES COMPILE_OPTIONS "-mssse3")
set_source_files_properties(src/avx2.cpp PROPERTIES COMPILE_OPTIONS "-mavx2")
set_source_files_properties(src/gfni.cpp PROPERTIES COMPILE_OPTIONS "-mavx2;-mgfni")
set_source_files_properties(src/vbmi.cpp PROPERTIES
  COMPILE_OPTIONS "-mavx512f;-mavx512bw;-mavx512vbmi;-mgfni")
set_source_files_properties(src/pclmul.cpp PROPERTIES COMPILE_OPTIONS "-mpclmul")
set_source_files_properties(src/vpclmul.cpp PROPERTIES
  COMPILE_OPTIONS "-mavx2;-mpclmul;-mvpclmulqdq")

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  set(mkv_gcm_standalone ON)
  include(CTest)
  set(mkv_gcm_build_tests "${BUILD_TESTING}")
else()
  set(mkv_gcm_standalone OFF)
  option(MKV_GCM_BUILD_TESTS "Build MKV-GCM tests in the parent project" OFF)
  set(mkv_gcm_build_tests "${MKV_GCM_BUILD_TESTS}")
endif()

if(mkv_gcm_build_tests)
  enable_testing()
  add_executable(mkv_tests tests/test.cpp)
  target_include_directories(mkv_tests PRIVATE src)
  target_link_libraries(mkv_tests PRIVATE mkv::gcm)
  add_test(NAME mkv_gcm COMMAND mkv_tests)
endif()

option(MKV_GCM_INSTALL "Install the MKV-GCM library and CMake package" "${mkv_gcm_standalone}")
if(MKV_GCM_INSTALL)
  include(GNUInstallDirs)
  include(CMakePackageConfigHelpers)
  target_include_directories(mkv_gcm PUBLIC "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")
  set(mkv_gcm_package_dir "${CMAKE_INSTALL_LIBDIR}/cmake/mkv_gcm")
  configure_package_config_file(cmake/mkv_gcmConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/mkv_gcmConfig.cmake"
    INSTALL_DESTINATION "${mkv_gcm_package_dir}")
  write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/mkv_gcmConfigVersion.cmake"
    VERSION "${PROJECT_VERSION}" COMPATIBILITY SameMinorVersion)

  install(TARGETS mkv_gcm EXPORT mkv_gcmTargets
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
  install(FILES include/mkv/gcm.hpp DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/mkv")
  install(FILES LICENSE DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/mkv_gcm")
  install(EXPORT mkv_gcmTargets NAMESPACE mkv:: DESTINATION "${mkv_gcm_package_dir}")
  install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/mkv_gcmConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/mkv_gcmConfigVersion.cmake"
    DESTINATION "${mkv_gcm_package_dir}")
endif()

option(MKV_BUILD_BENCHMARK "Build the OpenSSL comparison benchmark" OFF)
if(MKV_BUILD_BENCHMARK)
  find_package(OpenSSL REQUIRED COMPONENTS Crypto)
  add_executable(mkv_bench bench/bench.cpp)
  target_link_libraries(mkv_bench PRIVATE mkv::gcm OpenSSL::Crypto)
endif()
