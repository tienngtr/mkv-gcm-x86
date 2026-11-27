cmake_minimum_required(VERSION 3.20)
project(mkv_consumer LANGUAGES CXX)

include(CTest)
if(MKV_GCM_SOURCE_DIR)
  add_subdirectory("${MKV_GCM_SOURCE_DIR}" mkv)
  if(TARGET mkv_tests OR TARGET mkv_bench)
    message(FATAL_ERROR "Adding the library from source should build only the library by default")
  endif()
else()
  find_package(mkv_gcm 0.1 CONFIG REQUIRED)
endif()

# A consumer should also be able to link the static library into a shared library.
add_library(consumer SHARED consumer.cpp)
target_link_libraries(consumer PRIVATE mkv::gcm)
add_executable(consumer_test main.cpp)
target_link_libraries(consumer_test PRIVATE consumer)
add_test(NAME mkv_consumer COMMAND consumer_test)
