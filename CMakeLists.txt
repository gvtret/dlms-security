cmake_minimum_required(VERSION 3.16)

project(dlms_security
  VERSION 0.1.0
  LANGUAGES C CXX)

option(DLMS_BUILD_TESTS "Build GoogleTest tests" ON)
option(DLMS_USE_SYSTEM_GTEST "Use system-installed GoogleTest" OFF)

add_library(dlms_security
  src/security/in_memory_invocation_counter_store.cpp
  src/security/in_memory_key_store.cpp
  src/security/suite0_aes_gcm.cpp
  src/security/security_status.cpp
  src/security/security_types.cpp)

target_compile_features(dlms_security PUBLIC cxx_std_11)

target_include_directories(dlms_security
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(WIN32)
  target_link_libraries(dlms_security
    PUBLIC
      bcrypt)
endif()

set(DLMS_SECURITY_HAS_API ON CACHE INTERNAL
  "dlms-security exposes the security API required by upper-layer integration tests")

if(DLMS_BUILD_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test/CMakeLists.txt")
  enable_testing()
  add_subdirectory(test)
endif()
